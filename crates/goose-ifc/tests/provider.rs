mod support;

use async_trait::async_trait;
use futures::StreamExt;
use goose_ifc::provider::{stream_with_observer, Observer, ProviderObserver, SourcePolicy};
use goose_ifc::{content_digest, Domain, Label};
use goose_provider_types::base::{MessageStream, Provider};
use goose_provider_types::conversation::message::Message;
use goose_provider_types::errors::ProviderError;
use goose_provider_types::model::ModelConfig;
use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock, Tool};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use support::Log;

#[derive(Default)]
struct Stub {
    requests: Mutex<Vec<Value>>,
    outputs: Vec<Message>,
    hidden_context: bool,
    start_error: bool,
    stream_error: bool,
}

#[async_trait]
impl Provider for Stub {
    fn get_name(&self) -> &str {
        "fixture"
    }
    fn manages_own_context(&self) -> bool {
        self.hidden_context
    }

    async fn stream(
        &self,
        config: &ModelConfig,
        system: &str,
        messages: &[Message],
        tools: &[Tool],
    ) -> Result<MessageStream, ProviderError> {
        self.requests
            .lock()
            .unwrap()
            .push(json!({"config":config,"system":system,"messages":messages,"tools":tools}));
        if self.start_error {
            return Err(ProviderError::RequestFailed(
                "synthetic private error".into(),
            ));
        }
        let mut outputs = self
            .outputs
            .iter()
            .cloned()
            .map(|message| Ok((Some(message), None)))
            .collect::<Vec<_>>();
        if self.stream_error {
            outputs.push(Err(ProviderError::RequestFailed(
                "synthetic stream error".into(),
            )));
        }
        Ok(Box::pin(futures::stream::iter(outputs)))
    }
}

fn shared() -> Label {
    Label::readers("fixture", &["alice", "bob"])
}
fn private() -> Label {
    Label::readers("fixture", &["alice"])
}

struct Fixture {
    config: ModelConfig,
    system: String,
    messages: Vec<Message>,
    tools: Vec<Tool>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            config: ModelConfig::new("fixture-model"),
            system: "synthetic system prompt".into(),
            messages: vec![Message::user().with_text("synthetic task")],
            tools: vec![serde_json::from_value(json!({"name":"fixture.read", "description":"synthetic tool schema", "inputSchema":{"type":"object"}})).unwrap()],
        }
    }

    fn policy(&self) -> SourcePolicy {
        let mut policy = SourcePolicy::default();
        policy.domains.insert(
            "session".into(),
            Domain {
                audience: shared(),
                retained_context: shared(),
                policy_epoch: "fixture-v1".into(),
            },
        );
        for digest in std::iter::once(content_digest(&self.config))
            .chain(std::iter::once(content_digest(&self.system)))
            .chain(self.messages.iter().map(content_digest))
            .chain(self.tools.iter().map(content_digest))
        {
            policy.sources.insert(digest.unwrap(), shared());
        }
        policy
    }

    async fn invoke(
        &self,
        observer: Option<Observer>,
        provider: &Stub,
    ) -> Result<MessageStream, ProviderError> {
        stream_with_observer(
            observer,
            provider,
            "session",
            &self.config,
            &self.system,
            &self.messages,
            &self.tools,
        )
        .await
    }
}

fn observer(log: &Log, policy: SourcePolicy) -> Observer {
    Arc::new(Mutex::new(ProviderObserver::with_policy(
        log.clone(),
        policy,
    )))
}

#[tokio::test]
async fn exact_manifest_and_response_pass_through() {
    let fixture = Fixture::new();
    let output = Message::assistant().with_text("synthetic response");
    let stub = Stub {
        outputs: vec![output.clone()],
        ..Stub::default()
    };
    let log = Log::default();
    let mut stream = fixture
        .invoke(Some(observer(&log, fixture.policy())), &stub)
        .await
        .unwrap();
    assert_eq!(stream.next().await.unwrap().unwrap().0, Some(output));
    assert!(stream.next().await.is_none());
    assert_eq!(
        stub.requests.lock().unwrap().as_slice(),
        &[
            json!({"config":fixture.config,"system":fixture.system,"messages":fixture.messages,"tools":fixture.tools})
        ]
    );
    let records = log.records();
    let call = records
        .iter()
        .find(|record| record["operation"] == "model_call")
        .unwrap();
    assert_eq!(call["label"], json!(shared()));
    assert_eq!(call["inputs_complete"], true);
    for role in ["instructions", "settings", "history", "schemas"] {
        assert_eq!(call["dependencies"][role].as_array().unwrap().len(), 1);
    }
    let response = records.last().unwrap();
    assert_eq!(response["operation"], "model_output");
    assert_eq!(response["dependencies"]["inputs"], json!([call["id"]]));
    assert_eq!(response["label"], json!(shared()));
    assert!(!serde_json::to_string(&records)
        .unwrap()
        .contains("synthetic"));
}

#[tokio::test]
async fn private_schema_labels_every_output_including_proposed_tool_arguments() {
    let fixture = Fixture::new();
    let mut policy = fixture.policy();
    policy
        .sources
        .insert(content_digest(&fixture.tools[0]).unwrap(), private());
    let request = Message::assistant().with_tool_request(
        "opaque-request",
        Ok(CallToolRequestParams::new("fixture.read")),
    );
    let stub = Stub {
        outputs: vec![Message::assistant().with_text("looks harmless"), request],
        ..Stub::default()
    };
    let log = Log::default();
    fixture
        .invoke(Some(observer(&log, policy)), &stub)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await;
    let records = log.records();
    let derived = records
        .iter()
        .filter(|record| {
            ["model_call", "model_output", "tool_request"]
                .contains(&record["operation"].as_str().unwrap())
        })
        .collect::<Vec<_>>();
    assert_eq!(derived.len(), 4);
    assert!(derived
        .iter()
        .all(|record| record["label"] == json!(private())));
}

#[tokio::test]
async fn unclassified_or_stateful_inputs_remain_unknown() {
    let fixture = Fixture::new();
    for hidden in [false, true] {
        let log = Log::default();
        let policy = if hidden {
            fixture.policy()
        } else {
            SourcePolicy::default()
        };
        let stub = Stub {
            hidden_context: hidden,
            outputs: vec![Message::assistant().with_text("result")],
            ..Stub::default()
        };
        fixture
            .invoke(Some(observer(&log, policy)), &stub)
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;
        let records = log.records();
        let call = records
            .iter()
            .find(|record| record["operation"] == "model_call")
            .unwrap();
        assert_eq!(call["label"], json!(Label::Unknown));
        assert_eq!(call["inputs_complete"], !hidden);
        assert_eq!(records.last().unwrap()["label"], json!(Label::Unknown));
    }
}

#[tokio::test]
async fn tool_result_observation_links_the_source_and_request_without_reexecuting() {
    let mut fixture = Fixture::new();
    let request = Message::assistant()
        .with_tool_request("request", Ok(CallToolRequestParams::new("fixture.read")));
    let result = Message::user().with_tool_response(
        "request",
        Ok(CallToolResult::success(vec![ContentBlock::text(
            "synthetic private result",
        )])),
    );
    let mut policy = fixture.policy();
    policy
        .sources
        .insert(content_digest(&result).unwrap(), private());
    policy.sources.insert(
        content_digest(result.content[0].as_tool_response().unwrap()).unwrap(),
        private(),
    );
    let log = Log::default();
    let observer = observer(&log, policy);
    let stub = Stub {
        outputs: vec![request],
        ..Stub::default()
    };
    fixture
        .invoke(Some(observer.clone()), &stub)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await;
    fixture.messages.push(result);
    fixture
        .invoke(Some(observer), &Stub::default())
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await;
    let records = log.records();
    let tool_request = records
        .iter()
        .find(|record| record["operation"] == "tool_request")
        .unwrap();
    let tool_result = records
        .iter()
        .find(|record| record["operation"] == "tool_result")
        .unwrap();
    assert_eq!(
        tool_result["dependencies"]["control"],
        json!([tool_request["id"]])
    );
    assert_eq!(tool_result["label"], json!(private()));
    assert_eq!(records.last().unwrap()["label"], json!(private()));
    assert_eq!(stub.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn errors_and_disabled_observation_preserve_provider_behavior() {
    let fixture = Fixture::new();
    let stub = Stub {
        start_error: true,
        ..Stub::default()
    };
    let log = Log::default();
    let result = fixture
        .invoke(Some(observer(&log, fixture.policy())), &stub)
        .await;
    assert!(
        matches!(result, Err(ProviderError::RequestFailed(message)) if message == "synthetic private error")
    );
    assert!(log
        .records()
        .iter()
        .any(|record| record["operation"] == "error"));
    assert_eq!(
        log.records().last().unwrap()["label"],
        json!(Label::Unknown)
    );
    let stub = Stub {
        stream_error: true,
        ..Stub::default()
    };
    for enabled in [false, true] {
        let observer = enabled.then(|| observer(&log, fixture.policy()));
        let mut stream = fixture.invoke(observer, &stub).await.unwrap();
        assert!(
            matches!(stream.next().await, Some(Err(ProviderError::RequestFailed(message))) if message == "synthetic stream error")
        );
    }
    assert_eq!(stub.requests.lock().unwrap().len(), 2);
}

#[test]
fn model_authored_extra_policy_fields_are_not_accepted() {
    assert!(serde_json::from_value::<SourcePolicy>(
        json!({"domains":{},"sources":{},"grant":"admin"})
    )
    .is_err());
}

#[tokio::test]
async fn an_error_controlled_retry_cannot_reset_the_context() {
    let fixture = Fixture::new();
    let log = Log::default();
    let observer = observer(&log, fixture.policy());
    let failing = Stub {
        start_error: true,
        ..Stub::default()
    };
    assert!(fixture
        .invoke(Some(observer.clone()), &failing)
        .await
        .is_err());
    fixture
        .invoke(Some(observer), &Stub::default())
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await;
    let records = log.records();
    assert_eq!(records.last().unwrap()["operation"], "model_call");
    assert_eq!(records.last().unwrap()["label"], json!(Label::Unknown));
}

#[tokio::test]
async fn eviction_cannot_reapply_a_clean_initial_domain() {
    let fixture = Fixture::new();
    let log = Log::default();
    let observer = observer(&log, fixture.policy());
    let provider = Stub::default();
    fixture
        .invoke(Some(observer.clone()), &provider)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await;
    for index in 0..64 {
        stream_with_observer(
            Some(observer.clone()),
            &provider,
            &format!("other-{index}"),
            &fixture.config,
            &fixture.system,
            &fixture.messages,
            &fixture.tools,
        )
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await;
    }
    fixture
        .invoke(Some(observer), &provider)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await;
    assert_eq!(
        log.records().last().unwrap()["label"],
        json!(Label::Unknown)
    );
}

#[tokio::test]
async fn a_failed_trace_sink_does_not_change_the_stream() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("unavailable"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let fixture = Fixture::new();
    let output = Message::assistant().with_text("response");
    let provider = Stub {
        outputs: vec![output.clone()],
        ..Stub::default()
    };
    let observer = Arc::new(Mutex::new(ProviderObserver::new(Broken)));
    let mut stream = fixture.invoke(Some(observer), &provider).await.unwrap();
    assert_eq!(stream.next().await.unwrap().unwrap().0, Some(output));
    assert!(stream.next().await.is_none());
    assert_eq!(provider.requests.lock().unwrap().len(), 1);
}
