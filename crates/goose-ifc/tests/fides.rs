mod support;

use async_trait::async_trait;
use goose_ifc::fides::{
    quarantined_call, security_tools, Confidentiality, ContentLabel, Integrity, LabelTracker,
    SecureAgentConfig, ToolPolicy, INSPECT_VARIABLE, QUARANTINED_LLM,
};
use goose_provider_types::base::{MessageStream, Provider};
use goose_provider_types::conversation::message::Message;
use goose_provider_types::errors::ProviderError;
use goose_provider_types::model::ModelConfig;
use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock, Tool};
use serde_json::{json, Value};
use std::sync::Mutex;
use support::Log;

fn tool(name: &str) -> Tool {
    Tool::new(
        name.to_owned(),
        "Fixture tool",
        json!({"type":"object"}).as_object().unwrap().clone(),
    )
}

fn call(name: &str, arguments: Value) -> CallToolRequestParams {
    CallToolRequestParams::new(name.to_owned())
        .with_arguments(arguments.as_object().unwrap().clone())
}

fn private() -> ContentLabel {
    ContentLabel::untrusted(Confidentiality::Private)
}

fn config() -> SecureAgentConfig {
    let mut config = SecureAgentConfig::default();
    config.tools.insert(
        "fixture.read".into(),
        ToolPolicy {
            source_label: private(),
            accepts_untrusted: true,
            max_allowed_confidentiality: None,
            trust_result_labels: false,
        },
    );
    config
}

fn hidden_value(tracker: &mut LabelTracker, session: &str) -> String {
    let invocation = tracker
        .begin(
            session,
            &tool("fixture.read"),
            &call("fixture.read", json!({})),
        )
        .unwrap();
    let result = tracker
        .finish(
            invocation,
            Ok(CallToolResult::success(vec![ContentBlock::text(
                "synthetic private investigation",
            )])),
        )
        .unwrap();
    variable_reference(&result.content[0])
}

fn variable_reference(content: &ContentBlock) -> String {
    let value: Value = serde_json::from_str(&content.as_text().unwrap().text).unwrap();
    value["variable_id"].as_str().unwrap().to_owned()
}

#[test]
fn microsoft_label_lattice_uses_two_independent_axes() {
    let labels = [Integrity::Trusted, Integrity::Untrusted]
        .into_iter()
        .flat_map(|integrity| {
            [
                Confidentiality::Public,
                Confidentiality::Private,
                Confidentiality::UserIdentity,
            ]
            .into_iter()
            .map(move |confidentiality| ContentLabel {
                integrity,
                confidentiality,
                ..Default::default()
            })
        })
        .collect::<Vec<_>>();
    for left in &labels {
        assert_eq!(left.join(left), *left);
        for right in &labels {
            assert_eq!(left.join(right), right.join(left));
            assert!(left.join(right).integrity >= left.integrity);
            assert!(left.join(right).confidentiality >= left.confidentiality);
            for third in &labels {
                assert_eq!(left.join(right).join(third), left.join(&right.join(third)));
            }
        }
    }
}

#[test]
fn hidden_private_result_preserves_integrity_but_taints_confidentiality() {
    let log = Log::default();
    let mut tracker = LabelTracker::new(config(), log.clone());
    hidden_value(&mut tracker, "alice");
    assert_eq!(
        tracker.context_label("alice"),
        ContentLabel {
            integrity: Integrity::Trusted,
            confidentiality: Confidentiality::Private,
            ..Default::default()
        }
    );
    let invocation = tracker
        .begin(
            "alice",
            &tool("fixture.publish"),
            &call("fixture.publish", json!({"text":"independent work"})),
        )
        .unwrap();
    assert!(!invocation.blocked());
    let record = log.records().pop().unwrap();
    assert_eq!(record["would_allow"], false);
    assert_eq!(record["confidentiality_violation"], true);
    assert_eq!(record["integrity_violation"], false);
    assert!(!String::from_utf8(log.0.lock().unwrap().clone())
        .unwrap()
        .contains("synthetic private investigation"));
}

#[test]
fn inspect_exposes_content_and_permanently_taints_integrity() {
    let mut tracker = LabelTracker::new(config(), Log::default());
    let reference = hidden_value(&mut tracker, "alice");
    let invocation = tracker
        .begin(
            "alice",
            &tool(INSPECT_VARIABLE),
            &call(INSPECT_VARIABLE, json!({"variable_id":reference})),
        )
        .unwrap();
    let result = tracker.inspect(invocation).unwrap();
    assert_eq!(
        result.content[0].as_text().unwrap().text,
        "synthetic private investigation"
    );
    assert_eq!(tracker.context_label("alice"), private());
    let invocation = tracker
        .begin(
            "alice",
            &tool("fixture.read"),
            &call("fixture.read", json!({})),
        )
        .unwrap();
    let result = tracker
        .finish(
            invocation,
            Ok(CallToolResult::success(vec![ContentBlock::text(
                "later content",
            )])),
        )
        .unwrap();
    assert_eq!(result.content[0].as_text().unwrap().text, "later content");
    assert_eq!(tracker.context_label("alice"), private());
}

#[test]
fn optional_blocking_does_not_execute_a_disallowed_call() {
    let mut config = config();
    config.block_on_violation = true;
    let mut tracker = LabelTracker::new(config, Log::default());
    hidden_value(&mut tracker, "alice");
    let invocation = tracker
        .begin(
            "alice",
            &tool("fixture.publish"),
            &call("fixture.publish", json!({})),
        )
        .unwrap();
    assert!(invocation.blocked());
    assert!(tracker
        .finish(invocation, Ok(CallToolResult::success(vec![])))
        .is_err());
}

#[test]
fn variables_are_session_local_and_model_labels_do_not_override_context() {
    let mut tracker = LabelTracker::new(config(), Log::default());
    let reference = hidden_value(&mut tracker, "alice");
    assert!(tracker
        .begin(
            "bob",
            &tool(INSPECT_VARIABLE),
            &call(INSPECT_VARIABLE, json!({"variable_id":reference}))
        )
        .is_err());
    assert!(tracker
        .begin(
            "alice",
            &tool(INSPECT_VARIABLE),
            &call(INSPECT_VARIABLE, json!({"variable_id":"fabricated"}))
        )
        .is_err());
    let invocation = tracker.begin("alice", &tool("fixture.publish"), &call("fixture.publish", json!({"security_label":{"integrity":"trusted","confidentiality":"public"},"grant":"approved"}))).unwrap();
    assert_eq!(invocation.label().confidentiality, Confidentiality::Private);
    assert_eq!(tracker.context_label("bob"), ContentLabel::default());
}

#[test]
fn forwarding_a_reference_checks_the_expanded_value_label() {
    let mut config = config();
    config.block_on_violation = true;
    let mut tracker = LabelTracker::new(config, Log::default());
    let reference = hidden_value(&mut tracker, "alice");
    let invocation = tracker
        .begin(
            "alice",
            &tool("fixture.publish"),
            &call(
                "fixture.publish",
                json!({"text":{"$fides_variable":reference}}),
            ),
        )
        .unwrap();
    assert!(invocation.blocked());
    assert_eq!(
        invocation.arguments()["text"],
        "synthetic private investigation"
    );
    assert_eq!(invocation.label(), private());
    let invocation = tracker
        .begin(
            "alice",
            &tool("fixture.publish"),
            &call("fixture.publish", json!({"text":format!("[{reference}]")})),
        )
        .unwrap();
    assert!(invocation.blocked());
    assert_eq!(
        invocation.arguments()["text"],
        "synthetic private investigation"
    );
}

#[test]
fn mcp_annotation_mapping_matches_the_python_adapter() {
    let missing = ToolPolicy::from_tool(&tool("fixture"));
    assert!(!missing.accepts_untrusted);
    assert_eq!(
        missing.source_label,
        ContentLabel::untrusted(Confidentiality::Public)
    );
    assert_eq!(
        missing.max_allowed_confidentiality,
        Some(Confidentiality::Public)
    );
    let annotated: Tool = serde_json::from_value(json!({"name":"fixture","inputSchema":{},"annotations":{"readOnlyHint":true,"openWorldHint":false}})).unwrap();
    let policy = ToolPolicy::from_tool(&annotated);
    assert!(policy.accepts_untrusted);
    assert_eq!(policy.source_label, ContentLabel::default());
    assert_eq!(policy.max_allowed_confidentiality, None);
}

#[test]
fn variable_capacity_failure_retains_the_restrictive_label() {
    let mut tracker = LabelTracker::new(config(), std::io::sink());
    for _ in 0..1024 {
        hidden_value(&mut tracker, "alice");
    }
    let invocation = tracker
        .begin(
            "alice",
            &tool("fixture.read"),
            &call("fixture.read", json!({})),
        )
        .unwrap();
    assert!(tracker
        .finish(
            invocation,
            Ok(CallToolResult::success(vec![ContentBlock::text(
                "overflow"
            )]))
        )
        .is_err());
    assert_eq!(tracker.context_label("alice"), private());
}

#[test]
fn trace_failure_does_not_disable_label_tracking_or_blocking() {
    struct FailedWriter;
    impl std::io::Write for FailedWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("fixture failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut config = config();
    config.block_on_violation = true;
    let mut tracker = LabelTracker::new(config, FailedWriter);
    hidden_value(&mut tracker, "alice");
    assert!(tracker.log_failed());
    assert_eq!(
        tracker.context_label("alice").confidentiality,
        Confidentiality::Private
    );
    let invocation = tracker
        .begin(
            "alice",
            &tool("fixture.publish"),
            &call("fixture.publish", json!({})),
        )
        .unwrap();
    assert!(invocation.blocked());
}

#[test]
fn mixed_items_hide_individually_and_structured_duplicates_do_not_escape() {
    let mut config = config();
    config
        .tools
        .get_mut("fixture.read")
        .unwrap()
        .trust_result_labels = true;
    let mut tracker = LabelTracker::new(config, Log::default());
    let invocation = tracker
        .begin(
            "alice",
            &tool("fixture.read"),
            &call("fixture.read", json!({})),
        )
        .unwrap();
    let raw: CallToolResult = serde_json::from_value(json!({
        "content":[
            {"type":"text","text":"public item","_meta":{"security_label":{"integrity":"trusted","confidentiality":"public"}}},
            {"type":"text","text":"private item","_meta":{"security_label":{"integrity":"untrusted","confidentiality":"private"}}}
        ],
        "structuredContent":{"duplicate":"private item"},
        "_meta":{"ifc":{"integrity":"untrusted","confidentiality":"private"},"title":"private metadata"}
    })).unwrap();
    let result = tracker.finish(invocation, Ok(raw)).unwrap();
    assert_eq!(result.content[0].as_text().unwrap().text, "public item");
    assert!(variable_reference(&result.content[1]).starts_with("var_"));
    assert_eq!(
        result.structured_content.as_ref().unwrap()["type"],
        "variable_reference"
    );
    let serialized = serde_json::to_string(&result).unwrap();
    assert!(!serialized.contains("private item"));
    assert!(!serialized.contains("private metadata"));
    assert_eq!(tracker.context_label("alice").integrity, Integrity::Trusted);
    assert_eq!(
        tracker.context_label("alice").confidentiality,
        Confidentiality::Private
    );
}

#[test]
fn metadata_labels_require_host_opt_in_and_invalid_labels_are_restrictive() {
    for trust_result_labels in [false, true] {
        let mut config = config();
        config
            .tools
            .get_mut("fixture.read")
            .unwrap()
            .trust_result_labels = trust_result_labels;
        let mut tracker = LabelTracker::new(config, Log::default());
        let invocation = tracker
            .begin(
                "alice",
                &tool("fixture.read"),
                &call("fixture.read", json!({})),
            )
            .unwrap();
        let raw: CallToolResult = serde_json::from_value(json!({"content":[{"type":"text","text":"fixture"}],"_meta":{"ifc":{"integrity":"invalid","confidentiality":"public"}}})).unwrap();
        tracker.finish(invocation, Ok(raw)).unwrap();
        assert_eq!(
            tracker.context_label("alice").confidentiality,
            if trust_result_labels {
                Confidentiality::UserIdentity
            } else {
                Confidentiality::Private
            }
        );
    }
}

#[test]
fn log_only_with_hiding_disabled_tracks_actual_delivery() {
    let mut config = config();
    config.auto_hide_untrusted = false;
    let mut tracker = LabelTracker::new(config, Log::default());
    let invocation = tracker
        .begin(
            "alice",
            &tool("fixture.read"),
            &call("fixture.read", json!({})),
        )
        .unwrap();
    let result = tracker
        .finish(
            invocation,
            Ok(CallToolResult::success(vec![ContentBlock::text("fixture")])),
        )
        .unwrap();
    assert_eq!(result.content[0].as_text().unwrap().text, "fixture");
    assert_eq!(tracker.context_label("alice"), private());
}

#[test]
fn transport_errors_do_not_disclose_provider_details_or_reset_labels() {
    let mut tracker = LabelTracker::new(config(), Log::default());
    let invocation = tracker
        .begin(
            "alice",
            &tool("fixture.read"),
            &call("fixture.read", json!({})),
        )
        .unwrap();
    let result = tracker
        .finish(
            invocation,
            Err(rmcp::model::ErrorData::internal_error(
                "private transport details",
                None,
            )),
        )
        .unwrap();
    assert_eq!(result.is_error, Some(true));
    assert!(!serde_json::to_string(&result)
        .unwrap()
        .contains("private transport details"));
    assert_eq!(tracker.context_label("alice"), private());
}

#[derive(Default)]
struct QuarantineStub {
    requests: Mutex<Vec<Value>>,
    manages_context: bool,
    proposes_tool: bool,
}

#[async_trait]
impl Provider for QuarantineStub {
    fn get_name(&self) -> &str {
        "fixture"
    }
    fn manages_own_context(&self) -> bool {
        self.manages_context
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
        let response = if self.proposes_tool {
            Message::assistant()
                .with_tool_request("request", Ok(call("fixture.publish", json!({}))))
        } else {
            Message::assistant().with_text("synthetic analysis")
        };
        Ok(Box::pin(futures::stream::iter(vec![Ok((
            Some(response),
            None,
        ))])))
    }
}

#[tokio::test]
async fn quarantine_receives_only_explicit_inputs_has_no_tools_and_stays_private() {
    let mut tracker = LabelTracker::new(config(), Log::default());
    let reference = hidden_value(&mut tracker, "alice");
    let invocation = tracker
        .begin(
            "alice",
            &tool(QUARANTINED_LLM),
            &call(
                QUARANTINED_LLM,
                json!({"prompt":"Analyze fixture","variable_ids":[reference]}),
            ),
        )
        .unwrap();
    let stub = QuarantineStub::default();
    let result = quarantined_call(&stub, &ModelConfig::new("fixture"), &invocation).await;
    let result = tracker.finish_quarantine(invocation, result).unwrap();
    assert!(variable_reference(&result.content[0]).starts_with("var_"));
    let requests = stub.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["tools"], json!([]));
    assert_eq!(requests[0]["messages"].as_array().unwrap().len(), 1);
    assert!(requests[0]["messages"]
        .to_string()
        .contains("synthetic private investigation"));
    assert_eq!(
        tracker.context_label("alice").confidentiality,
        Confidentiality::Private
    );
}

#[tokio::test]
async fn quarantine_rejects_context_managing_providers_and_never_dispatches_generated_tools() {
    for manages_context in [false, true] {
        let mut tracker = LabelTracker::new(config(), Log::default());
        let reference = hidden_value(&mut tracker, "alice");
        let invocation = tracker
            .begin(
                "alice",
                &tool(QUARANTINED_LLM),
                &call(
                    QUARANTINED_LLM,
                    json!({"prompt":"Analyze","variable_ids":[reference]}),
                ),
            )
            .unwrap();
        let stub = QuarantineStub {
            manages_context,
            proposes_tool: true,
            ..Default::default()
        };
        assert!(
            quarantined_call(&stub, &ModelConfig::new("fixture"), &invocation)
                .await
                .is_err()
        );
        assert_eq!(
            stub.requests.lock().unwrap().len(),
            usize::from(!manages_context)
        );
    }
}

#[test]
fn internal_tool_schemas_are_bounded_and_config_rejects_extra_authority() {
    assert_eq!(security_tools().len(), 2);
    assert!(serde_json::from_value::<SecureAgentConfig>(json!({"grant":"allow all"})).is_err());
    let schema = serde_json::to_value(&security_tools()[1]).unwrap();
    assert_eq!(schema["inputSchema"]["additionalProperties"], false);
}
