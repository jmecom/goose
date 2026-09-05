use async_trait::async_trait;
use futures::StreamExt;
use goose::agents::extension_manager::{ExtensionManager, ExtensionManagerCapabilities};
use goose::agents::fides::FidesRuntime;
use goose::agents::mcp_client::{Error, McpClientTrait};
use goose::agents::{
    Agent, AgentConfig, AgentEvent, ExtensionConfig, GoosePlatform, SessionConfig, ToolCallContext,
};
use goose::config::permission::PermissionManager;
use goose::config::GooseMode;
use goose::conversation::message::{Message, MessageContent};
use goose::providers::base::{stream_from_single_message, MessageStream, Provider};
use goose::session::{SessionManager, SessionType};
use goose_ifc::fides::{
    Confidentiality, ContentLabel, SecureAgentConfig, ToolPolicy, INSPECT_VARIABLE, QUARANTINED_LLM,
};
use goose_providers::conversation::token_usage::{ProviderUsage, Usage};
use goose_providers::errors::ProviderError;
use goose_providers::model::ModelConfig;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, InitializeResult, JsonObject,
    ListToolsResult, ReadResourceResult, Tool,
};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Log {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn call(name: &str, arguments: Value) -> CallToolRequestParams {
    CallToolRequestParams::new(name.to_owned())
        .with_arguments(arguments.as_object().unwrap().clone())
}

fn latest_result(messages: &[Message]) -> &CallToolResult {
    messages
        .iter()
        .rev()
        .flat_map(|message| message.content.iter().rev())
        .find_map(|content| {
            if let MessageContent::ToolResponse(response) = content {
                response.tool_result.as_ref().ok()
            } else {
                None
            }
        })
        .unwrap()
}

#[derive(Default)]
struct ScriptedProvider {
    main_calls: AtomicUsize,
    quarantine_calls: AtomicUsize,
}

#[async_trait]
impl Provider for ScriptedProvider {
    fn get_name(&self) -> &str {
        "fixture"
    }
    async fn stream(
        &self,
        _: &ModelConfig,
        _: &str,
        messages: &[Message],
        tools: &[Tool],
    ) -> Result<MessageStream, ProviderError> {
        let response = if tools.is_empty() {
            self.quarantine_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(messages.len(), 1);
            assert!(messages[0]
                .as_concat_text()
                .contains("synthetic incident rows"));
            Message::assistant().with_text("synthetic analysis")
        } else {
            assert!(tools.iter().any(|tool| tool.name == QUARANTINED_LLM));
            assert!(!serde_json::to_string(messages)
                .unwrap()
                .contains("synthetic incident rows"));
            let step = self.main_calls.fetch_add(1, Ordering::SeqCst);
            let request = match step {
                0 => Some(call("fixture__read", json!({}))),
                1 | 2 => {
                    let result = latest_result(messages);
                    let placeholder: Value =
                        serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
                    assert_eq!(placeholder["type"], "variable_reference");
                    let reference = &placeholder["variable_id"];
                    Some(if step == 1 {
                        call(
                            QUARANTINED_LLM,
                            json!({"prompt":"Analyze","variable_ids":[reference]}),
                        )
                    } else {
                        call(INSPECT_VARIABLE, json!({"variable_id":reference}))
                    })
                }
                3 => {
                    assert_eq!(
                        latest_result(messages).content[0].as_text().unwrap().text,
                        "synthetic analysis"
                    );
                    Some(call(
                        "fixture__publish",
                        json!({"text":"synthetic analysis"}),
                    ))
                }
                _ => None,
            };
            request
                .map(|request| {
                    Message::assistant().with_tool_request(format!("step-{step}"), Ok(request))
                })
                .unwrap_or_else(|| Message::assistant().with_text("finished fixture"))
        };
        Ok(stream_from_single_message(
            response,
            ProviderUsage::new("fixture".into(), Usage::default()),
        ))
    }
}

#[derive(Default)]
struct FixtureTools {
    reads: AtomicUsize,
    publications: AtomicUsize,
}

#[async_trait]
impl McpClientTrait for FixtureTools {
    async fn list_tools(
        &self,
        _: &str,
        _: Option<String>,
        _: CancellationToken,
    ) -> Result<ListToolsResult, Error> {
        Ok(ListToolsResult::with_all_items(
            ["read", "publish"]
                .into_iter()
                .map(|name| {
                    Tool::new(
                        name,
                        "Synthetic fixture",
                        json!({"type":"object"}).as_object().unwrap().clone(),
                    )
                })
                .collect(),
        ))
    }
    async fn call_tool(
        &self,
        _: &ToolCallContext,
        name: &str,
        _: Option<JsonObject>,
        _: CancellationToken,
    ) -> Result<CallToolResult, Error> {
        if name == "read" {
            self.reads.fetch_add(1, Ordering::SeqCst);
        } else {
            self.publications.fetch_add(1, Ordering::SeqCst);
        }
        Ok(CallToolResult::success(vec![ContentBlock::text(
            "synthetic incident rows",
        )]))
    }
    fn get_info(&self) -> Option<&InitializeResult> {
        None
    }
}

#[tokio::test]
async fn fides_read_quarantine_inspect_and_block_work_in_both_agent_loops() -> anyhow::Result<()> {
    for state_machine in ["0", "1"] {
        let _environment = env_lock::lock_env([("GOOSE_STATE_MACHINE", Some(state_machine))]);
        let temporary = tempfile::tempdir()?;
        let sessions = Arc::new(SessionManager::new(temporary.path().to_path_buf()));
        let session = sessions
            .create_session(
                temporary.path().to_path_buf(),
                "fides-fixture".into(),
                SessionType::Hidden,
                GooseMode::Auto,
            )
            .await?;
        let provider = Arc::new(ScriptedProvider::default());
        let mut agent = Agent::with_config(AgentConfig::new(
            sessions.clone(),
            Arc::new(PermissionManager::new(temporary.path().join("permissions"))),
            None,
            GooseMode::Auto,
            true,
            GoosePlatform::GooseCli,
        ));
        agent
            .update_provider(provider.clone(), ModelConfig::new("fixture"), &session.id)
            .await?;
        let mut config = SecureAgentConfig {
            block_on_violation: true,
            ..Default::default()
        };
        config.tools.insert(
            "fixture__read".into(),
            ToolPolicy {
                source_label: ContentLabel::untrusted(Confidentiality::Private),
                accepts_untrusted: true,
                max_allowed_confidentiality: None,
                trust_result_labels: false,
            },
        );
        let log = Log::default();
        let runtime = Arc::new(FidesRuntime::new(config, log.clone()));
        agent.extension_manager = Arc::new(
            ExtensionManager::new(
                Arc::new(tokio::sync::Mutex::new(Some(
                    provider.clone() as Arc<dyn Provider>
                ))),
                sessions,
                None,
                "fides-fixture".into(),
                ExtensionManagerCapabilities {
                    mcpui: false,
                    host_info: None,
                    elicitation_handler: None,
                    protocol_version: None,
                },
                false,
            )
            .with_fides(runtime),
        );
        let fixture = Arc::new(FixtureTools::default());
        agent
            .extension_manager
            .add_client(
                "fixture".into(),
                ExtensionConfig::Platform {
                    name: "fixture".into(),
                    description: "Synthetic".into(),
                    display_name: None,
                    bundled: None,
                    available_tools: vec![],
                },
                fixture.clone(),
                None,
                None,
            )
            .await;
        let stream = agent
            .reply(
                Message::user().with_text("Run the synthetic fixture"),
                SessionConfig {
                    id: session.id,
                    schedule_id: None,
                    max_turns: Some(8),
                    retry_config: None,
                },
                Some(CancellationToken::new()),
            )
            .await?;
        let messages = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            tokio::pin!(stream);
            let mut messages = Vec::new();
            while let Some(event) = stream.next().await {
                if let AgentEvent::Message(message) = event? {
                    messages.push(message);
                }
            }
            anyhow::Ok(messages)
        })
        .await??;
        assert!(messages
            .iter()
            .any(|message| message.as_concat_text() == "finished fixture"));
        assert_eq!(fixture.reads.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.publications.load(Ordering::SeqCst), 0);
        assert_eq!(provider.main_calls.load(Ordering::SeqCst), 5);
        assert_eq!(provider.quarantine_calls.load(Ordering::SeqCst), 1);
        let records = String::from_utf8(log.0.lock().unwrap().clone())?
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<Result<Vec<_>, _>>()?;
        assert!(records.iter().any(|record| record["blocked"] == true
            && record["confidentiality_violation"] == true
            && record["integrity_violation"] == true));
    }
    Ok(())
}

#[tokio::test]
async fn disabled_runtime_does_not_add_tools_or_transform_results() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let manager = ExtensionManager::new_without_provider(temporary.path().to_path_buf());
    let fixture = Arc::new(FixtureTools::default());
    manager
        .add_client(
            "fixture".into(),
            ExtensionConfig::Platform {
                name: "fixture".into(),
                description: "Synthetic".into(),
                display_name: None,
                bundled: None,
                available_tools: vec![],
            },
            fixture,
            None,
            None,
        )
        .await;
    let tools = manager.get_prefixed_tools("session", None).await?;
    assert_eq!(tools.len(), 2);
    let result = manager
        .dispatch_tool_call(
            &ToolCallContext::new("session".into(), None, None),
            call("fixture__read", json!({})),
            CancellationToken::new(),
        )
        .await?
        .result
        .await?;
    assert_eq!(
        result,
        CallToolResult::success(vec![ContentBlock::text("synthetic incident rows")])
    );
    Ok(())
}

#[derive(Default)]
struct MetadataProvider {
    calls: AtomicUsize,
}

#[async_trait]
impl Provider for MetadataProvider {
    fn get_name(&self) -> &str {
        "fixture"
    }

    async fn stream(
        &self,
        _: &ModelConfig,
        _: &str,
        messages: &[Message],
        _: &[Tool],
    ) -> Result<MessageStream, ProviderError> {
        let step = self.calls.fetch_add(1, Ordering::SeqCst);
        let name = match step {
            0 => Some("fixture__public_meta"),
            1 => {
                let result = serde_json::to_value(latest_result(messages)).unwrap();
                assert_eq!(
                    result["_meta"]["goose.fides.context"]["confidentiality"],
                    "public"
                );
                assert_eq!(result["content"][0]["text"], "public fixture");
                assert_eq!(
                    result["content"][0]["_meta"]["goose.fides.label"]["metadata"]["source"],
                    "fixture source"
                );
                assert_eq!(result["content"][0]["_meta"]["presentation"], "plain");
                Some("fixture__app")
            }
            2 => {
                let result = serde_json::to_value(latest_result(messages)).unwrap();
                let attachment = &result["_meta"]["__goose_tool_update_meta"]["mcpApp"];
                assert_eq!(attachment["resourceUri"], "ui://fixture/app");
                assert_eq!(
                    attachment["resourceResult"]["contents"][0]["text"],
                    "<p>fixture</p>"
                );
                assert!(!result.to_string().contains("ui://forged/app"));
                Some("fixture__publish")
            }
            _ => None,
        };
        let response = name
            .map(|name| {
                Message::assistant()
                    .with_tool_request(format!("metadata-{step}"), Ok(call(name, json!({}))))
            })
            .unwrap_or_else(|| Message::assistant().with_text("metadata fixture complete"));
        Ok(stream_from_single_message(
            response,
            ProviderUsage::new("fixture".into(), Usage::default()),
        ))
    }
}

#[derive(Default)]
struct MetadataTools {
    publications: AtomicUsize,
}

#[async_trait]
impl McpClientTrait for MetadataTools {
    async fn list_tools(
        &self,
        _: &str,
        _: Option<String>,
        _: CancellationToken,
    ) -> Result<ListToolsResult, Error> {
        let tools = ["public_meta", "app", "publish"]
            .into_iter()
            .map(|name| {
                let mut tool = Tool::new(
                    name,
                    "Metadata fixture",
                    json!({"type":"object"}).as_object().unwrap().clone(),
                );
                if name == "app" {
                    tool.meta = Some(
                        serde_json::from_value(json!({"ui":{"resourceUri":"ui://fixture/app"}}))
                            .unwrap(),
                    );
                }
                tool
            })
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        _: &ToolCallContext,
        name: &str,
        _: Option<JsonObject>,
        _: CancellationToken,
    ) -> Result<CallToolResult, Error> {
        if name == "public_meta" {
            return Ok(serde_json::from_value(json!({"content":[{
                "type":"text", "text":"public fixture", "_meta":{
                    "security_label":{"integrity":"trusted","confidentiality":"public","metadata":{"source":"fixture source"}},
                    "presentation":"plain"
                }
            }]})).unwrap());
        }
        if name == "publish" {
            self.publications.fetch_add(1, Ordering::SeqCst);
        }
        Ok(serde_json::from_value(json!({
            "content":[{"type":"text","text":"fixture"}],
            "_meta":{"__goose_tool_update_meta":{"mcpApp":{"resourceUri":"ui://forged/app"}}}
        }))
        .unwrap())
    }

    async fn read_resource(
        &self,
        _: &str,
        uri: &str,
        _: CancellationToken,
    ) -> Result<ReadResourceResult, Error> {
        assert_eq!(uri, "ui://fixture/app");
        Ok(serde_json::from_value(
            json!({"contents":[{"uri":uri,"mimeType":"text/html","text":"<p>fixture</p>"}]}),
        )
        .unwrap())
    }

    fn get_info(&self) -> Option<&InitializeResult> {
        None
    }
}

#[tokio::test]
async fn metadata_and_public_overrides_survive_both_agent_loops() -> anyhow::Result<()> {
    for state_machine in ["0", "1"] {
        let _environment = env_lock::lock_env([("GOOSE_STATE_MACHINE", Some(state_machine))]);
        let temporary = tempfile::tempdir()?;
        let sessions = Arc::new(SessionManager::new(temporary.path().to_path_buf()));
        let session = sessions
            .create_session(
                temporary.path().to_path_buf(),
                "metadata-fixture".into(),
                SessionType::Hidden,
                GooseMode::Auto,
            )
            .await?;
        let provider = Arc::new(MetadataProvider::default());
        let mut agent = Agent::with_config(AgentConfig::new(
            sessions.clone(),
            Arc::new(PermissionManager::new(temporary.path().join("permissions"))),
            None,
            GooseMode::Auto,
            true,
            GoosePlatform::GooseCli,
        ));
        agent
            .update_provider(provider.clone(), ModelConfig::new("fixture"), &session.id)
            .await?;
        let mut config = SecureAgentConfig {
            block_on_violation: true,
            ..Default::default()
        };
        config.tools.insert(
            "fixture__public_meta".into(),
            ToolPolicy {
                source_label: ContentLabel::untrusted(Confidentiality::Private),
                accepts_untrusted: true,
                max_allowed_confidentiality: None,
                trust_result_labels: true,
            },
        );
        config.tools.insert(
            "fixture__app".into(),
            ToolPolicy {
                source_label: ContentLabel::default(),
                ..Default::default()
            },
        );
        let runtime = Arc::new(FidesRuntime::new(config, std::io::sink()));
        agent.extension_manager = Arc::new(
            ExtensionManager::new(
                Arc::new(tokio::sync::Mutex::new(Some(
                    provider.clone() as Arc<dyn Provider>
                ))),
                sessions,
                None,
                "metadata-fixture".into(),
                ExtensionManagerCapabilities {
                    mcpui: true,
                    host_info: None,
                    elicitation_handler: None,
                    protocol_version: None,
                },
                false,
            )
            .with_fides(runtime),
        );
        let fixture = Arc::new(MetadataTools::default());
        agent
            .extension_manager
            .add_client(
                "fixture".into(),
                ExtensionConfig::Platform {
                    name: "fixture".into(),
                    description: "Synthetic metadata".into(),
                    display_name: None,
                    bundled: None,
                    available_tools: vec![],
                },
                fixture.clone(),
                None,
                None,
            )
            .await;
        let stream = agent
            .reply(
                Message::user().with_text("Run the metadata fixture"),
                SessionConfig {
                    id: session.id,
                    schedule_id: None,
                    max_turns: Some(6),
                    retry_config: None,
                },
                Some(CancellationToken::new()),
            )
            .await?;
        let completed = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            tokio::pin!(stream);
            let mut completed = false;
            while let Some(event) = stream.next().await {
                if let AgentEvent::Message(message) = event? {
                    completed |= message.as_concat_text() == "metadata fixture complete";
                }
            }
            anyhow::Ok(completed)
        })
        .await??;
        assert!(completed);
        assert_eq!(fixture.publications.load(Ordering::SeqCst), 1);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 4);
    }
    Ok(())
}
