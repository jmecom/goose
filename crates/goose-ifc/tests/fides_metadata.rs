mod support;

use goose_ifc::fides::{
    Confidentiality, ContentLabel, LabelTracker, SecureAgentConfig, ToolPolicy, INSPECT_VARIABLE,
};
use rmcp::model::{CallToolRequestParams, CallToolResult, Tool};
use serde_json::{json, Value};
use support::Log;

fn tool(name: &str) -> Tool {
    Tool::new(name.to_owned(), "Metadata fixture", serde_json::Map::new())
}

fn tracker(source_label: ContentLabel, log: Log) -> LabelTracker {
    let mut config = SecureAgentConfig::default();
    config.tools.insert(
        "fixture".into(),
        ToolPolicy {
            source_label,
            accepts_untrusted: true,
            max_allowed_confidentiality: None,
            trust_result_labels: true,
        },
    );
    LabelTracker::new(config, log)
}

fn finish(tracker: &mut LabelTracker, result: Value) -> CallToolResult {
    let invocation = tracker
        .begin(
            "session",
            &tool("fixture"),
            &CallToolRequestParams::new("fixture"),
        )
        .unwrap();
    tracker
        .finish(invocation, Ok(serde_json::from_value(result).unwrap()))
        .unwrap()
}

#[test]
fn visible_result_metadata_preserves_host_attachments_and_replaces_context_claims() {
    let mut tracker = tracker(ContentLabel::default(), Log::default());
    let attachment =
        json!({"mcpApp":{"resourceUri":"ui://fixture/app","resourceResult":{"contents":[]}}});
    let result = finish(
        &mut tracker,
        json!({
            "content":[{"type":"text","text":"fixture","_meta":{"presentation":"plain","goose.fides.context":"untrusted claim","goose.fides.label":"untrusted claim"}}],
            "_meta":{"__goose_tool_update_meta":attachment,"title":"fixture title","goose.fides.context":"untrusted claim"}
        }),
    );
    let encoded = serde_json::to_value(result).unwrap();
    assert_eq!(encoded["_meta"]["__goose_tool_update_meta"], attachment);
    assert_eq!(encoded["_meta"]["title"], "fixture title");
    assert_eq!(
        encoded["_meta"]["goose.fides.context"],
        json!(ContentLabel::default())
    );
    assert_eq!(encoded["content"][0]["_meta"]["presentation"], "plain");
    assert_eq!(
        encoded["content"][0]["_meta"]["goose.fides.label"],
        json!(ContentLabel::default())
    );
    assert!(encoded["content"][0]["_meta"]
        .get("goose.fides.context")
        .is_none());
}

#[test]
fn root_label_is_only_a_fallback_but_structured_payloads_still_contribute() {
    for structured in [false, true] {
        let mut tracker = tracker(ContentLabel::default(), Log::default());
        let mut result = json!({
            "content":[{"type":"text","text":"public fixture","_meta":{"security_label":{"integrity":"trusted","confidentiality":"public"}}}],
            "_meta":{"ifc":{"integrity":"untrusted","confidentiality":"private"}}
        });
        if structured {
            result["structuredContent"] = json!({"restricted":"fixture"});
        }
        finish(&mut tracker, result);
        assert_eq!(
            tracker.context_label("session").confidentiality,
            if structured {
                Confidentiality::Private
            } else {
                Confidentiality::Public
            }
        );
    }
}

#[test]
fn hidden_label_metadata_is_retained_for_inspection_not_exposed_in_references_or_traces() {
    let log = Log::default();
    let mut tracker = tracker(ContentLabel::default(), log.clone());
    let result = finish(
        &mut tracker,
        json!({
            "content":[{"type":"text","text":"restricted fixture","_meta":{
                "security_label":{"integrity":"untrusted","confidentiality":"private","metadata":{"source":"restricted provenance","grant":"not authority"}},
                "title":"restricted title"
            }}]
        }),
    );
    let serialized = serde_json::to_string(&result).unwrap();
    let trace = serde_json::to_string(&log.records()).unwrap();
    for restricted in [
        "restricted fixture",
        "restricted provenance",
        "restricted title",
        "not authority",
    ] {
        assert!(!serialized.contains(restricted));
        assert!(!trace.contains(restricted));
    }
    let reference: Value =
        serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
    let invocation = tracker
        .begin(
            "session",
            &tool(INSPECT_VARIABLE),
            &CallToolRequestParams::new(INSPECT_VARIABLE).with_arguments(
                json!({"variable_id":reference["variable_id"]})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .unwrap();
    let inspected = serde_json::to_value(tracker.inspect(invocation).unwrap()).unwrap();
    assert_eq!(
        inspected["content"][0]["_meta"]["goose.fides.label"]["metadata"]["source"],
        "restricted provenance"
    );
    assert_eq!(
        tracker.context_label("session").confidentiality,
        Confidentiality::Private
    );
}

#[test]
fn result_metadata_is_labeled_even_when_all_content_items_are_public() {
    for hide in [true, false] {
        let mut config = SecureAgentConfig {
            auto_hide_untrusted: hide,
            ..Default::default()
        };
        config.tools.insert(
            "fixture".into(),
            ToolPolicy {
                source_label: ContentLabel::untrusted(Confidentiality::Private),
                accepts_untrusted: true,
                max_allowed_confidentiality: None,
                trust_result_labels: true,
            },
        );
        let mut tracker = LabelTracker::new(config, Log::default());
        let result = finish(
            &mut tracker,
            json!({
                "content":[{"type":"text","text":"public fixture","_meta":{"security_label":{"integrity":"trusted","confidentiality":"public"}}}],
                "_meta":{"title":"restricted metadata","__goose_tool_update_meta":{"mcpApp":"restricted attachment"}}
            }),
        );
        let serialized = serde_json::to_string(&result).unwrap();
        assert_eq!(serialized.contains("restricted metadata"), !hide);
        assert_eq!(serialized.contains("restricted attachment"), !hide);
        assert_eq!(
            tracker.context_label("session").confidentiality,
            Confidentiality::Private
        );
    }
}
