use goose_ifc::fides::{ContentLabel, LabelTracker, SecureAgentConfig, ToolPolicy};
use rmcp::model::{CallToolRequestParams, CallToolResult, Tool};
use serde_json::{json, Value};

fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/microsoft_fides.json")).unwrap()
}

fn label(fixtures: &Value, name: &Value) -> ContentLabel {
    serde_json::from_value(fixtures["labels"][name.as_str().unwrap()].clone()).unwrap()
}

fn tool() -> Tool {
    Tool::new("fixture", "Compatibility fixture", serde_json::Map::new())
}

#[test]
fn microsoft_label_fixtures() {
    let fixtures = fixtures();
    for case in fixtures["label_cases"].as_array().unwrap() {
        let inputs = case["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| label(&fixtures, name))
            .collect::<Vec<_>>();
        let actual = match case["operation"].as_str().unwrap() {
            "roundtrip" => inputs[0].clone(),
            "join" => inputs
                .iter()
                .fold(ContentLabel::default(), |joined, next| joined.join(next)),
            operation => panic!("Unknown fixture operation: {operation}"),
        };
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            fixtures["labels"][case["expected"].as_str().unwrap()],
            "{}",
            case["id"]
        );
    }
}

#[test]
fn microsoft_result_fixtures() {
    let fixtures = fixtures();
    for case in fixtures["result_cases"].as_array().unwrap() {
        let mut config = SecureAgentConfig {
            initial_label: label(&fixtures, &case["initial"]),
            auto_hide_untrusted: case["auto_hide"].as_bool().unwrap(),
            ..Default::default()
        };
        config.tools.insert(
            "fixture".into(),
            ToolPolicy {
                source_label: label(&fixtures, &case["fallback"]),
                accepts_untrusted: true,
                max_allowed_confidentiality: None,
                trust_result_labels: true,
            },
        );
        let mut tracker = LabelTracker::new(config, std::io::sink());
        let invocation = tracker
            .begin("fixture", &tool(), &CallToolRequestParams::new("fixture"))
            .unwrap();
        let items = case["items"].as_array().unwrap();
        let content = items
            .iter()
            .map(|item| {
                let mut metadata = item["metadata"].as_object().cloned().unwrap_or_default();
                if let Some(name) = item.get("label") {
                    metadata.insert("security_label".into(), json!(label(&fixtures, name)));
                }
                json!({"type":"text", "text":item["text"], "_meta":metadata})
            })
            .collect::<Vec<_>>();
        let result: CallToolResult = serde_json::from_value(json!({"content":content})).unwrap();
        let result = tracker.finish(invocation, Ok(result)).unwrap();
        assert_eq!(
            tracker.context_label("fixture"),
            label(&fixtures, &case["context"]),
            "{}",
            case["id"]
        );
        assert_eq!(result.content.len(), items.len());
        for (index, content) in result.content.iter().enumerate() {
            let expected_label = label(&fixtures, &case["expected_labels"][index]);
            if case["hidden"][index] == true {
                let reference: Value =
                    serde_json::from_str(&content.as_text().unwrap().text).unwrap();
                assert_eq!(reference["type"], "variable_reference", "{}", case["id"]);
                assert_eq!(
                    reference["security_label"],
                    json!(expected_label),
                    "{}",
                    case["id"]
                );
                assert!(!serde_json::to_string(content)
                    .unwrap()
                    .contains(items[index]["text"].as_str().unwrap()));
            } else {
                assert_eq!(
                    content.as_text().unwrap().text,
                    items[index]["text"].as_str().unwrap(),
                    "{}",
                    case["id"]
                );
                let encoded = serde_json::to_value(content).unwrap();
                assert_eq!(
                    encoded["_meta"]["goose.fides.label"],
                    json!(expected_label),
                    "{}",
                    case["id"]
                );
                if let Some(metadata) = items[index]["metadata"].as_object() {
                    for (key, value) in metadata {
                        assert_eq!(&encoded["_meta"][key], value, "{}", case["id"]);
                    }
                }
            }
        }
    }
}

#[test]
fn microsoft_annotation_fixtures() {
    let fixtures = fixtures();
    for case in fixtures["annotation_cases"].as_array().unwrap() {
        let mut tool = tool();
        tool.annotations = serde_json::from_value(case["annotations"].clone()).unwrap();
        let policy = ToolPolicy::from_tool(&tool);
        assert_eq!(
            json!(policy.source_label.integrity),
            case["integrity"],
            "{}",
            case["id"]
        );
        assert_eq!(
            json!(policy.max_allowed_confidentiality),
            case["maximum"],
            "{}",
            case["id"]
        );
        assert_eq!(
            json!(policy.accepts_untrusted),
            case["accepts_untrusted"],
            "{}",
            case["id"]
        );
    }
}

#[test]
fn microsoft_policy_fixtures() {
    let fixtures = fixtures();
    for case in fixtures["policy_cases"].as_array().unwrap() {
        let mut config = SecureAgentConfig {
            initial_label: label(&fixtures, &case["label"]),
            block_on_violation: case["block"].as_bool().unwrap(),
            ..Default::default()
        };
        config.tools.insert(
            "fixture".into(),
            ToolPolicy {
                accepts_untrusted: case["accepts_untrusted"].as_bool().unwrap(),
                max_allowed_confidentiality: serde_json::from_value(case["maximum"].clone())
                    .unwrap(),
                ..Default::default()
            },
        );
        let mut tracker = LabelTracker::new(config, std::io::sink());
        let invocation = tracker
            .begin("fixture", &tool(), &CallToolRequestParams::new("fixture"))
            .unwrap();
        assert_eq!(
            invocation.blocked(),
            case["blocked"].as_bool().unwrap(),
            "{}",
            case["id"]
        );
    }
}
