use goose_ifc::fides::{LabelTracker, SecureAgentConfig, INSPECT_VARIABLE, QUARANTINED_LLM};
use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock, Tool};
use serde_json::{json, Value};

fn tool(name: &str) -> Tool {
    Tool::new(
        name.to_owned(),
        "Synthetic fixture",
        json!({"type":"object"}).as_object().unwrap().clone(),
    )
}

fn call(name: &str, arguments: Value) -> CallToolRequestParams {
    CallToolRequestParams::new(name.to_owned())
        .with_arguments(arguments.as_object().unwrap().clone())
}

fn reference(result: &CallToolResult) -> String {
    let payload: Value = serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
    payload["variable_id"].as_str().unwrap().to_owned()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config: SecureAgentConfig =
        serde_json::from_str(include_str!("../fides-policy.example.json"))?;
    let mut tracker = LabelTracker::new(config, std::io::stdout());
    let invocation = tracker.begin(
        "fixture",
        &tool("fixture__read"),
        &call("fixture__read", json!({})),
    )?;
    let result = tracker.finish(
        invocation,
        Ok(CallToolResult::success(vec![ContentBlock::text(
            "Synthetic incident rows",
        )])),
    )?;
    let rows = reference(&result);
    let invocation = tracker.begin(
        "fixture",
        &tool(QUARANTINED_LLM),
        &call(
            QUARANTINED_LLM,
            json!({"prompt":"Analyze the fixture","variable_ids":[rows]}),
        ),
    )?;
    let result = tracker.finish_quarantine(
        invocation,
        Ok(CallToolResult::success(vec![ContentBlock::text(
            "Deterministic private analysis",
        )])),
    )?;
    let analysis = reference(&result);
    let invocation = tracker.begin(
        "fixture",
        &tool("fixture__publish"),
        &call(
            "fixture__publish",
            json!({"text":"Independent public work"}),
        ),
    )?;
    assert!(!invocation.blocked());
    let invocation = tracker.begin(
        "fixture",
        &tool(INSPECT_VARIABLE),
        &call(INSPECT_VARIABLE, json!({"variable_id":analysis})),
    )?;
    tracker.inspect(invocation)?;
    tracker.begin(
        "fixture",
        &tool("fixture__publish"),
        &call("fixture__publish", json!({"text":"Derived work"})),
    )?;
    eprintln!("Synthetic FIDES demo: hidden results retain confidentiality; inspection also taints integrity. Publication checks are logged, not executed.");
    Ok(())
}
