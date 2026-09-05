use crate::content_digest;
use goose_provider_types::base::Provider;
use goose_provider_types::conversation::message::{Message, MessageContent};
use goose_provider_types::model::ModelConfig;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, ErrorData, MetaObject, Tool,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use uuid::Uuid;

pub const INSPECT_VARIABLE: &str = "fides__inspect_variable";
pub const QUARANTINED_LLM: &str = "fides__quarantined_llm";
const MAX_VARIABLES: usize = 1024;
const MAX_STORED_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Integrity {
    #[default]
    Trusted,
    Untrusted,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidentiality {
    #[default]
    Public,
    Private,
    UserIdentity,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentLabel {
    pub integrity: Integrity,
    pub confidentiality: Confidentiality,
    #[serde(
        default,
        skip_serializing_if = "serde_json::Map::is_empty",
        deserialize_with = "deserialize_label_metadata"
    )]
    pub metadata: serde_json::Map<String, Value>,
}

fn deserialize_label_metadata<'de, Deserializer>(
    deserializer: Deserializer,
) -> Result<serde_json::Map<String, Value>, Deserializer::Error>
where
    Deserializer: serde::Deserializer<'de>,
{
    Ok(Option::<serde_json::Map<String, Value>>::deserialize(deserializer)?.unwrap_or_default())
}

impl ContentLabel {
    pub fn join(&self, other: &Self) -> Self {
        let mut metadata = self.metadata.clone();
        metadata.extend(other.metadata.clone());
        Self {
            integrity: self.integrity.max(other.integrity),
            confidentiality: self.confidentiality.max(other.confidentiality),
            metadata,
        }
    }

    fn classification(&self) -> Self {
        Self {
            integrity: self.integrity,
            confidentiality: self.confidentiality,
            metadata: Default::default(),
        }
    }

    pub fn untrusted(confidentiality: Confidentiality) -> Self {
        Self {
            integrity: Integrity::Untrusted,
            confidentiality,
            metadata: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolPolicy {
    pub source_label: ContentLabel,
    pub accepts_untrusted: bool,
    pub max_allowed_confidentiality: Option<Confidentiality>,
    pub trust_result_labels: bool,
}

impl Default for ToolPolicy {
    fn default() -> Self {
        Self {
            source_label: ContentLabel::untrusted(Confidentiality::Public),
            accepts_untrusted: false,
            max_allowed_confidentiality: Some(Confidentiality::Public),
            trust_result_labels: false,
        }
    }
}

impl ToolPolicy {
    pub fn from_tool(tool: &Tool) -> Self {
        let annotations = tool.annotations.as_ref();
        let read_only = annotations.and_then(|value| value.read_only_hint) == Some(true);
        let closed_world = annotations.and_then(|value| value.open_world_hint) == Some(false);
        Self {
            source_label: ContentLabel {
                integrity: if closed_world {
                    Integrity::Trusted
                } else {
                    Integrity::Untrusted
                },
                confidentiality: Confidentiality::Public,
                metadata: Default::default(),
            },
            accepts_untrusted: read_only,
            max_allowed_confidentiality: (!read_only).then_some(Confidentiality::Public),
            trust_result_labels: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecureAgentConfig {
    pub initial_label: ContentLabel,
    pub auto_hide_untrusted: bool,
    pub block_on_violation: bool,
    pub tools: HashMap<String, ToolPolicy>,
}

impl Default for SecureAgentConfig {
    fn default() -> Self {
        Self {
            initial_label: ContentLabel::default(),
            auto_hide_untrusted: true,
            block_on_violation: false,
            tools: HashMap::new(),
        }
    }
}

struct StoredVariable {
    payload: Value,
    label: ContentLabel,
}

struct Session {
    trace_id: String,
    label: ContentLabel,
    variables: HashMap<String, StoredVariable>,
    stored_bytes: usize,
}

pub struct ToolInvocation {
    id: String,
    session_id: String,
    name: String,
    arguments: serde_json::Map<String, Value>,
    label: ContentLabel,
    policy: ToolPolicy,
    variables: Vec<Value>,
    blocked: bool,
}

impl ToolInvocation {
    pub fn arguments(&self) -> &serde_json::Map<String, Value> {
        &self.arguments
    }
    pub fn blocked(&self) -> bool {
        self.blocked
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn label(&self) -> ContentLabel {
        self.label.clone()
    }

    pub fn quarantine_prompt(&self) -> Value {
        json!({"request": self.arguments.get("prompt"), "data": self.variables})
    }
}

pub struct LabelTracker {
    config: SecureAgentConfig,
    sessions: HashMap<String, Session>,
    log: Box<dyn Write + Send>,
    log_failed: bool,
}

pub fn security_error() -> ErrorData {
    ErrorData::invalid_params("FIDES operation unavailable or invalid", None)
}

pub async fn quarantined_call(
    provider: &dyn Provider,
    config: &ModelConfig,
    invocation: &ToolInvocation,
) -> Result<CallToolResult, ErrorData> {
    if invocation.name != QUARANTINED_LLM || invocation.blocked || provider.manages_own_context() {
        return Err(security_error());
    }
    let messages = [Message::user().with_text(invocation.quarantine_prompt().to_string())];
    let (response, _) = provider.complete(
        config,
        "Analyze the supplied data according to the request. You have no tools. Your response retains the inputs' security label.",
        &messages,
        &[],
    ).await.map_err(|_| security_error())?;
    if response
        .content
        .iter()
        .any(|content| matches!(content, MessageContent::ToolRequest(_)))
    {
        return Err(security_error());
    }
    Ok(CallToolResult::success(vec![ContentBlock::text(
        response.as_concat_text(),
    )]))
}

pub fn security_tools() -> Vec<Tool> {
    [
        (INSPECT_VARIABLE,
         "Reveal a FIDES variable to this conversation. This taints the conversation's integrity; it does not release confidential data.",
         json!({"variable_id":{"type":"string"},"reason":{"type":"string"}}),
         json!(["variable_id"])),
        (QUARANTINED_LLM,
         "Process FIDES variables in a fresh, tool-less LLM call. Returns a labeled variable, not sanitized or trusted text. Use variable_ids from hidden tool results.",
         json!({"prompt":{"type":"string"},"variable_ids":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":32}}),
         json!(["prompt","variable_ids"])),
    ].into_iter().map(|(name, description, properties, required)| {
        Tool::new(name, description, json!({"type":"object","properties":properties,"required":required,"additionalProperties":false}).as_object().unwrap().clone())
    }).collect()
}

impl LabelTracker {
    pub fn new(config: SecureAgentConfig, log: impl Write + Send + 'static) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            log: Box::new(log),
            log_failed: false,
        }
    }

    pub fn context_label(&self, session_id: &str) -> ContentLabel {
        self.sessions
            .get(session_id)
            .map(|session| session.label.clone())
            .unwrap_or_else(|| self.config.initial_label.clone())
    }

    pub fn log_failed(&self) -> bool {
        self.log_failed
    }

    fn emit(&mut self, event: Value) {
        if !self.log_failed {
            self.log_failed = serde_json::to_writer(&mut self.log, &event)
                .and_then(|_| self.log.write_all(b"\n").map_err(serde_json::Error::io))
                .is_err();
        }
    }

    pub fn begin(
        &mut self,
        session_id: &str,
        tool: &Tool,
        call: &CallToolRequestParams,
    ) -> Result<ToolInvocation, ErrorData> {
        if tool.name != call.name {
            return Err(security_error());
        }
        if self.sessions.len() >= 1024 && !self.sessions.contains_key(session_id) {
            return Err(security_error());
        }
        let session = self
            .sessions
            .entry(session_id.to_owned())
            .or_insert_with(|| Session {
                trace_id: Uuid::new_v4().to_string(),
                label: self.config.initial_label.clone(),
                variables: HashMap::new(),
                stored_bytes: 0,
            });
        let mut policy = self
            .config
            .tools
            .get(call.name.as_ref())
            .cloned()
            .unwrap_or_else(|| ToolPolicy::from_tool(tool));
        let mut arguments = call.arguments.clone().unwrap_or_default();
        let mut label = session.label.clone();
        let mut variables = Vec::new();
        let mut input_refs = Vec::new();
        let internal = matches!(call.name.as_ref(), INSPECT_VARIABLE | QUARANTINED_LLM);
        if internal {
            let ids: Vec<&str> = if call.name == INSPECT_VARIABLE {
                if arguments
                    .keys()
                    .any(|key| key != "variable_id" && key != "reason")
                {
                    return Err(security_error());
                }
                vec![arguments
                    .get("variable_id")
                    .and_then(Value::as_str)
                    .ok_or_else(security_error)?]
            } else {
                if arguments
                    .keys()
                    .any(|key| key != "variable_ids" && key != "prompt")
                {
                    return Err(security_error());
                }
                arguments
                    .get("prompt")
                    .and_then(Value::as_str)
                    .ok_or_else(security_error)?;
                arguments
                    .get("variable_ids")
                    .and_then(Value::as_array)
                    .ok_or_else(security_error)?
                    .iter()
                    .map(|value| value.as_str().ok_or_else(security_error))
                    .collect::<Result<_, _>>()?
            };
            if ids.is_empty() || ids.len() > 32 {
                return Err(security_error());
            }
            for reference in ids {
                let variable = session
                    .variables
                    .get(reference)
                    .ok_or_else(security_error)?;
                label = label.join(&variable.label);
                variables.push(variable.payload.clone());
                input_refs.push(reference.to_owned());
            }
            policy.accepts_untrusted = true;
            policy.max_allowed_confidentiality = None;
            policy.trust_result_labels = false;
        } else {
            for value in arguments.values_mut() {
                Self::expand(session, value, &mut label, &mut input_refs, 0)?;
            }
        }
        let integrity_violation =
            label.integrity == Integrity::Untrusted && !policy.accepts_untrusted;
        let confidentiality_violation = policy
            .max_allowed_confidentiality
            .is_some_and(|maximum| label.confidentiality > maximum);
        let allowed = !integrity_violation && !confidentiality_violation;
        let invocation = ToolInvocation {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.to_owned(),
            name: call.name.to_string(),
            arguments,
            label: label.clone(),
            policy,
            variables,
            blocked: !allowed && self.config.block_on_violation,
        };
        let event = json!({"version":1,"event":"tool_call","session":session.trace_id,"invocation":invocation.id,
            "tool_digest":content_digest(&call.name),"arguments_digest":content_digest(&invocation.arguments),
            "label":label.classification(),"input_refs":input_refs,"would_allow":allowed,"blocked":invocation.blocked,
            "integrity_violation":integrity_violation,"confidentiality_violation":confidentiality_violation});
        self.emit(event);
        Ok(invocation)
    }

    fn expand(
        session: &Session,
        value: &mut Value,
        label: &mut ContentLabel,
        input_refs: &mut Vec<String>,
        depth: usize,
    ) -> Result<(), ErrorData> {
        if depth > 32 {
            return Err(security_error());
        }
        let reference = value
            .as_object()
            .filter(|object| object.len() == 1)
            .and_then(|object| object.get("$fides_variable"))
            .and_then(Value::as_str)
            .or_else(|| {
                value
                    .as_str()
                    .and_then(|text| text.strip_prefix('[')?.strip_suffix(']'))
                    .filter(|reference| reference.starts_with("var_"))
            });
        if let Some(reference) = reference {
            let variable = session
                .variables
                .get(reference)
                .ok_or_else(security_error)?;
            *label = label.join(&variable.label);
            input_refs.push(reference.to_owned());
            *value = variable.payload.clone();
        } else {
            match value {
                Value::Array(values) => {
                    for child in values {
                        Self::expand(session, child, label, input_refs, depth + 1)?;
                    }
                }
                Value::Object(values) => {
                    for child in values.values_mut() {
                        Self::expand(session, child, label, input_refs, depth + 1)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn inspect(&mut self, invocation: ToolInvocation) -> Result<CallToolResult, ErrorData> {
        if invocation.name != INSPECT_VARIABLE {
            return Err(security_error());
        }
        let payload = invocation.variables.first().ok_or_else(security_error)?;
        let result = CallToolResult::success(vec![ContentBlock::text(
            payload
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| payload.to_string()),
        )]);
        let label = invocation.label.clone();
        self.finish_labeled(invocation, Ok(result), Some(label))
    }

    pub fn finish_quarantine(
        &mut self,
        invocation: ToolInvocation,
        result: Result<CallToolResult, ErrorData>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut label = invocation.label.clone();
        label.integrity = Integrity::Untrusted;
        self.finish_labeled(invocation, result, Some(label))
    }

    pub fn finish(
        &mut self,
        invocation: ToolInvocation,
        result: Result<CallToolResult, ErrorData>,
    ) -> Result<CallToolResult, ErrorData> {
        self.finish_labeled(invocation, result, None)
    }

    fn finish_labeled(
        &mut self,
        invocation: ToolInvocation,
        result: Result<CallToolResult, ErrorData>,
        override_label: Option<ContentLabel>,
    ) -> Result<CallToolResult, ErrorData> {
        if invocation.blocked {
            return Err(security_error());
        }
        let failed = result.is_err();
        let result = result.unwrap_or_else(|_| {
            CallToolResult::error(vec![ContentBlock::text("FIDES tool execution failed")])
        });
        let fallback = override_label
            .clone()
            .unwrap_or_else(|| invocation.policy.source_label.clone());
        let fallback = if failed || result.is_error == Some(true) {
            fallback.join(&ContentLabel::untrusted(invocation.label.confidentiality))
        } else {
            fallback
        };
        let root_label = if invocation.policy.trust_result_labels && override_label.is_none() {
            Self::metadata_label(result.meta.as_ref().map(|meta| &meta.0), fallback)
        } else {
            fallback
        };
        let mut output = CallToolResult::success(Vec::new());
        output.result_type = result.result_type;
        output.is_error = result.is_error;
        let mut labels = Vec::new();
        for item in result.content {
            let encoded = serde_json::to_value(&item).map_err(|_| security_error())?;
            let label = if invocation.policy.trust_result_labels && override_label.is_none() {
                Self::metadata_label(
                    encoded.get("_meta").and_then(Value::as_object),
                    root_label.clone(),
                )
            } else {
                root_label.clone()
            };
            let payload = item
                .as_text()
                .map(|text| Value::String(text.text.clone()))
                .unwrap_or_else(|| encoded.clone());
            let (visible, hidden) = self.present(&invocation, payload, &label)?;
            if hidden {
                output.content.push(ContentBlock::text(visible.to_string()));
            } else {
                let mut encoded = encoded;
                let metadata = encoded
                    .as_object_mut()
                    .ok_or_else(security_error)?
                    .entry("_meta")
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                    .ok_or_else(security_error)?;
                metadata.remove("security_label");
                metadata.remove("ifc");
                metadata.remove("goose.fides.context");
                metadata.insert("goose.fides.label".into(), json!(label));
                output
                    .content
                    .push(serde_json::from_value(encoded).map_err(|_| security_error())?);
            }
            labels.push((label, hidden));
        }
        if let Some(structured) = result.structured_content {
            let (visible, hidden) = self.present(&invocation, structured, &root_label)?;
            output.structured_content = Some(visible);
            labels.push((root_label.clone(), hidden));
        }
        let mut metadata = result.meta.map(|meta| meta.0).unwrap_or_default();
        for key in [
            "security_label",
            "ifc",
            "goose.fides.context",
            "goose.fides.label",
        ] {
            metadata.remove(key);
        }
        if !metadata.is_empty() {
            let (_, hidden) = self.present(&invocation, json!(metadata), &root_label)?;
            if !hidden {
                output.meta = Some(MetaObject(metadata));
            }
            labels.push((root_label.clone(), hidden));
        }
        let session = self
            .sessions
            .get_mut(&invocation.session_id)
            .ok_or_else(security_error)?;
        let before = session.label.classification();
        if labels.is_empty() {
            session.label.confidentiality = session
                .label
                .confidentiality
                .max(root_label.confidentiality);
        }
        for (label, hidden) in labels {
            session.label.confidentiality =
                session.label.confidentiality.max(label.confidentiality);
            if !hidden {
                session.label.integrity = session.label.integrity.max(label.integrity);
            }
        }
        if failed {
            session.label = session.label.join(&root_label.classification());
        }
        output
            .meta
            .get_or_insert_with(|| MetaObject(Default::default()))
            .0
            .insert(
                "goose.fides.context".into(),
                json!(session.label.classification()),
            );
        let event = json!({"version":1,"event":"tool_result","session":session.trace_id,"invocation":invocation.id,
            "context_before":before,"context_after":session.label.classification(),"error":output.is_error == Some(true)});
        self.emit(event);
        Ok(output)
    }

    fn metadata_label(
        metadata: Option<&serde_json::Map<String, Value>>,
        fallback: ContentLabel,
    ) -> ContentLabel {
        let explicit =
            metadata.and_then(|meta| meta.get("security_label").or_else(|| meta.get("ifc")));
        explicit
            .map(|label| {
                serde_json::from_value(label.clone())
                    .unwrap_or(ContentLabel::untrusted(Confidentiality::UserIdentity))
            })
            .unwrap_or(fallback)
    }

    fn present(
        &mut self,
        invocation: &ToolInvocation,
        payload: Value,
        label: &ContentLabel,
    ) -> Result<(Value, bool), ErrorData> {
        let session = self
            .sessions
            .get_mut(&invocation.session_id)
            .ok_or_else(security_error)?;
        let hidden = self.config.auto_hide_untrusted
            && label.integrity == Integrity::Untrusted
            && session.label.integrity == Integrity::Trusted
            && invocation.name != INSPECT_VARIABLE;
        let reference = format!("var_{}", Uuid::new_v4());
        let digest = content_digest(&payload);
        let visible = if hidden {
            let bytes = payload.to_string().len().saturating_add(
                serde_json::to_vec(label)
                    .map_err(|_| security_error())?
                    .len(),
            );
            if session.variables.len() >= MAX_VARIABLES
                || bytes > MAX_STORED_BYTES.saturating_sub(session.stored_bytes)
            {
                session.label = session.label.join(&label.classification());
                return Err(security_error());
            }
            session.stored_bytes += bytes;
            session.variables.insert(
                reference.clone(),
                StoredVariable {
                    payload,
                    label: label.clone(),
                },
            );
            json!({"type":"variable_reference","variable_id":reference,"security_label":label.classification()})
        } else {
            payload
        };
        let event = json!({"version":1,"event":"value","session":session.trace_id,"invocation":invocation.id,
            "value_ref":reference,"label":label.classification(),"hidden":hidden,"content_digest":digest});
        self.emit(event);
        Ok((visible, hidden))
    }
}
