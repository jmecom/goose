use crate::{
    content_digest, Context, Dependencies, Domain, Exposure, Label, Operation, Trace, Value,
};
use futures::StreamExt;
use goose_provider_types::base::{MessageStream, Provider};
use goose_provider_types::conversation::message::{Message, MessageContent};
use goose_provider_types::errors::ProviderError;
use goose_provider_types::model::ModelConfig;
use rmcp::model::Tool;
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, BTreeMap, HashMap, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

pub type Observer = Arc<Mutex<ProviderObserver>>;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePolicy {
    pub domains: BTreeMap<String, Domain>,
    pub sources: BTreeMap<String, Label>,
}

pub struct ProviderObserver {
    trace: Trace,
    policy: SourcePolicy,
    sessions: HashMap<String, Context>,
    session_order: VecDeque<String>,
    requests: HashMap<(String, String), Option<Value>>,
    request_order: VecDeque<(String, String)>,
    warned: bool,
}

impl ProviderObserver {
    pub fn new(sink: impl Write + Send + 'static) -> Self {
        Self::with_policy(sink, SourcePolicy::default())
    }

    pub fn with_policy(sink: impl Write + Send + 'static, policy: SourcePolicy) -> Self {
        Self {
            trace: Trace::new(sink),
            policy,
            sessions: HashMap::new(),
            session_order: VecDeque::new(),
            requests: HashMap::new(),
            request_order: VecDeque::new(),
            warned: false,
        }
    }

    fn source(&mut self, payload: &(impl Serialize + ?Sized)) -> Value {
        let label = content_digest(payload)
            .and_then(|digest| self.policy.sources.get(&digest))
            .cloned()
            .unwrap_or_default();
        self.trace.source(payload, label)
    }

    fn request(
        &mut self,
        session_id: &str,
        model_config: &ModelConfig,
        system: &str,
        messages: &[Message],
        tools: &[Tool],
        inputs_complete: bool,
    ) -> Value {
        if !self.sessions.contains_key(session_id) {
            let mut domain = self
                .policy
                .domains
                .get(session_id)
                .cloned()
                .unwrap_or(Domain {
                    audience: Label::Unknown,
                    retained_context: Label::Unknown,
                    policy_epoch: "unclassified-provider-v1".into(),
                });
            if self.sessions.len() >= 64 {
                domain.retained_context = Label::Unknown;
            }
            let context = self.trace.enter(domain);
            self.sessions.insert(session_id.to_owned(), context);
            self.session_order.push_back(session_id.to_owned());
            if self.session_order.len() > 64 {
                if let Some(expired) = self.session_order.pop_front() {
                    self.sessions.remove(&expired);
                }
            }
        }
        let mut dependencies = Dependencies {
            instructions: vec![self.source(system).reference()],
            settings: vec![self.source(model_config).reference()],
            ..Dependencies::default()
        };
        for tool in tools {
            dependencies.schemas.push(self.source(tool).reference());
        }
        for message in messages {
            dependencies.history.push(self.source(message).reference());
            for content in &message.content {
                if let MessageContent::ToolResponse(response) = content {
                    let source = self.source(response);
                    let request = self
                        .requests
                        .get(&(session_id.to_owned(), response.id.clone()))
                        .and_then(Option::as_ref);
                    let result = self.trace.tool_result(request, &source, response);
                    dependencies.inputs.push(result.reference());
                }
            }
        }
        let context = self
            .sessions
            .get_mut(session_id)
            .expect("context was inserted");
        for reference in dependencies.references() {
            self.trace
                .observe(context, reference.clone(), Exposure::Delivered);
        }
        self.trace
            .computation(context, dependencies, inputs_complete)
    }

    fn response(&mut self, session_id: &str, invocation: &Value, message: &Message) {
        let response = self
            .trace
            .output(invocation, Operation::ModelOutput, message);
        for content in &message.content {
            if let MessageContent::ToolRequest(request) = content {
                let value = self
                    .trace
                    .output(&response, Operation::ToolRequest, request);
                let key = (session_id.to_owned(), request.id.clone());
                match self.requests.entry(key.clone()) {
                    Entry::Occupied(mut entry) => {
                        entry.insert(None);
                        continue;
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(Some(value));
                    }
                }
                self.request_order.push_back(key);
                if self.request_order.len() > 4096 {
                    if let Some(expired) = self.request_order.pop_front() {
                        self.requests.remove(&expired);
                    }
                }
            }
        }
    }

    fn error(&mut self, session_id: &str, invocation: &Value, error: &ProviderError) {
        let result = self
            .trace
            .output(invocation, Operation::Error, &error.to_string());
        if let Some(context) = self.sessions.get_mut(session_id) {
            self.trace
                .observe(context, result.reference(), Exposure::Delivered);
        }
    }

    fn warn_if_failed(&mut self) {
        if self.trace.logging_failed() && !self.warned {
            self.warned = true;
            eprintln!("IFC trace writes failed; tracing stopped, agent execution is unchanged.");
        }
    }
}

fn with_observer<Result>(
    observer: &Observer,
    operation: impl FnOnce(&mut ProviderObserver) -> Result,
) -> Option<Result> {
    let mut observer = observer.lock().ok()?;
    let result = operation(&mut observer);
    observer.warn_if_failed();
    Some(result)
}

fn configured_observer() -> Option<Observer> {
    static OBSERVER: OnceLock<Option<Observer>> = OnceLock::new();
    OBSERVER
        .get_or_init(|| {
            let file_path = std::env::var_os("GOOSE_IFC_TRACE_FILE")?;
            let policy = match std::env::var_os("GOOSE_IFC_POLICY_FILE") {
                Some(policy_path) => match std::fs::read(policy_path)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                {
                    Some(policy) => policy,
                    None => {
                        eprintln!(
                            "IFC policy could not be loaded; all sources remain unclassified."
                        );
                        SourcePolicy::default()
                    }
                },
                None => SourcePolicy::default(),
            };
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(file_path) {
                Ok(file) => Some(Arc::new(Mutex::new(ProviderObserver::with_policy(
                    file, policy,
                )))),
                Err(_) => {
                    eprintln!("IFC trace could not be created; agent execution is unchanged.");
                    None
                }
            }
        })
        .clone()
}

pub async fn stream(
    provider: &dyn Provider,
    session_id: &str,
    model_config: &ModelConfig,
    system: &str,
    messages: &[Message],
    tools: &[Tool],
) -> Result<MessageStream, ProviderError> {
    stream_with_observer(
        configured_observer(),
        provider,
        session_id,
        model_config,
        system,
        messages,
        tools,
    )
    .await
}

pub async fn stream_with_observer(
    observer: Option<Observer>,
    provider: &dyn Provider,
    session_id: &str,
    model_config: &ModelConfig,
    system: &str,
    messages: &[Message],
    tools: &[Tool],
) -> Result<MessageStream, ProviderError> {
    let Some(observer) = observer else {
        return provider.stream(model_config, system, messages, tools).await;
    };
    let invocation = with_observer(&observer, |observer| {
        observer.request(
            session_id,
            model_config,
            system,
            messages,
            tools,
            !provider.manages_own_context(),
        )
    });
    let result = provider.stream(model_config, system, messages, tools).await;
    let Some(invocation) = invocation else {
        return result;
    };
    match result {
        Ok(stream) => {
            let session_id = session_id.to_owned();
            Ok(Box::pin(stream.map(move |result| {
                with_observer(&observer, |observer| match &result {
                    Ok((Some(message), _)) => observer.response(&session_id, &invocation, message),
                    Err(error) => {
                        observer.error(&session_id, &invocation, error);
                    }
                    _ => {}
                });
                result
            })))
        }
        Err(error) => {
            with_observer(&observer, |observer| {
                observer.error(session_id, &invocation, &error);
            });
            Err(error)
        }
    }
}
