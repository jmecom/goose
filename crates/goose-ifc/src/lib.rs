pub mod fides;
mod label;
pub mod provider;

pub use label::{Decision, Label, Readers};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::io::Write;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValueRef(pub String);

#[derive(Clone, Debug)]
pub struct Value {
    reference: ValueRef,
    label: Label,
}

impl Value {
    pub fn reference(&self) -> ValueRef {
        self.reference.clone()
    }
    pub fn label(&self) -> &Label {
        &self.label
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Domain {
    pub audience: Label,
    pub retained_context: Label,
    pub policy_epoch: String,
}

pub struct Context {
    domain: Domain,
    current: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Source,
    EnterContext,
    Exposure,
    ModelCall,
    ModelOutput,
    ToolRequest,
    ToolResult,
    Error,
    PublicationCheck,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    Delivered,
    Withheld,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Dependencies {
    pub inputs: Vec<ValueRef>,
    pub instructions: Vec<ValueRef>,
    pub history: Vec<ValueRef>,
    pub schemas: Vec<ValueRef>,
    pub settings: Vec<ValueRef>,
    pub control: Vec<ValueRef>,
}

impl Dependencies {
    fn references(&self) -> impl Iterator<Item = &ValueRef> {
        [
            &self.inputs,
            &self.instructions,
            &self.history,
            &self.schemas,
            &self.settings,
            &self.control,
        ]
        .into_iter()
        .flatten()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Record {
    pub version: u8,
    pub id: ValueRef,
    pub operation: Operation,
    pub label: Label,
    pub context_ref: Option<ValueRef>,
    pub dependencies: Dependencies,
    pub content_digest: Option<String>,
    pub inputs_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<Domain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposure: Option<Exposure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_ref: Option<ValueRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<Label>,
}

pub fn content_digest(payload: &(impl Serialize + ?Sized)) -> Option<String> {
    serde_json::to_vec(payload).ok().map(|bytes| {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    })
}

pub struct Trace {
    labels: HashMap<ValueRef, Label>,
    order: VecDeque<ValueRef>,
    capacity: usize,
    sink: Box<dyn Write + Send>,
    logging_failed: bool,
}

impl Trace {
    pub fn new(sink: impl Write + Send + 'static) -> Self {
        Self {
            labels: HashMap::new(),
            order: VecDeque::new(),
            capacity: 4096,
            sink: Box::new(sink),
            logging_failed: false,
        }
    }

    pub fn logging_failed(&self) -> bool {
        self.logging_failed
    }

    fn resolve(&self, reference: &ValueRef) -> Label {
        self.labels.get(reference).cloned().unwrap_or_default()
    }

    fn record(&mut self, mut record: Record) -> Value {
        record.label = record.label.normalized();
        let value = Value {
            reference: record.id.clone(),
            label: record.label.clone(),
        };
        self.labels.insert(record.id.clone(), record.label.clone());
        self.order.push_back(record.id.clone());
        if self.order.len() > self.capacity {
            if let Some(expired) = self.order.pop_front() {
                self.labels.remove(&expired);
            }
        }
        if !self.logging_failed {
            self.logging_failed = serde_json::to_vec(&record)
                .map_err(std::io::Error::other)
                .and_then(|mut bytes| {
                    bytes.push(b'\n');
                    self.sink.write_all(&bytes)
                })
                .is_err();
        }
        value
    }

    fn record_fields(operation: Operation, label: Label, dependencies: Dependencies) -> Record {
        Record {
            version: 1,
            id: ValueRef(uuid::Uuid::new_v4().to_string()),
            operation,
            label,
            context_ref: None,
            dependencies,
            content_digest: None,
            inputs_complete: true,
            domain: None,
            decision: None,
            exposure: None,
            checked_ref: None,
            destination: None,
        }
    }

    pub fn source(&mut self, payload: &(impl Serialize + ?Sized), label: Label) -> Value {
        let mut record = Self::record_fields(Operation::Source, label, Dependencies::default());
        record.content_digest = content_digest(payload);
        if record.content_digest.is_none() {
            record.label = Label::Unknown;
        }
        self.record(record)
    }

    pub fn enter(&mut self, domain: Domain) -> Context {
        let domain = Domain {
            audience: domain.audience.normalized(),
            retained_context: domain.retained_context.normalized(),
            ..domain
        };
        let mut record = Self::record_fields(
            Operation::EnterContext,
            domain.audience.join(&domain.retained_context),
            Dependencies::default(),
        );
        record.domain = Some(domain.clone());
        Context {
            domain,
            current: self.record(record),
        }
    }

    pub fn observe(
        &mut self,
        context: &mut Context,
        reference: ValueRef,
        actual: Exposure,
    ) -> Value {
        let input = self.resolve(&reference);
        let mut record = Self::record_fields(
            Operation::Exposure,
            context.current.label.clone(),
            Dependencies::default(),
        );
        record.context_ref = Some(context.current.reference());
        record.checked_ref = Some(reference.clone());
        record.decision = Some(input.check_audience(&context.domain.audience));
        record.exposure = Some(actual);
        if actual == Exposure::Delivered {
            record.label = record.label.join(&input);
            record.dependencies.inputs.push(reference);
        }
        context.current = self.record(record);
        context.current.clone()
    }

    pub fn computation(
        &mut self,
        context: &mut Context,
        dependencies: Dependencies,
        inputs_complete: bool,
    ) -> Value {
        let label = if inputs_complete {
            dependencies
                .references()
                .fold(context.current.label.clone(), |label, reference| {
                    label.join(&self.resolve(reference))
                })
        } else {
            Label::Unknown
        };
        let mut record = Self::record_fields(Operation::ModelCall, label, dependencies);
        record.context_ref = Some(context.current.reference());
        record.inputs_complete = inputs_complete;
        context.current = self.record(record);
        context.current.clone()
    }

    pub fn output(
        &mut self,
        invocation: &Value,
        operation: Operation,
        payload: &(impl Serialize + ?Sized),
    ) -> Value {
        let mut record = Self::record_fields(
            operation,
            invocation.label.clone(),
            Dependencies {
                inputs: vec![invocation.reference()],
                ..Dependencies::default()
            },
        );
        record.content_digest = content_digest(payload);
        if record.content_digest.is_none() || operation == Operation::Error {
            record.label = Label::Unknown;
        }
        self.record(record)
    }

    pub fn tool_result(
        &mut self,
        request: Option<&Value>,
        source: &Value,
        payload: &(impl Serialize + ?Sized),
    ) -> Value {
        let label = request
            .map(|request| request.label.join(&source.label))
            .unwrap_or_default();
        let mut record = Self::record_fields(
            Operation::ToolResult,
            label,
            Dependencies {
                inputs: vec![source.reference()],
                control: request.map(Value::reference).into_iter().collect(),
                ..Dependencies::default()
            },
        );
        record.content_digest = content_digest(payload);
        if record.content_digest.is_none() {
            record.label = Label::Unknown;
        }
        self.record(record)
    }

    pub fn check_publication(
        &mut self,
        context: &mut Context,
        reference: ValueRef,
        destination: Label,
        control: Vec<ValueRef>,
    ) -> Value {
        let dependencies = Dependencies {
            inputs: vec![reference.clone()],
            control,
            ..Dependencies::default()
        };
        let label = dependencies
            .references()
            .fold(context.current.label.clone(), |label, reference| {
                label.join(&self.resolve(reference))
            });
        let mut record =
            Self::record_fields(Operation::PublicationCheck, label.clone(), dependencies);
        record.context_ref = Some(context.current.reference());
        record.checked_ref = Some(reference);
        record.decision = Some(label.check_audience(&destination));
        record.destination = Some(destination.normalized());
        context.current = self.record(record);
        context.current.clone()
    }
}
