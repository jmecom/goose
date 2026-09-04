use goose_ifc::fides::{security_error, LabelTracker, SecureAgentConfig, ToolInvocation};
use rmcp::model::{CallToolRequestParams, CallToolResult, ErrorData, Tool};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

pub struct FidesRuntime {
    tracker: Mutex<LabelTracker>,
}

impl FidesRuntime {
    pub fn new(config: SecureAgentConfig, log: impl Write + Send + 'static) -> Self {
        Self {
            tracker: Mutex::new(LabelTracker::new(config, log)),
        }
    }

    pub fn configured() -> Option<Arc<Self>> {
        static RUNTIME: OnceLock<Option<Arc<FidesRuntime>>> = OnceLock::new();
        RUNTIME.get_or_init(|| {
            let config_path = std::env::var_os("GOOSE_FIDES_CONFIG")?;
            let initialize = || -> anyhow::Result<Self> {
                let config = serde_json::from_slice(&std::fs::read(config_path)?)?;
                let trace_path = std::env::var_os("GOOSE_FIDES_TRACE_FILE")
                    .ok_or_else(|| anyhow::anyhow!("FIDES trace file required"))?;
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                Ok(Self::new(config, options.open(trace_path)?))
            };
            Some(Arc::new(initialize().unwrap_or_else(|_| {
                panic!("Cannot initialize FIDES: check configuration and use a new writable trace file")
            })))
        }).clone()
    }

    fn with_tracker<ResultValue>(
        &self,
        operation: impl FnOnce(&mut LabelTracker) -> Result<ResultValue, ErrorData>,
    ) -> Result<ResultValue, ErrorData> {
        let mut tracker = self.tracker.lock().map_err(|_| security_error())?;
        let already_failed = tracker.log_failed();
        let result = operation(&mut tracker);
        if !already_failed && tracker.log_failed() {
            tracing::error!("FIDES trace write failed; label tracking remains active");
        }
        result
    }

    pub(crate) fn begin(
        &self,
        session: &str,
        tool: &Tool,
        call: &CallToolRequestParams,
    ) -> Result<ToolInvocation, ErrorData> {
        self.with_tracker(|tracker| tracker.begin(session, tool, call))
    }

    pub(crate) fn inspect(&self, invocation: ToolInvocation) -> Result<CallToolResult, ErrorData> {
        self.with_tracker(|tracker| tracker.inspect(invocation))
    }

    pub(crate) fn finish(
        &self,
        invocation: ToolInvocation,
        result: Result<CallToolResult, ErrorData>,
    ) -> Result<CallToolResult, ErrorData> {
        self.with_tracker(|tracker| tracker.finish(invocation, result))
    }

    pub(crate) fn finish_quarantine(
        &self,
        invocation: ToolInvocation,
        result: Result<CallToolResult, ErrorData>,
    ) -> Result<CallToolResult, ErrorData> {
        self.with_tracker(|tracker| tracker.finish_quarantine(invocation, result))
    }
}
