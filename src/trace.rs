use std::path::Path;

use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::time::ChronoUtc;

use crate::error::AgentError;

const TRACE_FILE_DIR_PATH: &str = "log";

const LOG_FILE_NAME_PREFIX: &str = "ppaass-agent";

pub fn init_global_tracing_subscriber(max_level: LevelFilter) -> Result<WorkerGuard, AgentError> {
    let (trace_file_appender, trace_appender_guard) = tracing_appender::non_blocking(
        tracing_appender::rolling::daily(Path::new(TRACE_FILE_DIR_PATH), LOG_FILE_NAME_PREFIX),
    );
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(max_level)
        .with_writer(trace_file_appender)
        .with_line_number(true)
        .with_level(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_timer(ChronoUtc::rfc_3339())
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).map_err(|e| {
        AgentError::Other(format!(
            "Fail to initialize tracing system because of error: {e:?}"
        ))
    })?;
    Ok(trace_appender_guard)
}
