use std::path::Path;
use std::str::FromStr;

use crate::config::AgentServerConfig;
use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::time::ChronoUtc;

use crate::error::AgentServerError;

const TRACE_FILE_DIR_PATH: &str = "log";

const LOG_FILE_NAME_PREFIX: &str = "ppaass-agent";

pub fn init_log(config: &AgentServerConfig) -> Result<WorkerGuard, AgentServerError> {
    let (trace_file_appender, trace_appender_guard) = tracing_appender::non_blocking(
        tracing_appender::rolling::daily(Path::new(TRACE_FILE_DIR_PATH), LOG_FILE_NAME_PREFIX),
    );
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(LevelFilter::from_str(config.max_log_level()).unwrap_or(LevelFilter::ERROR))
        .with_writer(trace_file_appender)
        .with_line_number(true)
        .with_level(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_timer(ChronoUtc::rfc_3339())
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Fail to initialize log system.");
    Ok(trace_appender_guard)
}
