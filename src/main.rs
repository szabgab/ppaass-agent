mod codec;
mod config;
mod crypto;
mod error;
mod proxy;
mod server;
mod trace;
mod transport;

pub const SOCKS_V5: u8 = 5;
pub const SOCKS_V4: u8 = 4;

use error::AgentError;
use tokio::runtime::Builder;
use tracing::error;
use {config::AGENT_CONFIG, server::AgentServer};

const LOG_FILE_NAME_PREFIX: &str = "ppaass-agent";
const AGENT_RUNTIME_NAME: &str = "AGENT";

fn main() -> Result<(), AgentError> {
    let (subscriber, _tracing_guard) = trace::init_global_tracing_subscriber(
        LOG_FILE_NAME_PREFIX,
        AGENT_CONFIG.get_max_log_level(),
    )?;
    tracing::subscriber::set_global_default(subscriber).map_err(|e| {
        AgentError::Other(format!(
            "Fail to initialize tracing system because of error: {e:?}"
        ))
    })?;

    let agent_server_runtime = Builder::new_multi_thread()
        .enable_all()
        .thread_name(AGENT_RUNTIME_NAME)
        .worker_threads(AGENT_CONFIG.get_worker_thread_number())
        .build()?;
    agent_server_runtime.block_on(async move {
        let mut agent_server = AgentServer::new();
        if let Err(e) = agent_server.start().await {
            error!("Fail to start agent server because of error: {e:?}");
        };
    });
    Ok(())
}
