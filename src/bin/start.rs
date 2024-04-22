use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use ppaass_agent::config::AgentServerConfig;
use ppaass_agent::log;
use ppaass_agent::server::AgentServer;
use tokio::runtime::Builder;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const AGENT_SERVER_RUNTIME_NAME: &str = "AGENT-SERVER";

fn main() -> Result<()> {
    let config = Arc::new(AgentServerConfig::parse());
    let _log_guard = log::init_log(config.clone())?;
    let agent_server = AgentServer::new(config.clone())?;
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .thread_name(AGENT_SERVER_RUNTIME_NAME)
        .worker_threads(config.worker_thread_number())
        .build()?;
    runtime.block_on(async move {
        let (_server_command_tx, mut server_event_rx) = agent_server.start();
        while let Some(server_event) = server_event_rx.recv().await {
            println!("{server_event:?}")
        }
    });
    Ok(())
}
