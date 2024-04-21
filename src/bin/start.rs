use clap::Parser;
use ppaass_agent::config::AgentServerConfig;
use ppaass_agent::error::AgentServerError;
use ppaass_agent::log;
use ppaass_agent::server::AgentServer;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> Result<(), AgentServerError> {
    let config = AgentServerConfig::parse();
    let _log_guard = log::init_log(&config)?;
    let agent_server = AgentServer::new(config)?;
    let (_guard, mut server_event_rx) = agent_server.start();
    while let Some(server_event) = server_event_rx.recv().await {
        println!("{server_event:?}")
    }
    Ok(())
}
