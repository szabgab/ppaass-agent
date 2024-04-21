use clap::Parser;
use ppaass_agent::error::AgentServerError;
use ppaass_agent::log;
use ppaass_agent::server::AgentServer;
use ppaass_agent::{config::AgentServerConfig, event::AgentServerEvent};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

async fn on_server_event(server_event: AgentServerEvent) {
    println!("{server_event:?}");
}

fn main() -> Result<(), AgentServerError> {
    let config = AgentServerConfig::parse();
    let _log_guard = log::init_log(&config)?;
    let agent_server = AgentServer::new(config)?;
    let mut guard = agent_server.start();
    guard.on_server_event(on_server_event);
    Ok(())
}
