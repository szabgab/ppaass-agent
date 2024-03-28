use clap::Parser;
use ppaass_agent::config::AgentConfig;
use ppaass_agent::error::AgentError;
use ppaass_agent::log;
use ppaass_agent::server::AgentServer;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> Result<(), AgentError> {
    let config = AgentConfig::parse();
    let _log_guard = log::init_log(&config)?;
    let agent_server = AgentServer::new(config)?;
    let guard = agent_server.start();
    guard.blocking();
    Ok(())
}
