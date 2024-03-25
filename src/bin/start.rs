use clap::Parser;
use ppaass_agent::config::AgentConfig;
use ppaass_agent::error::AgentError;
use ppaass_agent::server::AgentServer;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> Result<(), AgentError> {
    let agent_server = AgentServer::new(AgentConfig::parse())?;
    agent_server.start();
    Ok(())
}
