use anyhow::Result;

use log::error;
use ppaass_agent_windows_lib::{
    config::AGENT_CONFIG, crypto::AgentServerRsaCryptoFetcher, server::AgentServer,
};
use tokio::runtime::Builder;

const LOG_CONFIG_PATH: &str = "resources/config/ppaass-agent-log.yml";

fn main() -> Result<()> {
    log4rs::init_file(LOG_CONFIG_PATH, Default::default())?;
    RSA_CRYPTO_FETCHER
        .set(Arc::new(AgentServerRsaCryptoFetcher::new()?))
        .expect("Fail to set rsa crypto fetcher.");
    let agent_server_runtime = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(AGENT_CONFIG.get_worker_thread_number())
        .build()?;
    agent_server_runtime.block_on(async move {
        let mut agent_server = AgentServer::default();
        if let Err(e) = agent_server.start().await {
            error!("Fail to start agent server because of error: {e:?}");
        };
    });
    Ok(())
}
