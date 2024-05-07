use std::sync::{atomic::AtomicU64, Arc};

use ppaass_crypto::crypto::RsaCryptoFetcher;
use ppaass_protocol::message::values::address::PpaassUnifiedAddress;

use crate::{config::AgentServerConfig, proxy::ProxyConnectionFactory};

pub(crate) struct TunnelCreateRequest<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    pub src_address: PpaassUnifiedAddress,
    pub client_socket_address: PpaassUnifiedAddress,
    pub config: Arc<AgentServerConfig>,
    pub proxy_connection_factory: Arc<ProxyConnectionFactory<F>>,
    pub upload_bytes_amount: Arc<AtomicU64>,
    pub download_bytes_amount: Arc<AtomicU64>,
}
