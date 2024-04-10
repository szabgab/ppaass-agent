use std::{
    net::SocketAddr,
    sync::{atomic::AtomicU32, Arc},
};

use ppaass_crypto::crypto::RsaCryptoFetcher;
use ppaass_protocol::message::values::address::PpaassUnifiedAddress;

use crate::{config::AgentConfig, proxy::ProxyConnectionFactory};

pub(crate) struct ClientTransportCreateRequest<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    pub src_address: PpaassUnifiedAddress,
    pub client_socket_addr: SocketAddr,
    pub config: Arc<AgentConfig>,
    pub proxy_connection_factory: Arc<ProxyConnectionFactory<F>>,
    pub upload_bytes_amount: Arc<AtomicU32>,
    pub download_bytes_amount: Arc<AtomicU32>,
}
