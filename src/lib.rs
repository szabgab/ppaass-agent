use std::sync::{Arc, OnceLock};

use crypto::AgentServerRsaCryptoFetcher;

pub mod config;
pub mod crypto;
pub mod error;
pub(crate) mod pool;
pub mod server;
pub(crate) mod transport;

pub(crate) const SOCKS_V5: u8 = 5;
pub(crate) const SOCKS_V4: u8 = 4;

pub static RSA_CRYPTO_FETCHER: OnceLock<Arc<AgentServerRsaCryptoFetcher>> = OnceLock::new();
