use std::sync::{Arc, OnceLock};

use crypto::AgentServerRsaCryptoFetcher;

pub mod config;
pub mod crypto;
pub(crate) mod edge;
pub mod error;
pub(crate) mod handler;
pub mod server;
pub(crate) mod transport;

pub(crate) const SOCKS_V5: u8 = 5;
pub(crate) const SOCKS_V4: u8 = 4;

pub static RSA_CRYPTO_FETCHER: OnceLock<Arc<AgentServerRsaCryptoFetcher>> = OnceLock::new();
