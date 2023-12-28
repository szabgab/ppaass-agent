mod codec;
pub mod config;
pub(crate) mod crypto;
pub mod error;
pub(crate) mod proxy;
pub mod server;
pub(crate) mod transport;

pub(crate) const SOCKS_V5: u8 = 5;
pub(crate) const SOCKS_V4: u8 = 4;
