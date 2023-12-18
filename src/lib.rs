mod codec;
pub mod config;
pub(crate) mod connection;
pub(crate) mod crypto;
pub mod error;
pub mod server;
pub(crate) mod transport;
mod util;

pub(crate) const SOCKS_V5: u8 = 5;
pub(crate) const SOCKS_V4: u8 = 4;
