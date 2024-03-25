mod codec;
pub mod config;
mod crypto;
pub mod error;
mod proxy;
pub mod server;
pub mod trace;
mod transport;

pub const SOCKS_V5: u8 = 5;
pub const SOCKS_V4: u8 = 4;