pub mod error;
pub mod server;

mod codec;
pub mod config;
mod crypto;
pub mod log;
mod proxy;
mod transport;

pub const SOCKS_V5: u8 = 5;
pub const SOCKS_V4: u8 = 4;
