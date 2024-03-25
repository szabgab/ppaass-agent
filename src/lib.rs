pub mod error;
pub mod server;

mod codec;
pub mod config;
mod crypto;
mod proxy;
mod trace;
mod transport;

pub const SOCKS_V5: u8 = 5;
pub const SOCKS_V4: u8 = 4;
