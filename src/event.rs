use std::net::SocketAddr;

use ppaass_protocol::message::values::address::PpaassUnifiedAddress;

#[derive(Debug)]
pub enum AgentServerEvent {
    NetworkState {
        upload_bytes_amount: u64,
        upload_mb_per_second: f64,
        download_bytes_amount: u64,
        download_mb_per_second: f64,
    },
    FailToListen(String),
    SuccessToListen(String),
    ClientConnectionAcceptSuccess {
        client_socket_address: SocketAddr,
        message: String,
    },
    ClientConnectionAcceptFail(String),
    ClientConnectionBeforeRelayFail {
        client_socket_address: SocketAddr,
        message: String,
    },
    ClientConnectionTransportCreateProxyConnectionFail {
        client_socket_address: SocketAddr,
        dst_address: PpaassUnifiedAddress,
        message: String,
    },
    ClientConnectionTransportCreateProxyConnectionSuccess {
        client_socket_address: SocketAddr,
        dst_address: PpaassUnifiedAddress,
        message: String,
    },
    ClientConnectionTransportCreateSuccess {
        client_socket_address: SocketAddr,
        dst_address: PpaassUnifiedAddress,
        message: String,
    },
    ClientConnectionTransportCreateFail {
        client_socket_address: SocketAddr,
        dst_address: PpaassUnifiedAddress,
        message: String,
    },
    ClientConnectionReadProxyConnectionWriteClose {
        client_socket_address: SocketAddr,
        message: String,
    },
    ClientConnectionWriteProxyConnectionReadClose {
        client_socket_address: SocketAddr,
        message: String,
    },
}
