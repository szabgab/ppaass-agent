use ppaass_protocol::message::values::address::PpaassUnifiedAddress;

#[derive(Debug, Clone)]
pub enum AgentServerEvent {
    NetworkState {
        upload_mb_amount: f64,
        upload_mb_per_second: f64,
        download_mb_amount: f64,
        download_mb_per_second: f64,
    },
    ServerStartSuccess(u16),
    ServerStartFail {
        listening_port: u16,
        reason: String,
    },
    ServerStopSuccess(u16),
    ServerStopFail {
        listening_port: u16,
        reason: String,
    },
    TunnelInitializeSuccess {
        client_socket_address: PpaassUnifiedAddress,
        src_address: Option<PpaassUnifiedAddress>,
        dst_address: Option<PpaassUnifiedAddress>,
    },
    TunnelInitializeFail {
        client_socket_address: PpaassUnifiedAddress,
        src_address: Option<PpaassUnifiedAddress>,
        dst_address: Option<PpaassUnifiedAddress>,
        reason: String,
    },
    TunnelStartRelay {
        client_socket_address: PpaassUnifiedAddress,
        src_address: Option<PpaassUnifiedAddress>,
        dst_address: Option<PpaassUnifiedAddress>,
    },
    TunnelClose {
        client_socket_address: PpaassUnifiedAddress,
        src_address: Option<PpaassUnifiedAddress>,
        dst_address: Option<PpaassUnifiedAddress>,
    },
}
