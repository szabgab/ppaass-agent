use ppaass_codec::error::CodecError;
use ppaass_protocol::error::ProtocolError;
use std::io::Error as StdIoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentServerError {
    #[error("Agent error happen because of io: {0:?}")]
    StdIo(#[from] StdIoError),
    #[error(transparent)]
    ProxyEdgeCodec(#[from] CodecError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("Agent error happen because of reason: {0}")]
    Other(String),
}
