use ppaass_codec::error::CodecError;
use std::io::Error as StdIoError;
use thiserror::Error;
#[derive(Debug, Error)]
pub enum AgentError {
    #[error("Client side codec error happen: {0}")]
    ClientCodec(String),
    #[error("General I/O error happen: {0:?}")]
    GeneralIo(#[from] StdIoError),
    #[error("Codec error happen: {0:?}")]
    Codec(#[from] CodecError),
    #[error("Other error happen: {0}")]
    Other(String),
}
