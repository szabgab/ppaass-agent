use anyhow::Error as AnyhowError;
use ppaass_common::CommonError;
use std::io::Error as StdIoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("Network error happen: {0:?}")]
    Network(#[from] NetworkError),
    #[error("Encode error happen: {0:?}")]
    Encode(#[from] EncoderError),
    #[error("Decode error happen: {0:?}")]
    Decode(#[from] DecoderError),
    #[error(transparent)]
    Common(#[from] CommonError),
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error("Configuration error happen: {0:?}")]
    Configuration(String),
    #[error("Invalid proxy response error happen: {0:?}")]
    InvalidProxyResponse(String),
    #[error("IO error happen: {0:?}")]
    Io(#[from] StdIoError),
    #[error(transparent)]
    Other(#[from] AnyhowError),
}

#[derive(Debug, Error)]
pub enum EncoderError {
    #[error("Socks5 encode error: {0:?}")]
    Socks5(#[from] Socks5EncodeError),
    #[error("Http encode error: {0:?}")]
    Http(#[from] HttpEncodeError),
}

#[derive(Debug, Error)]
pub enum Socks5EncodeError {
    #[error("IO error happen: {0:?}")]
    Io(#[from] StdIoError),
}

#[derive(Debug, Error)]
pub enum HttpEncodeError {
    #[error("IO error happen: {0:?}")]
    Io(#[from] StdIoError),
    #[error("Low level encode error: {0:?}")]
    LowLevel(#[from] bytecodec::Error),
}

#[derive(Debug, Error)]
pub enum DecoderError {
    #[error("Socks5 decode error: {0:?}")]
    Socks5(#[from] Socks5DecodeError),
    #[error("Http decode error: {0:?}")]
    Http(#[from] HttpDecodeError),
    #[error("IO error happen: {0:?}")]
    Io(#[from] StdIoError),
    #[error("Unknown protocol")]
    UnknownProtocol,
    #[error("Unsupport protocol")]
    UnsupportProtocol,
}

#[derive(Debug, Error)]
pub enum Socks5DecodeError {
    #[error("Invalid socks5 version: {0}")]
    InvalidVersion(u8),
    #[error("Invalid socks5 init command type: {0}")]
    InvalidInitCommandType(u8),
    #[error("Invalid socks5 init command result status: {0}")]
    InvalidInitCommandResultStatus(u8),
    #[error("No remaining bytes: {0}")]
    NoRemaining(String),
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error("IO error happen: {0:?}")]
    Io(#[from] StdIoError),
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Input exhausted: {0}")]
    InputExhausted(String),
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}

#[derive(Debug, Error)]
pub enum ConversionError {
    #[error("Fail to convert because of IO error: {0:?}")]
    Io(#[from] StdIoError),
    #[error("Fail to convert because of format: {0}")]
    Format(String),
    #[error("Fail to convert url because of format: {0}")]
    UrlFormat(#[from] url::ParseError),
    #[error("No host found from url: {0}")]
    NoHost(String),
    #[error("No remaining bytes: {0}")]
    NoRemaining(String),
}

#[derive(Debug, Error)]
pub enum HttpDecodeError {
    #[error("IO error happen: {0:?}")]
    Io(#[from] StdIoError),
    #[error("Low level decode error: {0:?}")]
    LowLevel(#[from] bytecodec::Error),
}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("Fail to accept client connection because of error: {0:?}")]
    AcceptConnection(#[source] StdIoError),
    #[error("Fail to modify connection property because of error: {0:?}")]
    PropertyModification(#[source] StdIoError),
    #[error("Fail to bind tcp listener because of error: {0:?}")]
    TcpBind(#[source] StdIoError),
    #[error("Fail to create tcp connection because of error: {0:?}")]
    TcpConnect(#[source] StdIoError),
    #[error("Fail to receive client udp data because of error: {0:?}")]
    ClientUdpRecv(#[source] StdIoError),
    #[error("General I/O error happen: {0:?}")]
    General(#[source] StdIoError),
    #[error("Timeout error: {0:?}")]
    Timeout(u64),
    #[error("Nothing read from connection")]
    ConnectionExhausted,
}
