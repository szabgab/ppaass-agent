use crate::error::AgentError;
use bytes::BytesMut;
use futures::{Sink, Stream};
use pin_project::pin_project;
use ppaass_codec::codec::agent::encoder::AgentMessageEncoder;
use ppaass_codec::codec::proxy::decoder::ProxyMessageDecoder;
use ppaass_crypto::RsaCryptoFetcher;
use ppaass_protocol::message::agent::AgentMessage;
use ppaass_protocol::message::proxy::ProxyMessage;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder, Framed};
use uuid::Uuid;

struct ProxyEdgeCodec<F>
where
    F: RsaCryptoFetcher + Send + Sync + Clone + 'static,
{
    decoder: ProxyMessageDecoder<F>,
    encoder: AgentMessageEncoder<F>,
}

impl<F> ProxyEdgeCodec<F>
where
    F: RsaCryptoFetcher + Send + Sync + Clone + 'static,
{
    pub(crate) fn new(compress: bool, rsa_crypto_fetcher: F) -> ProxyEdgeCodec<F> {
        ProxyEdgeCodec {
            decoder: ProxyMessageDecoder::new(rsa_crypto_fetcher.clone()),
            encoder: AgentMessageEncoder::new(compress, rsa_crypto_fetcher),
        }
    }
}

impl<F> Decoder for ProxyEdgeCodec<F>
where
    F: RsaCryptoFetcher + Send + Sync + Clone + 'static,
{
    type Item = ProxyMessage;
    type Error = AgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decoder
            .decode(src)
            .map_err(AgentError::DecoderProxyEdge)
    }
}

impl<F> Encoder<AgentMessage> for ProxyEdgeCodec<F>
where
    F: RsaCryptoFetcher + Send + Sync + Clone + 'static,
{
    type Error = AgentError;

    fn encode(&mut self, item: AgentMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.encoder
            .encode(item, dst)
            .map_err(AgentError::EncoderProxyEdge)
    }
}

#[pin_project]
pub(crate) struct ProxyEdge<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    F: RsaCryptoFetcher + Send + Sync + Clone + 'static,
{
    #[pin]
    inner: Framed<T, ProxyEdgeCodec<F>>,
    connection_id: String,
    _marker: PhantomData<F>,
}

impl<T, F> ProxyEdge<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    F: RsaCryptoFetcher + Send + Sync + Clone + 'static,
{
    pub fn new(
        stream: T,
        rsa_crypto_fetcher: F,
        compress: bool,
        buffer_size: usize,
    ) -> ProxyEdge<T, F> {
        let connection_codec = ProxyEdgeCodec::new(compress, rsa_crypto_fetcher);
        let inner = Framed::with_capacity(stream, connection_codec, buffer_size);
        Self {
            inner,
            connection_id: Uuid::new_v4().to_string(),
            _marker: PhantomData,
        }
    }
}

impl<T, F> Sink<AgentMessage> for ProxyEdge<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    F: RsaCryptoFetcher + Send + Sync + Clone + 'static,
{
    type Error = AgentError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: AgentMessage) -> Result<(), Self::Error> {
        let this = self.project();
        this.inner.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_close(cx)
    }
}

impl<T, F> Stream for ProxyEdge<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    F: RsaCryptoFetcher + Send + Sync + Clone + 'static,
{
    type Item = Result<ProxyMessage, AgentError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        this.inner.poll_next(cx)
    }
}
