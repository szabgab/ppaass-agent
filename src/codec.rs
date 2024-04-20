use crate::error::AgentServerError;
use bytes::BytesMut;
use ppaass_codec::codec::agent::PpaassAgentMessageEncoder;
use ppaass_codec::codec::proxy::PpaassProxyMessageDecoder;
use ppaass_crypto::crypto::RsaCryptoFetcher;
use ppaass_protocol::message::{PpaassAgentMessage, PpaassProxyMessage};
use tokio_util::codec::{Decoder, Encoder};

pub(crate) struct PpaassProxyEdgeCodec<F>
where
    F: RsaCryptoFetcher,
{
    encoder: PpaassAgentMessageEncoder<F>,
    decoder: PpaassProxyMessageDecoder<F>,
}

impl<F> PpaassProxyEdgeCodec<F>
where
    F: RsaCryptoFetcher + Clone,
{
    pub fn new(compress: bool, rsa_crypto_fetcher: F) -> Self {
        Self {
            encoder: PpaassAgentMessageEncoder::new(compress, rsa_crypto_fetcher.clone()),
            decoder: PpaassProxyMessageDecoder::new(rsa_crypto_fetcher),
        }
    }
}

impl<F> Encoder<PpaassAgentMessage> for PpaassProxyEdgeCodec<F>
where
    F: RsaCryptoFetcher,
{
    type Error = AgentServerError;

    fn encode(&mut self, item: PpaassAgentMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.encoder
            .encode(item, dst)
            .map_err(AgentServerError::ProxyEdgeCodec)
    }
}

impl<F> Decoder for PpaassProxyEdgeCodec<F>
where
    F: RsaCryptoFetcher,
{
    type Item = PpaassProxyMessage;
    type Error = AgentServerError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decoder
            .decode(src)
            .map_err(AgentServerError::ProxyEdgeCodec)
    }
}
