use crate::crypto::AgentServerRsaCryptoFetcher;
use crate::error::AgentError;
use bytes::BytesMut;
use ppaass_codec::codec::agent::PpaassAgentMessageEncoder;
use ppaass_codec::codec::proxy::PpaassProxyMessageDecoder;
use ppaass_protocol::message::{PpaassAgentMessage, PpaassProxyMessage};
use tokio_util::codec::{Decoder, Encoder};

pub(crate) struct PpaassProxyEdgeCodec {
    encoder: PpaassAgentMessageEncoder<AgentServerRsaCryptoFetcher>,
    decoder: PpaassProxyMessageDecoder<AgentServerRsaCryptoFetcher>,
}

impl PpaassProxyEdgeCodec {
    pub fn new(compress: bool, rsa_crypto_fetcher: AgentServerRsaCryptoFetcher) -> Self {
        Self {
            encoder: PpaassAgentMessageEncoder::new(compress, rsa_crypto_fetcher.clone()),
            decoder: PpaassProxyMessageDecoder::new(rsa_crypto_fetcher),
        }
    }
}

impl Encoder<PpaassAgentMessage> for PpaassProxyEdgeCodec {
    type Error = AgentError;

    fn encode(&mut self, item: PpaassAgentMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.encoder.encode(item, dst).map_err(AgentError::ProxyEdgeCodec)
    }
}

impl Decoder for PpaassProxyEdgeCodec {
    type Item = PpaassProxyMessage;
    type Error = AgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decoder.decode(src).map_err(AgentError::ProxyEdgeCodec)
    }
}
