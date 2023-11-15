use bytecodec::{
    bytes::{BytesEncoder, RemainingBytesDecoder},
    ErrorKind,
};
use bytecodec::{io::IoDecodeExt, EncodeExt};

use bytes::{Buf, BufMut, BytesMut};
use httpcodec::{BodyDecoder, BodyEncoder, Request, RequestDecoder, Response, ResponseEncoder};

use log::error;
use tokio_util::codec::{Decoder, Encoder};

use crate::error::{HttpDecodeError, HttpEncodeError};

#[derive(Debug, Default)]
pub(crate) struct HttpCodec {
    request_decoder: RequestDecoder<BodyDecoder<RemainingBytesDecoder>>,
    response_encoder: ResponseEncoder<BodyEncoder<BytesEncoder>>,
}

impl Decoder for HttpCodec {
    type Item = Request<Vec<u8>>;
    type Error = HttpDecodeError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let decode_result = match self.request_decoder.decode_exact(src.chunk()) {
            Ok(decode_result) => decode_result,
            Err(e) => match e.kind() {
                ErrorKind::IncompleteDecoding => return Ok(None),
                other_kind => {
                    error!("Http agent fail to decode because of error: {other_kind:?}");
                    return Err(HttpDecodeError::LowLevel(e));
                },
            },
        };
        Ok(Some(decode_result))
    }
}

impl Encoder<Response<Vec<u8>>> for HttpCodec {
    type Error = HttpEncodeError;

    fn encode(&mut self, item: Response<Vec<u8>>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let encode_result = self.response_encoder.encode_into_bytes(item)?;
        dst.put_slice(encode_result.as_slice());
        Ok(())
    }
}
