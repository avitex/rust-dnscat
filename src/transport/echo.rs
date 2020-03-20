use std::convert::Infallible;

use bytes::BytesMut;
use futures::future;

use crate::packet::{
    LazyPacket, PacketBody, Sequence, SessionBodyBytes, SupportedSessionBody, SynBody,
};
use crate::transport::{Encode, ExchangeTransport};

#[derive(Debug, Clone)]
pub struct PacketEchoTransport;

impl ExchangeTransport<LazyPacket> for PacketEchoTransport {
    type Error = Infallible;

    type Future = future::Ready<Result<LazyPacket, Infallible>>;

    fn exchange(&mut self, mut datagram: LazyPacket) -> Self::Future {
        let kind = datagram.kind();
        let response = if kind.is_session_framed() {
            let session_body = datagram.body_mut().session_body_mut().unwrap();
            let mut body_bytes = session_body.bytes().clone();
            let tx_body = SupportedSessionBody::decode_kind(kind, &mut body_bytes).unwrap();
            let rx_body = match tx_body {
                SupportedSessionBody::Syn(syn) => {
                    let syn =
                        SynBody::new(Sequence::random(), syn.is_command(), syn.is_encrypted());
                    SupportedSessionBody::Syn(syn)
                }
                SupportedSessionBody::Msg(mut msg) => {
                    let data_len = msg.data().len() as u8;
                    msg.set_ack(msg.seq().add(data_len));
                    msg.set_seq(msg.ack().add(data_len));
                    SupportedSessionBody::Msg(msg)
                }
                other => other,
            };
            let mut body_bytes = BytesMut::new();
            rx_body.encode(&mut body_bytes);
            *session_body = SessionBodyBytes::new(kind, body_bytes.freeze());
            datagram
        } else {
            datagram
        };
        future::ok(response)
    }

    fn max_datagram_size(&self) -> usize {
        usize::max_value()
    }
}
