use std::convert::Infallible;

use bytes::BytesMut;
use futures::future;

use crate::packet::*;
use crate::transport::{Encode, ExchangeTransport};

#[derive(Debug, Clone)]
pub struct PacketEchoTransport;

impl ExchangeTransport<LazyPacket> for PacketEchoTransport {
    type Error = Infallible;

    type Future = future::Ready<Result<LazyPacket, Infallible>>;

    fn exchange(&mut self, datagram: LazyPacket) -> Self::Future {
        let kind = datagram.kind();
        let response = if kind.is_session() {
            let (head, mut body) = datagram.split_session().unwrap();
            let tx_body = SupportedSessionBody::decode_body(&head, &mut body.0).unwrap();
            let rx_body = match tx_body {
                SupportedSessionBody::Syn(syn) => {
                    let syn = SynBody::new(
                        Sequence(rand::random()),
                        syn.is_command(),
                        syn.is_encrypted(),
                    );
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
            Packet::new(
                SupportedHeader::Session(head),
                SupportedBody::Session(SessionBodyBytes(body_bytes.freeze())),
            )
        } else {
            datagram
        };
        future::ok(response)
    }

    fn max_datagram_size(&self) -> usize {
        usize::max_value()
    }
}
