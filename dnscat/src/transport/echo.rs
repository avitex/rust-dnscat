use std::convert::Infallible;
use std::task::{Context, Poll, Waker};

use bytes::BytesMut;

use crate::packet::*;
use crate::transport::{Encode, Transport};

#[derive(Debug, Clone)]
pub struct PacketEchoTransport {
    datagram: Option<LazyPacket>,
    send_task: Option<Waker>,
    recv_task: Option<Waker>,
}

impl Transport<LazyPacket> for PacketEchoTransport {
    type Error = Infallible;

    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        datagram: LazyPacket,
    ) -> Poll<Result<(), Self::Error>> {
        if self.datagram.is_some() {
            self.send_task = Some(cx.waker().clone());
            Poll::Pending
        } else {
            self.datagram = Some(datagram);
            if let Some(recv_task) = self.recv_task.take() {
                recv_task.wake();
            }
            Poll::Ready(Ok(()))
        }
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<LazyPacket, Self::Error>> {
        match self.datagram.take() {
            None => {
                self.recv_task = Some(cx.waker().clone());
                Poll::Pending
            }
            Some(datagram) => {
                let kind = datagram.kind();
                let response = if kind.is_session() {
                    let (head, mut body) = datagram.split_session().unwrap();
                    let tx_body = SupportedSessionBody::decode_body(&head, &mut body.0).unwrap();
                    let rx_body = match tx_body {
                        SupportedSessionBody::Syn(syn) => {
                            let syn = SynBody::new(Sequence(rand::random()), syn.is_command());
                            SupportedSessionBody::Syn(syn)
                        }
                        SupportedSessionBody::Msg(mut msg) => {
                            let data_len = msg.data().len() as u8;
                            msg.set_ack(msg.seq().add_data(data_len));
                            msg.set_seq(msg.ack().add_data(data_len));
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
                if let Some(send_task) = self.send_task.take() {
                    send_task.wake();
                }
                Poll::Ready(Ok(response))
            }
        }
    }

    fn max_datagram_size(&self) -> usize {
        usize::max_value()
    }
}
