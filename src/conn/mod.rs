mod builder;
mod echo;
mod handshake;

pub mod enc;

use std::borrow::Cow;
use std::cmp;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use futures::io::{self, AsyncRead, AsyncWrite};
use log::debug;

use crate::packet::*;
use crate::transport::*;

pub use self::builder::ConnectionBuilder;
pub use self::echo::PacketEchoTransport;
pub use self::enc::ConnectionEncryption;

///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum ConnectionError<TE, EE> {
    Closed,
    Timeout,
    EncryptionMismatch,
    Transport(TE),
    Encryption(EE),
    LengthTooLong,
    NoDatagramBudget,
    PacketDecode(PacketDecodeError),
    Unexpected(SupportedSessionBody),
    PeerAckInvalid { expected: Sequence, got: Sequence },
}

#[derive(Debug)]
pub struct Connection<T, E = ()>
where
    T: ExchangeTransport<LazyPacket>,
    E: ConnectionEncryption,
{
    sess_id: u16,
    sess_name: Option<Cow<'static, str>>,
    peer_seq: u16,
    self_seq: u16,
    command: bool,
    transport: T,
    encryption: Option<E>,
    send_buffer: BytesMut,
    recv_buffer: VecDeque<LazyPacket>,
    recv_timeout: Duration,
    recv_max_retry: usize,
    send_max_retry: usize,
}

impl<T, E> Connection<T, E>
where
    T: ExchangeTransport<LazyPacket>,
    E: ConnectionEncryption,
{
    /// Returns `true` if the connection is a command session.
    pub fn is_command(&self) -> bool {
        self.command
    }

    /// Returns `true` if the connection is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    /// Returns the max data chunk size that can be sent in one datagram.
    ///
    /// This is calculated based on the transport's indicated capability,
    /// minus the cost of the framing and/or encryption framing if enabled.
    pub fn max_data_chunk_size(&self) -> u16 {
        // First calculate the total fixed size of a msg packet.
        let constant_size = Packet::<SessionBodyFrame<MsgBody>>::header_size()
            + SessionBodyFrame::<MsgBody>::header_size()
            + MsgBody::header_size();
        // If this connection is encrypted, add the additional size required.
        let constant_size = if let Some(ref encryption) = self.encryption {
            constant_size + encryption.additional_size()
        } else {
            constant_size
        };
        // Subtract the total size required from what the transport
        // can provide to get the budget we can use.
        let budget = self.transport.max_datagram_size() - constant_size;
        // Limit the budget to the max size of a sequence (u16) value.
        if budget > Sequence::max_value() as usize {
            u16::max_value()
        } else {
            budget as u16
        }
    }

    fn calc_chunk_len(&self, data_len: usize) -> Result<u16, ConnectionError<T::Error, E::Error>> {
        let val = cmp::min(data_len, self.max_data_chunk_size() as usize) as u16;
        if val == 0 {
            Err(ConnectionError::NoDatagramBudget)
        } else {
            Ok(val)
        }
    }

    fn data_len_from_usize(len: usize) -> Result<u16, ConnectionError<T::Error, E::Error>> {
        if len > Sequence::max_value() as usize {
            Err(ConnectionError::LengthTooLong)
        } else {
            Ok(len as u16)
        }
    }

    fn handle_peer_msg(
        &mut self,
        peer_msg: MsgBody,
        expected_bytes_ack: u16,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        debug!(
            "data-rx: [seq: {}, ack: {}, data: {:?}]",
            peer_msg.seq(),
            peer_msg.ack(),
            peer_msg.data()
        );
        let next_self_seq = self.self_seq.wrapping_add(expected_bytes_ack);
        if peer_msg.ack() != next_self_seq {
            return Err(ConnectionError::PeerAckInvalid {
                expected: next_self_seq,
                got: peer_msg.ack(),
            });
        }
        let received_data_len = Self::data_len_from_usize(peer_msg.data().len())?;
        debug!(
            "data-ack: [rx: {}, tx: {}]",
            expected_bytes_ack, received_data_len
        );
        self.self_seq = next_self_seq;
        self.peer_seq = self.peer_seq.wrapping_add(received_data_len);
        Ok(())
    }

    pub async fn send_data(
        &mut self,
        mut data: Bytes,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        'send_main: loop {
            if data.is_empty() {
                return Ok(());
            }
            let mut data_chuck_attempt = 1;
            let data_chunk_len = self.calc_chunk_len(data.len())?;
            let data_chunk = data.split_to(data_chunk_len as usize);
            'send_chunk: loop {
                self.send_data_chunk(data_chunk.clone()).await?;
                match self.recv_packet().await? {
                    SupportedSessionBody::Msg(peer_msg) => {
                        match self.handle_peer_msg(peer_msg, data_chunk_len) {
                            Ok(()) => continue 'send_main,
                            Err(_) if data_chuck_attempt < self.send_max_retry => {
                                debug!("send chuck failed, retrying...");
                                data_chuck_attempt += 1;
                                continue 'send_chunk;
                            }
                            Err(err) => return Err(err),
                        }
                    }
                    unexpected_body => return Err(ConnectionError::Unexpected(unexpected_body)),
                }
            }
        }
    }

    async fn send_data_chunk(
        &mut self,
        data_chunk: Bytes,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        let mut msg_body = MsgBody::new(self.self_seq, self.peer_seq);
        msg_body.set_data(data_chunk);
        debug!(
            "data-tx: [seq: {}, ack: {}, data: {:?}]",
            msg_body.seq(),
            msg_body.ack(),
            msg_body.data()
        );
        self.send_packet(msg_body).await
    }

    async fn send_packet<B>(&mut self, body: B) -> Result<(), ConnectionError<T::Error, E::Error>>
    where
        B: Into<SupportedSessionBody>,
    {
        let packet_id = rand::random();
        let session_body = body.into();
        let packet_kind = session_body.packet_kind();
        session_body.encode(&mut self.send_buffer);
        let session_body_bytes = if let Some(ref mut encryption) = self.encryption {
            encryption.encrypt(&mut self.send_buffer)
        } else {
            self.send_buffer.to_bytes()
        };
        let session_body = SessionBodyBytes::new(packet_kind, session_body_bytes);
        let packet_body = SupportedBody::Session(SessionBodyFrame::new(self.sess_id, session_body));
        let packet = Packet::new(packet_id, packet_body);
        let response = self
            .transport
            .exchange(packet)
            .await
            .map_err(ConnectionError::Transport)?;
        self.recv_buffer.push_back(response);
        Ok(())
    }

    async fn recv_packet(
        &mut self,
    ) -> Result<SupportedSessionBody, ConnectionError<T::Error, E::Error>> {
        let session_frame = loop {
            // Sanity check
            let session_frame_opt = loop {
                if let Some(packet) = self.recv_buffer.pop_front() {
                    if packet.kind().is_session_framed() {
                        break packet.into_body().into_session_frame();
                    }
                } else {
                    break None;
                }
            };
            if let Some(session_frame) = session_frame_opt {
                break session_frame;
            } else {
                self.send_data_chunk(Bytes::new()).await?;
            }
        };
        if self.sess_id != session_frame.session_id() {
            unimplemented!()
        }
        let session_body = session_frame.into_body();
        let packet_kind = session_body.packet_kind();
        let mut session_body_bytes = session_body.into_bytes();
        let mut session_body_bytes = if let Some(ref mut encryption) = self.encryption {
            encryption.decrypt(&mut session_body_bytes)
        } else {
            session_body_bytes
        };
        SupportedSessionBody::decode_kind(packet_kind, &mut session_body_bytes)
            .map_err(ConnectionError::PacketDecode)
    }
}

impl<T, E> AsyncRead for Connection<T, E>
where
    T: ExchangeTransport<LazyPacket>,
    E: ConnectionEncryption,
{
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        unimplemented!()
    }
}

impl<T, E> AsyncWrite for Connection<T, E>
where
    T: ExchangeTransport<LazyPacket>,
    E: ConnectionEncryption,
{
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        unimplemented!()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), io::Error>> {
        unimplemented!()
    }
}
