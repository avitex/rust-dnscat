mod builder;
mod echo;
mod handshake;

pub mod enc;

use std::borrow::Cow;
use std::cmp;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use futures::io::{self, AsyncRead, AsyncWrite};
use log::debug;

use crate::packet::*;
use crate::transport::*;
use crate::util::StringBytes;

pub use self::builder::ConnectionBuilder;
pub use self::echo::PacketEchoTransport;
pub use self::enc::ConnectionEncryption;

macro_rules! debug_msg_body {
    ($ctx:expr, $msg:expr) => {
        debug!(
            concat!($ctx, ": [seq: {}, ack: {}, data: {:?}]"),
            $msg.seq().0,
            $msg.ack().0,
            $msg.data(),
        );
    };
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum ConnectionError<TE, EE> {
    Closed,
    Timeout,
    DataTooLong,
    Transport(TE),
    Encryption(EE),
    NoDatagramBudget,
    ReceiveBufferFull,
    EncryptionMismatch,
    PacketDecode(PacketDecodeError),
    UnexpectedPacketKind(PacketKind),
    PeerAbort { reason: StringBytes },
    PeerAckInvalid { expected: Sequence, got: Sequence },
}

// impl<TE, EE> ConnectionError<TE, EE> {
//     pub fn is_fatal(&self) -> bool {}
// }

#[derive(Debug)]
enum ConnectionState {
    Idle,
    Closed { reason: Option<StringBytes> },
    SendingChunk(u16),
}

#[derive(Debug)]
pub struct Connection<T, E = ()>
where
    T: ExchangeTransport<LazyPacket>,
    E: ConnectionEncryption,
{
    state: ConnectionState,
    sess_id: u16,
    sess_name: Option<Cow<'static, str>>,
    is_command: bool,
    peer_seq: Sequence,
    self_seq: Sequence,
    transport: T,
    encryption: Option<E>,
    send_buffer: BytesMut,
    send_retry_max: usize,
    recv_retry_max: usize,
    recv_data_buf: VecDeque<Bytes>,
    recv_datagram_buf: VecDeque<SupportedSessionBody>,
}

impl<T, E> Connection<T, E>
where
    T: ExchangeTransport<LazyPacket>,
    E: ConnectionEncryption,
{
    /// Retrieve session ID.
    pub fn session_id(&self) -> SessionId {
        self.sess_id
    }

    /// Retrieve session name
    pub fn session_name(&self) -> Option<&str> {
        self.sess_name.as_ref().map(AsRef::as_ref)
    }

    /// Returns `true` if the connection is a command session.
    pub fn is_command(&self) -> bool {
        self.is_command
    }

    /// Returns `true` if the connection is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    /// Returns `true` if the connection is closed.
    pub fn is_closed(&self) -> bool {
        unimplemented!()
    }

    /// Returns the max data chunk size that can be sent in one datagram.
    ///
    /// This is calculated based on the transport's indicated capability,
    /// minus the cost of the framing and/or encryption framing if enabled.
    pub fn max_data_chunk_size(&self) -> u8 {
        // First calculate the total fixed size of a msg packet.
        let constant_size = Packet::<SessionBodyFrame<MsgBody>>::header_size()
            + SessionBodyFrame::<MsgBody>::header_size()
            + MsgBody::header_size();
        // If this connection is encrypted, add the additional size required.
        let constant_size = if let Some(ref encryption) = self.encryption {
            constant_size as usize + encryption.additional_size()
        } else {
            constant_size as usize
        };
        // Subtract the total size required from what the transport
        // can provide to get the budget we can use.
        let budget = self.transport.max_datagram_size() - constant_size;
        // Limit the budget to the max size of a sequence (u16) value.
        if budget > LazyPacket::max_size() as usize {
            u8::max_value()
        } else {
            budget as u8
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

    fn validate_chunk_len(len: usize) -> Result<u8, ConnectionError<T::Error, E::Error>> {
        if len > LazyPacket::max_size() as usize {
            Err(ConnectionError::DataTooLong)
        } else {
            Ok(len as u8)
        }
    }

    fn handle_peer_msg(
        &mut self,
        peer_msg: MsgBody,
        expected_bytes_ack: u8,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        debug_msg_body!("data-rx", peer_msg);
        let next_self_seq = self.self_seq.clone().add(expected_bytes_ack);
        if peer_msg.ack() != next_self_seq {
            return Err(ConnectionError::PeerAckInvalid {
                expected: next_self_seq,
                got: peer_msg.ack(),
            });
        }
        let received_data_len = Self::validate_chunk_len(peer_msg.data().len())?;
        debug!(
            "data-ack: [rx: {}, tx: {}]",
            received_data_len, expected_bytes_ack
        );
        self.self_seq = next_self_seq;
        self.peer_seq.add(received_data_len);
        if self.recv_data_buf.len() == self.recv_data_buf.capacity() {
            Err(ConnectionError::ReceiveBufferFull)
        } else {
            self.recv_data_buf.push_front(peer_msg.into_data());
            Ok(())
        }
    }

    pub async fn recv_data(
        &mut self,
    ) -> Result<Option<Bytes>, ConnectionError<T::Error, E::Error>> {
        unimplemented!()
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
                match self.send_data_chunk(data_chunk.clone()).await {
                    Ok(()) => continue 'send_main,
                    err @ Err(ConnectionError::ReceiveBufferFull) => return err,
                    Err(_) if data_chuck_attempt < self.send_retry_max => {
                        debug!("send chuck failed, retrying...");
                        data_chuck_attempt += 1;
                        continue 'send_chunk;
                    }
                    Err(err) => return Err(err),
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
        debug_msg_body!("data-tx", msg_body);
        self.send_session_body(msg_body).await
    }

    fn handle_response(
        &mut self,
        response: LazyPacket,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        let response_kind = response.kind();
        if let Some(session_frame) = response.into_body().into_session_frame() {
            if self.sess_id != session_frame.session_id() {
                unimplemented!()
            } else {
                let mut body_bytes = session_frame.into_body().into_bytes();
                let mut body_bytes = if let Some(ref mut encryption) = self.encryption {
                    encryption.decrypt(&mut body_bytes)
                } else {
                    body_bytes
                };
                let body = SupportedSessionBody::decode_kind(response_kind, &mut body_bytes)
                    .map_err(ConnectionError::PacketDecode)?;
                self.handle_response_body(body)
            }
        } else {
            Err(ConnectionError::UnexpectedPacketKind(response_kind))
        }
    }

    fn handle_response_body(
        &mut self,
        body: SupportedSessionBody,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        // match body {
        //     SupportedSessionBody::Msg(peer_msg) => self.handle_peer_msg(peer_msg, data_chunk_len)
        // }
        // self.recv_datagram_buf.push_back(body);
        unimplemented!()
    }

    async fn send_session_body<B>(
        &mut self,
        body: B,
    ) -> Result<(), ConnectionError<T::Error, E::Error>>
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
        let mut session_body = SessionBodyBytes::new(packet_kind);
        session_body.set_bytes(session_body_bytes);
        let packet_body = SupportedBody::Session(SessionBodyFrame::new(self.sess_id, session_body));
        let packet = Packet::new(packet_id, packet_body);
        let response = self
            .transport
            .exchange(packet)
            .await
            .map_err(ConnectionError::Transport)?;
        self.handle_response(response)
    }

    async fn recv_session_body<B>(&mut self) -> Result<B, ConnectionError<T::Error, E::Error>>
    where
        B: From<SupportedSessionBody>,
    {
        loop {
            if let Some(body) = self.recv_datagram_buf.pop_front() {
                return Ok(body.into());
            } else {
                self.send_data_chunk(Bytes::new()).await?;
            }
        }
    }

    fn close_if_error<RT, RE>(&mut self, result: Result<RT, RE>) -> Result<RT, RE> {
        if result.is_err() {
            self.is_closed = true;
        }
        result
    }

    fn check_open(&self) -> Result<(), ConnectionError<T::Error, E::Error>> {
        if self.is_closed() {
            Err(ConnectionError::Closed)
        } else {
            Ok(())
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Async Read + Write

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
