mod builder;
mod echo;

pub mod enc;

use std::borrow::Cow;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::{cmp, fmt};

use bytes::{Buf, Bytes, BytesMut};
use futures::io::{self, AsyncRead, AsyncWrite};
use futures::{future, ready};
use log::debug;

use crate::packet::*;
use crate::transport::*;
use crate::util::StringBytes;

pub use self::builder::ConnectionBuilder;
pub use self::echo::PacketEchoTransport;
pub use self::enc::ConnectionEncryption;

///////////////////////////////////////////////////////////////////////////////

type StatePoll<T, E> = Poll<
    Result<
        ConnectionState<<T as ExchangeTransport<LazyPacket>>::Future>,
        ConnectionError<
            <T as ExchangeTransport<LazyPacket>>::Error,
            <E as ConnectionEncryption>::Error,
        >,
    >,
>;

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
    PeerAbort,
    DataTooLong,
    Transport(TE),
    Encryption(EE),
    SendBufferFull,
    RecvBufferFull,
    NoDatagramBudget,
    EncryptionMismatch,
    PacketDecode(PacketDecodeError),
    UnexpectedSessionId(SessionId),
    UnexpectedPacketKind(PacketKind),
    UnexpectedPeerAck {
        expected: Sequence,
        actual: Sequence,
    },
}

impl<TE, EE> From<ConnectionError<TE, EE>> for std::io::Error {
    fn from(_err: ConnectionError<TE, EE>) -> Self {
        unimplemented!()
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct Connection<T, E = ()>
where
    T: ExchangeTransport<LazyPacket>,
{
    inner: ConnectionInner<T, E>,
    state: ConnectionState<T::Future>,
}

impl<T, E> Connection<T, E>
where
    T: ExchangeTransport<LazyPacket>,
    T::Future: Unpin,
    E: ConnectionEncryption,
{
    /// Retrieve session ID.
    pub fn session_id(&self) -> SessionId {
        self.inner.sess_id
    }

    /// Retrieve session name
    pub fn session_name(&self) -> Option<&str> {
        self.inner.sess_name.as_ref().map(AsRef::as_ref)
    }

    /// Returns `true` if the connection is a command session.
    pub fn is_command(&self) -> bool {
        self.inner.is_command
    }

    /// Returns `true` if the connection is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.inner.encryption.is_some()
    }

    /// Returns `true` if the connection is closed.
    pub fn is_closed(&self) -> bool {
        match self.state {
            ConnectionState::Closed { .. } => true,
            _ => false,
        }
    }

    pub fn is_client(&self) -> bool {
        self.inner.is_client
    }

    ///////////////////////////////////////////////////////////////////////////
    // Client methods

    async fn client_handshake(mut self) -> Result<Self, ConnectionError<T::Error, E::Error>> {
        debug_assert_eq!(self.state, ConnectionState::None);
        debug!("starting client handshake");
        if self.is_encrypted() {
            self = self.client_encryption_handshake().await?;
        } else {
            debug!("skipping encryption handshake");
        }
        let mut client_syn =
            SynBody::new(self.inner.self_seq, self.is_command(), self.is_encrypted());
        if let Some(ref sess_name) = self.inner.sess_name {
            client_syn.set_session_name(sess_name.clone());
        }
        let exchange = self.inner.new_exchange(client_syn.into(), false)?;
        self.set_state(ConnectionState::SessionInit { exchange });
        future::poll_fn(|cx| self.poll_ready(cx)).await?;
        Ok(self)
    }

    async fn client_encryption_handshake(
        self,
    ) -> Result<Self, ConnectionError<T::Error, E::Error>> {
        unimplemented!()
    }

    ///////////////////////////////////////////////////////////////////////////
    // State

    fn set_state(&mut self, state: ConnectionState<T::Future>) {
        debug!("state `{:?}` changed to `{:?}`", self.state, state);
        self.state = state;
    }

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ConnectionError<T::Error, E::Error>>> {
        let Self { inner, state } = self;
        let poll_result = match state {
            ConnectionState::None => unimplemented!(),
            ConnectionState::EncryptInit { exchange } => {
                inner.poll_encrypt_init_state(cx, exchange)
            }
            ConnectionState::EncryptAuth { exchange } => {
                inner.poll_encrypt_auth_state(cx, exchange)
            }
            ConnectionState::SessionInit { exchange } => {
                inner.poll_session_init_state(cx, exchange)
            }
            ConnectionState::Ready => inner.poll_ready_state(cx),
            ConnectionState::SendRecv {
                exchange,
                is_closing,
            } => inner.poll_send_recv_state(cx, exchange, *is_closing),
            ConnectionState::Closing => inner.poll_closing_state(cx),
            ConnectionState::Closed { .. } => panic!("polled closed connection"),
        };
        match ready!(poll_result) {
            Ok(ConnectionState::Ready) => {
                self.set_state(ConnectionState::Ready);
                self.inner.send_notify_task.take().map(Waker::wake);
                Poll::Pending
            }
            Ok(next_state) => {
                self.set_state(next_state);
                Poll::Ready(Ok(()))
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Bytes, ConnectionError<T::Error, E::Error>>> {
        match self.inner.recv_data_queue.pop_front() {
            Some(bytes) => Poll::Ready(Ok(bytes)),
            None => {
                ready!(self.poll_ready(cx))?;
                self.inner.read_notify_task = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
    }

    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<(), ConnectionError<T::Error, E::Error>>> {
        ready!(self.poll_ready(cx))?;
        if self.state.is_ready() {
            let bytes = buf.to_vec().into();
            let exchange = self.inner.new_chunk_exchange(bytes)?;
            self.set_state(ConnectionState::SendRecv {
                exchange,
                is_closing: false,
            });
            self.poll_ready(cx)
        } else {
            self.inner.send_notify_task = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

impl<T, E> AsyncRead for Connection<T, E>
where
    T: ExchangeTransport<LazyPacket> + Unpin,
    T::Future: Unpin,
    E: ConnectionEncryption + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        if this.inner.recv_data_head.is_empty() {
            this.inner.recv_data_head = ready!(this.poll_recv(cx))?;
        }
        let head = &mut this.inner.recv_data_head;
        let len = cmp::min(buf.len(), head.len());
        head.split_to(len).copy_to_slice(buf);
        Poll::Ready(Ok(len))
    }
}

impl<T, E> AsyncWrite for Connection<T, E>
where
    T: ExchangeTransport<LazyPacket> + Unpin,
    T::Future: Unpin,
    E: ConnectionEncryption + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        ready!(this.poll_send(cx, buf))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), io::Error>> {
        unimplemented!()
    }
}

///////////////////////////////////////////////////////////////////////////////

struct ExchangeState<T> {
    /// The transport future.
    fut: T,
    /// The session body of the packet being sent.
    body: SessionBodyBytes,
    /// The attempt of the exchange.
    attempt: usize,
}

struct ChunkExchangeState<T> {
    inner: ExchangeState<T>,
    /// The remaining bytes to be sent.
    remaining: Bytes,
    /// The amount of bytes being sent in this chunk.
    chunk_len: u8,
}

///////////////////////////////////////////////////////////////////////////////

enum ConnectionState<T> {
    /// Connection has no state.
    None,
    /// Connection is initialising encryption.
    EncryptInit { exchange: ExchangeState<T> },
    /// Connection is authenticating encryption.
    EncryptAuth { exchange: ExchangeState<T> },
    /// Connection is initialising session.
    SessionInit { exchange: ExchangeState<T> },
    /// Connection is ready for a operation.
    Ready,
    /// Connection is sending/receiving data.
    SendRecv {
        exchange: ChunkExchangeState<T>,
        /// `true` if the connection is closing.
        is_closing: bool,
    },
    /// Connection is closing.
    Closing,
    /// Connection is closed.
    Closed {
        /// The reason the connection was closed
        reason: Option<StringBytes>,
    },
}

impl<T> ConnectionState<T> {
    fn name(&self) -> &str {
        match self {
            Self::None => "None",
            Self::EncryptInit { .. } => "EncryptInit",
            Self::EncryptAuth { .. } => "EncryptAuth",
            Self::SessionInit { .. } => "SessionInit",
            Self::Ready => "Ready",
            Self::SendRecv { .. } => "SendRecv",
            Self::Closing => "Closing",
            Self::Closed { .. } => "Closed",
        }
    }

    fn is_ready(&self) -> bool {
        match self {
            Self::Ready => true,
            _ => false,
        }
    }
}

impl<T> PartialEq for ConnectionState<T> {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}

impl<T> fmt::Debug for ConnectionState<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct ConnectionInner<T, E> {
    sess_id: SessionId,
    sess_name: Option<Cow<'static, str>>,
    is_client: bool,
    is_command: bool,
    peer_seq: Sequence,
    self_seq: Sequence,
    transport: T,
    encryption: Option<E>,
    prefer_peer_name: bool,
    send_notify_task: Option<Waker>,
    read_notify_task: Option<Waker>,
    send_retry_max: usize,
    recv_retry_max: usize,
    recv_data_head: Bytes,
    recv_data_queue: VecDeque<Bytes>,
    send_data_queue: VecDeque<Bytes>,
}

impl<T, E> ConnectionInner<T, E>
where
    T: ExchangeTransport<LazyPacket>,
    T::Future: Unpin,
    E: ConnectionEncryption,
{
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

    fn init_from_peer_syn(
        &mut self,
        syn: SynBody,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        // Extract the peer session name if we should and can
        if (self.sess_name.is_none() || self.prefer_peer_name) && syn.session_name().is_some() {
            debug!("using peer session name");
            self.sess_name = syn.session_name().map(ToString::to_string).map(Into::into);
        }
        // Extract if the peer indicates this is a command session
        self.is_command = syn.is_command();
        // Check the encrypted flags match
        if self.encryption.is_some() != syn.is_encrypted() {
            return Err(ConnectionError::EncryptionMismatch);
        }
        // Extract the peer initial sequence
        self.peer_seq = syn.initial_sequence();
        // Woo!
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////////
    // State management

    fn poll_encrypt_init_state(
        &mut self,
        _cx: &mut Context<'_>,
        _exchange: &mut ExchangeState<T::Future>,
    ) -> StatePoll<T, E> {
        unimplemented!()
    }

    fn poll_encrypt_auth_state(
        &mut self,
        _cx: &mut Context<'_>,
        _exchange: &mut ExchangeState<T::Future>,
    ) -> StatePoll<T, E> {
        unimplemented!()
    }

    fn poll_session_init_state(
        &mut self,
        cx: &mut Context<'_>,
        exchange: &mut ExchangeState<T::Future>,
    ) -> StatePoll<T, E> {
        ready!(self.poll_exchange(exchange, cx))
            .and_then(|body| self.extract_session_body(body, false))
            .and_then(|body| match body {
                SupportedSessionBody::Syn(syn) => {
                    self.init_from_peer_syn(syn)?;
                    // Set the connection state ready to accept data
                    Ok(ConnectionState::Ready)
                }
                body => self.handle_unexpected(body),
            })
            .into()
    }

    fn poll_ready_state(&mut self, _cx: &mut Context<'_>) -> StatePoll<T, E> {
        // TODO: poll for data if client
        Poll::Ready(Ok(ConnectionState::Ready))
    }

    fn poll_send_recv_state(
        &mut self,
        cx: &mut Context<'_>,
        exchange: &mut ChunkExchangeState<T::Future>,
        is_closing: bool,
    ) -> StatePoll<T, E> {
        let body = ready!(self.poll_exchange(&mut exchange.inner, cx))
            .and_then(|body| self.extract_session_body(body, false))?;

        if let SupportedSessionBody::Msg(body) = body {
            debug_msg_body!("data-rx", body);
            let expected_bytes_ack = exchange.chunk_len;
            let next_self_seq = self.self_seq.clone().add(expected_bytes_ack);

            if body.ack() != next_self_seq {
                Err(ConnectionError::UnexpectedPeerAck {
                    expected: next_self_seq,
                    actual: body.ack(),
                })?;
            }

            let received_data_len = Self::validate_chunk_len(body.data().len())?;

            debug!(
                "data-ack: [rx: {}, tx: {}]",
                received_data_len, expected_bytes_ack
            );

            self.self_seq = next_self_seq;
            self.peer_seq.add(received_data_len);

            self.push_recv_data(body.into_data())?;

            let next_state = match self.next_chuck_exchange(exchange)? {
                Some(exchange) => ConnectionState::SendRecv {
                    exchange,
                    is_closing,
                },
                None if is_closing => ConnectionState::Closing,
                None => ConnectionState::Ready,
            };

            Poll::Ready(Ok(next_state))
        } else {
            self.handle_unexpected(body).into()
        }
    }

    fn poll_closing_state(&mut self, _cx: &mut Context<'_>) -> StatePoll<T, E> {
        unimplemented!()
    }

    fn handle_unexpected(
        &mut self,
        _unexpected: SupportedSessionBody,
    ) -> Result<ConnectionState<T::Future>, ConnectionError<T::Error, E::Error>> {
        unimplemented!()
    }

    ///////////////////////////////////////////////////////////////////////////
    // Data chunking

    fn push_recv_data(&mut self, data: Bytes) -> Result<(), ConnectionError<T::Error, E::Error>> {
        if self.recv_data_queue.len() == self.recv_data_queue.capacity() {
            Err(ConnectionError::RecvBufferFull)?;
        }
        self.read_notify_task.take().map(Waker::wake);
        if !data.is_empty() {
            self.recv_data_queue.push_front(data);
        }
        Ok(())
    }

    fn calc_chunk_len(&self, data_len: usize) -> Result<u8, ConnectionError<T::Error, E::Error>> {
        let val = cmp::min(data_len, self.max_data_chunk_size() as usize) as u8;
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

    fn new_chunk_exchange(
        &mut self,
        mut data: Bytes,
    ) -> Result<ChunkExchangeState<T::Future>, ConnectionError<T::Error, E::Error>> {
        let chunk_len = self.calc_chunk_len(data.len())?;
        let chunk = data.split_to(chunk_len as usize);
        let mut msg_body = MsgBody::new(self.self_seq, self.peer_seq);
        msg_body.set_data(chunk);
        debug_msg_body!("data-tx", msg_body);
        Ok(ChunkExchangeState {
            inner: self.new_exchange(msg_body.into(), false)?,
            chunk_len,
            remaining: data,
        })
    }

    fn next_chuck_exchange(
        &mut self,
        exchange: &mut ChunkExchangeState<T::Future>,
    ) -> Result<Option<ChunkExchangeState<T::Future>>, ConnectionError<T::Error, E::Error>> {
        let remaining = &mut exchange.remaining;
        if remaining.is_empty() {
            Ok(None)
        } else {
            self.new_chunk_exchange(remaining.to_bytes()).map(Some)
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // Packet helpers

    fn build_packet(&self, tx_body: SessionBodyBytes) -> LazyPacket {
        // Generate our packet ID.
        let tx_id = rand::random();
        // Wrap the encoded session body in a session body frame with the session id and packet kind.
        let session_frame = SessionBodyFrame::new(self.sess_id, tx_body.clone());
        // Wrap the session body frame in a packet frame.
        Packet::new(tx_id, SupportedBody::Session(session_frame))
    }

    fn build_session_body(
        &mut self,
        tx_body: SupportedSessionBody,
        plain: bool,
    ) -> Result<SessionBodyBytes, ConnectionError<T::Error, E::Error>> {
        let tx_kind = tx_body.packet_kind();
        let mut tx_buf = BytesMut::new();
        tx_body.encode(&mut tx_buf);
        let tx_body_bytes = if plain {
            tx_buf.freeze()
        } else {
            // If encryption is enabled, encrypt our session body
            if let Some(ref mut encryption) = self.encryption {
                encryption.encrypt(&mut tx_buf)
            } else {
                tx_buf.freeze()
            }
        };
        Ok(SessionBodyBytes::new(tx_kind, tx_body_bytes))
    }

    fn extract_session_body(
        &mut self,
        rx_body: SessionBodyBytes,
        plain: bool,
    ) -> Result<SupportedSessionBody, ConnectionError<T::Error, E::Error>> {
        let rx_kind = rx_body.packet_kind();
        let mut rx_body_bytes = rx_body.into_bytes();
        let mut rx_body_bytes = if plain {
            rx_body_bytes
        } else {
            // If encryption is enabled, decrypt our session body
            if let Some(ref mut encryption) = self.encryption {
                encryption.decrypt(&mut rx_body_bytes)
            } else {
                rx_body_bytes
            }
        };
        let rx_body = SupportedSessionBody::decode_kind(rx_kind, &mut rx_body_bytes)
            .map_err(ConnectionError::PacketDecode)?;
        Ok(rx_body)
    }

    ///////////////////////////////////////////////////////////////////////////
    // Transport exchange

    fn new_exchange(
        &mut self,
        tx_body: SupportedSessionBody,
        plain: bool,
    ) -> Result<ExchangeState<T::Future>, ConnectionError<T::Error, E::Error>> {
        self.build_session_body(tx_body, plain).map(|body| {
            let packet = self.build_packet(body.clone());
            ExchangeState {
                fut: self.transport.exchange(packet),
                body,
                attempt: 1,
            }
        })
    }

    fn poll_exchange(
        &mut self,
        exchange: &mut ExchangeState<T::Future>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<SessionBodyBytes, ConnectionError<T::Error, E::Error>>> {
        let result = ready!(Pin::new(&mut exchange.fut).poll(cx))
            .map_err(ConnectionError::Transport)
            .and_then(|rx_packet| {
                let rx_kind = rx_packet.kind();
                // Consume the received packet into a session frame if applicable
                if let Some(session_frame) = rx_packet.into_body().into_session_frame() {
                    let rx_sess_id = session_frame.session_id();
                    // Check the session ID returned matches our session ID
                    if self.sess_id != rx_sess_id {
                        Err(ConnectionError::UnexpectedSessionId(rx_sess_id))
                    } else {
                        // Return the framed session body bytes.
                        Ok(session_frame.into_body().into())
                    }
                } else {
                    Err(ConnectionError::UnexpectedPacketKind(rx_kind))
                }
            });

        match result {
            Ok(body) => Poll::Ready(Ok(body)),
            // TODO
            Err(_) if exchange.attempt < self.send_retry_max && false => {
                let tx_packet = self.build_packet(exchange.body.clone());
                exchange.fut = self.transport.exchange(tx_packet);
                exchange.attempt += 1;
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}
