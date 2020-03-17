//mod io;
mod builder;
mod echo;

pub mod enc;

use std::borrow::Cow;
use std::collections::VecDeque;
use std::{cmp, fmt};

use bytes::{Bytes, BytesMut};
use log::{debug, warn};

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
    PeerAbort,
    DataTooLong,
    Transport(TE),
    Encryption(EE),
    NoDatagramBudget,
    ReceiveBufferFull,
    EncryptionMismatch,
    PacketDecode(PacketDecodeError),
    UnexpectedSessionId(SessionId),
    UnexpectedPacketKind(PacketKind),
    UnexpectedPeerAck {
        expected: Sequence,
        actual: Sequence,
    },
}

#[derive(PartialEq)]
enum ConnectionState {
    Uninit,
    EncInit,
    EncAuth,
    Handshake,
    Idle,
    Sending { len: u8 },
    Closing,
    Closed { reason: Option<StringBytes> },
}

impl fmt::Debug for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Uninit => "uninit",
            Self::EncInit => "enc-init",
            Self::EncAuth => "enc-auth",
            Self::Handshake => "handshake",
            Self::Idle => "idle",
            Self::Sending { .. } => "sending",
            Self::Closing => "closing",
            Self::Closed { .. } => "closed",
        };
        write!(f, "{}", name)
    }
}

impl ConnectionState {
    fn can_encrypt(&self) -> bool {
        match self {
            Self::Uninit | Self::EncInit | Self::EncAuth => false,
            _ => true,
        }
    }
}

#[derive(Debug)]
pub struct Connection<T, E = ()>
where
    T: ExchangeTransport<LazyPacket>,
    E: ConnectionEncryption,
{
    state: ConnectionState,
    sess_id: SessionId,
    sess_name: Option<Cow<'static, str>>,
    is_client: bool,
    is_command: bool,
    peer_seq: Sequence,
    self_seq: Sequence,
    transport: T,
    encryption: Option<E>,
    prefer_peer_name: bool,
    send_retry_max: usize,
    recv_retry_max: usize,
    recv_data_buf: VecDeque<Bytes>,
    send_data_buf: VecDeque<Bytes>,
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
        match self.state {
            ConnectionState::Closed { .. } => true,
            _ => false,
        }
    }

    pub fn is_client(&self) -> bool {
        self.is_client
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

    ///////////////////////////////////////////////////////////////////////////
    // Data chucking

    pub async fn recv_data(
        &mut self,
    ) -> Result<Option<Bytes>, ConnectionError<T::Error, E::Error>> {
        debug_assert_eq!(self.state, ConnectionState::Idle);
        if self.is_client && self.recv_data_buf.is_empty() {
            self.client_heartbeat().await?;
        }
        Ok(self.recv_data_buf.pop_front())
    }

    pub async fn send_data(
        &mut self,
        mut data: Bytes,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        debug_assert_eq!(self.state, ConnectionState::Idle);
        'send_main: loop {
            if data.is_empty() {
                self.set_state(ConnectionState::Idle);
                return Ok(());
            }
            let mut data_chuck_attempt = 1;
            let data_chunk_len = self.calc_chunk_len(data.len())?;
            let data_chunk = data.split_to(data_chunk_len as usize);
            self.set_state(ConnectionState::Sending {
                len: data_chunk_len,
            });
            'send_chunk: loop {
                // TODO: refactor error handling.
                match self.send_data_chunk(data_chunk.clone()).await {
                    Ok(()) => continue 'send_main,
                    err @ Err(ConnectionError::ReceiveBufferFull)
                    | err @ Err(ConnectionError::Timeout) => return err,
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
        debug_assert_eq!(
            self.state,
            ConnectionState::Sending {
                len: data_chunk.len() as u8
            }
        );
        let mut msg_body = MsgBody::new(self.self_seq, self.peer_seq);
        msg_body.set_data(data_chunk);
        debug_msg_body!("data-tx", msg_body);
        self.send_session_body(msg_body).await
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

    ///////////////////////////////////////////////////////////////////////////
    // Client/Server methods

    async fn send_session_body<B>(
        &mut self,
        body: B,
    ) -> Result<(), ConnectionError<T::Error, E::Error>>
    where
        B: Into<SupportedSessionBody>,
    {
        use SupportedSessionBody::*;
        match self
            .exchange_session_body(body.into(), self.state.can_encrypt())
            .await
        {
            Ok(Syn(body)) if self.is_client() => self.client_handle_server_syn(body).await,
            Ok(Syn(body)) => self.server_handle_client_syn(body).await,
            Ok(Fin(body)) => self.handle_peer_fin(body).await,
            Ok(Msg(body)) => self.handle_peer_msg(body).await,
            Ok(Enc(body)) => self.handle_peer_enc(body).await,
            Err(err) => Err(err),
        }
    }

    async fn handle_peer_fin(
        &mut self,
        peer_fin: FinBody,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        self.set_state(ConnectionState::Closed {
            reason: Some(peer_fin.into_reason()),
        });
        Err(ConnectionError::PeerAbort)
    }

    async fn handle_peer_msg(
        &mut self,
        peer_msg: MsgBody,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        let expected_bytes_ack = match self.state {
            ConnectionState::Sending { len } => len,
            _ => 0,
        };
        debug_msg_body!("data-rx", peer_msg);
        let next_self_seq = self.self_seq.clone().add(expected_bytes_ack);
        if peer_msg.ack() != next_self_seq {
            return Err(ConnectionError::UnexpectedPeerAck {
                expected: next_self_seq,
                actual: peer_msg.ack(),
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
            if received_data_len > 0 {
                self.recv_data_buf.push_front(peer_msg.into_data());
            }
            Ok(())
        }
    }

    async fn handle_peer_enc(
        &mut self,
        _peer_enc: EncBody,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        unimplemented!()
    }

    fn init_from_peer_syn(
        &mut self,
        syn: &SynBody,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        if self.state != ConnectionState::Handshake {
            warn!("got peer syn in invalid conn state: {:?}", self.state);
            return Err(ConnectionError::UnexpectedPacketKind(PacketKind::SYN));
        }
        // Extract the peer session name if we should and can
        if (self.sess_name.is_none() || self.prefer_peer_name) && syn.session_name().is_some() {
            debug!("using peer session name");
            self.sess_name = syn.session_name().map(ToString::to_string).map(Into::into);
        }
        // Extract if the peer indicates this is a command session
        self.is_command = syn.is_command();
        // Check the encrypted flags match
        if self.is_encrypted() != syn.is_encrypted() {
            return Err(ConnectionError::EncryptionMismatch);
        }
        // Extract the peer initial sequence
        self.peer_seq = syn.initial_sequence();
        // Set the connection state ready to accept data
        self.set_state(ConnectionState::Idle);
        // Woo!
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////////
    // Client methods

    async fn client_handshake(mut self) -> Result<Self, ConnectionError<T::Error, E::Error>> {
        debug_assert_eq!(self.state, ConnectionState::Uninit);
        debug!("starting client handshake");
        if self.is_encrypted() {
            self = self.client_encryption_handshake().await?;
        } else {
            debug!("skipping encryption handshake");
        }
        self.set_state(ConnectionState::Handshake);
        let mut client_syn = SynBody::new(self.self_seq, self.is_command(), self.is_encrypted());
        if let Some(ref sess_name) = self.sess_name {
            client_syn.set_session_name(sess_name.clone());
        }
        self.send_session_body(client_syn).await?;
        Ok(self)
    }

    async fn client_encryption_handshake(
        self,
    ) -> Result<Self, ConnectionError<T::Error, E::Error>> {
        unimplemented!()
        // self.set_state(ConnectionState::EncInit);
        // // TODO: impl encryption handshake.
        // self.set_state(ConnectionState::EncAuth);
        // // let encryption = self.encryption.unwrap();
    }

    async fn client_handle_server_syn(
        &mut self,
        server_syn: SynBody,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        self.init_from_peer_syn(&server_syn)
    }

    async fn client_heartbeat(&mut self) -> Result<(), ConnectionError<T::Error, E::Error>> {
        self.set_state(ConnectionState::Sending { len: 0 });
        self.send_data_chunk(Bytes::new()).await?;
        self.set_state(ConnectionState::Idle);
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////////
    // Server methods

    async fn server_handle_client_syn(
        &mut self,
        client_syn: SynBody,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        self.init_from_peer_syn(&client_syn)
    }

    ///////////////////////////////////////////////////////////////////////////
    // Session body exchange

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

    async fn exchange_session_body(
        &mut self,
        tx_body: SupportedSessionBody,
        plain: bool,
    ) -> Result<SupportedSessionBody, ConnectionError<T::Error, E::Error>> {
        let tx_body = self.build_session_body(tx_body, plain)?;
        let mut attempt = 1;
        loop {
            match self.exchange_session_body_bytes(tx_body.clone()).await {
                Ok(rx_body) => return self.extract_session_body(rx_body, plain),
                Err(ConnectionError::Timeout) if attempt < self.recv_retry_max => {
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn exchange_session_body_bytes(
        &mut self,
        tx_body: SessionBodyBytes,
    ) -> Result<SessionBodyBytes, ConnectionError<T::Error, E::Error>> {
        // Generate our packet ID.
        let tx_id = rand::random();
        // Wrap the encoded session body in a session body frame with the session id and packet kind.
        let session_frame = SessionBodyFrame::new(self.sess_id, tx_body);
        // Wrap the session body frame in a packet frame.
        let tx_packet = Packet::new(tx_id, SupportedBody::Session(session_frame));
        // Exchange the packet with the transport
        let rx_packet = self
            .transport
            .exchange(tx_packet)
            .await
            .map_err(ConnectionError::Transport)?;
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
    }

    ///////////////////////////////////////////////////////////////////////////
    // State helpers

    fn set_state(&mut self, state: ConnectionState) {
        debug!("state `{:?}` changed to `{:?}`", self.state, state);
        self.state = state;
    }

    // fn close_if_error<RT, RE>(&mut self, result: Result<RT, RE>) -> Result<RT, RE> {
    //     if result.is_err() {
    //         self.is_closed = true;
    //     }
    //     result
    // }

    // fn check_open(&self) -> Result<(), ConnectionError<T::Error, E::Error>> {
    //     if self.is_closed() {
    //         Err(ConnectionError::Closed)
    //     } else {
    //         Ok(())
    //     }
    // }
}
