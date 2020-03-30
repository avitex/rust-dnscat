use std::borrow::Cow;
use std::time::Instant;
use std::{cmp, fmt};

use bytes::Bytes;
use failure::Fail;
use log::{debug, trace};
use rand::Rng;

use crate::encryption::*;
use crate::packet::*;
use crate::transport::*;

#[derive(Debug, Fail)]
pub enum SessionError {
    #[fail(display = "Session is closed")]
    Closed,
    #[fail(display = "Encryption error: {}", _0)]
    Encryption(EncryptionError),
    #[fail(display = "Max re-transmit attempts reached")]
    MaxTransmitAttempts,
    #[fail(display = "Encryption mismatch")]
    EncryptionMismatch,
    #[fail(
        display = "Unexpected session ID (expected: {}, got: {})",
        expected, actual
    )]
    UnexpectedId {
        expected: SessionId,
        actual: SessionId,
    },
    #[fail(display = "Unexpected packet kind `{:?}` in stage `{:?}`", kind, stage)]
    UnexpectedKind {
        kind: PacketKind,
        stage: SessionStage,
    },
    #[fail(
        display = "Unexpected peer sequence (expected: {}, got: {})",
        expected, actual
    )]
    UnexpectedPeerSeq {
        expected: Sequence,
        actual: Sequence,
    },
    #[fail(
        display = "Unexpected peer acknowledgement (expected: {}, got: {})",
        expected, actual
    )]
    UnexpectedPeerAck {
        expected: Sequence,
        actual: Sequence,
    },
    #[fail(
        display = "Unexpected peer encryption kind (expected: {:?}, got: {:?})",
        expected, actual
    )]
    UnexpectedEncKind {
        expected: EncBodyKind,
        actual: EncBodyKind,
    },
    #[fail(display = "Session packet decode error: {}", _0)]
    SessionBodyDecode(PacketDecodeError),
}

impl From<PacketDecodeError> for SessionError {
    fn from(err: PacketDecodeError) -> Self {
        Self::SessionBodyDecode(err)
    }
}

impl From<EncryptionError> for SessionError {
    fn from(err: EncryptionError) -> Self {
        Self::Encryption(err)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionStage {
    /// Session is uninitialized.
    Uninit,
    /// Session is initialising encryption.
    EncryptInit,
    /// Session is authenticating encryption.
    EncryptAuth,
    /// Session is initialising session.
    SessionInit,
    /// Session is sending data.
    Send,
    /// Session is receiving data.
    Recv,
    /// Session is closed.
    Closed,
}

impl SessionStage {
    pub fn is_established(self) -> bool {
        use SessionStage::*;
        match self {
            Send | Recv => true,
            Uninit | EncryptInit | EncryptAuth | SessionInit | Closed => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionRole {
    /// The session is a client.
    Client,
    /// The session is a server.
    Server,
}

#[derive(Debug)]
pub struct Session<T, R> {
    /// The ID for this session.
    pub(crate) id: SessionId,
    /// The name if set for this session.
    pub(crate) name: Option<Cow<'static, str>>,
    /// Random source.
    pub(crate) random: R,
    /// The peer sequence for receiving data.
    pub(crate) peer_seq: Sequence,
    /// This session's sequence for sending data.
    pub(crate) self_seq: Sequence,
    /// The peer sequence we expect in the next message.
    pub(crate) self_seq_pending: Sequence,
    /// Whether or not this is a command session.
    pub(crate) is_command: bool,
    /// Whether or not this is a client to server session.
    pub(crate) role: SessionRole,
    /// Session stage.
    pub(crate) stage: SessionStage,
    /// The reason the session was closing/closed.
    pub(crate) close_reason: Option<Cow<'static, str>>,
    /// The session encryption if set.
    pub(crate) encryption: Option<T>,
    /// Whether the session prefers the peer name or
    /// its own if it was set.
    pub(crate) prefer_peer_name: bool,
    /// Whether or not packet bodies should be traced.
    pub(crate) packet_trace: bool,
    /// The last instant we attempted an exchange.
    pub(crate) last_exchange: Option<Instant>,
    /// The current if any attempt of exchanges.
    pub(crate) exchange_attempt: Option<usize>,
    /// The max number of retransmissions before closing.
    pub(crate) max_exchange_attempts: Option<usize>,
}

impl<T, R> Session<T, R>
where
    T: Encryption,
    R: Rng,
{
    /// Returns session ID.
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// Returns session name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_ref().map(AsRef::as_ref)
    }

    /// Returns `true` if this is a command session.
    pub fn is_command(&mut self) -> bool {
        self.is_command
    }

    /// Returns `true` if the session is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    /// Returns the current session stage.
    pub fn stage(&self) -> SessionStage {
        self.stage
    }

    /// Returns `true` if the session is closed.
    pub fn is_closed(&self) -> bool {
        self.stage == SessionStage::Closed
    }

    ///////////////////////////////////////////////////////////////////////////

    pub fn handle_inbound(
        &mut self,
        packet: Packet<SessionBodyBytes>,
    ) -> Result<Option<Bytes>, SessionError> {
        use PacketKind::*;
        use SessionRole::*;
        use SessionStage::*;
        // Check the session ID returned matches our session ID
        if packet.head.session_id != self.id {
            return Err(SessionError::UnexpectedId {
                expected: self.id,
                actual: packet.head.session_id,
            });
        }
        let result = match (self.role, self.stage, packet.kind()) {
            // We are a uninitialized server session and this is the
            // client's `ENC|INIT` request.
            (Server, Uninit, ENC) => match self.handle_encrypt_init(packet) {
                Ok(()) => Ok((None, EncryptInit)),
                Err(err) => Err(err),
            },
            // We are a client and this is the server's `ENC|INIT` response.
            (Client, EncryptInit, ENC) => match self.handle_encrypt_init(packet) {
                Ok(()) => Ok((None, EncryptAuth)),
                Err(err) => Err(err),
            },
            // We are a server and this is the client's `ENC|AUTH` request.
            (Server, EncryptAuth, ENC) => match self.handle_encrypt_auth(packet) {
                Ok(()) => Ok((None, EncryptAuth)),
                Err(err) => Err(err),
            },
            // We are a client and this is the server's `ENC|AUTH` response.
            (Client, EncryptAuth, ENC) => match self.handle_encrypt_auth(packet) {
                Ok(()) => Ok((None, SessionInit)),
                Err(err) => Err(err),
            },
            // We are a server and this is the client's `SYN` request.
            // This could be from a uninitialized session, or we just established encryption.
            (Server, Uninit, SYN) | (Server, EncryptAuth, SYN) => match self.handle_syn(packet) {
                Ok(()) => Ok((None, SessionInit)),
                Err(err) => Err(err),
            },
            // We are a client and this is the server's `SYN` response.
            (Client, SessionInit, SYN) => match self.handle_syn(packet) {
                Ok(()) => Ok((None, Send)),
                Err(err) => Err(err),
            },
            // We are either a server or client and this is a `MSG` from our peer.
            (_, Recv, MSG) => match self.handle_msg(packet) {
                Ok(data) => Ok((data, Send)),
                Err(err) => Err(err),
            },
            // We received a FIN from the server.
            (Client, _, FIN) => match self.handle_fin(packet) {
                Ok(()) => Ok((None, Closed)),
                Err(err) => Err(err),
            },
            // This session is closed.
            (_, Closed, _) => Err(SessionError::Closed),
            // We received something unexpected.
            (_, stage, kind) => Err(SessionError::UnexpectedKind { kind, stage }),
        };
        match result {
            Ok((_, Closed)) => {
                self.set_stage(Closed);
                self.mark_exchange_end();
                Err(SessionError::Closed)
            }
            Ok((data, next_stage)) => {
                self.set_stage(next_stage);
                self.mark_exchange_end();
                Ok(data)
            }
            Err(err) => Err(err),
        }
    }

    fn handle_encrypt_init(
        &mut self,
        packet: Packet<SessionBodyBytes>,
    ) -> Result<(), SessionError> {
        if let Some(ref mut encryption) = self.encryption {
            let body: EncBody = Self::parse_packet(packet, None, self.packet_trace)?;
            let peer_pub_key = match body.into_body() {
                EncBodyVariant::Init { public_key } => public_key,
                EncBodyVariant::Auth { .. } => {
                    return Err(SessionError::UnexpectedEncKind {
                        expected: EncBodyKind::INIT,
                        actual: EncBodyKind::AUTH,
                    })
                }
            };
            encryption.handshake(peer_pub_key)?;
            Ok(())
        } else {
            Err(SessionError::EncryptionMismatch)
        }
    }

    fn handle_encrypt_auth(
        &mut self,
        packet: Packet<SessionBodyBytes>,
    ) -> Result<(), SessionError> {
        if let Some(ref mut encryption) = self.encryption {
            let body: EncBody = Self::parse_packet(packet, Some(encryption), self.packet_trace)?;
            let peer_auth = match body.into_body() {
                EncBodyVariant::Init { .. } => {
                    return Err(SessionError::UnexpectedEncKind {
                        expected: EncBodyKind::AUTH,
                        actual: EncBodyKind::INIT,
                    })
                }
                EncBodyVariant::Auth { authenticator } => authenticator,
            };
            encryption.authenticate(peer_auth)?;
            Ok(())
        } else {
            Err(SessionError::EncryptionMismatch)
        }
    }

    fn handle_syn(&mut self, packet: Packet<SessionBodyBytes>) -> Result<(), SessionError> {
        let body: SynBody =
            Self::parse_packet(packet, self.encryption.as_mut(), self.packet_trace)?;
        self.init_from_peer_syn(body, self.prefer_peer_name)
    }

    fn handle_msg(
        &mut self,
        packet: Packet<SessionBodyBytes>,
    ) -> Result<Option<Bytes>, SessionError> {
        let body: MsgBody =
            Self::parse_packet(packet, self.encryption.as_mut(), self.packet_trace)?;
        self.validate_exchange(body.seq(), body.ack(), body.data_len())?;
        let data = body.into_data();
        if data.is_empty() {
            Ok(None)
        } else {
            Ok(Some(data))
        }
    }

    fn handle_fin(&mut self, packet: Packet<SessionBodyBytes>) -> Result<(), SessionError> {
        let body: FinBody =
            Self::parse_packet(packet, self.encryption.as_mut(), self.packet_trace)?;
        self.close_reason = Some(body.reason().to_owned().into());
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////////

    pub fn build_enc_init(&mut self) -> Result<Packet<SessionBodyBytes>, SessionError> {
        match self.role {
            SessionRole::Client => self.assert_stage(SessionStage::Uninit),
            SessionRole::Server => self.assert_stage(SessionStage::EncryptInit),
        }
        let encryption = self.encryption.as_ref().expect("client has no encryption");
        let public_key = encryption.public_key();
        let body = EncBody::new(0, EncBodyVariant::Init { public_key });
        match self.role {
            SessionRole::Client => self.set_stage(SessionStage::EncryptInit),
            SessionRole::Server => self.set_stage(SessionStage::EncryptAuth),
        }
        self.mark_exchange_start();
        Self::build_packet(body, self.id, &mut self.random, None, self.packet_trace)
    }

    pub fn build_enc_auth(&mut self) -> Result<Packet<SessionBodyBytes>, SessionError> {
        self.assert_stage(SessionStage::EncryptAuth);
        let encryption = self.encryption.as_mut().expect("client has no encryption");
        let authenticator = encryption.authenticator();
        let body = EncBody::new(0, EncBodyVariant::Auth { authenticator });
        match self.role {
            SessionRole::Client => self.set_stage(SessionStage::EncryptAuth),
            SessionRole::Server => self.set_stage(SessionStage::SessionInit),
        }
        self.mark_exchange_start();
        Self::build_packet(
            body,
            self.id,
            &mut self.random,
            self.encryption.as_mut(),
            self.packet_trace,
        )
    }

    pub fn build_syn(&mut self) -> Result<Packet<SessionBodyBytes>, SessionError> {
        if self.is_encrypted() {
            self.assert_stage(SessionStage::SessionInit);
        } else {
            self.assert_stage(SessionStage::Uninit);
        }
        let mut body = SynBody::new(self.self_seq, self.is_command);
        if let Some(ref name) = self.name {
            body.set_session_name(name.clone());
        }
        match self.role {
            SessionRole::Client => self.set_stage(SessionStage::SessionInit),
            SessionRole::Server => self.set_stage(SessionStage::Recv),
        }
        self.mark_exchange_start();
        Self::build_packet(
            body,
            self.id,
            &mut self.random,
            self.encryption.as_mut(),
            self.packet_trace,
        )
    }

    pub fn build_msg(&mut self, chunk: Bytes) -> Result<Packet<SessionBodyBytes>, SessionError> {
        self.assert_stage(SessionStage::Send);
        let mut body = MsgBody::new(self.self_seq, self.peer_seq);
        body.set_data(chunk);
        self.set_pending_ack(body.data_len());
        self.set_stage(SessionStage::Recv);
        self.mark_exchange_start();
        Self::build_packet(
            body,
            self.id,
            &mut self.random,
            self.encryption.as_mut(),
            self.packet_trace,
        )
    }

    pub fn build_fin<S>(&mut self, reason: S) -> Result<Packet<SessionBodyBytes>, SessionError>
    where
        S: Into<Cow<'static, str>>,
    {
        let reason = reason.into();
        let mut body = FinBody::new();
        if !reason.is_empty() {
            body.set_reason(reason.to_string());
            self.close_reason = Some(reason);
        }
        self.set_stage(SessionStage::Closed);
        self.mark_exchange_start();
        let encryption = if self.stage.is_established() {
            self.encryption.as_mut()
        } else {
            None
        };
        Self::build_packet(
            body,
            self.id,
            &mut self.random,
            encryption,
            self.packet_trace,
        )
    }

    ///////////////////////////////////////////////////////////////////////////

    fn set_stage(&mut self, stage: SessionStage) {
        if self.stage != stage {
            trace!("session stage {:?} changed to {:?}", self.stage, stage);
            self.stage = stage;
        }
    }

    fn assert_stage(&self, expect: SessionStage) {
        if expect != self.stage {
            panic!("expected stage {:?}, got stage: {:?}", expect, self.stage);
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    fn set_pending_ack(&mut self, sent: u8) {
        self.self_seq_pending = self.self_seq.add_data(sent);
    }

    fn validate_exchange(
        &mut self,
        peer_seq: Sequence,
        peer_ack: Sequence,
        recv_len: u8,
    ) -> Result<(), SessionError> {
        // We first validate that the peer acknowledged
        // the data (if any) we sent.
        if peer_ack != self.self_seq_pending {
            return Err(SessionError::UnexpectedPeerAck {
                expected: self.self_seq_pending,
                actual: peer_ack,
            });
        }
        // We now validate we are current with the peer's
        // current sequence.
        if peer_seq != self.peer_seq {
            return Err(SessionError::UnexpectedPeerSeq {
                expected: self.peer_seq,
                actual: peer_seq,
            });
        }
        // Print out the length of data we received and sent.
        let sent_len = self.self_seq.steps_to(peer_ack);
        debug!("data-ack: [rx: {}, tx: {}]", recv_len, sent_len);
        // Update our sequence values.
        self.peer_seq = self.peer_seq.add_data(recv_len);
        self.self_seq = self.self_seq_pending;
        // Woo!
        Ok(())
    }

    fn init_from_peer_syn(
        &mut self,
        syn: SynBody,
        prefer_peer_name: bool,
    ) -> Result<(), SessionError> {
        // Extract the peer session name if we should and can
        if (self.name.is_none() || prefer_peer_name) && syn.session_name().is_some() {
            debug!("using peer session name");
            self.name = syn.session_name().map(ToString::to_string).map(Into::into);
        }
        // Extract if the peer indicates this is a command session
        self.is_command = syn.is_command();
        // Extract the peer initial sequence
        self.peer_seq = syn.initial_sequence();
        // Woo!
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////////

    fn parse_packet<B>(
        packet: Packet<SessionBodyBytes>,
        encryption: Option<&mut T>,
        packet_trace: bool,
    ) -> Result<B, SessionError>
    where
        B: PacketBody<Head = SessionHeader>,
        B: fmt::Debug,
    {
        let (head, body) = packet.split();
        // If encryption is enabled, decrypt our session body.
        let mut body_bytes = match encryption {
            // TODO: what if packet size < head_size?
            Some(enc) => {
                let args_size = enc.args_size() as usize;
                let args = &body.0[..args_size];
                let mut data = Vec::from(&body.0[args_size..]);
                enc.decrypt(&head, args, &mut data[..])?;
                data.into()
            }
            _ => body.0,
        };

        // Decode the session body bytes and return.
        let body = B::decode_body(&head, &mut body_bytes)?;
        if packet_trace {
            debug!("body-rx: {:?}", body);
        }
        Ok(body)
    }

    fn build_packet<B>(
        body: B,
        session_id: SessionId,
        random: &mut R,
        encryption: Option<&mut T>,
        packet_trace: bool,
    ) -> Result<Packet<SessionBodyBytes>, SessionError>
    where
        B: Into<SupportedSessionBody>,
    {
        let body = body.into();
        if packet_trace {
            debug!("body-tx: {:?}", body);
        }
        // Get the packet kind of the body.
        let kind = body.packet_kind();
        // Create the packet header.
        let head = SessionHeader::new(random.gen(), kind, session_id);
        // Encode the body into a buffer.
        let mut body_bytes = Vec::with_capacity(256);
        // If encryption is enabled, encrypt our session body
        match encryption {
            Some(enc) => {
                let args_size = enc.args_size() as usize;
                body_bytes.resize(args_size, 0);
                body.encode(&mut body_bytes);
                let (args, data) = body_bytes.split_at_mut(args_size);
                enc.encrypt(&head, args, data)?;
            }
            _ => body.encode(&mut body_bytes),
        }

        let body = SessionBodyBytes(body_bytes.into());
        // Return the new session body
        Ok(Packet::new(head, body))
    }

    ///////////////////////////////////////////////////////////////////////////

    pub fn exchange_attempt(&self) -> Option<usize> {
        self.exchange_attempt
    }

    pub fn last_exchange(&self) -> Option<Instant> {
        self.last_exchange
    }

    fn mark_exchange_start(&mut self) {
        self.last_exchange = Some(Instant::now());
        self.exchange_attempt = Some(1);
    }

    fn mark_exchange_end(&mut self) {
        self.last_exchange = Some(Instant::now());
        self.exchange_attempt = None;
    }

    pub fn prepare_retransmit(
        &mut self,
        mut packet: Packet<SessionBodyBytes>,
    ) -> Result<Packet<SessionBodyBytes>, SessionError> {
        self.assert_stage(SessionStage::Recv);
        if let Some(max_exchange_attempts) = self.max_exchange_attempts {
            let attempt = self.exchange_attempt.unwrap_or(1);
            if max_exchange_attempts >= attempt {
                return Err(SessionError::MaxTransmitAttempts);
            }
            self.exchange_attempt = Some(attempt);
        }
        self.last_exchange = Some(Instant::now());
        packet.head.set_packet_id(self.random.gen());
        Ok(packet)
    }

    ///////////////////////////////////////////////////////////////////////////

    /// Returns the max data chunk size that can be sent in one datagram.
    ///
    /// This is calculated based on a budget, minus the cost of the framing
    /// and/or encryption framing if enabled.
    pub fn max_data_chunk_size(&self, budget: usize) -> u8 {
        // Subtract the total size required from what the transport
        // can provide to get the budget we can use.
        let budget = budget - self.msg_packet_min_size() as usize;
        // Limit the budget to the max size of a packet (u8).
        if budget > LazyPacket::max_size() as usize {
            LazyPacket::max_size()
        } else {
            budget as u8
        }
    }

    pub fn calc_chunk_len(&self, data_len: usize, budget: usize) -> u8 {
        let max = self.max_data_chunk_size(budget);
        let val = cmp::min(data_len, max as usize) as u8;
        assert_ne!(val, 0);
        val
    }

    fn msg_packet_min_size(&self) -> u8 {
        match self.encryption {
            Some(ref enc) => MsgBody::packet_size_no_data() + enc.args_size(),
            _ => MsgBody::packet_size_no_data(),
        }
    }

    pub(crate) fn random(&mut self) -> &mut R {
        &mut self.random
    }
}
