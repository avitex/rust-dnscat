use std::borrow::Cow;
use std::cmp;

use bytes::{Bytes, BytesMut};
use failure::Fail;
use log::debug;

use crate::encryption::*;
use crate::packet::*;
use crate::transport::*;

#[derive(Debug, Fail)]
pub enum SessionError<E: Fail> {
    #[fail(display = "Session is closed")]
    Closed,
    #[fail(display = "Encryption error: {}", _0)]
    Encryption(E),
    #[fail(display = "Encryption flag mismatch")]
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
    #[fail(display = "Session packet decode error: {}", _0)]
    SessionBodyDecode(PacketDecodeError),
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

#[derive(Debug)]
pub struct Session<T> {
    /// The ID for this session.
    id: SessionId,
    /// The name if set for this session.
    name: Option<Cow<'static, str>>,
    /// The peer sequence for receiving data.
    peer_seq: Sequence,
    /// This session's sequence for sending data.
    self_seq: Sequence,
    /// The peer sequence we expect in the next message.
    self_seq_pending: Sequence,
    /// Whether or not this is a command session.
    is_command: bool,
    /// Whether or not this is a client to server session.
    is_client: bool,
    /// Session stage.
    stage: SessionStage,
    /// The reason the session was closing/closed.
    close_reason: Option<Cow<'static, str>>,
    /// The session encryption if set.
    encryption: Option<T>,
    /// Whether the session prefers the peer name or
    /// its own if it was set.
    prefer_peer_name: bool,
    /// Whether or not packet bodies should be traced.
    packet_trace: bool,
}

impl<T> Session<T>
where
    T: Encryption,
{
    pub fn new(
        id: SessionId,
        name: Option<Cow<'static, str>>,
        init_seq: Sequence,
        is_command: bool,
        is_client: bool,
        encryption: Option<T>,
        prefer_peer_name: bool,
        packet_trace: bool,
    ) -> Self {
        Self {
            id,
            name,
            self_seq: init_seq,
            self_seq_pending: init_seq,
            peer_seq: Sequence(0),
            is_command,
            is_client,
            close_reason: None,
            encryption,
            stage: SessionStage::Uninit,
            prefer_peer_name,
            packet_trace,
        }
    }

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
        packet: LazyPacket,
    ) -> Result<Option<Bytes>, SessionError<T::Error>> {
        let body = self.parse_packet(packet)?;
        let result = match (self.stage, body.packet_kind()) {
            (SessionStage::Recv, PacketKind::MSG) => return self.handle_msg(body),
            (SessionStage::SessionInit, PacketKind::SYN) => self.handle_syn(body),
            (SessionStage::EncryptInit, PacketKind::ENC) => self.handle_encrypt_init(body),
            (SessionStage::EncryptAuth, PacketKind::ENC) => self.handle_encrypt_auth(body),
            (SessionStage::Closed, _) => Err(SessionError::Closed),
            (stage, kind) => Err(SessionError::UnexpectedKind { kind, stage }),
        };
        result.map(|_| None)
    }

    fn handle_encrypt_auth(
        &mut self,
        _body: SessionBodyBytes,
    ) -> Result<(), SessionError<T::Error>> {
        unimplemented!()
    }

    fn handle_encrypt_init(
        &mut self,
        _body: SessionBodyBytes,
    ) -> Result<(), SessionError<T::Error>> {
        unimplemented!()
    }

    fn handle_syn(&mut self, body: SessionBodyBytes) -> Result<(), SessionError<T::Error>> {
        let body: SynBody = self.parse_body(body, true)?;
        self.init_from_peer_syn(body, self.prefer_peer_name)?;
        if self.is_client {
            self.set_stage(SessionStage::Send);
        } else {
            self.set_stage(SessionStage::Recv);
        }
        Ok(())
    }

    fn handle_msg(
        &mut self,
        body: SessionBodyBytes,
    ) -> Result<Option<Bytes>, SessionError<T::Error>> {
        let body: MsgBody = self.parse_body(body, true)?;
        self.validate_exchange(body.seq(), body.ack(), body.data_len())?;
        let data = body.into_data();
        if self.is_client {
            self.set_stage(SessionStage::Send);
        } else {
            self.set_stage(SessionStage::Recv);
        }
        if data.is_empty() {
            Ok(None)
        } else {
            Ok(Some(data))
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    pub fn build_fin<S>(&mut self, reason: S) -> FinBody
    where
        S: Into<Cow<'static, str>>,
    {
        let reason = reason.into();
        self.set_stage(SessionStage::Closed);
        let mut body = FinBody::new();
        if !reason.is_empty() {
            body.set_reason(reason.to_string());
            self.close_reason = Some(reason);
        }
        body
    }

    pub fn build_msg(&mut self, chunk: Bytes) -> MsgBody {
        self.assert_stage(&[SessionStage::Send]);
        let mut body = MsgBody::new(self.self_seq, self.peer_seq);
        body.set_data(chunk);
        self.set_pending_ack(body.data_len());
        self.set_stage(SessionStage::Recv);
        body
    }

    pub fn build_syn(&mut self) -> SynBody {
        self.assert_stage(&[SessionStage::Uninit, SessionStage::EncryptAuth]);
        let mut body = SynBody::new(self.self_seq, self.is_command, self.is_encrypted());
        if let Some(ref name) = self.name {
            body.set_session_name(name.clone());
        }
        self.set_stage(SessionStage::SessionInit);
        body
    }

    ///////////////////////////////////////////////////////////////////////////

    fn set_stage(&mut self, stage: SessionStage) {
        self.stage = stage;
    }

    fn assert_stage(&self, expect: &'static [SessionStage]) {
        if !expect.contains(&self.stage) {
            panic!(
                "expected stage(s) {:?}, got stage: {:?}",
                expect, self.stage
            );
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    fn set_pending_ack(&mut self, sent: u8) {
        self.self_seq_pending = self.self_seq.add(sent);
    }

    fn validate_exchange(
        &mut self,
        peer_seq: Sequence,
        peer_ack: Sequence,
        recv_len: u8,
    ) -> Result<(), SessionError<T::Error>> {
        // We first validate that the peer acknowledged
        // the data (if any) we sent.
        if peer_ack != self.self_seq_pending {
            Err(SessionError::UnexpectedPeerAck {
                expected: self.self_seq_pending,
                actual: peer_ack,
            })?;
        }
        // We now validate we are current with the peer's
        // current sequence.
        if peer_seq != self.peer_seq {
            Err(SessionError::UnexpectedPeerSeq {
                expected: self.peer_seq,
                actual: peer_seq,
            })?;
        }
        // Print out the length of data we received and sent.
        let sent_len = self.self_seq.steps_to(peer_ack);
        debug!("data-ack: [rx: {}, tx: {}]", recv_len, sent_len);
        // Update our sequence values.
        self.peer_seq = self.peer_seq.add(recv_len);
        self.self_seq = self.self_seq_pending;
        // Woo!
        Ok(())
    }

    fn init_from_peer_syn(
        &mut self,
        syn: SynBody,
        prefer_peer_name: bool,
    ) -> Result<(), SessionError<T::Error>> {
        // Extract the peer session name if we should and can
        if (self.name.is_none() || prefer_peer_name) && syn.session_name().is_some() {
            debug!("using peer session name");
            self.name = syn.session_name().map(ToString::to_string).map(Into::into);
        }
        // Extract if the peer indicates this is a command session
        self.is_command = syn.is_command();
        // Check the encrypted flags match
        if self.encryption.is_some() != syn.is_encrypted() {
            return Err(SessionError::EncryptionMismatch);
        }
        // Extract the peer initial sequence
        self.peer_seq = syn.initial_sequence();
        // Woo!
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////////

    pub fn parse_body<B>(
        &mut self,
        body: SessionBodyBytes,
        encrypted: bool,
    ) -> Result<B, SessionError<T::Error>>
    where
        B: PacketBody,
    {
        // Get the packet kind of the body.
        let kind = body.packet_kind();
        // Get the session body bytes.
        let mut body_bytes = body.into_bytes();
        // If encryption is enabled, decrypt our session body.
        let mut body_bytes = if encrypted {
            if let Some(ref mut encryption) = self.encryption {
                encryption
                    .decrypt(&mut body_bytes)
                    .map_err(SessionError::Encryption)?
            } else {
                body_bytes
            }
        } else {
            body_bytes
        };
        // Decode the session body bytes and return.
        let body =
            B::decode_kind(kind, &mut body_bytes).map_err(SessionError::SessionBodyDecode)?;
        if self.packet_trace {
            debug!("body-rx: {:?}", body);
        }
        Ok(body)
    }

    pub fn build_body<B>(
        &mut self,
        body: B,
        encrypted: bool,
    ) -> Result<SessionBodyBytes, SessionError<T::Error>>
    where
        B: Into<SupportedSessionBody>,
    {
        let body = body.into();
        if self.packet_trace {
            debug!("body-tx: {:?}", body);
        }
        // Get the packet kind of the body.
        let kind = body.packet_kind();
        // Encode the body into a buffer.
        let mut body_bytes = BytesMut::new();
        body.encode(&mut body_bytes);
        // If encryption is enabled, encrypt our session body
        let body_bytes = if encrypted {
            if let Some(ref mut encryption) = self.encryption {
                encryption
                    .encrypt(&mut body_bytes)
                    .map_err(SessionError::Encryption)?
            } else {
                body_bytes.freeze()
            }
        } else {
            body_bytes.freeze()
        };
        // Return the new session body
        Ok(SessionBodyBytes::new(kind, body_bytes))
    }

    ///////////////////////////////////////////////////////////////////////////

    fn parse_packet(&self, packet: LazyPacket) -> Result<SessionBodyBytes, SessionError<T::Error>> {
        let kind = packet.kind();
        // Consume the received packet into a session frame if applicable
        if let Some(frame) = packet.into_body().into_session_frame() {
            // Check the session ID returned matches our session ID
            if self.id != frame.session_id() {
                Err(SessionError::UnexpectedId {
                    expected: self.id,
                    actual: frame.session_id(),
                })
            } else {
                // Return the framed session body bytes.
                Ok(frame.into_body().into())
            }
        } else {
            Err(SessionError::UnexpectedKind {
                kind,
                stage: self.stage,
            })
        }
    }

    pub fn build_packet(&self, body: SessionBodyBytes) -> LazyPacket {
        // Generate our packet ID.
        let packet_id = rand::random();
        // Wrap the encoded session body in a session body frame with the session id and packet kind.
        let session_frame = SessionBodyFrame::new(self.id, body.clone());
        // Wrap the session body frame in a packet frame and return.
        Packet::new(packet_id, SupportedBody::Session(session_frame))
    }

    ///////////////////////////////////////////////////////////////////////////

    /// Returns the max data chunk size that can be sent in one datagram.
    ///
    /// This is calculated based on a budget, minus the cost of the framing
    /// and/or encryption framing if enabled.
    pub fn max_data_chunk_size(&self, budget: usize, encryption: bool) -> u8 {
        // Subtract the total size required from what the transport
        // can provide to get the budget we can use.
        let budget = budget - self.packet_min_size(encryption) as usize;
        // Limit the budget to the max size of a packet (u8).
        if budget > LazyPacket::max_size() as usize {
            LazyPacket::max_size()
        } else {
            budget as u8
        }
    }

    pub fn calc_chunk_len(&self, data_len: usize, budget: usize) -> u8 {
        let max = self.max_data_chunk_size(budget, true);
        let val = cmp::min(data_len, max as usize) as u8;
        assert_ne!(val, 0);
        val
    }

    fn packet_min_size(&self, encryption: bool) -> u8 {
        // First calculate the total fixed size of a msg packet.
        let constant_size = Packet::<SessionBodyFrame<MsgBody>>::header_size()
            + SessionBodyFrame::<MsgBody>::header_size()
            + MsgBody::header_size();
        if encryption {
            // If this session is encrypted, add the additional size required.
            if let Some(ref encryption) = self.encryption {
                constant_size + encryption.additional_size()
            } else {
                constant_size
            }
        } else {
            constant_size
        }
    }
}
