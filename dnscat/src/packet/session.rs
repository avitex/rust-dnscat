use std::{fmt, mem};

use bytes::{Buf, BufMut, Bytes};

use crate::encryption::{Authenticator, PublicKey};
use crate::util::{parse, Decode, Encode, StringBytes};

use super::*;

/// Session ID (`u16`).
pub type SessionId = u16;

#[derive(Debug, Clone, PartialEq)]
pub struct SessionHeader {
    packet: PacketHeader,
    pub session_id: SessionId,
}

impl SessionHeader {
    pub const fn new(packet_id: PacketId, packet_kind: PacketKind, session_id: SessionId) -> Self {
        Self {
            packet: PacketHeader {
                id: packet_id,
                kind: packet_kind,
            },
            session_id,
        }
    }

    pub const fn len() -> usize {
        PacketHeader::len() + mem::size_of::<SessionId>()
    }

    pub fn set_packet_id(&mut self, packet_id: PacketId) {
        self.packet.id = packet_id
    }
}

impl Encode for SessionHeader {
    fn encode<B: BufMut + ?Sized>(&self, b: &mut B) {
        self.packet.encode(b);
        b.put_u16(self.session_id);
    }
}

impl AsRef<PacketHeader> for SessionHeader {
    fn as_ref(&self) -> &PacketHeader {
        &self.packet
    }
}

impl PacketHead for SessionHeader {
    fn decode_head(head: PacketHeader, b: &mut Bytes) -> Result<Self, PacketDecodeError> {
        assert!(head.kind.is_session());
        Ok(Self {
            packet: head,
            session_id: parse::be_u16(b)?,
        })
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, PartialEq)]
pub struct SessionBodyBytes(pub Bytes);

impl Encode for SessionBodyBytes {
    fn encode<B: BufMut + ?Sized>(&self, b: &mut B) {
        b.put_slice(self.0.as_ref())
    }
}

impl PacketBody for SessionBodyBytes {
    type Head = SessionHeader;

    fn decode_body(_head: &Self::Head, b: &mut Bytes) -> Result<Self, PacketDecodeError> {
        Ok(Self(b.copy_to_bytes(b.remaining())))
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Clone, PartialEq)]
pub enum SupportedSessionBody {
    Syn(SynBody),
    Msg(MsgBody),
    Fin(FinBody),
    Enc(EncBody),
}

impl SupportedSessionBody {
    pub fn packet_kind(&self) -> PacketKind {
        match self {
            Self::Syn(_) => PacketKind::SYN,
            Self::Msg(_) => PacketKind::MSG,
            Self::Fin(_) => PacketKind::FIN,
            Self::Enc(_) => PacketKind::ENC,
        }
    }
}

impl From<SynBody> for SupportedSessionBody {
    fn from(packet: SynBody) -> Self {
        Self::Syn(packet)
    }
}

impl From<MsgBody> for SupportedSessionBody {
    fn from(packet: MsgBody) -> Self {
        Self::Msg(packet)
    }
}

impl From<FinBody> for SupportedSessionBody {
    fn from(packet: FinBody) -> Self {
        Self::Fin(packet)
    }
}

impl From<EncBody> for SupportedSessionBody {
    fn from(packet: EncBody) -> Self {
        Self::Enc(packet)
    }
}

impl fmt::Debug for SupportedSessionBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syn(p) => write!(f, "{:?}", p),
            Self::Msg(p) => write!(f, "{:?}", p),
            Self::Fin(p) => write!(f, "{:?}", p),
            Self::Enc(p) => write!(f, "{:?}", p),
        }
    }
}

impl Encode for SupportedSessionBody {
    fn encode<B: BufMut + ?Sized>(&self, b: &mut B) {
        match self {
            Self::Syn(p) => p.encode(b),
            Self::Msg(p) => p.encode(b),
            Self::Fin(p) => p.encode(b),
            Self::Enc(p) => p.encode(b),
        }
    }
}

impl PacketBody for SupportedSessionBody {
    type Head = SessionHeader;

    fn decode_body(head: &Self::Head, b: &mut Bytes) -> Result<Self, PacketDecodeError> {
        match head.packet.kind {
            PacketKind::SYN => SynBody::decode(b).map(Self::Syn),
            PacketKind::MSG => MsgBody::decode(b).map(Self::Msg),
            PacketKind::FIN => FinBody::decode(b).map(Self::Fin),
            PacketKind::ENC => EncBody::decode(b).map(Self::Enc),
            other => Err(PacketDecodeError::UnexpectedKind(other.into())),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// SYN Packet

/// A `SYN` packet.
#[derive(Debug, Clone, PartialEq)]
pub struct SynBody {
    init_seq: Sequence,
    flags: PacketFlags,
    sess_name: StringBytes,
}

impl SynBody {
    /// Constructs a new `SYN` packet.
    pub fn new<S>(init_seq: S, command: bool) -> Self
    where
        S: Into<Sequence>,
    {
        let mut flags = PacketFlags::empty();
        let init_seq = init_seq.into();
        if command {
            flags.insert(PacketFlags::COMMAND);
        }
        Self {
            init_seq,
            flags,
            sess_name: StringBytes::new(),
        }
    }

    /// Retrives the initial sequence.
    pub fn initial_sequence(&self) -> Sequence {
        self.init_seq
    }

    /// Retrives the packet flags.
    pub fn flags(&self) -> PacketFlags {
        self.flags
    }

    /// Returns `true` if the `COMMAND` flag is set.
    pub fn is_command(&self) -> bool {
        self.flags().contains(PacketFlags::COMMAND)
    }

    /// Retrives the session name.
    pub fn session_name(&self) -> Option<&str> {
        if self.has_session_name() {
            Some(self.sess_name.as_ref())
        } else {
            None
        }
    }

    /// Returns `true` if the `NAME` packet flag is set, `false` if not.
    pub fn has_session_name(&self) -> bool {
        self.flags.contains(PacketFlags::NAME)
    }

    /// Sets the session name field and flag.
    ///
    /// # Panics
    ///
    /// Panics if session name length including `NULL` is zero or greater
    /// than `Packet::max_size()`.
    ///
    /// Returns the size added to the packet.
    pub fn set_session_name<S>(&mut self, sess_name: S) -> u8
    where
        S: Into<StringBytes>,
    {
        let sess_name = sess_name.into();
        assert!(!sess_name.is_empty(), "session name is empty");
        self.flags.insert(PacketFlags::NAME);
        self.sess_name = sess_name;
        as_valid_len(self.sess_name.len() + 1)
    }
}

impl Encode for SynBody {
    fn encode<B: BufMut + ?Sized>(&self, b: &mut B) {
        b.put_u16(self.init_seq.0);
        b.put_u16(self.flags.bits());
        if self.has_session_name() {
            b.put_slice(self.sess_name.as_bytes());
            b.put_u8(0);
        }
    }
}

impl Decode for SynBody {
    type Error = PacketDecodeError;

    fn decode(b: &mut Bytes) -> Result<Self, Self::Error> {
        let init_seq = Sequence(parse::be_u16(b)?);
        let flags_raw = parse::be_u16(b)?;
        let flags = PacketFlags::from_bits_truncate(flags_raw);
        let sess_name = if flags.contains(PacketFlags::NAME) {
            parse::nt_string::<PacketDecodeError>(b)?
        } else {
            StringBytes::new()
        };
        Ok(Self {
            init_seq,
            flags,
            sess_name,
        })
    }
}

impl PacketBody for SynBody {
    type Head = SessionHeader;

    fn decode_body(head: &Self::Head, b: &mut Bytes) -> Result<Self, PacketDecodeError> {
        match head.packet.kind {
            PacketKind::SYN => Self::decode(b),
            other => Err(PacketDecodeError::UnexpectedKind(other.into())),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// MSG Packet

/// `u16` sequence value.
#[derive(Clone, Copy, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Sequence(pub u16);

impl Sequence {
    pub const fn max_value() -> u16 {
        u16::max_value()
    }

    pub fn get(self) -> u16 {
        self.0
    }

    pub fn steps_to(self, next: Sequence) -> u16 {
        // If we wrapped.
        if self > next {
            let steps_to_max = u16::max_value() - self.0;
            steps_to_max + next.0 + 1
        } else {
            next.0 - self.0
        }
    }

    pub fn add_data(self, len: u8) -> Self {
        Self(self.0.wrapping_add(len as u16))
    }
}

impl From<u16> for Sequence {
    fn from(seq: u16) -> Self {
        Self(seq)
    }
}

impl fmt::Debug for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A `MSG` packet.
#[derive(Debug, Clone, PartialEq)]
pub struct MsgBody {
    seq: Sequence,
    ack: Sequence,
    data: Bytes,
}

impl MsgBody {
    /// Constructs a new empty `MSG` packet.
    pub fn new<S>(seq: S, ack: S) -> Self
    where
        S: Into<Sequence>,
    {
        Self {
            seq: seq.into(),
            ack: ack.into(),
            data: Bytes::new(),
        }
    }

    /// Returns the seq number.
    pub fn seq(&self) -> Sequence {
        self.seq
    }

    /// Returns the ack number.
    pub fn ack(&self) -> Sequence {
        self.ack
    }

    /// Sets the seq number.
    pub fn set_seq(&mut self, seq: Sequence) {
        self.seq = seq;
    }

    /// Sets the ack number.
    pub fn set_ack(&mut self, ack: Sequence) {
        self.ack = ack;
    }

    /// Set the message data.
    ///
    /// # Panics
    ///
    /// Panics if data length is greater than `Packet::max_size()`.
    ///
    /// Returns the size added to the message.
    pub fn set_data(&mut self, data: Bytes) -> u8 {
        self.data = data;
        self.data_len()
    }

    /// Returns the message data.
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Returns the message data length.
    pub fn data_len(&self) -> u8 {
        as_valid_len(self.data.len())
    }

    /// Consumes self into the message data.
    pub fn into_data(self) -> Bytes {
        self.data
    }

    pub const fn packet_size_no_data() -> u8 {
        (SessionHeader::len() + mem::size_of::<Sequence>() * 2) as u8
    }
}

impl Encode for MsgBody {
    fn encode<B: BufMut + ?Sized>(&self, b: &mut B) {
        b.put_u16(self.seq.get());
        b.put_u16(self.ack.get());
        b.put_slice(&self.data[..]);
    }
}

impl Decode for MsgBody {
    type Error = PacketDecodeError;

    fn decode(b: &mut Bytes) -> Result<Self, Self::Error> {
        let seq = Sequence(parse::be_u16(b)?);
        let ack = Sequence(parse::be_u16(b)?);
        let mut msg = Self::new(seq, ack);
        msg.set_data(b.copy_to_bytes(b.remaining()));
        Ok(msg)
    }
}

impl PacketBody for MsgBody {
    type Head = SessionHeader;

    fn decode_body(head: &Self::Head, b: &mut Bytes) -> Result<Self, PacketDecodeError> {
        match head.packet.kind {
            PacketKind::MSG => Self::decode(b),
            other => Err(PacketDecodeError::UnexpectedKind(other.into())),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// FIN Packet

/// A `FIN` packet.
#[derive(Debug, Clone, PartialEq)]
pub struct FinBody {
    reason: StringBytes,
}

impl FinBody {
    /// Constructs a new `FIN` packet.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            reason: StringBytes::new(),
        }
    }

    /// Retrives the reason for disconnect.
    pub fn reason(&self) -> &str {
        self.reason.as_ref()
    }

    /// Consumes self into the reason for ending a session.
    pub fn into_reason(self) -> StringBytes {
        self.reason
    }

    /// Sets the reason for ending a session.
    ///
    /// # Panics
    ///
    /// Panics if reason length including `NULL` is greater than `Packet::max_size()`.
    ///
    /// Returns the size added to the packet.
    pub fn set_reason<S>(&mut self, reason: S) -> u8
    where
        S: Into<StringBytes>,
    {
        let reason = reason.into();
        self.reason = reason;
        as_valid_len(self.reason.len() + 1)
    }
}

impl Encode for FinBody {
    fn encode<B: BufMut + ?Sized>(&self, b: &mut B) {
        b.put_slice(self.reason.as_bytes());
        b.put_u8(0);
    }
}

impl Decode for FinBody {
    type Error = PacketDecodeError;

    fn decode(b: &mut Bytes) -> Result<Self, Self::Error> {
        let reason = parse::nt_string::<PacketDecodeError>(b)?;
        let mut fin = Self::new();
        fin.set_reason(reason);
        Ok(fin)
    }
}

impl PacketBody for FinBody {
    type Head = SessionHeader;

    fn decode_body(head: &Self::Head, b: &mut Bytes) -> Result<Self, PacketDecodeError> {
        match head.packet.kind {
            PacketKind::FIN => Self::decode(b),
            other => Err(PacketDecodeError::UnexpectedKind(other.into())),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// ENC Packet

/// Crypto flags (`u16`).
pub type CryptoFlags = u16;

/// A `ENC` packet.
#[derive(Debug, Clone, PartialEq)]
pub struct EncBody {
    cryp_flags: CryptoFlags,
    body: EncBodyVariant,
}

impl EncBody {
    /// Constructs a new `ENC` packet.
    pub fn new(cryp_flags: CryptoFlags, body: EncBodyVariant) -> Self {
        Self { cryp_flags, body }
    }

    /// Retrives the crypto flags.
    ///
    /// # Notes
    ///
    /// This field is currently not used in the original specification.
    pub fn crypto_flags(&self) -> CryptoFlags {
        self.cryp_flags
    }

    /// Retrives the encryption packet kind.
    pub fn kind(&self) -> EncBodyKind {
        self.body.kind()
    }

    /// Retrives a reference to the encryption packet body.
    pub fn body(&self) -> &EncBodyVariant {
        &self.body
    }

    /// Consumes self into the encryption packet body.
    pub fn into_body(self) -> EncBodyVariant {
        self.body
    }
}

impl Encode for EncBody {
    fn encode<B: BufMut + ?Sized>(&self, b: &mut B) {
        b.put_u16(self.body.kind() as u16);
        b.put_u16(self.cryp_flags);
        self.body.encode(b);
    }
}

impl Decode for EncBody {
    type Error = PacketDecodeError;

    fn decode(b: &mut Bytes) -> Result<Self, Self::Error> {
        let enc_kind = parse::be_u16(b)?;
        let enc_kind =
            EncBodyKind::from_u16(enc_kind).ok_or(PacketDecodeError::UnknownEncKind(enc_kind))?;
        let cryp_flags = parse::be_u16(b)?;
        let body = EncBodyVariant::decode_kind(enc_kind, b)?;
        Ok(Self::new(cryp_flags, body))
    }
}

impl PacketBody for EncBody {
    type Head = SessionHeader;

    fn decode_body(head: &Self::Head, b: &mut Bytes) -> Result<Self, PacketDecodeError> {
        match head.packet.kind {
            PacketKind::ENC => Self::decode(b),
            other => Err(PacketDecodeError::UnexpectedKind(other.into())),
        }
    }
}

/// Enum of all supported encryption packet bodies.
#[derive(Debug, Clone, PartialEq)]
pub enum EncBodyVariant {
    /// `INIT` encyption packet body.
    Init {
        /// The encoded public key.
        public_key: PublicKey,
    },
    /// `AUTH` encyption packet body.
    Auth {
        /// Authenticator value.
        authenticator: Authenticator,
    },
}

impl EncBodyVariant {
    /// Retrives the encryption packet kind.
    pub fn kind(&self) -> EncBodyKind {
        match self {
            Self::Init { .. } => EncBodyKind::INIT,
            Self::Auth { .. } => EncBodyKind::AUTH,
        }
    }

    /// Decodes a encryption packet body given the encryption packet kind.
    ///
    /// Returns a tuple of the remaining buffer not used and the decoded encryption
    /// packet body on success or a packet decode error on failure.
    pub fn decode_kind(kind: EncBodyKind, b: &mut Bytes) -> Result<Self, PacketDecodeError> {
        match kind {
            EncBodyKind::INIT => Ok(Self::Init {
                public_key: parse::split_to_array(b)?,
            }),
            EncBodyKind::AUTH => Ok(Self::Auth {
                authenticator: parse::split_to_array(b)?,
            }),
        }
    }
}

impl Encode for EncBodyVariant {
    fn encode<B: BufMut + ?Sized>(&self, b: &mut B) {
        match self {
            Self::Init { ref public_key } => b.put_slice(&public_key[..]),
            Self::Auth { ref authenticator } => b.put_slice(&authenticator[..]),
        }
    }
}

/// Enum of all supported encryption packet kinds.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum EncBodyKind {
    /// `INIT` encryption packet kind.
    INIT = 0x00,
    /// `AUTH` encryption packet kind.
    AUTH = 0x01,
}

impl EncBodyKind {
    /// Converts a encryption packet kind value to a supported variant.
    pub fn from_u16(kind: u16) -> Option<Self> {
        match kind {
            0x00 => Some(Self::INIT),
            0x01 => Some(Self::AUTH),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{Authenticator, PublicKey};
    use generic_array::sequence::GenericSequence;

    fn assert_pkt_encdec_works(
        packet_in: &'static [u8],
        valid: Packet<SupportedBody<SupportedSessionBody>>,
    ) {
        let mut bytes = Bytes::from_static(packet_in);
        let decoded = match Packet::decode(&mut bytes) {
            Ok(decoded) if bytes.is_empty() => decoded,
            Ok(_) => panic!("bytes remaining after decode: {:?}", bytes),
            Err(err) => panic!("error decoding packet: {:?}", err),
        };
        let mut packet_out = Vec::new();
        assert_eq!(valid, decoded, "valid = decoded");
        valid.encode(&mut packet_out);
        assert_eq!(
            packet_in,
            &packet_out[..],
            "packet = encoded (len {} vs {} )",
            packet_in.len(),
            packet_out.len()
        )
    }

    fn new_session_packet<B: Into<SupportedSessionBody>>(
        packet_id: PacketId,
        packet_kind: PacketKind,
        session_id: SessionId,
        body: B,
    ) -> Packet<SupportedBody<SupportedSessionBody>> {
        Packet::new(
            SupportedHeader::Session(SessionHeader::new(packet_id, packet_kind, session_id)),
            SupportedBody::Session(body.into()),
        )
    }

    #[test]
    #[rustfmt::skip]
    fn test_parse_pkt_syn() {
        assert_pkt_encdec_works(
            &[
                0x00, 0x01, // Packet ID
                0x00, // Packet kind
                0x00, 0x01, // Session ID
                0x00, 0x01, // Init sequence
                0x00, 0x01, // Flags (has name)
                b'h', b'e', b'l', b'l', b'o', 0x00, // Session name
            ],
            new_session_packet(1, PacketKind::SYN, 1, SynBody {
                init_seq: Sequence(1),
                flags: PacketFlags::NAME,
                sess_name: "hello".into(),
            })
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_parse_pkt_msg() {
        assert_pkt_encdec_works(
            &[
                0x00, 0x01, // Packet ID
                0x01, // Packet kind
                0x00, 0x01, // Session ID
                0x00, 0x02, // SEQ
                0x00, 0x03, // ACK
                b'h', b'e', b'l', b'l', b'o', // Data
            ],
            new_session_packet(1, PacketKind::MSG, 1, MsgBody {
                seq: Sequence(2),
                ack: Sequence(3),
                data: Bytes::from_static(b"hello"),
            }),
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_parse_pkt_fin() {
        assert_pkt_encdec_works(
            &[
                0x00, 0x01, // Packet ID
                0x02, // Packet kind
                0x00, 0x01, // Session ID
                b'd', b'r', b'a', b'g', b'o', b'n', b's', 0x00, // Reason
            ],
            new_session_packet(1, PacketKind::FIN, 1, FinBody {
                reason: "dragons".into(),
            }),
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_parse_pkt_enc_init() {
        assert_pkt_encdec_works(
            &[
                0x00, 0x01, // Packet ID
                0x03, // Packet kind
                0x00, 0x01, // Session ID
                0x00, EncBodyKind::INIT as u8, // Encryption kind
                0x00, 0x02, // Crypto flags
                0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, // Pubkey X (1)
                0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, // Pubkey X (2)
                0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, // Pubkey Y (1)
                0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, // Pubkey Y (2)
            ],
            new_session_packet(1, PacketKind::ENC, 1, EncBody {
                cryp_flags: 2,
                body: EncBodyVariant::Init {
                    public_key: PublicKey::generate(|_| 0x66),
                },
            }),
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_parse_pkt_enc_auth() {
        assert_pkt_encdec_works(
            &[
                0x00, 0x01, // Packet ID
                0x03, // Packet kind
                0x00, 0x01, // Session ID
                0x00, EncBodyKind::AUTH as u8, // Encryption kind
                0x00, 0x02, // Crypto flags
                0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, // Auth (1)
                0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, // Auth (2)
            ],
            new_session_packet(1, PacketKind::ENC, 1, EncBody {
                cryp_flags: 2,
                body: EncBodyVariant::Auth {
                    authenticator: Authenticator::generate(|_| 0x66),
                },
            }),
        );
    }
}
