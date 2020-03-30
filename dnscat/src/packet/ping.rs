use crate::util::{Encode, StringBytes};

use super::*;

/// Ping ID (`u16`).
pub type PingId = u16;

/// A `PING` packet header.
#[derive(Debug, Clone, PartialEq)]
pub struct PingHeader {
    packet: PacketHeader,
    pub ping_id: PingId,
}

impl AsRef<PacketHeader> for PingHeader {
    fn as_ref(&self) -> &PacketHeader {
        &self.packet
    }
}

impl Encode for PingHeader {
    fn encode<B: BufMut + ?Sized>(&self, b: &mut B) {
        self.packet.encode(b);
        b.put_u16(self.ping_id);
    }
}

impl PacketHead for PingHeader {
    fn decode_head(head: PacketHeader, b: &mut Bytes) -> Result<Self, PacketDecodeError> {
        Ok(Self {
            packet: head,
            ping_id: parse::be_u16(b)?,
        })
    }
}

/// A `PING` packet body.
#[derive(Debug, Clone, PartialEq)]
pub struct PingBody {
    data: StringBytes,
}

impl PingBody {
    /// Constructs a new `PING` packet.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            data: StringBytes::new(),
        }
    }

    /// Retrives the ping data.
    pub fn data(&self) -> &str {
        self.data.as_ref()
    }

    pub fn set_data<S>(&mut self, data: S) -> u8
    where
        S: Into<StringBytes>,
    {
        self.data = data.into();
        as_valid_len(self.data.len())
    }
}

impl Encode for PingBody {
    fn encode<B: BufMut + ?Sized>(&self, b: &mut B) {
        b.put_slice(self.data.as_bytes());
        b.put_u8(0);
    }
}

impl PacketBody for PingBody {
    type Head = PingHeader;

    fn decode_body(_head: &Self::Head, b: &mut Bytes) -> Result<Self, PacketDecodeError> {
        let data = parse::nt_string::<PacketDecodeError>(b)?;
        let mut ping = Self::new();
        ping.set_data(data);
        Ok(ping)
    }
}
