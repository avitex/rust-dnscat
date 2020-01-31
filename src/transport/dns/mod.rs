mod client;
mod name;

pub use self::client::*;
pub use self::name::*;

use trust_dns_proto::{error::ProtoError, rr::RecordType};

pub(crate) const SOCKET_PORT: u16 = 53;

pub enum DnsTransportError {
    TypeMismatch,
    TypeUnsupported(RecordType),
    DatagramOverflow,
    DatagramUnderflow,
    Proto(ProtoError),
}

impl From<ProtoError> for DnsTransportError {
    fn from(err: ProtoError) -> Self {
        Self::Proto(err)
    }
}
