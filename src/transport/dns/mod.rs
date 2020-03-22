mod client;
mod endpoint;
mod name;

#[cfg(feature = "trust-dns-resolver")]
mod resolver;

pub use self::client::*;
pub use self::endpoint::*;
pub use self::name::*;

use failure::Fail;
use trust_dns_proto::error::ProtoError;

pub use trust_dns_proto::rr::{Name, RecordType};

#[cfg(feature = "trust-dns-resolver")]
pub use self::resolver::get_system_dns_server;

use crate::transport::DatagramError;

#[derive(Debug, Fail)]
pub enum DnsTransportError<D: Fail> {
    #[fail(display = "DNS protocol error: {}", _0)]
    Proto(ProtoError),
    #[fail(display = "Datagram error: {}", _0)]
    Datagram(DatagramError<D>),
    #[fail(display = "DNS endpoint error: {}", _0)]
    Endpoint(DnsEndpointError),
    #[fail(display = "No answers were returned")]
    NoAnswers,
}

impl<D: Fail> From<ProtoError> for DnsTransportError<D> {
    fn from(err: ProtoError) -> Self {
        Self::Proto(err)
    }
}

impl<D: Fail> From<DatagramError<D>> for DnsTransportError<D> {
    fn from(err: DatagramError<D>) -> Self {
        Self::Datagram(err)
    }
}

impl<D: Fail> From<DnsEndpointError> for DnsTransportError<D> {
    fn from(err: DnsEndpointError) -> Self {
        Self::Endpoint(err)
    }
}
