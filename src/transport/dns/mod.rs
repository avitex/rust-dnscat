mod client;
mod endpoint;
mod name;

pub use self::client::*;
pub use self::endpoint::*;
pub use self::name::*;

use trust_dns_proto::error::ProtoError;

pub use trust_dns_proto::rr::{Name, RecordType};

use crate::transport::DatagramError;

#[derive(Debug)]
pub enum DnsTransportError<D> {
    Proto(ProtoError),
    Datagram(DatagramError<D>),
    Endpoint(DnsEndpointError),
}

impl<D> From<ProtoError> for DnsTransportError<D> {
    fn from(err: ProtoError) -> Self {
        Self::Proto(err)
    }
}

impl<D> From<DatagramError<D>> for DnsTransportError<D> {
    fn from(err: DatagramError<D>) -> Self {
        Self::Datagram(err)
    }
}

impl<D> From<DnsEndpointError> for DnsTransportError<D> {
    fn from(err: DnsEndpointError) -> Self {
        Self::Endpoint(err)
    }
}
