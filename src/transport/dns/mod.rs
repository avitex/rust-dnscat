mod client;
mod endpoint;

pub use self::client::*;
pub use self::endpoint::*;

use trust_dns_proto::error::ProtoError;

use crate::transport::DatagramError;

#[derive(Debug)]
pub enum DnsTransportError<D> {
    Proto(ProtoError),
    Datagram(DatagramError<D>),
    //Endpoint(DnsEndpointError),
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

// impl<D> From<DnsEndpointError> for DnsTransportError<D> {
//     fn from(err: DnsEndpointError) -> Self {
//         Self::Endpoint(err)
//     }
// }
