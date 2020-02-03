use bytes::BytesMut;
use trust_dns_proto::rr::{Name, RecordType};

use crate::transport::{Datagram, DatagramError};
use crate::util::hex;

pub trait DnsEndpoint: Send + Sync + 'static {
    fn parse(&self, name: Name, rx: &mut BytesMut) -> Result<(), DnsEndpointError>;

    fn build<D>(&self, datagram: D) -> Result<(Name, RecordType), DatagramError<D::Error>>
    where
        D: Datagram;
}

pub enum DnsEndpointError {
    InvalidRoot,
    Hex(hex::DecodeError),
    Custom(&'static str),
}

pub struct BasicDnsEndpoint {
    root: Name,
}

impl DnsEndpoint for BasicDnsEndpoint {
    fn parse(&self, name: Name, rx: &mut BytesMut) -> Result<(), DnsEndpointError> {
        unimplemented!()
    }

    fn build<D>(&self, datagram: D) -> Result<(Name, RecordType), DatagramError<D::Error>>
    where
        D: Datagram,
    {
        unimplemented!()
    }
}
