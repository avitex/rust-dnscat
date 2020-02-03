use std::convert::identity;

use bytes::{BufMut, BytesMut};
use trust_dns_proto::{
    error::ProtoError,
    rr::{Name, RecordType},
};

use crate::transport::Datagram;
use crate::util::hex;

pub trait DnsEndpoint: Send + Sync + 'static {
    fn parse(&self, name: Name, buf: &mut BytesMut) -> Result<(), DnsEndpointError>;

    fn build<D>(&self, datagram: D) -> Result<(Name, RecordType), DnsEndpointError>
    where
        D: Datagram;
}

#[derive(Debug)]
pub enum DnsEndpointError {
    InvalidRoot,
    Proto(ProtoError),
    Hex(hex::DecodeError),
    Custom(&'static str),
}

pub struct BasicDnsEndpoint {
    root: Name,
}

impl BasicDnsEndpoint {
    pub fn new(root: Name) -> Self {
        Self { root }
    }
}

impl DnsEndpoint for BasicDnsEndpoint {
    fn parse(&self, name: Name, buf: &mut BytesMut) -> Result<(), DnsEndpointError> {
        if self.root.zone_of(&name) {
            let data_labels_count = (name.num_labels() - self.root.num_labels()) as usize;
            let data_labels = name.iter().take(data_labels_count);
            parse_hex_labels_into_buf(buf, data_labels)?;
        }
        Ok(())
    }

    fn build<D>(&self, datagram: D) -> Result<(Name, RecordType), DnsEndpointError>
    where
        D: Datagram,
    {
        let mut hex_buf = BytesMut::new();
        let mut datagram_buf = BytesMut::new();
        datagram.encode(&mut datagram_buf);
        hex::encode_into_buf(&mut hex_buf, datagram_buf.as_ref());
        let name_data = Name::from_labels(hex_buf.chunks(63))
            .map_err(DnsEndpointError::Proto)?
            .append_domain(&self.root);
        Ok((name_data, RecordType::A))
    }
}

pub fn parse_hex_labels_into_buf<'a, I>(
    buf: &mut BytesMut,
    labels: I,
) -> Result<(), DnsEndpointError>
where
    I: Iterator<Item = &'a [u8]>,
{
    let nibble_iter = labels.flat_map(identity).copied();
    let byte_iter = hex::decode_hex_iter(nibble_iter, true);
    for byte_res in byte_iter {
        buf.put_u8(byte_res.map_err(DnsEndpointError::Hex)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_dns_endpoint_parse() {
        let mut buf = BytesMut::new();
        let root_name = Name::from_ascii("example.com").unwrap();
        let data_name = Name::from_ascii("dead.beef.example.com").unwrap();
        let endpoint = BasicDnsEndpoint::new(root_name);
        endpoint.parse(data_name, &mut buf).unwrap();
        assert_eq!(buf, &[0xDE, 0xAD, 0xBE, 0xEF][..]);
    }
}
