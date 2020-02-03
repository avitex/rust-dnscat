use std::convert::identity;

use bytes::{BufMut, BytesMut};
use trust_dns_proto::rr::{Name, RecordType};

use super::DnsTransportError;
use crate::transport::{Datagram, DatagramError};
use crate::util::hex;

pub trait DnsEndpoint: Send + Sync + 'static {
    fn build<D>(&self, datagram: D) -> Result<(Name, RecordType), DnsTransportError<D::Error>>
    where
        D: Datagram;

    fn parse<D>(&self, name: Name) -> Result<D, DnsTransportError<D::Error>>
    where
        D: Datagram;

    fn parse_mx<D>(&self, name: Name) -> Result<D, DnsTransportError<D::Error>>
    where
        D: Datagram,
    {
        self.parse(name)
    }

    fn parse_cname<D>(&self, name: Name) -> Result<D, DnsTransportError<D::Error>>
    where
        D: Datagram,
    {
        self.parse(name)
    }
}

// #[derive(Debug)]
// pub enum DnsEndpointError {
//     InvalidRoot,
//     Proto(ProtoError),
//     Custom(&'static str),
//}

pub struct BasicDnsEndpoint {
    root: Name,
    label_chunk_size: usize,
}

impl BasicDnsEndpoint {
    pub fn new(root: Name) -> Self {
        Self {
            root,
            label_chunk_size: 63,
        }
    }
}

impl DnsEndpoint for BasicDnsEndpoint {
    fn parse<D>(&self, name: Name) -> Result<D, DnsTransportError<D::Error>>
    where
        D: Datagram,
    {
        let mut datagram_buf = BytesMut::new();
        if self.root.zone_of(&name) {
            let labels_len = (name.num_labels() - self.root.num_labels()) as usize;
            let labels = name.iter().take(labels_len);
            parse_hex_labels_into_buf(&mut datagram_buf, labels).map_err(DatagramError::Hex)?;
        }
        let datagram = D::decode(&mut datagram_buf.freeze()).map_err(DatagramError::Decode)?;
        Ok(datagram)
    }

    fn build<D>(&self, datagram: D) -> Result<(Name, RecordType), DnsTransportError<D::Error>>
    where
        D: Datagram,
    {
        // Encode the datagram into a buffer.
        let mut datagram_buf = BytesMut::new();
        datagram.encode(&mut datagram_buf);
        // Encode the datagram buffer into hex.
        let mut hex_buf = BytesMut::new();
        hex::encode_into_buf(&mut hex_buf, &datagram_buf[..]);
        //
        let labels = hex_buf.chunks(self.label_chunk_size);
        let name_data = Name::from_labels(labels)?.append_domain(&self.root);
        Ok((name_data, RecordType::A))
    }
}

pub fn parse_hex_labels_into_buf<'a, I>(
    buf: &mut BytesMut,
    labels: I,
) -> Result<(), hex::DecodeError>
where
    I: Iterator<Item = &'a [u8]>,
{
    let nibble_iter = labels.flat_map(identity).copied();
    let byte_iter = hex::decode_iter(nibble_iter, true);
    for byte_res in byte_iter {
        buf.put_u8(byte_res?);
    }
    Ok(())
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_basic_dns_endpoint() {
//         let mut buf = BytesMut::new();
//         let root_name = Name::from_ascii("example.com").unwrap();
//         let data_name = Name::from_ascii("dead.beef.example.com").unwrap();
//         let endpoint = BasicDnsEndpoint::new(root_name);
//         let datagram = endpoint.parse(data_name).unwrap();
//         assert_eq!(buf, &[0xDE, 0xAD, 0xBE, 0xEF][..]);
//         endpoint.build(datagram)
//     }
// }
