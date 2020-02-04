use bytes::{BufMut, Bytes, BytesMut};
use trust_dns_proto::{
    error::ProtoError,
    rr::{Name, RecordType},
};

use super::DnsTransportError;
use crate::util::hex;

pub type DnsEndpointRequest = (Name, RecordType);

pub trait DnsEndpoint: Send + Sync + 'static {
    /// Returns the max size for request data.
    fn max_request_size(&self) -> usize;

    /// Build an endpoint request given data.
    fn build_request(&self, data: Bytes) -> Result<DnsEndpointRequest, DnsEndpointError>;

    /// Parse an endpoint request into data.
    fn parse_request(&self, req: DnsEndpointRequest) -> Result<Bytes, DnsEndpointError>;

    /// Build a MX response given data.
    fn build_mx_response(&self, data: Bytes) -> Result<Name, DnsEndpointError>;

    /// Parse a MX response into data.
    fn parse_mx_response(&self, name: Name) -> Result<Bytes, DnsEndpointError>;

    /// Build a CNAME response given data.
    fn build_cname_response(&self, data: Bytes) -> Result<Name, DnsEndpointError>;

    /// Parse a CNAME response into data.
    fn parse_cname_response(&self, name: Name) -> Result<Bytes, DnsEndpointError>;
}

#[derive(Debug)]
pub enum DnsEndpointError {
    InvalidRoot,
    Proto(ProtoError),
    Custom(&'static str),
}

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

// impl DnsEndpoint for BasicDnsEndpoint {
//     fn parse<D>(&self, name: Name) -> Result<D, DnsTransportError<D::Error>>
//     where
//         D: Datagram,
//     {
//         let mut datagram_buf = BytesMut::new();
//         if self.root.zone_of(&name) {
//             let labels_len = (name.num_labels() - self.root.num_labels()) as usize;
//             let labels = name.iter().take(labels_len);
//             parse_hex_labels_into_buf(&mut datagram_buf, labels).map_err(DatagramError::Hex)?;
//         }
//         let datagram = D::decode(&mut datagram_buf.freeze()).map_err(DatagramError::Decode)?;
//         Ok(datagram)
//     }

//     fn build<D>(&self, datagram: D) -> Result<(Name, RecordType), DnsTransportError<D::Error>>
//     where
//         D: Datagram,
//     {
//         // Encode the datagram into a buffer.
//         let mut datagram_buf = BytesMut::new();
//         datagram.encode(&mut datagram_buf);
//         // Encode the datagram buffer into hex.
//         let mut hex_buf = BytesMut::new();
//         hex::encode_into_buf(&mut hex_buf, &datagram_buf[..]);
//         //
//         let labels = hex_buf.chunks(self.label_chunk_size);
//         let name_data = Name::from_labels(labels)?.append_domain(&self.root);
//         Ok((name_data, RecordType::A))
//     }
// }

// pub fn build_name_from_bytes(
//     bytes: Bytes,
//     root_name: Option<&Name>,
//     tag_name: Option<&Name>,
//     chunker: LabelChunker,
// ) -> Result<Name, DnsEndpointError> {
//     let hex_iter = hex::encode_iter(bytes.iter().copied());
//     let labels = chunker.chunk(hex_iter);
//     let name = Name::from_labels(labels)?;
//     let name = if let Some(root_name) = root_name {
//         name.append_domain(root_name)
//     } else {
//         name
//     };
//     let name = if let Some(tag_name) = tag_name {
//         tag_name.append_domain(name)
//     } else {
//         name
//     };
// }

// pub fn parse_hex_labels_into_buf<'a, I>(
//     buf: &mut BytesMut,
//     labels: I,
// ) -> Result<(), hex::DecodeError>
// where
//     I: Iterator<Item = &'a [u8]>,
// {
//     let nibble_iter = labels.flatten().copied();
//     let byte_iter = hex::decode_iter(nibble_iter, true);
//     for byte_res in byte_iter {
//         buf.put_u8(byte_res?);
//     }
//     Ok(())
// }

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
