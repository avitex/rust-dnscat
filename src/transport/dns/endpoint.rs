use std::sync::{Arc, Mutex, MutexGuard};

use bytes::Bytes;
use failure::Fail;
use trust_dns_proto::{
    error::ProtoError,
    rr::{Name, RecordType},
};

use super::{Labeller, NameEncoder, NameEncoderError};

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

#[derive(Debug, Fail)]
pub enum DnsEndpointError {
    #[fail(display = "DNS protocol error: {}", _0)]
    Proto(ProtoError),
    #[fail(display = "{}", _0)]
    Custom(&'static str),
    #[fail(display = "Name encoder error: {}", _0)]
    Name(NameEncoderError),
}

impl From<NameEncoderError> for DnsEndpointError {
    fn from(err: NameEncoderError) -> Self {
        Self::Name(err)
    }
}

#[derive(Debug)]
pub struct BasicDnsEndpoint {
    max_request_size: usize,
    name_encoder: Arc<Mutex<NameEncoder>>,
    request_record_type: RecordType,
}

impl BasicDnsEndpoint {
    pub fn new(constant: Name) -> Result<Self, DnsEndpointError> {
        let name_encoder = NameEncoder::new(constant, Labeller::random())?;
        Ok(Self::new_with_encoder(name_encoder))
    }

    pub fn new_with_encoder(name_encoder: NameEncoder) -> Self {
        let max_request_size = name_encoder.max_hex_data() as usize;
        let name_encoder = Arc::new(Mutex::new(name_encoder));
        Self {
            name_encoder,
            max_request_size,
            request_record_type: RecordType::A,
        }
    }

    fn lock_name_encoder(&self) -> MutexGuard<NameEncoder> {
        self.name_encoder
            .lock()
            .expect("name encoder lock poisoned")
    }

    fn decode_name(&self, name: &Name) -> Result<Bytes, NameEncoderError> {
        self.lock_name_encoder().decode_hex(name)
    }

    fn encode_name(&self, bytes: &[u8]) -> Result<Name, NameEncoderError> {
        self.lock_name_encoder().encode_hex(bytes)
    }
}

impl DnsEndpoint for BasicDnsEndpoint {
    fn max_request_size(&self) -> usize {
        self.max_request_size
    }

    fn build_request(&self, data: Bytes) -> Result<DnsEndpointRequest, DnsEndpointError> {
        let name_data = self.encode_name(&data[..])?;
        Ok((name_data, self.request_record_type))
    }

    fn parse_request(&self, req: DnsEndpointRequest) -> Result<Bytes, DnsEndpointError> {
        Ok(self.decode_name(&req.0)?)
    }

    fn build_mx_response(&self, data: Bytes) -> Result<Name, DnsEndpointError> {
        Ok(self.encode_name(&data[..])?)
    }

    fn parse_mx_response(&self, name: Name) -> Result<Bytes, DnsEndpointError> {
        Ok(self.decode_name(&name)?)
    }

    fn build_cname_response(&self, data: Bytes) -> Result<Name, DnsEndpointError> {
        Ok(self.encode_name(&data[..])?)
    }

    fn parse_cname_response(&self, name: Name) -> Result<Bytes, DnsEndpointError> {
        Ok(self.decode_name(&name)?)
    }
}
