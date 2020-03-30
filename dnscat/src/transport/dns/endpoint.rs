use std::sync::{Arc, Mutex, MutexGuard};

use bytes::Bytes;
use failure::Fail;
use rand::{rngs::OsRng, seq::SliceRandom, Rng};
use trust_dns_proto::{
    error::ProtoError,
    rr::{Name, RecordType},
};

use super::{Labeller, NameEncoder, NameEncoderError};

pub type DnsEndpointRequest = (Name, RecordType);

pub trait DnsEndpoint: Send + Sync + 'static {
    fn supported_queries() -> &'static [RecordType];

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
    #[fail(display = "Unsupported record type: {}", _0)]
    UnsupportedQuery(RecordType),
}

impl From<NameEncoderError> for DnsEndpointError {
    fn from(err: NameEncoderError) -> Self {
        Self::Name(err)
    }
}

#[derive(Debug)]
struct BasicInner<R> {
    random: R,
    name_encoder: NameEncoder,
    query_types: Vec<RecordType>,
}

#[derive(Debug)]
pub struct BasicDnsEndpoint<R: Rng = OsRng> {
    inner: Arc<Mutex<BasicInner<R>>>,
    max_request_size: usize,
}

impl BasicDnsEndpoint {
    pub fn new_with_defaults(
        query_types: Vec<RecordType>,
        constant: Name,
    ) -> Result<Self, DnsEndpointError> {
        let name_encoder = NameEncoder::new(constant, Labeller::random())?;
        Self::new(query_types, name_encoder, OsRng)
    }
}

impl<R> BasicDnsEndpoint<R>
where
    R: Rng + Send + 'static,
{
    pub fn new(
        query_types: Vec<RecordType>,
        name_encoder: NameEncoder,
        random: R,
    ) -> Result<Self, DnsEndpointError> {
        assert_ne!(query_types.len(), 0);
        let unsupported_query = query_types
            .iter()
            .find(|query| !Self::supported_queries().contains(query));
        if let Some(query) = unsupported_query {
            return Err(DnsEndpointError::UnsupportedQuery(*query));
        }
        let max_request_size = name_encoder.max_hex_data() as usize;
        let inner = BasicInner {
            random,
            query_types,
            name_encoder,
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            max_request_size,
        })
    }

    fn lock_inner(&self) -> MutexGuard<'_, BasicInner<R>> {
        self.inner.lock().expect("endpoint inner poisoned")
    }

    fn decode_name(&self, name: &Name) -> Result<Bytes, NameEncoderError> {
        self.lock_inner().name_encoder.decode_hex(name)
    }

    fn encode_name(&self, bytes: &[u8]) -> Result<Name, NameEncoderError> {
        self.lock_inner().name_encoder.encode_hex(bytes)
    }
}

impl<R> DnsEndpoint for BasicDnsEndpoint<R>
where
    R: Rng + Send + 'static,
{
    fn supported_queries() -> &'static [RecordType] {
        &[
            RecordType::TXT,
            RecordType::MX,
            RecordType::CNAME,
            RecordType::A,
            RecordType::AAAA,
        ]
    }

    fn max_request_size(&self) -> usize {
        self.max_request_size
    }

    fn build_request(&self, data: Bytes) -> Result<DnsEndpointRequest, DnsEndpointError> {
        let BasicInner {
            ref mut name_encoder,
            ref query_types,
            ref mut random,
        } = *self.lock_inner();
        let name_data = name_encoder.encode_hex(&data[..])?;
        let query_type = query_types.choose(random).unwrap();
        Ok((name_data, *query_type))
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
