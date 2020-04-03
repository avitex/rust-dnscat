use bytes::Bytes;
use failure::Fail;
use rand::{rngs::OsRng, seq::SliceRandom, Rng};
use trust_dns_proto::{
    error::ProtoError,
    rr::{Name, RecordType},
};

use super::{Labeller, NameEncoder, NameEncoderError};

pub type DnsEndpointRequest = (Name, RecordType);

pub trait DnsEndpoint {
    fn supported_queries() -> &'static [RecordType];

    /// Returns the max size for request data.
    fn max_request_size(&self) -> usize;

    /// Build an endpoint request given data.
    fn build_request(&mut self, data: Bytes) -> Result<DnsEndpointRequest, DnsEndpointError>;

    /// Parse an endpoint request into data.
    fn parse_request(&mut self, req: DnsEndpointRequest) -> Result<Bytes, DnsEndpointError>;

    /// Build a MX response given data.
    fn build_mx_response(&mut self, data: Bytes) -> Result<Name, DnsEndpointError>;

    /// Parse a MX response into data.
    fn parse_mx_response(&mut self, name: Name) -> Result<Bytes, DnsEndpointError>;

    /// Build a CNAME response given data.
    fn build_cname_response(&mut self, data: Bytes) -> Result<Name, DnsEndpointError>;

    /// Parse a CNAME response into data.
    fn parse_cname_response(&mut self, name: Name) -> Result<Bytes, DnsEndpointError>;
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
pub struct BasicDnsEndpoint<R: Rng = OsRng> {
    random: R,
    name_encoder: NameEncoder,
    query_types: Vec<RecordType>,
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
    R: Rng,
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
        Ok(Self {
            random,
            query_types,
            name_encoder,
            max_request_size,
        })
    }
}

impl<R> DnsEndpoint for BasicDnsEndpoint<R>
where
    R: Rng,
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

    fn build_request(&mut self, data: Bytes) -> Result<DnsEndpointRequest, DnsEndpointError> {
        let name_data = self.name_encoder.encode_hex(&data[..])?;
        let query_type = self
            .query_types
            .choose(&mut self.random)
            .expect("random query type");
        Ok((name_data, *query_type))
    }

    fn parse_request(&mut self, req: DnsEndpointRequest) -> Result<Bytes, DnsEndpointError> {
        Ok(self.name_encoder.decode_hex(&req.0)?)
    }

    fn build_mx_response(&mut self, data: Bytes) -> Result<Name, DnsEndpointError> {
        Ok(self.name_encoder.encode_hex(&data[..])?)
    }

    fn parse_mx_response(&mut self, name: Name) -> Result<Bytes, DnsEndpointError> {
        Ok(self.name_encoder.decode_hex(&name)?)
    }

    fn build_cname_response(&mut self, data: Bytes) -> Result<Name, DnsEndpointError> {
        Ok(self.name_encoder.encode_hex(&data[..])?)
    }

    fn parse_cname_response(&mut self, name: Name) -> Result<Bytes, DnsEndpointError> {
        Ok(self.name_encoder.decode_hex(&name)?)
    }
}
