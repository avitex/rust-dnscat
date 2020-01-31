use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
use futures::future;
use tokio::net::UdpSocket;
use tokio::runtime;
use trust_dns_client::{
    client::AsyncClient,
    op::Query,
    rr::{Name, RData, Record, RecordType},
    udp::UdpClientStream,
};
use trust_dns_proto::{
    udp::UdpResponse,
    xfer::{DnsHandle, DnsRequestOptions},
};

use crate::transport::{
    BoxExchangeFuture, Datagram, ExchangeError, ExchangeTransport, SplitDatagram,
};

use super::DnsTransportError;

const DEFAULT_LOOKUP_OPTIONS: DnsRequestOptions = DnsRequestOptions {
    expects_multiple_responses: false,
};

#[derive(Debug, Clone, PartialEq)]
pub struct DnsRequest {
    pub name: Name,
    pub kind: RecordType,
}

pub trait DnsEndpoint: Send + 'static {
    fn build(&mut self, tx: &[u8]) -> Option<DnsRequest>;
}

pub struct DnsClient<H, E> {
    dns_handle: H,
    encode_buf: BytesMut,
    runtime_handle: runtime::Handle,
    endpoint: Arc<Mutex<E>>,
}

impl<H, E> Clone for DnsClient<H, E>
where
    H: DnsHandle,
{
    fn clone(&self) -> Self {
        Self {
            dns_handle: self.dns_handle.clone(),
            runtime_handle: self.runtime_handle.clone(),
            encode_buf: self.encode_buf.clone(),
            endpoint: self.endpoint.clone(),
        }
    }
}

impl<H, E> DnsClient<H, E>
where
    H: DnsHandle,
    E: DnsEndpoint,
{
    pub fn new(dns_handle: H, endpoint: E, runtime_handle: runtime::Handle) -> Self {
        Self {
            dns_handle,
            runtime_handle,
            encode_buf: BytesMut::new(),
            endpoint: Arc::new(Mutex::new(endpoint)),
        }
    }

    async fn lookup_and_extract(
        &mut self,
        request_kind: RecordType,
        name: Name,
    ) -> Result<Bytes, DnsTransportError> {
        // let query = Query::query(name, request_kind);
        // let response = self
        //     .dns_handle
        //     .lookup(query, DEFAULT_LOOKUP_OPTIONS)
        //     .await?;
        //let response_kind = response.record_type();
        // let answers = response.take_answers().into_iter().map(||);
        // if request_kind != response_kind {
        //     return Err(DnsTransportError::TypeMismatch);
        // }
        // let mut datagram = SplitDatagram::with_capacity(answers.len());
        let mut bytes = BytesMut::new();
        Ok(bytes.freeze())
    }

    fn build_request<D: Datagram>(&mut self, datagram: D) -> Result<DnsRequest, DnsTransportError> {
        let mut endpoint = self
            .endpoint
            .lock()
            .expect("dns client state lock poisoned");
        datagram.encode(&mut self.encode_buf);
        let request_opt = endpoint.build(self.encode_buf.as_ref());
        self.encode_buf.clear();
        request_opt.ok_or(DnsTransportError::DatagramOverflow)
    }

    async fn send_request<D: Datagram>(
        mut self,
        request: DnsRequest,
    ) -> Result<D, ExchangeError<D::Error, DnsTransportError>> {
        let DnsRequest { kind, name } = request;
        let mut bytes = self
            .lookup_and_extract(kind, name)
            .await
            .map_err(ExchangeError::Transport)?;
        let datagram = D::decode(&mut bytes).map_err(ExchangeError::Datagram)?;
        if bytes.is_empty() {
            Ok(datagram)
        } else {
            Err(ExchangeError::Transport(
                DnsTransportError::DatagramUnderflow,
            ))
        }
    }
}

impl<E> DnsClient<AsyncClient<UdpResponse>, E>
where
    E: DnsEndpoint,
{
    pub async fn connect(
        addr: SocketAddr,
        endpoint: E,
        rt: runtime::Handle,
    ) -> Result<Self, DnsTransportError> {
        let stream = UdpClientStream::<UdpSocket>::new(addr);
        let (client, bg) = AsyncClient::connect(stream).await?;
        rt.spawn(bg);
        Ok(Self::new(client, endpoint, rt))
    }
}

impl<H, E, CS, SC> ExchangeTransport<CS, SC> for DnsClient<H, E>
where
    H: DnsHandle,
    E: DnsEndpoint,
    CS: Datagram,
    SC: Datagram,
    SC::Error: Send,
{
    type Error = DnsTransportError;

    type Future = BoxExchangeFuture<SC, Self::Error>;

    fn exchange(&mut self, datagram: CS) -> Self::Future {
        match self.build_request(datagram) {
            Ok(request) => Box::pin(self.clone().send_request(request)),
            Err(err) => Box::pin(future::err(ExchangeError::Transport(err))),
        }
    }
}
