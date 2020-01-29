use std::net::{IpAddr, SocketAddr};

use bytes::{BufMut, Bytes};
use futures::future::{BoxFuture, TryFutureExt};
use tokio::net::UdpSocket;
use tokio::runtime;
use trust_dns_client::{
    client::AsyncClient,
    op::{DnsResponse, Query},
    rr::{Name, RData, RecordType},
    udp::UdpClientStream,
};
use trust_dns_proto::{
    error::ProtoError,
    udp::UdpResponse,
    xfer::{DnsHandle, DnsRequestOptions},
};

use crate::transport::ExchangeClient;

const DNS_SOCKET_PORT: u16 = 53;

type ClientInner = AsyncClient<UdpResponse>;

pub struct DnsClient {
    rt: runtime::Handle,
}

impl DnsClient {
    pub fn new(rt: runtime::Handle) -> Self {
        Self { rt }
    }

    async fn client_for_host(&self, host: IpAddr) -> Result<ClientInner, ProtoError> {
        let addr = SocketAddr::new(host, DNS_SOCKET_PORT);
        let stream = UdpClientStream::<UdpSocket>::new(addr);
        let (client, bg) = ClientInner::connect(stream).await?;
        self.rt.spawn(bg);
        Ok(client)
    }
}

impl ExchangeClient for DnsClient {
    type Error = ProtoError;
    type Query = (IpAddr, Query);

    type Future = BoxFuture<'static, Result<Bytes, Self::Error>>;

    fn build(&mut self, buf: &[u8]) -> Result<Option<Self::Query>, Self::Error> {
        //let record_type = RecordType::A;
        //let query = Query::query(name, record_type);
        unimplemented!()
    }

    fn query(&mut self, query: Self::Query) -> Self::Future {
        let (host, query) = query;
        let query_opts = DnsRequestOptions {
            expects_multiple_responses: true,
        };

        let fut = self
            .client_for_host(host)
            .and_then(|mut c| c.lookup(query, query_opts));

        //Box::pin(fut)
        unimplemented!()
    }
}
