use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use dnscat2::conn::ConnectionBuilder;
use dnscat2::transport::dns::*;

const DNS_SERVER_PORT: u16 = 53531;

#[tokio::main]
async fn main() {
    let rt = tokio::runtime::Handle::current();
    let dns_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), DNS_SERVER_PORT);
    let dns_server_name = Name::from_ascii("example.com.").unwrap();
    let dns_endpoint = Arc::new(BasicDnsEndpoint::new(dns_server_name).unwrap());
    let dns_client = DnsClient::connect(dns_addr, dns_endpoint, rt)
        .await
        .unwrap();
    let conn = ConnectionBuilder::default()
        .session_name("test")
        .connect_insecure(dns_client)
        .await
        .unwrap();
    dbg!(conn);
    // TODO
}
