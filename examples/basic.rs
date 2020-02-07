use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dnscat2::conn::ConnectionBuilder;
use dnscat2::transport::dns::*;

use futures_timer::Delay;
use log::debug;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

const DNS_SERVER_PORT: u16 = 53531;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    let rt = tokio::runtime::Handle::current();
    let dns_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), DNS_SERVER_PORT);
    let dns_server_name = Name::from_ascii("example.com.").unwrap();
    let dns_endpoint = Arc::new(BasicDnsEndpoint::new(dns_server_name).unwrap());
    let dns_client = DnsClient::connect(dns_addr, dns_endpoint, rt)
        .await
        .unwrap();

    let mut conn = ConnectionBuilder::default()
        .session_name("test")
        .connect_insecure(dns_client)
        .await
        .unwrap();

    debug!("connected: {:?}", conn);

    let mut rng = thread_rng();

    loop {
        // Generate some data
        let data_len = rng.gen_range(0, 64);
        let data: String = rng
            .sample_iter(&Alphanumeric)
            .take(data_len)
            .collect();
        // Send it
        conn.send_data(data.into()).await.unwrap();
        // Repeat after a delay
        Delay::new(Duration::from_millis(1000)).await;
    }
}
