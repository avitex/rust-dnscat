use std::net::{Ipv4Addr, SocketAddr};
use std::str;

use dnscat::client::ClientBuilder;
use dnscat::transport::dns::*;

use futures::{AsyncReadExt, AsyncWriteExt};
use log::debug;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

const DNS_SERVER_PORT: u16 = 53531;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    let dns_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), DNS_SERVER_PORT);
    let dns_server_name = Name::from_ascii("example.com.").unwrap();
    let dns_endpoint =
        BasicDnsEndpoint::new_with_defaults(vec![RecordType::A], dns_server_name).unwrap();
    let dns_client = DnsClient::connect(dns_addr, dns_endpoint).await.unwrap();

    let mut conn = ClientBuilder::default()
        .session_name("test")
        .connect_insecure(dns_client)
        .await
        .unwrap();

    debug!("connected: {:#?}", conn);

    let rng = &mut thread_rng();

    loop {
        // Generate some data
        let write_data_len = rng.gen_range(0..50);
        let write_data: Vec<u8> = rng
            .sample_iter(&Alphanumeric)
            .take(write_data_len)
            .collect();
        // Send it
        conn.write(write_data.as_ref()).await.unwrap();
        // Wait for a reply
        let mut buf = [0; 16];
        let read = conn.read(&mut buf).await.unwrap();
        println!("received: {}", str::from_utf8(&buf[..read]).unwrap().trim());
    }
}
