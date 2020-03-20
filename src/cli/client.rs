use std::net::SocketAddr;
use std::sync::Arc;

use clap::Clap;
use log::info;

use super::Opts;

use crate::client::ClientBuilder;
use crate::transport::dns::{BasicDnsEndpoint, DnsClient, Labeller, Name, NameEncoder};

#[derive(Clap)]
pub(crate) struct ClientOpts {
    /// DNS endpoint name.
    name: String,
    /// DNS server address.
    host: String,
    #[clap(long = "command")]
    command: bool,
    // #[clap(long = "request-record-type", default_value = "A")]
    // request_record_type: RecordType,
    #[clap(long = "random-label-chunking")]
    random_label_chunking: bool,
    #[clap(long = "session-id")]
    session_id: Option<u16>,
    #[clap(long = "session-name")]
    session_name: Option<String>,
    #[clap(long = "max-attempts")]
    max_attempts: Option<u8>,
    #[clap(long = "prefer-peer-name")]
    prefer_peer_name: Option<bool>,
    #[clap(long = "recv-queue-size")]
    recv_queue_size: Option<usize>,
}

pub(crate) async fn start(_opts: &Opts, client_opts: &ClientOpts) {
    let dns_addr: SocketAddr = client_opts.host.parse().unwrap();
    let dns_endpoint_name = Name::from_ascii(client_opts.name.clone()).unwrap();
    let dns_name_labeller = if client_opts.random_label_chunking {
        Labeller::random()
    } else {
        Labeller::default()
    };
    let dns_name_encoder = NameEncoder::new(dns_endpoint_name, dns_name_labeller).unwrap();
    let dns_endpoint = Arc::new(BasicDnsEndpoint::new_with_encoder(dns_name_encoder));
    let dns_client = DnsClient::connect(dns_addr, dns_endpoint).await.unwrap();

    let mut conn = ClientBuilder::default().is_command(client_opts.command);

    if let Some(session_id) = client_opts.session_id {
        conn = conn.session_id(session_id)
    }
    if let Some(ref session_name) = client_opts.session_name {
        conn = conn.session_name(session_name.clone())
    }
    if let Some(max_attempts) = client_opts.max_attempts {
        conn = conn.max_exchange_attempts(max_attempts)
    }
    if let Some(prefer_peer_name) = client_opts.prefer_peer_name {
        conn = conn.prefer_peer_name(prefer_peer_name)
    }
    if let Some(recv_queue_size) = client_opts.recv_queue_size {
        conn = conn.recv_queue_size(recv_queue_size)
    }

    let conn = conn.connect_insecure(dns_client).await.unwrap();

    info!(
        "connected to `{}` using `{}` with session ID {}",
        client_opts.host,
        client_opts.name,
        conn.session().id()
    );
}
