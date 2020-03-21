#![allow(unused)]

use std::net::SocketAddr;
use std::sync::Arc;

use clap::{ArgSettings, Clap};
use log::{error, info};

use super::Opts;

use crate::client::ClientBuilder;
use crate::transport::dns::{BasicDnsEndpoint, DnsClient, Name, RecordType};

#[derive(Clap, Debug)]
pub(crate) struct ClientOpts {
    /// DNS endpoint name.
    domain: Name,

    /// Set the DNS server address, which by default is auto-detected.
    #[clap(long)]
    server: Option<SocketAddr>,

    /// Set the query types for DNS requests (comma-delimited).
    #[clap(
        long,
        multiple = true,
        use_delimiter = true,
        default_values = &["TXT", "MX", "A"],
        possible_values = &["TXT", "MX", "CNAME", "A", "AAAA"]
    )]
    query: Vec<RecordType>,

    /// Set the minimum delay in milliseconds between packets.
    ///
    /// This can be set to avoid flooding a network or server with
    /// DNS requests when sending a larger amount of data.
    #[clap(long, default_value = "0")]
    min_delay: u64,

    /// Set the maximum delay in milliseconds between packets.
    ///
    /// If no data has been sent to the server after this delay,
    /// an empty packet will be sent to poll for any data waiting
    /// to be received.
    #[clap(long, default_value = "1000")]
    max_delay: u64,

    /// If set, will select a random delay for each transmit between 
    /// <min-delay> and <max-delay>.
    #[clap(long)]
    random_delay: bool,

    /// Set the max re-transmits attempted before assuming the
    /// server is dead and aborting.
    #[clap(long, default_value = "20")]
    max_retransmits: usize,

    /// If set, will re-transmit forever until a server sends a
    /// valid response.
    #[clap(long, conflicts_with_all = &["max_retransmits", "retransmit_backoff"])]
    retransmit_forever: bool,

    /// If set, will exponentially backoff in delay from 
    /// re-attempting a transmit.
    #[clap(long, conflicts_with = "retransmit_forever")]
    retransmit_backoff: bool,

    /// Set the shared secret used for encryption.
    #[clap(long)]
    secret: Option<String>,

    /// If set, will turn off encryption/authentication.
    #[clap(long, conflicts_with = "secret")]
    insecure: bool,

    /// Set the session ID manually.
    #[clap(long)]
    session_id: Option<u16>,

    /// Set the session name manually.
    #[clap(long)]
    session_name: Option<String>,

    /// If set, prefer the server's session name.
    #[clap(long)]
    prefer_server_name: Option<bool>,

    /// Set the receive chunk buffer size.
    #[clap(long)]
    recv_queue_size: Option<usize>,
    // TODO
    // /// Display incoming/outgoing DNSCAT2 packets.
    // #[clap(long)]
    // packet_trace: bool,

    // TODO
    // /// Start an interactive 'command' session (default).
    // #[clap(long = "command")]
    // command: bool,

    // TODO
    // /// Send/receive output to the console.
    // #[clap(long)]
    // console: bool,

    // TODO
    // /// Execute the given process and link it to the stream.
    // #[clap(long = "exec", short = "e")]
    // exec: bool,

    // TODO
    // /// Send/receive output to the console.
    // #[clap(long = "ping")]
    // ping: bool,
}

pub(crate) async fn start(_opts: &Opts, client_opts: &ClientOpts) {
    let dns_server_addr = client_opts
        .server
        .unwrap_or_else(|| "8.8.8.8:53".parse().unwrap());
    let dns_endpoint = BasicDnsEndpoint::new(client_opts.domain.clone()).unwrap();
    let dns_client = DnsClient::connect(dns_server_addr, Arc::new(dns_endpoint))
        .await
        .unwrap();

    let mut conn = ClientBuilder::default();

    if let Some(session_id) = client_opts.session_id {
        conn = conn.session_id(session_id)
    }
    if let Some(ref session_name) = client_opts.session_name {
        conn = conn.session_name(session_name.clone())
    }
    // if let Some(max_retransmits) = client_opts.max_retransmits {
    //     conn = conn.max_retransmits(max_retransmits)
    // }
    if let Some(prefer_server_name) = client_opts.prefer_server_name {
        conn = conn.prefer_server_name(prefer_server_name)
    }
    if let Some(recv_queue_size) = client_opts.recv_queue_size {
        conn = conn.recv_queue_size(recv_queue_size)
    }

    info!(
        "connecting to `{}` using `{}`",
        dns_server_addr, client_opts.domain
    );

    let conn = match conn.connect_insecure(dns_client).await {
        Ok(conn) => conn,
        Err(err) => {
            error!("failed to connect with {}", err);
            return;
        }
    };

    info!("connected with session ID {}", conn.session().id());
}
