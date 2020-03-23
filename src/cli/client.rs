use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;

use clap::{AppSettings, Clap};
use futures::future;
use log::{error, info, warn};
use tokio::{io, process};

use crate::client::ClientBuilder;
use crate::transport::dns::{self, BasicDnsEndpoint, DnsClient, Name, RecordType};

#[derive(Clap, Debug)]
#[clap(version = "0.1", author = "James Dyson <theavitex@gmail.com>", setting = AppSettings::TrailingVarArg)]
pub(crate) struct Opts {
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
    #[clap(long, conflicts_with = "max_retransmits")]
    retransmit_forever: bool,

    /// If set, will exponentially backoff in delay from
    /// re-attempting a transmit.
    #[clap(long, conflicts_with = "retransmit_forever")]
    retransmit_backoff: bool,

    /// Set the shared secret used for encryption.
    #[clap(long, required_unless = "insecure")]
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

    /// If set, display incoming/outgoing DNSCAT2 packets.
    #[clap(long)]
    packet_trace: bool,

    /// If set, indicate to the server this is a command session.
    #[clap(long)]
    command: bool,

    /// Execute a process and attach stdin/stdout.
    #[clap(long, short)]
    exec: bool,

    #[clap(last = true, multiple = true, allow_hyphen_values = true)]
    exec_opts: Vec<String>,
}

pub(crate) async fn start(opts: &Opts) {
    // Build DNS client
    let dns_server_addr = if let Some(server) = opts.server {
        server
    } else {
        let server = match dns::get_system_dns_server() {
            Ok(Some(server_addr)) => server_addr,
            Ok(None) => panic!("no valid system DNS servers"),
            Err(err) => panic!("failed to load system DNS config: {}", err),
        };
        if !opts.domain.is_fqdn() {
            // Unless you've changed system configuration to point to a
            // DNSCAT2 server, this will most certainly not work.
            warn!("non-FQDN is being used with a system DNS server");
        }
        server
    };
    // Build the DNS endpoint
    let dns_endpoint =
        BasicDnsEndpoint::new_with_defaults(opts.query.clone(), opts.domain.clone()).unwrap();
    // Build the DNS client
    let dns_client = DnsClient::connect(dns_server_addr, Arc::new(dns_endpoint))
        .await
        .unwrap();
    // Start building the client connection
    let mut conn = ClientBuilder::default()
        .is_command(opts.command)
        .packet_trace(opts.packet_trace);

    // opts.min_delay, opts.max_delay, opts.random_delay
    // opts.max_retransmits, opts.retransmit_forever, opts.retransmit_backoff

    if let Some(session_id) = opts.session_id {
        conn = conn.session_id(session_id)
    }
    if let Some(ref session_name) = opts.session_name {
        conn = conn.session_name(session_name.clone())
    }
    if let Some(prefer_server_name) = opts.prefer_server_name {
        conn = conn.prefer_server_name(prefer_server_name)
    }
    if let Some(recv_queue_size) = opts.recv_queue_size {
        conn = conn.recv_queue_size(recv_queue_size)
    }

    info!(
        "connecting to `{}` using `{}`",
        dns_server_addr, opts.domain
    );

    let conn = if let Some(ref _secret) = opts.secret {
        unimplemented!()
    } else {
        assert!(opts.insecure);
        match conn.connect_insecure(dns_client).await {
            Ok(conn) => conn,
            Err(err) => {
                error!("failed to connect with {}", err);
                return;
            }
        }
    };

    info!(
        "connected with session (id: {}, name: {})",
        conn.session().id(),
        conn.session().name().unwrap_or("<none>")
    );

    let (reader, writer) = io::split(conn);

    if opts.exec {
        let process = opts
            .exec_opts
            .get(1)
            .expect("exec specified with no process");
        let result = process::Command::new(process)
            .args(&opts.exec_opts[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn();
        match result {
            Ok(child) => {
                let stdin = child.stdin.unwrap();
                let stdout = child.stdout.unwrap();
                start_rw(stdout, stdin, reader, writer).await
            }
            Err(err) => panic!("failed to start `{}`: {}", process, err),
        }
    } else {
        start_rw(io::stdin(), io::stdout(), reader, writer).await
    }
}

async fn start_rw<R1, W1, R2, W2>(
    mut read: R1,
    mut write: W1,
    mut client_read: R2,
    mut client_write: W2,
) where
    R1: io::AsyncRead + Unpin,
    W1: io::AsyncWrite + Unpin,
    R2: io::AsyncRead + Unpin,
    W2: io::AsyncWrite + Unpin,
{
    let to_server_fut = io::copy(&mut read, &mut client_write);
    let to_client_fut = io::copy(&mut client_read, &mut write);

    match future::select(to_server_fut, to_client_fut).await {
        future::Either::Left((result, _)) => result.unwrap(),
        future::Either::Right((result, _)) => result.unwrap(),
    };
}
