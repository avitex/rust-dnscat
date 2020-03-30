use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use futures::future;
use log::{error, info, warn};
use structopt::StructOpt;
use tokio::{io, process};

use crate::client::{Client, ClientBuilder};
use crate::encryption::{Encryption, StandardEncryption};
use crate::packet::LazyPacket;
use crate::transport::dns::{self, BasicDnsEndpoint, DnsClient, Name, RecordType};
use crate::transport::ExchangeTransport;

#[derive(StructOpt, Debug)]
#[structopt(version = "0.1", author = "James Dyson <theavitex@gmail.com>")]
pub(crate) struct Opts {
    /// DNS name constant.
    constant: Name,

    /// Set the DNS server address, which by default is auto-detected.
    #[structopt(long)]
    server: Option<SocketAddr>,

    /// Set the query types for DNS requests (comma-delimited).
    #[structopt(
        long,
        multiple = true,
        use_delimiter = true,
        default_value = "TXT,MX,A",
        possible_values = &["TXT", "MX", "CNAME", "A", "AAAA"]
    )]
    query: Vec<RecordType>,

    /// Set the minimum delay in milliseconds between packets.
    ///
    /// This can be set to avoid flooding a network or server with
    /// DNS requests when sending a larger amount of data.
    #[structopt(long, default_value = "0")]
    min_delay: u64,

    /// Set the maximum delay in milliseconds between packets.
    ///
    /// If no data has been sent to the server after this delay,
    /// an empty packet will be sent to poll for any data waiting
    /// to be received.
    #[structopt(long, default_value = "1000")]
    max_delay: u64,

    /// If set, will select a random delay for each transmit between
    /// <min-delay> and <max-delay>.
    #[structopt(long)]
    random_delay: bool,

    /// Set the max re-transmits attempted before assuming the
    /// server is dead and aborting.
    #[structopt(long, default_value = "20")]
    max_retransmits: usize,

    /// If set, will re-transmit forever until a server sends a
    /// valid response.
    #[structopt(long, conflicts_with = "max_retransmits")]
    retransmit_forever: bool,

    /// If set, will exponentially backoff in delay from
    /// re-attempting a transmit.
    #[structopt(long, conflicts_with = "retransmit_forever")]
    retransmit_backoff: bool,

    /// Set the shared secret used for encryption.
    #[structopt(long, required_unless = "insecure")]
    secret: Option<String>,

    /// If set, will turn off encryption/authentication.
    #[structopt(long, conflicts_with = "secret")]
    insecure: bool,

    /// Set the session ID manually.
    #[structopt(long)]
    session_id: Option<u16>,

    /// Set the session name manually.
    #[structopt(long)]
    session_name: Option<String>,

    /// If set, prefer the server's session name.
    #[structopt(long)]
    prefer_server_name: bool,

    /// Set the receive chunk buffer size.
    #[structopt(long, default_value = "16")]
    recv_queue_size: usize,

    /// If set, display incoming/outgoing DNSCAT2 packets.
    #[structopt(long)]
    packet_trace: bool,

    /// If set, indicate to the server this is a command session.
    #[structopt(long)]
    command: bool,

    /// Execute a process and attach stdin/stdout.
    #[structopt(long, short, multiple = true, allow_hyphen_values = true)]
    exec: Vec<String>,
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
        if !opts.constant.is_fqdn() {
            // Unless you've changed system configuration to point to a
            // DNSCAT2 server, this will most certainly not work.
            warn!("non-FQDN is being used with a system DNS server");
        }
        server
    };

    // Build the DNS endpoint
    let dns_endpoint =
        BasicDnsEndpoint::new_with_defaults(opts.query.clone(), opts.constant.clone()).unwrap();

    // Build the DNS client
    let dns_client = DnsClient::connect(dns_server_addr, Arc::new(dns_endpoint))
        .await
        .unwrap();

    // Start building the client connection
    let mut conn = ClientBuilder::default()
        .command(opts.command)
        .min_delay(Duration::from_millis(opts.min_delay))
        .max_delay(Duration::from_millis(opts.max_delay))
        .random_delay(opts.random_delay)
        .retransmit_backoff(opts.retransmit_backoff)
        .random_delay(opts.random_delay)
        .prefer_server_name(opts.prefer_server_name)
        .recv_queue_size(opts.recv_queue_size)
        .packet_trace(opts.packet_trace);

    if let Some(session_id) = opts.session_id {
        conn = conn.session_id(session_id)
    }
    if let Some(ref session_name) = opts.session_name {
        conn = conn.session_name(session_name.clone())
    }
    if opts.retransmit_forever {
        conn = conn.max_retransmits(None);
    } else {
        conn = conn.max_retransmits(Some(opts.max_retransmits));
    }

    info!(
        "connecting to `{}` using `{}`",
        dns_server_addr, opts.constant
    );

    let result = if let Some(ref secret) = opts.secret {
        let preshared_key = Some(Vec::from(secret.clone()));
        let encryption = StandardEncryption::new_with_ephemeral(true, preshared_key).unwrap();
        match conn.connect(dns_client, encryption).await {
            Ok(client) => Ok(start_session(client, opts).await),
            Err(err) => Err(err),
        }
    } else {
        assert!(opts.insecure);
        match conn.connect_insecure(dns_client).await {
            Ok(client) => Ok(start_session(client, opts).await),
            Err(err) => Err(err),
        }
    };
    if let Err(err) = result {
        error!("failed to connect with {}", err)
    }
}

async fn start_session<T, E>(client: Client<T, E>, opts: &Opts)
where
    T: ExchangeTransport<LazyPacket> + Unpin,
    T::Future: Unpin,
    E: Encryption + Unpin,
{
    info!(
        "connected with session (id: {}, name: {})",
        client.session().id(),
        client.session().name().unwrap_or("<none>")
    );

    let (reader, writer) = io::split(client);

    if let Some(process) = opts.exec.get(0) {
        let result = process::Command::new(process)
            .args(&opts.exec[1..])
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
