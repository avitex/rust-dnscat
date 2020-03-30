[![Build Status](https://travis-ci.org/avitex/rust-dnscat.svg?branch=master)](https://travis-ci.org/avitex/rust-dnscat)
[![Crate](https://img.shields.io/crates/v/dnscat.svg)](https://crates.io/crates/dnscat)
[![Docs](https://docs.rs/dnscat/badge.svg)](https://docs.rs/dnscat)

# rust-dnscat

**Rust implementation of the DNSCAT2 protocol**  
Documentation hosted on [docs.rs](https://docs.rs/dnscat).

```toml
dnscat = "0.1"
```

## Client CLI Usage

First install the standalone dnscat client with:

```text
cargo install dnscat-client
```

```text
$ dnscat-client -h
dnscat-client 0.1
James Dyson <theavitex@gmail.com>
DNSCAT client

USAGE:
    dnscat-client [FLAGS] [OPTIONS] <domain>

ARGS:
    <domain>    DNS endpoint name

FLAGS:
        --command               If set, indicate to the server this is a command session
    -h, --help                  Prints help information
        --insecure              If set, will turn off encryption/authentication
        --packet-trace          If set, display incoming/outgoing DNSCAT2 packets
        --prefer-server-name    If set, prefer the server's session name
        --random-delay          If set, will select a random delay for each transmit between <min-delay> and <max-delay>
        --retransmit-backoff    If set, will exponentially backoff in delay from re-attempting a transmit
        --retransmit-forever    If set, will re-transmit forever until a server sends a valid response
    -V, --version               Prints version information

OPTIONS:
    -e, --exec <exec>...                       Execute a process and attach stdin/stdout
        --max-delay <max-delay>                Set the maximum delay in milliseconds between packets [default: 1000]
        --max-retransmits <max-retransmits>    Set the max re-transmits attempted before assuming the server is dead and
                                               aborting [default: 20]
        --min-delay <min-delay>                Set the minimum delay in milliseconds between packets [default: 0]
        --query <query>...                     Set the query types for DNS requests (comma-delimited) [default: TXT MX
                                               A]  [possible values: TXT, MX, CNAME, A, AAAA]
        --recv-queue-size <recv-queue-size>    Set the receive chunk buffer size [default: 16]
        --secret <secret>                      Set the shared secret used for encryption
        --server <server>                      Set the DNS server address, which by default is auto-detected
        --session-id <session-id>              Set the session ID manually
        --session-name <session-name>          Set the session name manually
```

Start the client with the DNSCAT2 stream attached to netcat:

```text
dnscat-client example.com. --server 127.0.0.1:53531 \
  --insecure --session-name my-session --exec nc -l 8081
```
