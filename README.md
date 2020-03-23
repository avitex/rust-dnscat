[![Build Status](https://travis-ci.org/avitex/rust-dnscat.svg?branch=master)](https://travis-ci.org/avitex/rust-dnscat)
[![Crate](https://img.shields.io/crates/v/dnscat.svg)](https://crates.io/crates/dnscat)
[![Docs](https://docs.rs/dnscat/badge.svg)](https://docs.rs/dnscat)

# rust-dnscat

**Rust implementation of the DNSCAT2 protocol**  
Documentation hosted on [docs.rs](https://docs.rs/dnscat).

```toml
dnscat = "0.1.0"
```

## CLI Usage

First install dnscat with:

```text
cargo install dnscat
```

Start the client with the DNSCAT2 stream attached to netcat:

```text
dnscat client example.com. --server 127.0.0.1:53531 \
  --insecure --session-name my-session --exec nc -l 8081
```
