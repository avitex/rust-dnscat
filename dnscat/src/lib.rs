#![doc(html_root_url = "https://docs.rs/dnscat/0.1.0")]
#![deny(
    warnings,
    // TODO: v0.1.1
    // missing_docs,
    missing_debug_implementations,
    intra_doc_link_resolution_failure,
    rust_2018_idioms,
    unreachable_pub
)]

#[cfg(feature = "client-cli")]
pub mod cli;
pub mod client;
pub mod encryption;
/// Packet support for establishing a connection in a transport.
pub mod packet;
pub mod session;
pub mod transport;

#[allow(unreachable_pub)]
mod util {
    mod encdec;
    mod sbytes;

    pub mod hex;
    pub mod parse;

    pub use self::encdec::{Decode, Encode};
    pub use self::sbytes::StringBytes;
}
