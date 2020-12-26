#![doc(html_root_url = "https://docs.rs/dnscat/0.1.1")]
#![deny(
    warnings,
    // TODO: v0.1.2
    // missing_docs,
    missing_debug_implementations,
    broken_intra_doc_links,
    rust_2018_idioms,
    unreachable_pub
)]

#[cfg(feature = "client-cli")]
pub mod cli;
pub mod client;
pub mod encryption;
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
