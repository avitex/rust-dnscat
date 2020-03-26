#![doc(html_root_url = "https://docs.rs/dnscat/0.1.0")]
// #![deny(
//     warnings,
//     //missing_docs,
//     missing_debug_implementations,
//     intra_doc_link_resolution_failure,
//     rust_2018_idioms,
//     unreachable_pub
// )]

#[cfg(feature = "cli")]
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

    pub use digest::generic_array;
    pub use digest::generic_array::typenum;

    pub use constant_time_eq::constant_time_eq;
}
