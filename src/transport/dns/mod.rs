mod ip;
mod name;
mod client;

pub use self::ip::*;
pub use self::name::*;
pub use self::client::*;

use trust_dns_proto::error::ProtoError;

pub(crate) const SOCKET_PORT: u16 = 53;

pub enum DnsTransportError {
    Proto(ProtoError),
}

// #[derive(Debug, Clone, Copy, PartialEq)]
// pub enum DnsQueryMethod {
//     A,
//     AAAA,
//     CNAME,
//     TXT,
//     MX,
// }
