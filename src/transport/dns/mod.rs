mod ip;
mod name;
mod trust_impl;

pub use self::ip::*;
pub use self::name::*;
pub use self::trust_impl::*;

// #[derive(Debug, Clone, Copy, PartialEq)]
// pub enum DnsQueryMethod {
//     A,
//     AAAA,
//     CNAME,
//     TXT,
//     MX,
// }
