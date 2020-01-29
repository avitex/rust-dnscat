pub mod encdec;
/// Packet support for establishing a connection in a transport.
pub mod packet;
pub mod transport;

mod util {
    mod string_bytes;

    pub mod hex;
    pub mod parse;

    pub use self::string_bytes::StringBytes;
}

mod private {
    pub trait Sealed {}
}
