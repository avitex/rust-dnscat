/// Packet support for establishing a connection in a transport.
pub mod packet;
pub mod transport;

mod util {
    pub mod hex;
    pub mod parse;
}

mod private {
    pub trait Sealed {}
}
