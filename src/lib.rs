/// Packet support for establishing a connection in a transport.
pub mod packet;
pub mod transport;

mod util {
    mod bbuf_mut;

    pub mod hex;
    pub mod parse;

    pub use self::bbuf_mut::BoundedBufMut;
}

mod private {
    pub trait Sealed {}
}
