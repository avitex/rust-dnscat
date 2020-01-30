pub mod conn;
/// Packet support for establishing a connection in a transport.
pub mod packet;
pub mod transport;

mod util {
    mod sbytes;
    mod encdec;

    pub mod hex;
    pub mod parse;    

    pub use self::sbytes::StringBytes;
    pub use self::encdec::{Encode, Decode};
}

mod private {
    pub trait Sealed {}
}
