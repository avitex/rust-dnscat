//#![warn(missing_docs)]

pub mod conn;
/// Packet support for establishing a connection in a transport.
pub mod packet;
pub mod transport;

mod util {
    mod encdec;
    mod sbytes;

    pub mod hex;
    pub mod parse;

    pub use self::encdec::{Decode, Encode};
    pub use self::sbytes::StringBytes;
}

mod private {
    pub trait Sealed {}
}
