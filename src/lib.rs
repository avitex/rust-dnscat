mod hex;

pub mod message;
pub mod payload;

pub struct Message {}

// const MAX_DOMAIN_NAME_LEN: usize = 253;
// pub type DOMAIN_NAME_BYTE_ARRAY = [u8; MAX_DOMAIN_NAME_LEN];

mod private {
    pub trait Sealed {}
}
