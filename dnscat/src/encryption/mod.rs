mod standard;

use failure::Fail;

use crate::packet::SessionHeader;
use crate::util::generic_array::GenericArray;
use crate::util::typenum::{U32, U64};

pub use self::standard::*;

pub type PublicKey = GenericArray<u8, U64>;
pub type Authenticator = GenericArray<u8, U32>;

#[derive(Debug, Fail)]
pub enum EncryptionError {
    #[fail(display = "Encryption needs to be renegotiated")]
    Renegotiate,
    #[fail(display = "Failed to agree on a shared secret")]
    Handshake,
    #[fail(display = "Authentication failed")]
    Authentication,
    #[fail(display = "Keypair generation failed")]
    Keygen,
    #[fail(display = "Invalid signature")]
    Signature,
    #[fail(display = "{}", _0)]
    Custom(&'static str),
}

pub trait Encryption {
    fn args_size(&self) -> u8;

    fn public_key(&self) -> PublicKey;

    fn authenticator(&self) -> Authenticator;

    fn handshake(&mut self, peer: PublicKey) -> Result<(), EncryptionError>;

    fn authenticate(&mut self, peer: Authenticator) -> Result<(), EncryptionError>;

    fn encrypt(
        &mut self,
        head: &SessionHeader,
        args: &mut [u8],
        data: &mut [u8],
    ) -> Result<(), EncryptionError>;

    fn decrypt(
        &mut self,
        head: &SessionHeader,
        args: &[u8],
        data: &mut [u8],
    ) -> Result<(), EncryptionError>;
}

#[derive(Debug)]
pub enum NoEncryption {}

impl Encryption for NoEncryption {
    fn args_size(&self) -> u8 {
        unreachable!()
    }

    fn public_key(&self) -> PublicKey {
        unreachable!()
    }

    fn authenticator(&self) -> Authenticator {
        unreachable!()
    }

    fn handshake(&mut self, _peer: PublicKey) -> Result<(), EncryptionError> {
        unreachable!()
    }

    fn authenticate(&mut self, _peer: Authenticator) -> Result<(), EncryptionError> {
        unreachable!()
    }

    fn encrypt(
        &mut self,
        _head: &SessionHeader,
        _args: &mut [u8],
        _data: &mut [u8],
    ) -> Result<(), EncryptionError> {
        unreachable!()
    }

    fn decrypt(
        &mut self,
        _head: &SessionHeader,
        _args: &[u8],
        _data: &mut [u8],
    ) -> Result<(), EncryptionError> {
        unreachable!()
    }
}
