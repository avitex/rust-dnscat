#[cfg(feature = "encryption")]
mod standard;

use failure::Fail;
use generic_array::typenum::{U32, U64};
use generic_array::GenericArray;

use crate::packet::SessionHeader;

#[cfg(feature = "encryption")]
pub use self::standard::{StandardEncryption, StandardEncryptionAcceptor};

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

pub trait EncryptionAcceptor {
    type Encryption: Encryption;

    fn accept(&mut self, client: PublicKey) -> Result<Self::Encryption, EncryptionError>;
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

impl EncryptionAcceptor for NoEncryption {
    type Encryption = NoEncryption;

    fn accept(&mut self, _client: PublicKey) -> Result<Self::Encryption, EncryptionError> {
        unimplemented!()
    }
}
