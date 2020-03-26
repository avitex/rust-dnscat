use std::borrow::Borrow;
use std::mem;

use bytes::BufMut;

use ring::agreement::{self, agree_ephemeral};
use ring::rand;
use salsa20::{stream_cipher::*, Salsa20};
use secstr::SecStr;
use sha3::{Digest, Sha3_256};

use super::{Authenticator, Encryption, EncryptionError, PublicKey};

use crate::packet::SessionHeader;
use crate::util::generic_array::GenericArray;
use crate::util::typenum::U32;
use crate::util::{constant_time_eq, Encode};

// signature + nonce
const STANDARD_ARGS_SIZE: usize = 6 + 2;

type EncryptionKey = GenericArray<u8, <Salsa20 as NewStreamCipher>::KeySize>;
type EncryptionNonce = GenericArray<u8, <Salsa20 as NewStreamCipher>::NonceSize>;
type EncryptionMac = GenericArray<u8, U32>;

#[derive(Debug)]
pub struct StandardEncryption {
    is_client: bool,
    nonce: u16,
    preshared_key: Option<SecStr>,
    self_pub_key: agreement::PublicKey,
    self_authenticator: Option<Authenticator>,
    peer_authenticator: Option<Authenticator>,
    self_priv_key: Option<agreement::EphemeralPrivateKey>,
    peer_pub_key: Option<agreement::UnparsedPublicKey<PublicKey>>,
    stream_keys: Option<StreamKeys>,
}

impl StandardEncryption {
    pub fn new_with_ephemeral(
        is_client: bool,
        preshared_key: Option<Vec<u8>>,
    ) -> Result<Self, EncryptionError> {
        let rand = rand::SystemRandom::new();
        let preshared_key = preshared_key.map(Into::into);
        let (self_pub_key, self_priv_key) =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rand)
                .and_then(|priv_key| {
                    priv_key
                        .compute_public_key()
                        .map(|pub_key| (pub_key, priv_key))
                })
                .or(Err(EncryptionError::Keygen))?;

        Ok(Self {
            nonce: 1,
            is_client,
            preshared_key,
            self_pub_key,
            peer_pub_key: None,
            self_authenticator: None,
            peer_authenticator: None,
            self_priv_key: Some(self_priv_key),
            stream_keys: None,
        })
    }

    fn next_nouce(&mut self) -> Result<u16, EncryptionError> {
        if self.nonce == u16::max_value() {
            Err(EncryptionError::Renegotiate)
        } else {
            self.nonce += 1;
            Ok(self.nonce)
        }
    }
}

impl Encryption for StandardEncryption {
    fn args_size(&self) -> u8 {
        STANDARD_ARGS_SIZE as u8
    }

    fn public_key(&self) -> PublicKey {
        GenericArray::clone_from_slice(&self.self_pub_key.as_ref()[1..])
    }

    fn handshake(&mut self, peer: PublicKey) -> Result<(), EncryptionError> {
        let peer_pub_key = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer);
        let shared_key = agree_ephemeral(
            self.self_priv_key.take().expect("no private key"),
            &peer_pub_key,
            EncryptionError::Handshake,
            |key| Ok(Sha3_256::digest(key)),
        )?;
        self.self_authenticator = Some(calc_authenticator(
            self.is_client,
            self.self_pub_key.as_ref(),
            peer_pub_key.bytes(),
            &shared_key[..],
            self.preshared_key.as_ref().map(Borrow::borrow),
        ));
        self.peer_authenticator = Some(calc_authenticator(
            !self.is_client,
            self.self_pub_key.as_ref(),
            peer_pub_key.bytes(),
            &shared_key[..],
            self.preshared_key.as_ref().map(Borrow::borrow),
        ));
        self.peer_pub_key = Some(peer_pub_key);
        self.stream_keys = Some(StreamKeys::from_shared(&shared_key[..]));
        Ok(())
    }

    fn authenticator(&mut self) -> Result<Authenticator, EncryptionError> {
        Ok(self.self_authenticator.unwrap())
    }

    fn authenticate(&mut self, peer: Authenticator) -> Result<(), EncryptionError> {
        let valid = self.peer_authenticator.unwrap();
        if constant_time_eq(&valid[..], &peer[..]) {
            Ok(())
        } else {
            Err(EncryptionError::Authentication)
        }
    }

    fn encrypt(
        &mut self,
        head: &SessionHeader,
        mut args: &mut [u8],
        data: &mut [u8],
    ) -> Result<(), EncryptionError> {
        let (cipher_key, mac_key) = self
            .stream_keys
            .as_ref()
            .expect("keys not set")
            .get_write_keys(self.is_client);
        let nonce = self.next_nouce()?.to_be_bytes();
        let mut cipher = Salsa20::new(&cipher_key, &calc_nonce(nonce));

        cipher.encrypt(data);

        let sig = calc_signature(head, &nonce[..], &mac_key[..], data);

        args.put_slice(&nonce[..]);
        args.put_slice(&sig[..]);

        Ok(())
    }

    fn decrypt(
        &mut self,
        _head: &SessionHeader,
        args: &[u8],
        data: &mut [u8],
    ) -> Result<(), EncryptionError> {
        let (cipher_key, _mac_key) = self
            .stream_keys
            .as_ref()
            .expect("keys not set")
            .get_read_keys(self.is_client);

        let nonce = [args[0], args[1]];
        //let sig = [args[2], args[3], args[4], args[5], args[6], args[7]];
        let mut cipher = Salsa20::new(&cipher_key, &calc_nonce(nonce));

        cipher.decrypt(data);

        // TODO: verify sig.

        Ok(())
    }
}

#[derive(Debug)]
struct StreamKeys {
    client_mac: EncryptionMac,
    server_mac: EncryptionMac,
    client_write: EncryptionKey,
    server_write: EncryptionKey,
}

impl StreamKeys {
    fn get_write_keys(&self, is_client: bool) -> (EncryptionKey, EncryptionMac) {
        if is_client {
            (self.client_write, self.client_mac)
        } else {
            (self.server_write, self.server_mac)
        }
    }

    fn get_read_keys(&self, is_client: bool) -> (EncryptionKey, EncryptionMac) {
        self.get_write_keys(!is_client)
    }

    fn from_shared(key: &[u8]) -> Self {
        let mut hash = Sha3_256::new();

        // client_write
        hash.input(key);
        hash.input("client_write_key");
        let client_write = hash.result_reset();

        // client_mac
        hash.input(key);
        hash.input("client_write_key");
        let client_mac = hash.result_reset();

        // server_write
        hash.input(key);
        hash.input("server_write_key");
        let server_write = hash.result_reset();

        // server_mac
        hash.input(key);
        hash.input("server_mac_key");
        let server_mac = hash.result();

        Self {
            client_write,
            server_write,
            client_mac,
            server_mac,
        }
    }
}

fn calc_nonce(nonce: [u8; 2]) -> EncryptionNonce {
    let mut nonce_array = [0u8; 8];
    nonce_array[0] = nonce[0];
    nonce_array[0] = nonce[1];
    nonce_array.into()
}

fn calc_authenticator(
    for_client: bool,
    pubkey_client: &[u8],
    pubkey_server: &[u8],
    shared_key: &[u8],
    preshared_key: Option<&[u8]>,
) -> Authenticator {
    let mut hash = Sha3_256::new();
    if for_client {
        hash.input("client");
    } else {
        hash.input("server");
    }
    hash.input(shared_key);
    hash.input(pubkey_client);
    hash.input(pubkey_server);
    if let Some(preshared_key) = preshared_key {
        hash.input(preshared_key);
    }
    hash.result()
}

fn calc_signature(
    head: &SessionHeader,
    nonce: &[u8],
    mac_key: &[u8],
    ciphertext: &mut [u8],
) -> [u8; 6] {
    let mut head_bytes = [0u8; mem::size_of::<SessionHeader>()];
    head.encode(&mut &mut head_bytes[..]);

    let mut hash = Sha3_256::new();

    hash.input(mac_key);
    hash.input(&head_bytes[..]);
    hash.input(nonce);
    hash.input(ciphertext);

    let res = hash.result();

    [res[0], res[1], res[2], res[3], res[4], res[5]]
}
