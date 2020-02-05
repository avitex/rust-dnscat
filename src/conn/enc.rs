use bytes::{Buf, Bytes};

pub trait ConnectionEncryption {
    fn encrypt<B: Buf>(&mut self, payload: &mut B) -> Bytes {
        payload.to_bytes()
    }

    fn decrypt<B: Buf>(&mut self, payload: &mut B) -> Bytes {
        payload.to_bytes()
    }
}

impl ConnectionEncryption for () {}
