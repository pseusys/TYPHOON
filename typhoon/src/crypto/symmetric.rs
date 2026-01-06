use chacha20poly1305::aead::AeadMutInPlace;
use chacha20poly1305::{AeadCore, Key, KeyInit, XChaCha20Poly1305, XNonce};

use simple_error::bail;

use crate::bytes::ByteBuffer;
use crate::random::get_rng;
use crate::generic::DynResult;

// TODO: move it!
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const MAC_LEN: usize = 16;

#[derive(Clone)]
#[cfg(feature = "software")]
pub struct Symmetric {
    cipher: XChaCha20Poly1305,
}

#[cfg(feature = "software")]
impl Symmetric {
    pub fn new(key: &ByteBuffer) -> DynResult<Self> {
        let private_bytes = <[u8; KEY_LEN]>::try_from(&key.slice()[..])?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&private_bytes));
        Ok(Self { cipher })
    }

    pub fn encrypt<'a>(&mut self, plaintext: ByteBuffer<'a>, additional_data: Option<&ByteBuffer>) -> DynResult<ByteBuffer<'a>> {
        let mut plaintext_buffer = plaintext.ensure_size(plaintext.len() + MAC_LEN);
        let nonce = XChaCha20Poly1305::generate_nonce(get_rng());
        let result = match additional_data {
            Some(res) => self.cipher.encrypt_in_place(&nonce, &res.slice(), &mut plaintext_buffer),
            None => self.cipher.encrypt_in_place(&nonce, &[], &mut plaintext_buffer),
        };
        match result {
            Ok(_) => Ok(plaintext_buffer.prepend(&nonce)),
            Err(err) => bail!("Error encrypting plaintext: {err}"),
        }
    }

    pub fn decrypt<'a>(&mut self, ciphertext_with_nonce: ByteBuffer<'a>, additional_data: Option<&ByteBuffer>) -> DynResult<ByteBuffer<'a>> {
        let (nonce_bytes, mut ciphertext) = ciphertext_with_nonce.split_buf(NONCE_LEN);
        let nonce = XNonce::clone_from_slice(&nonce_bytes.slice());
        let result = match additional_data {
            Some(res) => self.cipher.decrypt_in_place(&nonce, &res.slice(), &mut ciphertext),
            None => self.cipher.decrypt_in_place(&nonce, &[], &mut ciphertext),
        };
        match result {
            Ok(_) => Ok(ciphertext),
            Err(err) => bail!("Error encrypting plaintext: {err}"),
        }
    }
}
