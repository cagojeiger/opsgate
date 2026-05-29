use aes_gcm::aead::{Aead, OsRng, rand_core::RngCore};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use zeroize::Zeroize;

use crate::{Error, Result};

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;

#[derive(Clone)]
pub struct Cipher {
    cipher: Aes256Gcm,
}

impl Cipher {
    pub fn new(base64_key: &str) -> Result<Self> {
        if base64_key.is_empty() {
            return Err(Error::validation(
                "master key is empty (set OPSGATE_MASTER_KEY)",
            ));
        }
        let mut key = base64::engine::general_purpose::STANDARD
            .decode(base64_key)
            .map_err(|error| Error::validation(format!("master key base64 decode: {error}")))?;
        if key.len() != KEY_BYTES {
            key.zeroize();
            return Err(Error::validation(format!(
                "master key: want {KEY_BYTES} bytes"
            )));
        }
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|error| Error::internal(format!("aes-gcm init failed: {error}")))?;
        key.zeroize();
        Ok(Self { cipher })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.seal_with_aad(plaintext, &[])
    }

    pub fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>> {
        self.open_with_aad(blob, &[])
    }

    pub fn seal_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|error| Error::internal(format!("gcm seal failed: {error}")))?;
        let mut out = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn open_with_aad(&self, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = blob
            .get(..NONCE_BYTES)
            .ok_or_else(|| Error::validation("ciphertext too short"))?;
        let ciphertext = blob
            .get(NONCE_BYTES..)
            .ok_or_else(|| Error::validation("ciphertext too short"))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|error| Error::validation(format!("gcm open failed: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;

    fn dev_key() -> String {
        base64::engine::general_purpose::STANDARD.encode([7_u8; KEY_BYTES])
    }

    #[test]
    fn rejects_empty_and_wrong_length_keys() {
        assert!(Cipher::new("").is_err());
        let short = base64::engine::general_purpose::STANDARD.encode([1_u8; 16]);
        assert!(Cipher::new(&short).is_err());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() -> Result<()> {
        let cipher = Cipher::new(&dev_key())?;
        let plaintext = br#"{"token":"fake"}"#;
        let ciphertext = cipher.encrypt(plaintext)?;
        assert_ne!(ciphertext, plaintext);
        let got = cipher.decrypt(&ciphertext)?;
        assert_eq!(got, plaintext);
        Ok(())
    }

    #[test]
    fn fresh_nonce_changes_ciphertext() -> Result<()> {
        let cipher = Cipher::new(&dev_key())?;
        let a = cipher.encrypt(b"same")?;
        let b = cipher.encrypt(b"same")?;
        assert_ne!(a, b);
        Ok(())
    }

    #[test]
    fn tamper_fails() -> Result<()> {
        let cipher = Cipher::new(&dev_key())?;
        let mut ciphertext = cipher.encrypt(b"hello")?;
        if let Some(last) = ciphertext.last_mut() {
            *last ^= 1;
        }
        assert!(cipher.decrypt(&ciphertext).is_err());
        Ok(())
    }
}
