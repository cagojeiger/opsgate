use crate::{Error, Result};

use super::Cipher;

#[derive(Clone)]
pub struct Sealer {
    cipher: Cipher,
}

impl Sealer {
    pub fn new(cipher: Cipher) -> Self {
        Self { cipher }
    }

    pub fn seal(&self, domain: &str, name: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let aad = build_aad(domain, name)?;
        self.cipher.seal_with_aad(plaintext, &aad)
    }

    pub fn open(&self, domain: &str, name: &str, blob: &[u8]) -> Result<Vec<u8>> {
        let aad = build_aad(domain, name)?;
        self.cipher.open_with_aad(blob, &aad)
    }
}

fn build_aad(domain: &str, name: &str) -> Result<Vec<u8>> {
    if domain.is_empty() {
        return Err(Error::validation("sealer: domain must not be empty"));
    }
    if name.is_empty() {
        return Err(Error::validation("sealer: name must not be empty"));
    }
    let domain_len = u32::try_from(domain.len())
        .map_err(|_error| Error::validation("sealer: domain is too long"))?;
    let name_len = u32::try_from(name.len())
        .map_err(|_error| Error::validation("sealer: name is too long"))?;
    let mut aad = Vec::with_capacity(8 + domain.len() + name.len());
    aad.extend_from_slice(&domain_len.to_be_bytes());
    aad.extend_from_slice(domain.as_bytes());
    aad.extend_from_slice(&name_len.to_be_bytes());
    aad.extend_from_slice(name.as_bytes());
    Ok(aad)
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;

    fn sealer() -> Result<Sealer> {
        let key = base64::engine::general_purpose::STANDARD.encode([9_u8; 32]);
        Ok(Sealer::new(Cipher::new(&key)?))
    }

    #[test]
    fn roundtrip() -> Result<()> {
        let sealer = sealer()?;
        let blob = sealer.seal("credentials", "prod", b"token")?;
        let got = sealer.open("credentials", "prod", &blob)?;
        assert_eq!(got, b"token");
        Ok(())
    }

    #[test]
    fn rejects_cross_domain_and_name() -> Result<()> {
        let sealer = sealer()?;
        let blob = sealer.seal("credentials", "prod", b"token")?;
        assert!(sealer.open("argocd", "prod", &blob).is_err());
        assert!(sealer.open("credentials", "stage", &blob).is_err());
        Ok(())
    }

    #[test]
    fn length_prefix_prevents_colon_collision() -> Result<()> {
        let sealer = sealer()?;
        let blob = sealer.seal("credentials", "a:b", b"token")?;
        assert!(sealer.open("credentials:a", "b", &blob).is_err());
        Ok(())
    }

    #[test]
    fn aad_free_ciphertext_does_not_open() -> Result<()> {
        let key = base64::engine::general_purpose::STANDARD.encode([3_u8; 32]);
        let cipher = Cipher::new(&key)?;
        let blob = cipher.encrypt(b"token")?;
        let sealer = Sealer::new(cipher);
        assert!(sealer.open("credentials", "prod", &blob).is_err());
        Ok(())
    }
}
