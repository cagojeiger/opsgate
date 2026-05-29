use std::io::Cursor;

use crate::{Error, Result};

pub fn parse_certificate_pem_bundle(pem: &str) -> Result<Vec<Vec<u8>>> {
    let mut reader = Cursor::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .map(|cert| {
            cert.map(|cert| cert.as_ref().to_vec())
                .map_err(|error| Error::validation(format!("invalid TLS server CA PEM: {error}")))
        })
        .collect::<Result<Vec<_>>>()?;
    if certs.is_empty() {
        return Err(Error::validation(
            "TLS server CA PEM contains no certificates",
        ));
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::parse_certificate_pem_bundle;

    #[test]
    fn rejects_bad_pem() {
        assert!(parse_certificate_pem_bundle("not a certificate").is_err());
    }
}
