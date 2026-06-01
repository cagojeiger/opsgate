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

pub fn parse_client_certificate_pem(pem: &str) -> Result<()> {
    let mut reader = Cursor::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .map(|cert| {
            cert.map_err(|error| {
                Error::validation(format!("invalid client certificate PEM: {error}"))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if certs.is_empty() {
        return Err(Error::validation(
            "client certificate PEM contains no certificates",
        ));
    }
    Ok(())
}

pub fn parse_client_private_key_pem(pem: &str) -> Result<()> {
    let mut reader = Cursor::new(pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|error| Error::validation(format!("invalid client private key PEM: {error}")))?;
    if key.is_none() {
        return Err(Error::validation(
            "client private key PEM contains no private key",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        parse_certificate_pem_bundle, parse_client_certificate_pem, parse_client_private_key_pem,
    };

    #[test]
    fn rejects_bad_pem() {
        assert!(parse_certificate_pem_bundle("not a certificate").is_err());
    }

    #[test]
    fn rejects_client_cert_without_certificate() {
        assert!(parse_client_certificate_pem("not a certificate").is_err());
    }

    #[test]
    fn rejects_client_key_without_private_key() {
        assert!(parse_client_private_key_pem("not a private key").is_err());
    }
}
