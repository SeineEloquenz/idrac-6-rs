//! Legacy TLS for iDRAC 6. Its 1024-bit RSA cert and DH params fall below OpenSSL 3's default
//! SECLEVEL 1 (`dh key too small`), so this connector runs at security level 0 with a legacy
//! cipher list and verification disabled. Raising any of these breaks the handshake.

use std::pin::Pin;

use anyhow::{Context, Result};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Build an OpenSSL connector that tolerates iDRAC 6's obsolete TLS.
pub fn legacy_connector() -> Result<SslConnector> {
    let mut b = SslConnector::builder(SslMethod::tls()).context("SslConnector::builder")?;
    b.set_verify(SslVerifyMode::NONE);
    b.set_security_level(0);
    b.set_min_proto_version(Some(SslVersion::TLS1)).ok();
    b.set_cipher_list("ALL:COMPLEMENTOFDEFAULT:@SECLEVEL=0")
        .ok();
    Ok(b.build())
}

/// Wrap an established TCP stream in TLS using the permissive connector.
pub async fn upgrade(
    stream: TcpStream,
    domain: &str,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send> {
    let connector = legacy_connector()?;
    let ssl = connector
        .configure()
        .context("connector.configure")?
        .use_server_name_indication(false)
        .verify_hostname(false)
        .into_ssl(domain)
        .context("into_ssl")?;
    let mut tls = tokio_openssl::SslStream::new(ssl, stream).context("SslStream::new")?;
    Pin::new(&mut tls)
        .connect()
        .await
        .context("TLS handshake")?;
    Ok(tls)
}
