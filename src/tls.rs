//! Legacy TLS for iDRAC 6.
//!
//! iDRAC 6 negotiates TLS 1.0 (sometimes SSLv3) with weak ciphers and a small,
//! SHA1-signed self-signed certificate. Modern stacks (rustls, default OpenSSL 3)
//! reject all of that, so we build an intentionally permissive OpenSSL connector:
//! security level 0, TLS 1.0 floor, verification disabled.

use std::pin::Pin;

use anyhow::{Context, Result};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Build an OpenSSL connector that tolerates iDRAC 6's obsolete TLS.
pub fn legacy_connector() -> Result<SslConnector> {
    let mut b = SslConnector::builder(SslMethod::tls()).context("SslConnector::builder")?;
    b.set_verify(SslVerifyMode::NONE);
    // SECLEVEL 0 re-enables SHA1 certs, small RSA keys, and legacy ciphers.
    b.set_security_level(0);
    b.set_min_proto_version(Some(SslVersion::TLS1)).ok();
    // Accept the broad legacy cipher set the appliance offers.
    b.set_cipher_list("ALL:COMPLEMENTOFDEFAULT:@SECLEVEL=0").ok();
    Ok(b.build())
}

/// Wrap an established TCP stream in TLS using the permissive connector.
pub async fn upgrade(stream: TcpStream, domain: &str) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send> {
    let connector = legacy_connector()?;
    let ssl = connector
        .configure()
        .context("connector.configure")?
        .use_server_name_indication(false)
        .verify_hostname(false)
        .into_ssl(domain)
        .context("into_ssl")?;
    let mut tls = tokio_openssl::SslStream::new(ssl, stream).context("SslStream::new")?;
    Pin::new(&mut tls).connect().await.context("TLS handshake")?;
    Ok(tls)
}
