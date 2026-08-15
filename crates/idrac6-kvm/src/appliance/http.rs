//! Tiny HTTPS/1.1 client over the legacy-TLS layer (iDRAC 6 web UI).
//!
//! iDRAC 6 serves TLS 1.2 but with a 1024-bit RSA cert and 1024-bit DH parameters that OpenSSL
//! 3's default SECLEVEL 1 rejects (`dh key too small`); `reqwest`/`native-tls` don't expose the
//! security level, so they can't connect. We drive `hyper` over our own SECLEVEL-0 `tls::upgrade`
//! stream instead, one request per connection.

use std::borrow::Cow;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{CONNECTION, HOST};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use super::tls;

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// All `Set-Cookie` name=value pairs (attributes stripped).
    pub fn cookies(&self) -> Vec<(String, String)> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .filter_map(|(_, v)| {
                let (name, val) = v.split(';').next()?.split_once('=')?;
                Some((name.trim().to_string(), val.trim().to_string()))
            })
            .collect()
    }

    pub fn body_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }
}

/// Perform one HTTPS request over legacy TLS and return the parsed response.
pub async fn request(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<Response> {
    let tcp = TcpStream::connect((host, port)).await.context("tcp connect")?;
    let tls = tls::upgrade(tcp, host).await?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.context("http1 handshake")?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = hyper::Request::builder().method(method).uri(path).header(HOST, host).header(CONNECTION, "close");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder
        .body(Full::new(body.map(Bytes::copy_from_slice).unwrap_or_default()))
        .context("build request")?;

    let exchange = async {
        let resp = sender.send_request(req).await.context("send request")?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
            .collect();
        let body = resp.into_body().collect().await.context("read body")?.to_bytes().to_vec();
        Ok::<_, anyhow::Error>((status, headers, body))
    };
    let (status, headers, body) = tokio::time::timeout(Duration::from_secs(12), exchange)
        .await
        .map_err(|_| anyhow::anyhow!("HTTP timeout for {method} {path}"))??;

    if !(200..400).contains(&status) {
        bail!("HTTP {status} for {method} {path}");
    }
    Ok(Response { status, headers, body })
}
