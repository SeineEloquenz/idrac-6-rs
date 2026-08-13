//! Tiny HTTPS/1.1 client over the legacy-TLS layer.
//!
//! iDRAC 6's web server uses the same obsolete TLS as the KVM channel, so `reqwest`/rustls
//! can't talk to it. This hand-rolls just enough HTTP to log in and fetch the jnlp: one
//! request per connection with `Connection: close`, read to EOF.

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::tls;

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
                let first = v.split(';').next()?;
                let (name, val) = first.split_once('=')?;
                Some((name.trim().to_string(), val.trim().to_string()))
            })
            .collect()
    }

    pub fn body_str(&self) -> std::borrow::Cow<'_, str> {
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
    let mut stream = tls::upgrade(tcp, host).await?;

    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");

    stream.write_all(req.as_bytes()).await.context("write request head")?;
    if let Some(b) = body {
        stream.write_all(b).await.context("write request body")?;
    }
    stream.flush().await.ok();

    let read = read_response(&mut stream);
    let (status, headers, body) = tokio::time::timeout(std::time::Duration::from_secs(12), read)
        .await
        .map_err(|_| anyhow::anyhow!("HTTP timeout for {method} {path}"))??;

    if !(200..400).contains(&status) {
        bail!("HTTP {status} for {method} {path}");
    }
    Ok(Response { status, headers, body })
}

/// Read a full HTTP/1.1 response, honoring Content-Length (falling back to read-to-EOF for
/// Connection: close). iDRAC keeps connections alive, so read-to-EOF alone would hang.
async fn read_response<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let sep = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        let n = stream.read(&mut tmp).await.context("read headers")?;
        if n == 0 {
            bail!("connection closed before headers");
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = std::str::from_utf8(&buf[..sep]).context("non-utf8 response head")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().context("empty response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .with_context(|| format!("bad status line: {status_line:?}"))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();

    let content_len = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok());

    let mut body = buf[sep + 4..].to_vec();
    match content_len {
        Some(len) => {
            while body.len() < len {
                let n = stream.read(&mut tmp).await.context("read body")?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&tmp[..n]);
            }
            body.truncate(len);
        }
        None => loop {
            let n = stream.read(&mut tmp).await.context("read body")?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        },
    }
    Ok((status, headers, body))
}
