//! iDRAC 6 KVM authentication. KVM does not accept the account password, only a rotating one-time
//! token the iDRAC mints per Virtual Console launch, which [`login_and_get_token`] reproduces
//! (web login, then fetch a fresh `viewer.jnlp`).

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{info, warn};

use crate::{apcp, http};

/// Credentials + endpoint for a KVM session, plus the web-session handle (if minted via
/// web login) so it can be released with [`web_logout`].
#[derive(Debug, Clone)]
pub struct Session {
    pub host: String,
    pub user: String,
    pub password: String,
    pub video_port: u16,
    pub kvm_port: u16,
    pub web_cookies: Vec<(String, String)>,
    pub web_st1: Option<String>,
}

/// Parse a `viewer.jnlp` into a session. Its `passwd` is the rotating one-time KVM token, not
/// the account password.
pub fn parse_jnlp(xml: &str) -> Result<Session> {
    let mut args: HashMap<&str, &str> = HashMap::new();
    for chunk in xml.split("<argument>").skip(1) {
        let Some(end) = chunk.find("</argument>") else {
            continue;
        };
        let kv = &chunk[..end];
        if let Some(eq) = kv.find('=') {
            args.insert(kv[..eq].trim(), kv[eq + 1..].trim());
        }
    }
    let get = |k: &str| args.get(k).map(|s| s.to_string());
    Ok(Session {
        host: get("ip").context("jnlp missing `ip` argument")?,
        user: get("user").context("jnlp missing `user` argument")?,
        password: get("passwd").context("jnlp missing `passwd` argument")?,
        video_port: get("vport").and_then(|s| s.parse().ok()).unwrap_or(5900),
        kvm_port: get("kmport").and_then(|s| s.parse().ok()).unwrap_or(5900),
        web_cookies: Vec::new(),
        web_st1: None,
    })
}

/// Extract the text of a simple, non-nested XML element.
fn xml_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    Some(xml[start..end].trim())
}

/// A login failure the caller can act on. The web UI maps each variant to an HTTP status.
/// Anything that is not a distinct iDRAC verdict (network, jnlp, parsing) stays an opaque `Other`.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("maximum iDRAC sessions reached; wait for old sessions to time out or clear them, then retry")]
    MaxSessions,
    #[error("this account lacks the 'Login to iDRAC' privilege")]
    NoPrivilege,
    #[error("wrong username or password")]
    BadCredentials,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Log into the iDRAC web UI, returning the session cookies and the `ST1` token from the forward URL.
pub(crate) async fn web_login(
    host: &str,
    user: &str,
    password: &str,
) -> Result<(Vec<(String, String)>, Option<String>), AuthError> {
    let body = format!("user={user}&password={password}");
    let resp = http::request(
        host,
        443,
        "POST",
        "/data/login",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        Some(body.as_bytes()),
    )
    .await
    .context("POST /data/login")?;

    let text = resp.body_str();
    match xml_tag(&text, "authResult") {
        Some("0") => {}
        Some("5") => return Err(AuthError::MaxSessions),
        Some("3") => return Err(AuthError::NoPrivilege),
        _ => return Err(AuthError::BadCredentials),
    }
    let st1 = xml_tag(&text, "forwardUrl")
        .and_then(|u| u.split("ST1=").nth(1))
        .map(|s| s.split(['&', '"', '\'']).next().unwrap_or(s).to_string());
    let cookies = resp.cookies();
    if cookies.is_empty() {
        warn!("web login returned no Set-Cookie; relying on ST1 token only");
    }
    Ok((cookies, st1))
}

/// Fetch a freshly minted `viewer.jnlp` for an authenticated session. The iDRAC 6 URL packs its
/// args `@`-joined inside literal parens, `/viewer.jnlp(<host>@0@<title>@<epoch_ms>@ST1=<token>)`,
/// with the title form-encoded and the ST1 token authorizing the request (the cookie alone yields
/// 401).
pub async fn fetch_jnlp(
    host: &str,
    user: &str,
    cookies: &[(String, String)],
    st1: Option<&str>,
) -> Result<String> {
    let st1 = st1.context("no ST1 token from login; cannot authorize viewer.jnlp")?;
    let cookie_hdr = cookie_header(cookies);
    let epoch_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let raw_title = format!("[{host}], Virtual Console, User:{user}");
    let title: String = form_urlencoded::byte_serialize(raw_title.as_bytes()).collect();
    let path = format!("/viewer.jnlp({host}@0@{title}@{epoch_ms}@ST1={st1})");

    info!(url = %path, "fetching viewer.jnlp");
    let r = http::request(host, 443, "GET", &path, &[("Cookie", &cookie_hdr)], None)
        .await
        .context("GET viewer.jnlp")?;
    let body = r.body_str();
    if !(body.contains("passwd=") || body.contains("<jnlp")) {
        bail!(
            "viewer.jnlp fetch returned HTTP {} but no jnlp body ({} bytes)",
            r.status,
            r.body.len()
        );
    }
    Ok(body.into_owned())
}

/// Web login with the account credentials, then mint and parse the jnlp token. The returned
/// session carries the web cookies and ST1 so the caller can [`web_logout`].
pub async fn login_and_get_token(
    host: &str,
    user: &str,
    password: &str,
) -> Result<Session, AuthError> {
    let (cookies, st1) = web_login(host, user, password).await?;
    info!(cookies = cookies.len(), st1 = st1.is_some(), "web login ok");
    let jnlp = fetch_jnlp(host, user, &cookies, st1.as_deref()).await?;
    let mut s = parse_jnlp(&jnlp)?;
    s.web_cookies = cookies;
    s.web_st1 = st1;
    Ok(s)
}

/// Release the iDRAC web session so it does not count against the session limit. Best-effort.
pub async fn web_logout(host: &str, cookies: &[(String, String)], st1: Option<&str>) -> Result<()> {
    if cookies.is_empty() {
        return Ok(());
    }
    let cookie_hdr = cookie_header(cookies);
    let path = match st1 {
        Some(st1) => format!("/data/logout?ST1={st1}"),
        None => "/data/logout".to_string(),
    };
    http::request(host, 443, "GET", &path, &[("Cookie", &cookie_hdr)], None).await?;
    Ok(())
}

/// Login body layout for the extended (type 258) request. userLen(1) + user(96) + passLen(1) +
/// pass(96) + session(8, zero) + o(1) + p(1) + r(4 BE), then q(1) when extended.
fn build_login_body(user: &str, password: &str, o: u8, p: u8, r: u32, q: Option<u8>) -> Vec<u8> {
    let mut b = Vec::with_capacity(209);
    push_len_field(&mut b, user.as_bytes(), 96);
    push_len_field(&mut b, password.as_bytes(), 96);
    b.extend_from_slice(&[0u8; 8]); // session id, unset on the connect path
    b.push(o);
    b.push(p);
    b.extend_from_slice(&r.to_be_bytes());
    if let Some(q) = q {
        b.push(q);
    }
    b
}

/// One length-prefixed, zero-padded fixed-width field (length byte counts the real bytes).
fn push_len_field(out: &mut Vec<u8>, src: &[u8], width: usize) {
    let n = src.len().min(width);
    out.push(n as u8);
    out.extend_from_slice(&src[..n]);
    out.extend(std::iter::repeat_n(0u8, width - n));
}

/// Send the Login Request, returning the random session id it carried. The caller must keep it to
/// link the media channel. `extended` (protocol >= 2) adds a trailing byte and uses packet type 258.
pub async fn send_login<S: AsyncWrite + Unpin>(
    s: &mut S,
    user: &str,
    password: &str,
    extended: bool,
) -> Result<u32> {
    let r: u32 = (openssl_rand_u32() % 10_000_000).max(1);
    let body = build_login_body(user, password, 0, 0, r, extended.then_some(0));
    let kind = if extended {
        apcp::PacketType::LoginExt
    } else {
        apcp::PacketType::Login
    };
    apcp::write_packet(s, kind, &body).await?;
    Ok(r)
}

/// Read the control channel until the appliance's login response arrives. Times out after 10s. A
/// non-zero status byte is a rejection.
pub async fn await_login_ok<R: AsyncRead + Unpin>(rd: &mut R) -> Result<()> {
    loop {
        let pkt = tokio::time::timeout(Duration::from_secs(10), apcp::read_packet(rd))
            .await
            .map_err(|_| anyhow::anyhow!("timeout waiting for login response"))??;
        if matches!(
            pkt.kind,
            apcp::PacketType::LoginResponse | apcp::PacketType::LoginResponseAlt
        ) {
            return match pkt.body.first() {
                Some(0) => Ok(()),
                other => bail!("login rejected (status {other:?})"),
            };
        }
    }
}

/// Join cookie name=value pairs into a `Cookie` request header value.
fn cookie_header(cookies: &[(String, String)]) -> String {
    cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn openssl_rand_u32() -> u32 {
    let mut b = [0u8; 4];
    openssl::rand::rand_bytes(&mut b).ok();
    u32::from_be_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_body_is_209_bytes_extended() {
        let body = build_login_body("root", "calvin", 0, 0, 12345, Some(0));
        assert_eq!(body.len(), 1 + 96 + 1 + 96 + 8 + 1 + 1 + 4 + 1);
        assert_eq!(body[0], 4); // "root"
        assert_eq!(&body[1..5], b"root");
        assert_eq!(body[97], 6); // "calvin"
    }

    #[test]
    fn login_body_is_208_bytes_plain() {
        let body = build_login_body("root", "calvin", 0, 0, 1, None);
        assert_eq!(body.len(), 208);
    }

    #[test]
    fn jnlp_title_encoding_matches_idrac_format() {
        let raw = "[idrac-0.i.eloque.nz], Virtual Console, User:root";
        let enc: String = form_urlencoded::byte_serialize(raw.as_bytes()).collect();
        assert_eq!(
            enc,
            "%5Bidrac-0.i.eloque.nz%5D%2C+Virtual+Console%2C+User%3Aroot"
        );
    }

    #[test]
    fn parses_r710_jnlp() {
        let xml = r#"
            <application-desc main-class="com.avocent.idrac.kvm.Main">
              <argument>ip=idrac-0.i.eloque.nz</argument>
              <argument>user=root</argument>
              <argument>passwd=abcdef0123</argument>
              <argument>kmport=5900</argument>
              <argument>vport=5900</argument>
            </application-desc>"#;
        let s = parse_jnlp(xml).unwrap();
        assert_eq!(s.host, "idrac-0.i.eloque.nz");
        assert_eq!(s.user, "root");
        assert_eq!(s.password, "abcdef0123");
        assert_eq!(s.video_port, 5900);
    }
}
