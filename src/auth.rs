//! iDRAC 6 KVM authentication.
//!
//! The jnlp passes `user`/`passwd` directly, and the applet authenticates with a
//! "Login Request" APCP packet (type 256, or 258 "extended" for protocol >= 2), built in
//! `com/avocent/kvm/b/a/ab.java` and sent from `com/avocent/kvm/b/r.java`. There is no
//! separate web-login / token step for this firmware.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWrite;
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

/// Parse a `viewer.jnlp` into a session. On this firmware `passwd` is a rotating,
/// server-minted one-time KVM token (the account password is not accepted for KVM), so a
/// freshly downloaded jnlp is the reliable credential source until the web-login flow is
/// automated.
pub fn parse_jnlp(xml: &str) -> Result<Session> {
    let mut args: HashMap<&str, &str> = HashMap::new();
    for chunk in xml.split("<argument>").skip(1) {
        let Some(end) = chunk.find("</argument>") else { continue };
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

/// Log into the iDRAC web UI (`POST /data/login`) and return the session cookies plus the
/// `ST1` token from the forward URL. This is what "Launch Virtual Console" does before the
/// appliance will mint a KVM token.
pub async fn web_login(host: &str, user: &str, password: &str) -> Result<(Vec<(String, String)>, Option<String>)> {
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
        Some("5") => bail!(
            "iDRAC login failed: maximum sessions reached (authResult=5). Old sessions from \
             earlier runs are still open; wait for them to time out or terminate them in the \
             iDRAC web UI, then retry."
        ),
        Some("3") => bail!("iDRAC login failed: user lacks the 'Login to iDRAC' privilege (authResult=3)"),
        other => bail!("iDRAC login failed: wrong username/password (authResult={other:?})"),
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

/// Fetch a freshly minted `viewer.jnlp` for an authenticated session. The iDRAC 6 URL is
/// `/viewer.jnlp(<host>@0@<url-encoded-title>@<epoch_ms>@ST1=<token>)`: args are `@`-joined
/// inside literal parens, the title is form-encoded, and the ST1 session token authorizes
/// the request (the session cookie alone yields 401).
pub async fn fetch_jnlp(host: &str, user: &str, cookies: &[(String, String)], st1: Option<&str>) -> Result<String> {
    let st1 = st1.context("no ST1 token from login; cannot authorize viewer.jnlp")?;
    let cookie_hdr = cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let epoch_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
    let title = form_encode(&format!("[{host}], Virtual Console, User:{user}"));
    let path = format!("/viewer.jnlp({host}@0@{title}@{epoch_ms}@ST1={st1})");

    info!(url = %path, "fetching viewer.jnlp");
    let r = http::request(host, 443, "GET", &path, &[("Cookie", &cookie_hdr)], None)
        .await
        .context("GET viewer.jnlp")?;
    let body = r.body_str();
    if !(body.contains("passwd=") || body.contains("<jnlp")) {
        bail!("viewer.jnlp fetch returned HTTP {} but no jnlp body ({} bytes)", r.status, r.body.len());
    }
    Ok(body.into_owned())
}

/// application/x-www-form-urlencoded encoding (space -> `+`), for the jnlp URL title.
fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Full self-service flow: web login with account credentials, mint + parse the jnlp token.
/// The returned session carries the web cookies/ST1 so the caller can [`web_logout`].
pub async fn login_and_get_token(host: &str, user: &str, password: &str) -> Result<Session> {
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
    let cookie_hdr = cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
    let path = match st1 {
        Some(st1) => format!("/data/logout?ST1={st1}"),
        None => "/data/logout".to_string(),
    };
    http::request(host, 443, "GET", &path, &[("Cookie", &cookie_hdr)], None).await?;
    Ok(())
}

/// Login body layout (extended, type 258), per `ab.b()`:
/// userLen(1) + user(96) + passLen(1) + pass(96) + session(8, zero) + o(1) + p(1) + r(4 BE)
/// followed by q(1) when extended.
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

/// Send the Login Request and return the random session id `C` it carried. `C` links the
/// second (media) channel via the `ac` packet, so the caller must keep it. `extended`
/// (protocol >= 2) adds the trailing `q` byte and uses packet type 258.
pub async fn send_login<S: AsyncWrite + Unpin>(
    s: &mut S,
    user: &str,
    password: &str,
    extended: bool,
) -> Result<u32> {
    let r: u32 = (openssl_rand_u32() % 10_000_000).max(1);
    let body = build_login_body(user, password, 0, 0, r, extended.then_some(0));
    let kind = if extended { apcp::ptype::LOGIN_EXT } else { apcp::ptype::LOGIN };
    apcp::write_packet(s, kind, &body).await?;
    Ok(r)
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
