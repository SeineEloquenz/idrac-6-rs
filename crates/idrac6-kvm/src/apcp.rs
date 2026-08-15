//! APCP transport: the initial handshake and the post-handshake packet framing, from the
//! decompiled applet (`com/avocent/kvm/b/l.java`, `com/avocent/kvm/b/a/b.java`).
//!
//! 1. A fixed 53-byte **handshake** right after TCP connect (magic `APCP`, big-endian).
//!    The capability/redirect reply selects plaintext vs TLS; this firmware requires TLS.
//! 2. After the TLS upgrade, **session packets** with an 8-byte header: magic `BEEF`
//!    + type (u16 BE) + total length (u16 BE), followed by the body.

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::tls;

pub const MAGIC: &[u8; 4] = b"APCP";
pub const HANDSHAKE_LEN: usize = 53;
pub const VER_MAJOR: u8 = 2;
pub const VER_MINOR: u8 = 34;

/// Capability bit in the handshake reply's flags field: the appliance requires TLS.
pub const FLAG_TLS_REQUIRED: u32 = 1 << 2;

/// Connection kind sent in the handshake (`by` in the applet). `a()` -> 3, `b()` -> 4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnKind {
    Primary = 3,
    Secondary = 4,
}

/// APCP session-packet type codes, from the applet's dispatch table
/// (`com/avocent/kvm/b/a/a.java`). Requests are low numbers; the appliance's replies
/// carry the high bit (e.g. login 256 -> reply 257; video 128.. -> 34304..). The trailing
/// comment on each is the applet's symbol for it.
pub mod ptype {
    pub const FRAME_ACK: u16 = 0; // cb
    pub const LINK: u16 = 1; // ac
    pub const LOGIN: u16 = 256;
    pub const LOGIN_REPLY: u16 = 257;
    pub const LOGIN_EXT: u16 = 258;
    pub const KEYBOARD: u16 = 512; // f
    pub const POINTER: u16 = 513; // gc
    pub const RESOLUTION_ACK: u16 = 769; // n
    pub const SET_RESOLUTION: u16 = 770; // x
    pub const VIDEO_START: u16 = 772; // o
    pub const VIDEO_CONFIG: u16 = 782; // db
    pub const KEEPALIVE: u16 = 1024; // p
    pub const VIDEO_HB: u16 = 0x0081; // hb, video/screen tile
    pub const CONFIG_REQUEST: u16 = 0x0084; // xb, appliance requests video config
    pub const RESOLUTION_REPORT: u16 = 0x8201; // jb, appliance reports screen resolution
    pub const LOGIN_RESPONSE_ALT: u16 = 0x8300; // vb
    pub const LOGIN_RESPONSE: u16 = 0x8305; // vb
}

/// Media-channel flow-control window `W`: send a `cb` frame-ack after this many received video
/// packets (per `r.B()`), or the appliance's send window drains and it goes quiet.
pub const FLOW_CONTROL_WINDOW: u8 = 20;

/// Human label for a packet type, for capture logging.
pub fn ptype_name(t: u16) -> &'static str {
    use self::ptype::*;
    match t {
        LOGIN | LOGIN_EXT => "LoginRequest",
        LOGIN_REPLY | LOGIN_RESPONSE | LOGIN_RESPONSE_ALT => "LoginResponse",
        FRAME_ACK => "FrameRequest(cb)",
        RESOLUTION_ACK => "ResolutionAck(n)",
        SET_RESOLUTION => "SetResolution",
        VIDEO_START => "VideoStart(o)",
        VIDEO_CONFIG => "VideoStart(db)",
        128..=138 => "video/screen",
        34304..=34314 => "video/screen(reply)",
        _ => "?",
    }
}

/// After a successful login the applet requests video by sending three packets (`y()` in
/// `com/avocent/kvm/b/r.java`): db(true), the client resolution, and o(). Only then does the
/// appliance stream frames.
pub async fn send_video_start<S: AsyncWrite + Unpin>(s: &mut S, width: u16, height: u16) -> Result<()> {
    write_packet(s, ptype::VIDEO_CONFIG, &[1, 1, 0, 0, 0, 0, 0, 0]).await?; // db(true)
    let mut res = [0u8; 8];
    res[0..2].copy_from_slice(&width.to_be_bytes());
    res[2..4].copy_from_slice(&height.to_be_bytes());
    write_packet(s, ptype::SET_RESOLUTION, &res).await?; // x(width, height)
    write_packet(s, ptype::VIDEO_START, &[0u8; 8]).await?; // o()
    Ok(())
}

/// `n()` (type 769), sent once the appliance reports the screen resolution (`r.b()`).
pub async fn send_resolution_ack<S: AsyncWrite + Unpin>(s: &mut S) -> Result<()> {
    write_packet(s, ptype::RESOLUTION_ACK, &[0u8; 8]).await
}

/// `cb` flow-control ack (type 0), sent on the MEDIA channel every W=20 received video
/// packets, per `r.B()`. Byte 0 carries the count of frames since the last ack; without it
/// the appliance's send window drains and it goes quiet (or a wrong-channel flood stalls it).
pub async fn send_frame_ack<S: AsyncWrite + Unpin>(s: &mut S, count: u8) -> Result<()> {
    write_packet(s, ptype::FRAME_ACK, &[count, 0, 0, 0, 0, 0, 0, 0]).await
}

/// `ac` (type 1), sent on the second (media) channel to bind it to the authenticated session,
/// carrying the login session id `c` (=`C`) and `d` (=`D`, 0 here). Both big-endian.
pub async fn send_link<S: AsyncWrite + Unpin>(s: &mut S, c: u32, d: u32) -> Result<()> {
    let mut body = [0u8; 8];
    body[0..4].copy_from_slice(&c.to_be_bytes());
    body[4..8].copy_from_slice(&d.to_be_bytes());
    write_packet(s, ptype::LINK, &body).await
}

/// A duplex stream that is either plaintext or TLS-wrapped.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Parsed handshake reply from the appliance.
#[derive(Debug, Clone)]
pub struct HandshakeReply {
    pub flags: u32,
    pub redirect_port: u16,
    pub ver_major: u8,
    pub ver_minor: u8,
}

impl HandshakeReply {
    pub fn tls_required(&self) -> bool {
        self.flags & FLAG_TLS_REQUIRED != 0
    }
}

/// Encode the 53-byte handshake request. `enc_pref` mirrors the applet's `h` field
/// (1 = plaintext, 4 = TLS). `payload` is the 32-byte client nonce (padded/truncated).
pub fn encode_handshake(kind: ConnKind, enc_pref: u32, payload: &[u8]) -> [u8; HANDSHAKE_LEN] {
    let mut buf = [0u8; HANDSHAKE_LEN];
    buf[0..4].copy_from_slice(MAGIC);
    buf[4..8].copy_from_slice(&(HANDSHAKE_LEN as u32).to_be_bytes());
    buf[8..10].copy_from_slice(&256u16.to_be_bytes());
    buf[10..12].copy_from_slice(&0u16.to_be_bytes());
    buf[12] = kind as u8;
    buf[13] = VER_MAJOR;
    buf[14] = VER_MINOR;
    buf[15] = 0;
    buf[16..20].copy_from_slice(&enc_pref.to_be_bytes());
    let n = payload.len().min(32);
    buf[20] = n as u8;
    buf[21..21 + n].copy_from_slice(&payload[..n]);
    buf
}

/// Read and parse the 53-byte handshake reply.
async fn read_handshake<S: AsyncRead + Unpin>(s: &mut S) -> Result<HandshakeReply> {
    let mut buf = [0u8; HANDSHAKE_LEN];
    s.read_exact(&mut buf).await.context("read handshake reply")?;
    if &buf[0..4] != MAGIC {
        bail!("bad handshake magic: {:02x?}", &buf[0..4]);
    }
    let marker = u16::from_be_bytes([buf[8], buf[9]]);
    if marker != 0x8100 {
        bail!("unexpected handshake marker {marker:#06x}");
    }
    let ver_major = buf[12];
    let ver_minor = buf[13];
    let flags = u32::from_be_bytes([buf[14], buf[15], buf[16], buf[17]]);
    let redirect_port = u16::from_be_bytes([buf[18], buf[19]]);
    Ok(HandshakeReply { flags, redirect_port, ver_major, ver_minor })
}

/// Perform TCP connect + handshake, honoring a port redirect and upgrading to TLS.
///
/// The iDRAC 6 KVM channel requires TLS: it sends no handshake reply at all to a
/// plaintext (`enc_pref=1`) request, and its reply flags carry `TLS_REQUIRED`. We
/// therefore request `enc_pref=4` and TLS-wrap unless `plaintext` is explicitly set (an
/// escape hatch for other/older appliances). Returns the ready channel plus the reply.
pub async fn open_channel(
    host: &str,
    port: u16,
    kind: ConnKind,
    plaintext: bool,
) -> Result<(Box<dyn Stream>, HandshakeReply)> {
    let mut tcp = TcpStream::connect((host, port)).await.context("tcp connect")?;
    tcp.set_nodelay(true).ok();

    let nonce = random_nonce();
    // The applet advertises 5 (bits 0|2 = plaintext-capable + TLS-capable); the appliance
    // then selects TLS. A plaintext-only (1) request gets no reply at all.
    let enc_pref = if plaintext { 1 } else { 5 };
    tcp.write_all(&encode_handshake(kind, enc_pref, &nonce))
        .await
        .context("write handshake")?;
    let reply = read_handshake(&mut tcp).await?;

    // Some firmware redirects the media stream to another port; this one keeps 5900.
    let mut stream = tcp;
    if reply.redirect_port != 0 && reply.redirect_port != port {
        stream = TcpStream::connect((host, reply.redirect_port))
            .await
            .context("tcp reconnect to redirect port")?;
        stream.set_nodelay(true).ok();
    }

    if plaintext {
        Ok((Box::new(stream), reply))
    } else {
        let tls = tls::upgrade(stream, host).await?;
        Ok((Box::new(tls), reply))
    }
}

/// One APCP session packet: an 8-byte `BEEF` header (magic + u16 type + u16 total-length,
/// all big-endian) followed by a body. The length field counts header + body.
pub const PKT_MAGIC: &[u8; 4] = b"BEEF";

#[derive(Debug, Clone)]
pub struct Packet {
    pub kind: u16,
    pub body: Vec<u8>,
}

/// Write a packet: `BEEF` + type + (8 + body.len()) + body.
pub async fn write_packet<S: AsyncWrite + Unpin>(s: &mut S, kind: u16, body: &[u8]) -> Result<()> {
    let total = (8 + body.len()) as u16;
    let mut frame = Vec::with_capacity(8 + body.len());
    frame.extend_from_slice(PKT_MAGIC);
    frame.extend_from_slice(&kind.to_be_bytes());
    frame.extend_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(body);
    s.write_all(&frame).await.context("write packet")?;
    s.flush().await.ok();
    Ok(())
}

/// Read one packet. The type is at header offset 4, the total length at offset 6; the body
/// is `len - 8` bytes. The magic is not required on inbound frames (the applet reads type
/// and length positionally).
pub async fn read_packet<S: AsyncRead + Unpin>(s: &mut S) -> Result<Packet> {
    let mut hdr = [0u8; 8];
    s.read_exact(&mut hdr).await.context("read packet header")?;
    let kind = u16::from_be_bytes([hdr[4], hdr[5]]);
    let total = u16::from_be_bytes([hdr[6], hdr[7]]) as usize;
    if !(8..=65535).contains(&total) {
        bail!("implausible packet length {total} (type {kind})");
    }
    let mut body = vec![0u8; total - 8];
    s.read_exact(&mut body).await.context("read packet body")?;
    Ok(Packet { kind, body })
}

fn random_nonce() -> [u8; 32] {
    let mut b = [0u8; 32];
    openssl::rand::rand_bytes(&mut b).ok();
    b
}
