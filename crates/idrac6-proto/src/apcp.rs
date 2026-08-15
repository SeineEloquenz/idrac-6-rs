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

pub(crate) const MAGIC: &[u8; 4] = b"APCP";
pub(crate) const HANDSHAKE_LEN: usize = 53;
pub(crate) const VER_MAJOR: u8 = 2;
pub(crate) const VER_MINOR: u8 = 34;

/// Connection kind sent in the handshake (`by` in the applet). `a()` -> 3, `b()` -> 4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnKind {
    Primary = 3,
    Secondary = 4,
}

/// An APCP session-packet type, from the applet's dispatch table (`com/avocent/kvm/b/a/a.java`).
/// Requests are low numbers; the appliance's replies carry the high bit (login 256 -> reply 257;
/// video 128.. -> 34304..). The trailing comment is the applet's symbol. Unrecognized codes read
/// back as `Other`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    FrameAck,         // cb, 0
    Link,             // ac, 1
    Login,            // 256
    LoginReply,       // 257
    LoginExt,         // 258
    Keyboard,         // f, 512
    Pointer,          // gc, 513
    ResolutionAck,    // n, 769
    SetResolution,    // x, 770
    VideoStart,       // o, 772
    VideoConfig,      // db, 782
    Keepalive,        // p, 1024
    VideoHb,          // hb, 0x0081
    ConfigRequest,    // xb, 0x0084
    ResolutionReport, // jb, 0x8201
    LoginResponseAlt, // vb, 0x8300
    LoginResponse,    // vb, 0x8305
    Other(u16),
}

impl PacketType {
    /// The wire code for this type.
    pub const fn code(self) -> u16 {
        match self {
            Self::FrameAck => 0,
            Self::Link => 1,
            Self::Login => 256,
            Self::LoginReply => 257,
            Self::LoginExt => 258,
            Self::Keyboard => 512,
            Self::Pointer => 513,
            Self::ResolutionAck => 769,
            Self::SetResolution => 770,
            Self::VideoStart => 772,
            Self::VideoConfig => 782,
            Self::Keepalive => 1024,
            Self::VideoHb => 0x0081,
            Self::ConfigRequest => 0x0084,
            Self::ResolutionReport => 0x8201,
            Self::LoginResponseAlt => 0x8300,
            Self::LoginResponse => 0x8305,
            Self::Other(c) => c,
        }
    }

    /// Resolve a wire code to its type, `Other` for anything unrecognized.
    pub fn from_code(code: u16) -> Self {
        match code {
            0 => Self::FrameAck,
            1 => Self::Link,
            256 => Self::Login,
            257 => Self::LoginReply,
            258 => Self::LoginExt,
            512 => Self::Keyboard,
            513 => Self::Pointer,
            769 => Self::ResolutionAck,
            770 => Self::SetResolution,
            772 => Self::VideoStart,
            782 => Self::VideoConfig,
            1024 => Self::Keepalive,
            0x0081 => Self::VideoHb,
            0x0084 => Self::ConfigRequest,
            0x8201 => Self::ResolutionReport,
            0x8300 => Self::LoginResponseAlt,
            0x8305 => Self::LoginResponse,
            other => Self::Other(other),
        }
    }
}

/// Media-channel flow-control window `W`: send a `cb` frame-ack after this many received video
/// packets (per `r.B()`), or the appliance's send window drains and it goes quiet.
pub const FLOW_CONTROL_WINDOW: u8 = 20;

/// After a successful login the applet requests video by sending three packets (`y()` in
/// `com/avocent/kvm/b/r.java`): db(true), the client resolution, and o(). Only then does the
/// appliance stream frames.
pub async fn send_video_start<S: AsyncWrite + Unpin>(s: &mut S, width: u16, height: u16) -> Result<()> {
    write_packet(s, PacketType::VideoConfig, &[1, 1, 0, 0, 0, 0, 0, 0]).await?; // db(true)
    let mut res = [0u8; 8];
    res[0..2].copy_from_slice(&width.to_be_bytes());
    res[2..4].copy_from_slice(&height.to_be_bytes());
    write_packet(s, PacketType::SetResolution, &res).await?; // x(width, height)
    write_packet(s, PacketType::VideoStart, &[0u8; 8]).await?; // o()
    Ok(())
}

/// `n()` (type 769), sent once the appliance reports the screen resolution (`r.b()`).
pub async fn send_resolution_ack<S: AsyncWrite + Unpin>(s: &mut S) -> Result<()> {
    write_packet(s, PacketType::ResolutionAck, &[0u8; 8]).await
}

/// `cb` flow-control ack (type 0), sent on the MEDIA channel every W=20 received video
/// packets, per `r.B()`. Byte 0 carries the count of frames since the last ack; without it
/// the appliance's send window drains and it goes quiet (or a wrong-channel flood stalls it).
pub async fn send_frame_ack<S: AsyncWrite + Unpin>(s: &mut S, count: u8) -> Result<()> {
    write_packet(s, PacketType::FrameAck, &[count, 0, 0, 0, 0, 0, 0, 0]).await
}

/// `ac` (type 1), sent on the second (media) channel to bind it to the authenticated session,
/// carrying the login session id `c` (=`C`) and `d` (=`D`, 0 here). Both big-endian.
pub async fn send_link<S: AsyncWrite + Unpin>(s: &mut S, c: u32, d: u32) -> Result<()> {
    let mut body = [0u8; 8];
    body[0..4].copy_from_slice(&c.to_be_bytes());
    body[4..8].copy_from_slice(&d.to_be_bytes());
    write_packet(s, PacketType::Link, &body).await
}

/// A boxed duplex byte stream for a KVM channel (TLS-wrapped).
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Encode the 53-byte handshake request. `enc_pref` mirrors the applet's `h` field
/// (1 = plaintext, 4 = TLS). `payload` is the 32-byte client nonce (padded/truncated).
pub(crate) fn encode_handshake(kind: ConnKind, enc_pref: u32, payload: &[u8]) -> [u8; HANDSHAKE_LEN] {
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

/// Read the 53-byte handshake reply, returning the redirect port (0 = none).
async fn read_handshake<S: AsyncRead + Unpin>(s: &mut S) -> Result<u16> {
    let mut buf = [0u8; HANDSHAKE_LEN];
    s.read_exact(&mut buf).await.context("read handshake reply")?;
    if &buf[0..4] != MAGIC {
        bail!("bad handshake magic: {:02x?}", &buf[0..4]);
    }
    let marker = u16::from_be_bytes([buf[8], buf[9]]);
    if marker != 0x8100 {
        bail!("unexpected handshake marker {marker:#06x}");
    }
    Ok(u16::from_be_bytes([buf[18], buf[19]]))
}

/// Perform TCP connect + handshake, honoring a port redirect and upgrading to TLS.
///
/// The iDRAC 6 KVM channel requires TLS: it sends no handshake reply to a plaintext request. We
/// advertise `enc=5` (plaintext- and TLS-capable), the appliance selects TLS, and we wrap the
/// channel.
pub async fn open_channel(host: &str, port: u16, kind: ConnKind) -> Result<Box<dyn Stream>> {
    let mut tcp = TcpStream::connect((host, port)).await.context("tcp connect")?;
    tcp.set_nodelay(true).ok();

    let nonce = random_nonce();
    tcp.write_all(&encode_handshake(kind, 5, &nonce)).await.context("write handshake")?;
    let redirect_port = read_handshake(&mut tcp).await?;

    // Some firmware redirects the media stream to another port; this one keeps 5900.
    let mut stream = tcp;
    if redirect_port != 0 && redirect_port != port {
        stream = TcpStream::connect((host, redirect_port))
            .await
            .context("tcp reconnect to redirect port")?;
        stream.set_nodelay(true).ok();
    }

    let tls = tls::upgrade(stream, host).await?;
    Ok(Box::new(tls))
}

/// One APCP session packet: an 8-byte `BEEF` header (magic + u16 type + u16 total-length,
/// all big-endian) followed by a body. The length field counts header + body.
pub(crate) const PKT_MAGIC: &[u8; 4] = b"BEEF";

#[derive(Debug, Clone)]
pub struct Packet {
    pub kind: PacketType,
    pub body: Vec<u8>,
}

/// Write a packet: `BEEF` + type + (8 + body.len()) + body.
pub async fn write_packet<S: AsyncWrite + Unpin>(s: &mut S, kind: PacketType, body: &[u8]) -> Result<()> {
    let total = (8 + body.len()) as u16;
    let mut frame = Vec::with_capacity(8 + body.len());
    frame.extend_from_slice(PKT_MAGIC);
    frame.extend_from_slice(&kind.code().to_be_bytes());
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
    let code = u16::from_be_bytes([hdr[4], hdr[5]]);
    let total = u16::from_be_bytes([hdr[6], hdr[7]]) as usize;
    if !(8..=65535).contains(&total) {
        bail!("implausible packet length {total} (type {code:#06x})");
    }
    let mut body = vec![0u8; total - 8];
    s.read_exact(&mut body).await.context("read packet body")?;
    Ok(Packet { kind: PacketType::from_code(code), body })
}

fn random_nonce() -> [u8; 32] {
    let mut b = [0u8; 32];
    openssl::rand::rand_bytes(&mut b).ok();
    b
}

#[cfg(test)]
mod tests {
    use super::PacketType;

    #[test]
    fn known_types_round_trip_through_their_code() {
        for kind in [
            PacketType::FrameAck, PacketType::Link, PacketType::Login, PacketType::LoginReply,
            PacketType::LoginExt, PacketType::Keyboard, PacketType::Pointer, PacketType::ResolutionAck,
            PacketType::SetResolution, PacketType::VideoStart, PacketType::VideoConfig,
            PacketType::Keepalive, PacketType::VideoHb, PacketType::ConfigRequest,
            PacketType::ResolutionReport, PacketType::LoginResponseAlt, PacketType::LoginResponse,
        ] {
            assert_eq!(PacketType::from_code(kind.code()), kind);
        }
    }

    #[test]
    fn unknown_code_is_other() {
        assert_eq!(PacketType::from_code(0x1234), PacketType::Other(0x1234));
        assert_eq!(PacketType::Other(0x1234).code(), 0x1234);
    }
}
