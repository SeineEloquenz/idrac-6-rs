//! APCP transport for the iDRAC 6 KVM channel. A fixed 53-byte `APCP` handshake right after TCP
//! connect, then TLS-wrapped session packets with an 8-byte `BEEF` header (magic, u16 type, u16
//! total-length, all big-endian) and a body.

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::tls;

pub(crate) const MAGIC: &[u8; 4] = b"APCP";
pub(crate) const HANDSHAKE_LEN: usize = 53;
pub(crate) const VER_MAJOR: u8 = 2;
pub(crate) const VER_MINOR: u8 = 34;

/// Connection kind sent in the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnKind {
    Primary = 3,
    Secondary = 4,
}

/// An APCP session-packet type. Requests are low numbers, replies carry the high bit. The trailing
/// comment on a variant is the applet's symbol for it. Unrecognized codes read back as `Other`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    FrameAck, // cb
    Link,     // ac
    Login,
    LoginReply,
    LoginExt,
    Keyboard,         // f
    Pointer,          // gc
    ResolutionAck,    // n
    SetResolution,    // x
    VideoStart,       // o
    VideoConfig,      // db
    Keepalive,        // p
    VideoHb,          // hb
    ConfigRequest,    // xb
    ResolutionReport, // jb
    LoginResponseAlt, // vb
    LoginResponse,    // vb
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

/// Send a flow-control ack after this many received video packets.
pub const FLOW_CONTROL_WINDOW: u8 = 20;

/// Request video after login. The appliance streams frames only once it receives this sequence of
/// config-enable, client resolution, and start.
pub async fn send_video_start<S: AsyncWrite + Unpin>(
    s: &mut S,
    width: u16,
    height: u16,
) -> Result<()> {
    write_packet(s, PacketType::VideoConfig, &[1, 1, 0, 0, 0, 0, 0, 0]).await?; // enable
    let mut res = [0u8; 8];
    res[0..2].copy_from_slice(&width.to_be_bytes());
    res[2..4].copy_from_slice(&height.to_be_bytes());
    write_packet(s, PacketType::SetResolution, &res).await?;
    write_packet(s, PacketType::VideoStart, &[0u8; 8]).await?;
    Ok(())
}

/// Acknowledge the appliance's reported screen resolution.
pub async fn send_resolution_ack<S: AsyncWrite + Unpin>(s: &mut S) -> Result<()> {
    write_packet(s, PacketType::ResolutionAck, &[0u8; 8]).await
}

/// Flow-control ack on the media channel, sent every [`FLOW_CONTROL_WINDOW`] video packets. Byte 0
/// is the count since the last ack. Without it the appliance's send window drains and it goes quiet.
pub async fn send_frame_ack<S: AsyncWrite + Unpin>(s: &mut S, count: u8) -> Result<()> {
    write_packet(s, PacketType::FrameAck, &[count, 0, 0, 0, 0, 0, 0, 0]).await
}

/// Bind the media channel to the authenticated session, carrying the login session id (big-endian).
pub async fn send_link<S: AsyncWrite + Unpin>(s: &mut S, c: u32, d: u32) -> Result<()> {
    let mut body = [0u8; 8];
    body[0..4].copy_from_slice(&c.to_be_bytes());
    body[4..8].copy_from_slice(&d.to_be_bytes());
    write_packet(s, PacketType::Link, &body).await
}

/// A boxed duplex byte stream for a KVM channel (TLS-wrapped).
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Encode the 53-byte handshake request. `enc_pref` advertises capabilities (1 plaintext, 4 TLS, 5 both).
pub(crate) fn encode_handshake(
    kind: ConnKind,
    enc_pref: u32,
    payload: &[u8],
) -> [u8; HANDSHAKE_LEN] {
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
    s.read_exact(&mut buf)
        .await
        .context("read handshake reply")?;
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
    let mut tcp = TcpStream::connect((host, port))
        .await
        .context("tcp connect")?;
    tcp.set_nodelay(true).ok();

    let nonce = random_nonce();
    tcp.write_all(&encode_handshake(kind, 5, &nonce))
        .await
        .context("write handshake")?;
    let redirect_port = read_handshake(&mut tcp).await?;

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

pub(crate) const PKT_MAGIC: &[u8; 4] = b"BEEF";

#[derive(Debug, Clone)]
pub struct Packet {
    pub kind: PacketType,
    pub body: Vec<u8>,
}

pub async fn write_packet<S: AsyncWrite + Unpin>(
    s: &mut S,
    kind: PacketType,
    body: &[u8],
) -> Result<()> {
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

/// Read one packet. Inbound frames are parsed positionally, so the `BEEF` magic is not validated.
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
    Ok(Packet {
        kind: PacketType::from_code(code),
        body,
    })
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
            PacketType::FrameAck,
            PacketType::Link,
            PacketType::Login,
            PacketType::LoginReply,
            PacketType::LoginExt,
            PacketType::Keyboard,
            PacketType::Pointer,
            PacketType::ResolutionAck,
            PacketType::SetResolution,
            PacketType::VideoStart,
            PacketType::VideoConfig,
            PacketType::Keepalive,
            PacketType::VideoHb,
            PacketType::ConfigRequest,
            PacketType::ResolutionReport,
            PacketType::LoginResponseAlt,
            PacketType::LoginResponse,
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
