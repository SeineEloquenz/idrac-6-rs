use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use tokio::net::TcpListener;
use tracing::info;

use idrac6_kvm::apcp::{self, ConnKind};
use idrac6_kvm::{auth, http, kvm, rfb, video};

#[derive(Parser)]
#[command(name = "idrac6-kvm", about = "Modern KVM console proxy for Dell iDRAC 6")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Connect, authenticate, and log the APCP handshake + typed packets (M0/M1 spike).
    Capture(CaptureArgs),
    /// Run the full proxy: KVM session in, RFB/VNC server out.
    Serve(ServeArgs),
    /// Run the self-serve web UI: browser login (iDRAC creds) + noVNC, no stored secret.
    #[cfg(feature = "web")]
    Web(WebArgs),
    /// Debug: issue one HTTPS GET over the legacy-TLS layer and print the response.
    Get(GetArgs),
    /// Offline: decode a captured frames.bin dump to a PPM image (decoder development).
    Decode(DecodeArgs),
}

#[derive(Args)]
struct DecodeArgs {
    /// Input dump written by `capture --dump`.
    #[arg(long, default_value = "frames.bin")]
    input: std::path::PathBuf,
    /// Output PPM path.
    #[arg(long, default_value = "frame.ppm")]
    out: std::path::PathBuf,
    /// Number of frames to composite (0 = all).
    #[arg(long, default_value_t = 0)]
    frames: usize,
}

#[derive(Args)]
struct GetArgs {
    #[arg(long)]
    host: String,
    #[arg(long, default_value = "/login.html")]
    path: String,
}

#[derive(Args, Clone)]
struct ConnArgs {
    /// Path to a freshly downloaded viewer.jnlp (supplies host, user, one-time passwd, ports).
    #[arg(long)]
    jnlp: Option<std::path::PathBuf>,
    /// iDRAC hostname or IP (ignored when --jnlp is given).
    #[arg(long, env = "IDRAC_HOST")]
    host: Option<String>,
    /// iDRAC username (defaults to root; ignored when --jnlp is given).
    #[arg(long, env = "IDRAC_USER")]
    user: Option<String>,
    /// KVM credential (the jnlp `passwd` token; ignored when --jnlp is given).
    #[arg(long, env = "IDRAC_PASSWORD")]
    password: Option<String>,
    /// Primary (video) channel port. iDRAC 6 on the R710 multiplexes everything on 5900.
    #[arg(long, default_value_t = 5900)]
    video_port: u16,
    /// Keyboard/mouse channel port.
    #[arg(long, default_value_t = 5900)]
    kvm_port: u16,
    /// Request a plaintext channel (escape hatch; the R710 iDRAC 6 requires TLS).
    #[arg(long)]
    plaintext: bool,
}

impl ConnArgs {
    /// Resolve a KVM session: parse a supplied jnlp, or web-login with account credentials
    /// to mint a fresh KVM token.
    async fn session(&self) -> Result<auth::Session> {
        if let Some(path) = &self.jnlp {
            let xml = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
            return auth::parse_jnlp(&xml);
        }
        let host = self.host.clone().context("--host or --jnlp required")?;
        let user = self.user.clone().unwrap_or_else(|| "root".into());
        let password = self.password.clone().context("--password/IDRAC_PASSWORD or --jnlp required")?;
        info!(%host, %user, "web login to mint KVM token");
        let mut s = auth::login_and_get_token(&host, &user, &password).await?;
        // Honor explicit port overrides.
        if self.video_port != 5900 {
            s.video_port = self.video_port;
        }
        if self.kvm_port != 5900 {
            s.kvm_port = self.kvm_port;
        }
        Ok(s)
    }
}

#[derive(Args)]
struct CaptureArgs {
    #[command(flatten)]
    conn: ConnArgs,
    /// Seconds to log packets before exiting.
    #[arg(long, default_value_t = 10)]
    seconds: u64,
    /// Write raw media-channel (ch2) packet bodies to this file for offline decoder work.
    /// Format: repeated u32-LE length + body.
    #[arg(long)]
    dump: Option<std::path::PathBuf>,
}

#[derive(Args)]
struct ServeArgs {
    #[command(flatten)]
    conn: ConnArgs,
    /// Address to expose the RFB/VNC server on.
    #[arg(long, env = "IDRAC_LISTEN", default_value = "127.0.0.1:5900")]
    listen: String,
    /// Offline self-test: serve a captured frames.bin over RFB instead of connecting to iDRAC.
    #[arg(long)]
    replay: Option<std::path::PathBuf>,
}

#[cfg(feature = "web")]
#[derive(Args)]
struct WebArgs {
    /// iDRAC hostname or IP. Credentials are entered in the browser, never stored here.
    #[arg(long, env = "IDRAC_HOST")]
    host: String,
    /// Username pre-filled on the login form.
    #[arg(long, default_value = "root")]
    user: String,
    /// Address to expose the web UI on (plain HTTP; front it with a TLS reverse proxy).
    #[arg(long, env = "IDRAC_LISTEN", default_value = "127.0.0.1:8080")]
    listen: String,
    /// Directory of noVNC web assets (e.g. `${pkgs.novnc}/share/webapps/novnc`).
    #[arg(long, env = "IDRAC_NOVNC_ROOT")]
    novnc_root: std::path::PathBuf,
    /// Release the KVM session after this many seconds with no connected viewer.
    #[arg(long, default_value_t = 600)]
    idle_timeout: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "idrac6_kvm=info,info".into()),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Capture(a) => capture(a).await,
        Cmd::Serve(a) => serve(a).await,
        #[cfg(feature = "web")]
        Cmd::Web(a) => idrac6_kvm::web::run(a.host, a.user, a.listen, a.novnc_root, a.idle_timeout).await,
        Cmd::Get(a) => {
            let r = http::request(&a.host, 443, "GET", &a.path, &[], None).await?;
            info!(status = r.status, cookies = ?r.cookies(), "response");
            println!("{}", r.body_str());
            Ok(())
        }
        Cmd::Decode(a) => decode_dump(a),
    }
}

/// Reassemble hb fragments from a capture dump and decode to a PPM (offline decoder dev).
fn decode_dump(a: DecodeArgs) -> Result<()> {
    let raw = std::fs::read(&a.input).with_context(|| format!("read {}", a.input.display()))?;
    let frames = reassemble(&raw);
    info!(reassembled = frames.len(), "frames");
    let Some((_, _, first)) = frames.first() else {
        anyhow::bail!("no video frames in {}", a.input.display());
    };
    let (w, h) = (frames[0].1 as u32, frames[0].0 as u32);
    info!(width = w, height = h, first_frame_bytes = first.len(), "decoding");

    let mut fb = video::Framebuffer::new(w, h);
    let mut dec = video::decoder::Decoder::new(w, h);
    let n = if a.frames == 0 { frames.len() } else { a.frames.min(frames.len()) };
    for (i, (_, _, payload)) in frames.iter().take(n).enumerate() {
        let (ops, _) = dec.decode_frame(payload, &mut fb);
        info!(frame = i, bytes = payload.len(), ops, "decoded");
    }
    fb.write_ppm(&a.out)?;
    info!(out = %a.out.display(), "wrote PPM");
    Ok(())
}

async fn capture(a: CaptureArgs) -> Result<()> {
    let s = a.conn.session().await?;
    let out = run_capture(&a, &s).await;
    if !s.web_cookies.is_empty() {
        info!("releasing iDRAC web session");
        let _ = auth::web_logout(&s.host, &s.web_cookies, s.web_st1.as_deref()).await;
    }
    out
}

async fn run_capture(a: &CaptureArgs, s: &auth::Session) -> Result<()> {
    use std::time::Duration;

    // Channel 1 (type 3): control + login.
    info!(host = %s.host, port = s.video_port, user = %s.user, "opening control channel (type 3)");
    let (mut ch1, reply) =
        apcp::open_channel(&s.host, s.video_port, ConnKind::Primary, a.conn.plaintext).await?;
    info!(version = format!("{}.{}", reply.ver_major, reply.ver_minor), tls = reply.tls_required(), "handshake ok");
    let c = auth::send_login(&mut ch1, &s.user, &s.password, true).await?;
    info!(session_id = c, "login sent");

    let (mut rd1, mut wr1) = tokio::io::split(ch1);

    // Wait for the login response on channel 1.
    loop {
        let pkt = tokio::time::timeout(Duration::from_secs(10), apcp::read_packet(&mut rd1))
            .await
            .map_err(|_| anyhow::anyhow!("timeout waiting for login response"))??;
        info!(chan = "ch1", type = format!("{:#06x}", pkt.kind), name = apcp::ptype_name(pkt.kind), len = pkt.body.len(), head = hex_prefix(&pkt.body, 24), "pkt");
        if pkt.kind == 0x8305 || pkt.kind == 0x8300 {
            match pkt.body.first() {
                Some(0) => { info!("login OK"); break; }
                other => anyhow::bail!("login rejected, status byte = {other:?}"),
            }
        }
    }

    // Channel 2 (type 4): media/video, bound to the session with the `ac` packet.
    info!(port = s.kvm_port, "opening media channel (type 4)");
    let (mut ch2, _r2) = apcp::open_channel(&s.host, s.kvm_port, ConnKind::Secondary, a.conn.plaintext).await?;
    apcp::send_link(&mut ch2, c, 0).await?;
    info!("media channel linked (ac); pumping frame requests");
    let (mut rd2, _wr2) = tokio::io::split(ch2);

    // Reader tasks per channel -> mpsc, so select! never cancels a partial read.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(&'static str, apcp::Packet)>(128);
    let tx1 = tx.clone();
    tokio::spawn(async move {
        while let Ok(p) = apcp::read_packet(&mut rd1).await {
            if tx1.send(("ch1", p)).await.is_err() { break; }
        }
    });
    tokio::spawn(async move {
        while let Ok(p) = apcp::read_packet(&mut rd2).await {
            if tx.send(("ch2", p)).await.is_err() { break; }
        }
    });

    let mut dump = match &a.dump {
        Some(p) => Some(std::io::BufWriter::new(
            std::fs::File::create(p).with_context(|| format!("create {}", p.display()))?,
        )),
        None => None,
    };

    let stop = tokio::time::sleep(Duration::from_secs(a.seconds));
    tokio::pin!(stop);
    let mut pump = tokio::time::interval(Duration::from_millis(1000));
    let (mut n1, mut n2) = (0u64, 0u64);
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = pump.tick() => { apcp::send_frame_ack(&mut wr1, 20).await.ok(); }
            msg = rx.recv() => match msg {
                None => break,
                Some((chan, pkt)) => {
                    if chan == "ch1" {
                        n1 += 1
                    } else {
                        n2 += 1;
                        if let Some(w) = dump.as_mut() {
                            use std::io::Write;
                            let _ = w.write_all(&(pkt.body.len() as u32).to_le_bytes());
                            let _ = w.write_all(&pkt.body);
                        }
                    }
                    info!(
                        chan,
                        type = format!("{:#06x}", pkt.kind),
                        name = apcp::ptype_name(pkt.kind),
                        len = pkt.body.len(),
                        head = hex_prefix(&pkt.body, 32),
                        "pkt"
                    );
                    // Reactive video-start, mirroring the applet's handlers:
                    match pkt.kind {
                        // xb (132): appliance asks for the video config -> y() sends db/x/o.
                        0x0084 => {
                            info!("xb received -> sending video config (db/x/o)");
                            apcp::send_video_start(&mut wr1, 1024, 768).await.ok();
                        }
                        // jb (0x8201): resolution reported -> b() sends n().
                        0x8201 => { apcp::send_resolution_ack(&mut wr1).await.ok(); }
                        _ => {}
                    }
                }
            }
        }
    }
    if let Some(mut w) = dump {
        use std::io::Write;
        let _ = w.flush();
        info!(path = ?a.dump, "wrote media-channel dump");
    }
    info!(ch1_pkts = n1, ch2_pkts = n2, "capture done");
    Ok(())
}

async fn serve(a: ServeArgs) -> Result<()> {
    let listener = TcpListener::bind(&a.listen).await.with_context(|| format!("bind {}", a.listen))?;

    if let Some(path) = &a.replay {
        let shared = load_replay(path)?;
        let (input_tx, _rx) = tokio::sync::mpsc::channel(16);
        info!(listen = %a.listen, "RFB server (replay self-test) listening");
        return rfb::serve(listener, shared, input_tx).await;
    }

    let s = a.conn.session().await?;
    // Keep the web-session handle for logout on shutdown (the KVM token is bound to it, so we
    // must not log out while streaming).
    let (host, cookies, st1) = (s.host.clone(), s.web_cookies.clone(), s.web_st1.clone());
    // Reconnect by re-minting from the same web session (no-op for a --jnlp session with no ST1).
    let user = a.conn.user.clone().unwrap_or_else(|| "root".into());
    let refresh = kvm::refresh_from_web(host.clone(), user, cookies.clone(), st1.clone());
    let (shared, input, _task) = kvm::spawn(refresh, s);
    info!(listen = %a.listen, "RFB server listening — point a VNC client here (Ctrl-C to stop)");

    // Serve until the RFB loop ends or a shutdown signal arrives, then always clean up.
    let out = tokio::select! {
        r = rfb::serve(listener, shared, input) => r,
        _ = idrac6_kvm::shutdown_signal() => { info!("shutting down"); Ok(()) }
    };
    if !cookies.is_empty() {
        info!("logging out iDRAC web session");
        let _ = auth::web_logout(&host, &cookies, st1.as_deref()).await;
    }
    // Dropping here closes the KVM sockets, ending the appliance-side KVM session cleanly.
    out
}

/// Reassemble hb fragments from a capture dump into (height, width, payload) frames.
fn reassemble(raw: &[u8]) -> Vec<(u16, u16, Vec<u8>)> {
    let mut frames = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut dims = (0u16, 0u16);
    let mut off = 0;
    while off + 4 <= raw.len() {
        let len = u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]) as usize;
        off += 4;
        if off + len > raw.len() {
            break;
        }
        let body = &raw[off..off + len];
        off += len;
        if body.len() < 12 || &body[0..4] != b"\xde\xad\xbe\xef" {
            continue;
        }
        let h = u16::from_be_bytes([body[4], body[5]]);
        let w = u16::from_be_bytes([body[6], body[7]]);
        if body[8] & 1 != 0 {
            cur.clear();
            dims = (h, w);
        }
        cur.extend_from_slice(&body[12..]);
        if body[8] & 2 != 0 {
            frames.push((dims.0, dims.1, std::mem::take(&mut cur)));
        }
    }
    frames
}

/// Decode a whole dump into a shared framebuffer for the RFB replay self-test.
fn load_replay(path: &std::path::Path) -> Result<kvm::SharedFb> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let frames = reassemble(&raw);
    let (h, w, _) = *frames.first().context("no frames in dump")?;
    let shared = kvm::shared(w as u32, h as u32);
    let mut dec = video::decoder::Decoder::new(w as u32, h as u32);
    {
        let mut g = shared.lock().unwrap();
        for (_, _, payload) in &frames {
            dec.decode_frame(payload, &mut g.fb);
        }
        g.generation = 1;
    }
    Ok(shared)
}

fn hex_prefix(b: &[u8], n: usize) -> String {
    let take = b.len().min(n);
    let mut s = String::with_capacity(take * 2);
    for byte in &b[..take] {
        s.push_str(&format!("{byte:02x}"));
    }
    if b.len() > take {
        s.push('…');
    }
    s
}
