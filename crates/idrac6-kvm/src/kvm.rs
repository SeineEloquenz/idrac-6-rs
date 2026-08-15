//! Live KVM session: connect + authenticate, then decode the ch2 video stream into a shared
//! framebuffer while pumping frame requests and forwarding input.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::apcp::{self, ConnKind};
use crate::auth;
use crate::input::{send_input, Input, Mods};
use crate::video::{decoder::Decoder, Framebuffer};

/// Shared framebuffer with a generation counter bumped on every decoded frame and the union of
/// changed pixel ranges (half-open linear indices) since a client last consumed them.
pub struct FbState {
    pub fb: Framebuffer,
    pub generation: u64,
    dirty: Option<(usize, usize)>,
}

impl FbState {
    /// Union a decoded frame's changed span into the pending damage.
    pub fn mark_dirty(&mut self, (lo, hi): (usize, usize)) {
        self.dirty = Some(match self.dirty {
            Some((a, b)) => (a.min(lo), b.max(hi)),
            None => (lo, hi),
        });
    }

    /// Take and clear the pending damage span.
    pub fn take_dirty(&mut self) -> Option<(usize, usize)> {
        self.dirty.take()
    }
}

pub type SharedFb = Arc<Mutex<FbState>>;

pub fn shared(width: u32, height: u32) -> SharedFb {
    Arc::new(Mutex::new(FbState { fb: Framebuffer::new(width, height), generation: 0, dirty: None }))
}

/// The control-channel (ch1) write half, shared between the long-lived input task and each
/// connection's video loop, and swapped out on every reconnect.
type Ch1Writer = tokio::io::WriteHalf<Box<dyn apcp::Stream>>;
type SharedWriter = Arc<tokio::sync::Mutex<Option<Ch1Writer>>>;

/// Mints a fresh [`auth::Session`] for each (re)connect. The KVM token is one-time, so a reconnect
/// needs a new one. A `BadCredentials`/`NoPrivilege` result stops the supervisor; anything else is
/// retried with backoff.
pub type Refresh = Box<dyn FnMut() -> Pin<Box<dyn Future<Output = Result<auth::Session, auth::AuthError>> + Send>> + Send>;

const MAX_FAILS: u32 = 6;
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Build a [`Refresh`] that re-mints a KVM token from a still-valid web session (cookies + ST1),
/// reusing that one web session so reconnects don't leak sessions toward the appliance's limit.
pub fn refresh_from_web(host: String, user: String, cookies: Vec<(String, String)>, st1: Option<String>) -> Refresh {
    Box::new(move || {
        let (host, user, cookies, st1) = (host.clone(), user.clone(), cookies.clone(), st1.clone());
        Box::pin(async move {
            let jnlp = auth::fetch_jnlp(&host, &user, &cookies, st1.as_deref()).await?;
            let mut s = auth::parse_jnlp(&jnlp)?;
            s.web_cookies = cookies;
            s.web_st1 = st1;
            Ok(s)
        })
    })
}

/// Supervise the KVM connection: keep `shared` + `input_rx` alive across reconnects, and on every
/// drop re-mint a session and reconnect with exponential backoff. Input + keep-alive run on one
/// long-lived task writing to whichever control channel is currently up.
async fn supervise(mut refresh: Refresh, initial: auth::Session, shared: SharedFb, mut input_rx: mpsc::Receiver<Input>) {
    let writer: SharedWriter = Arc::new(tokio::sync::Mutex::new(None));

    let w_io = writer.clone();
    let input_task = tokio::spawn(async move {
        let mut keepalive = tokio::time::interval(Duration::from_secs(2));
        let mut mods = Mods::default();
        loop {
            tokio::select! {
                _ = keepalive.tick() => {
                    if let Some(w) = w_io.lock().await.as_mut() {
                        let _ = apcp::write_packet(w, apcp::ptype::KEEPALIVE, &[0u8; 8]).await;
                    }
                }
                ev = input_rx.recv() => match ev {
                    None => break,
                    Some(input) => {
                        if let Some(w) = w_io.lock().await.as_mut() {
                            let _ = send_input(w, input, &mut mods).await;
                        }
                    }
                }
            }
        }
    });

    let mut session = Some(initial);
    let mut backoff = Duration::from_secs(1);
    let mut fails = 0u32;
    loop {
        let s = match session.take() {
            Some(s) => s,
            None => match refresh().await {
                Ok(s) => s,
                Err(auth::AuthError::BadCredentials | auth::AuthError::NoPrivilege) => {
                    warn!("reconnect rejected (credentials/privilege); giving up");
                    break;
                }
                Err(e) => {
                    fails += 1;
                    warn!(fails, "reconnect token refresh failed: {e}");
                    if fails > MAX_FAILS {
                        break;
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    continue;
                }
            },
        };

        let clean = match connect_once(&s, &shared, &writer).await {
            Ok(()) => {
                info!("KVM session ended");
                true
            }
            Err(e) => {
                warn!("KVM session error: {e:#}");
                false
            }
        };
        *writer.lock().await = None;

        if clean {
            fails = 0;
            backoff = Duration::from_secs(1);
            tokio::time::sleep(Duration::from_secs(1)).await;
        } else {
            fails += 1;
            if fails > MAX_FAILS {
                warn!(fails, "giving up reconnecting");
                break;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }
    input_task.abort();
    warn!("KVM supervisor stopped");
}

/// Open one KVM connection (control + media channels), authenticate, publish the control writer,
/// and decode video into `shared` until the connection drops. Returns `Ok` on a clean drop.
async fn connect_once(s: &auth::Session, shared: &SharedFb, writer: &SharedWriter) -> Result<()> {
    info!(host = %s.host, "connecting KVM session");
    let (mut ch1, _) = apcp::open_channel(&s.host, s.video_port, ConnKind::Primary, false).await?;
    let c = auth::send_login(&mut ch1, &s.user, &s.password, true).await?;
    let (mut rd1, wr1) = tokio::io::split(ch1);

    auth::await_login_ok(&mut rd1).await?;
    info!("login ok; opening media channel");
    // Publish the control-channel writer so the input task can reach it.
    *writer.lock().await = Some(wr1);

    let (mut ch2, _) = apcp::open_channel(&s.host, s.kvm_port, ConnKind::Secondary, false).await?;
    apcp::send_link(&mut ch2, c, 0).await?;
    let (mut rd2, mut wr2) = tokio::io::split(ch2);

    let (tx, mut rx) = mpsc::channel::<(&'static str, apcp::Packet)>(256);
    let tx1 = tx.clone();
    let r1 = tokio::spawn(async move {
        while let Ok(p) = apcp::read_packet(&mut rd1).await {
            if tx1.send(("ch1", p)).await.is_err() {
                break;
            }
        }
    });
    let r2 = tokio::spawn(async move {
        while let Ok(p) = apcp::read_packet(&mut rd2).await {
            if tx.send(("ch2", p)).await.is_err() {
                break;
            }
        }
    });

    // Video loop: decode ch2 frames into the shared framebuffer, ack flow control on ch2, and
    // drive the ch1 config reactions (through the shared control writer).
    let mut dec: Option<Decoder> = None;
    let mut frame: Vec<u8> = Vec::new();
    let mut dims = (0u16, 0u16);
    let mut frames_decoded = 0u64;
    let mut hb_count = 0u32; // media packets since last flow-control ack

    while let Some((_chan, pkt)) = rx.recv().await {
        match pkt.kind {
            apcp::ptype::CONFIG_REQUEST => {
                if let Some(w) = writer.lock().await.as_mut() {
                    apcp::send_video_start(w, 1024, 768).await.ok();
                }
            }
            apcp::ptype::RESOLUTION_REPORT => {
                if let Some(w) = writer.lock().await.as_mut() {
                    apcp::send_resolution_ack(w).await.ok();
                }
            }
            apcp::ptype::VIDEO_HB => {
                hb_count += 1;
                if hb_count >= apcp::FLOW_CONTROL_WINDOW as u32 {
                    apcp::send_frame_ack(&mut wr2, hb_count as u8).await.ok();
                    hb_count = 0;
                }
                let b = &pkt.body;
                if b.len() >= 12 && &b[0..4] == b"\xde\xad\xbe\xef" {
                    let flags = b[8];
                    if flags & 1 != 0 {
                        frame.clear();
                        dims = (u16::from_be_bytes([b[6], b[7]]), u16::from_be_bytes([b[4], b[5]]));
                    }
                    frame.extend_from_slice(&b[12..]);
                    if flags & 2 != 0 && dims.0 > 0 && dims.1 > 0 {
                        decode_into_fb(shared, &mut dec, &frame, dims.0 as u32, dims.1 as u32);
                        frames_decoded += 1;
                        if frames_decoded.is_multiple_of(300) {
                            info!(frames_decoded, "video frames decoded");
                        }
                        frame.clear();
                    }
                }
            }
            _ => {}
        }
    }
    r1.abort();
    r2.abort();
    warn!("KVM channels closed");
    Ok(())
}

/// Decode one reassembled frame payload into `shared`, resizing the framebuffer if the resolution
/// changed. The generation advances only on real damage, so a no-op frame never wakes a client
/// into the empty-dirty full-frame fallback.
fn decode_into_fb(shared: &SharedFb, dec: &mut Option<Decoder>, payload: &[u8], w: u32, h: u32) {
    let mut g = shared.lock().unwrap();
    if g.fb.width != w || g.fb.height != h {
        g.fb = Framebuffer::new(w, h);
        *dec = Some(Decoder::new(w, h));
    }
    let d = dec.get_or_insert_with(|| Decoder::new(w, h));
    let (_, dirty) = d.decode_frame(payload, &mut g.fb);
    if let Some(r) = dirty {
        g.mark_dirty(r);
        g.generation = g.generation.wrapping_add(1);
    }
}

/// Build the shared framebuffer and spawn the reconnect supervisor. Returns the framebuffer, an
/// input sender, and the supervisor task handle (abort it to stop the session and reconnect loop).
pub fn spawn(refresh: Refresh, initial: auth::Session) -> (SharedFb, mpsc::Sender<Input>, tokio::task::JoinHandle<()>) {
    let shared = shared(1024, 768);
    let (tx, rx) = mpsc::channel(256);
    let fb = shared.clone();
    let handle = tokio::spawn(supervise(refresh, initial, fb, rx));
    (shared, tx, handle)
}

#[cfg(test)]
mod tests {
    use super::{shared, supervise, Refresh};
    use crate::auth;
    use std::time::Duration;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn supervisor_stops_on_fatal_refresh() {
        // Initial session points at a dead port so connect_once errors quickly; the refresh then
        // returns a fatal auth error, so the supervisor must give up (not loop forever).
        let initial = auth::Session {
            host: "127.0.0.1".into(),
            user: "x".into(),
            password: "x".into(),
            video_port: 1,
            kvm_port: 1,
            web_cookies: vec![],
            web_st1: None,
        };
        let refresh: Refresh = Box::new(|| Box::pin(async { Err(auth::AuthError::BadCredentials) }));
        let (_tx, rx) = mpsc::channel(4);
        tokio::time::timeout(Duration::from_secs(8), supervise(refresh, initial, shared(8, 8), rx))
            .await
            .expect("supervisor must terminate on a fatal refresh, not hang");
    }
}
