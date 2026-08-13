//! Minimal RFB 3.8 (VNC) server exposing the shared framebuffer. Security = None, one Raw
//! encoding. Any native VNC client works; browser access is layered on via noVNC + websockify
//! (NixOS module). Input events are forwarded to the KVM session.

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::kvm::{Input, SharedFb};

pub async fn serve(listener: TcpListener, shared: SharedFb, input: mpsc::Sender<Input>) -> Result<()> {
    loop {
        let (sock, peer) = listener.accept().await.context("accept")?;
        info!(%peer, "RFB client connected");
        let fb = shared.clone();
        let tx = input.clone();
        tokio::spawn(async move {
            if let Err(e) = client(sock, fb, tx).await {
                warn!(%peer, "RFB client ended: {e:#}");
            }
        });
    }
}

async fn client(mut sock: TcpStream, shared: SharedFb, input: mpsc::Sender<Input>) -> Result<()> {
    sock.set_nodelay(true).ok();

    // ProtocolVersion
    sock.write_all(b"RFB 003.008\n").await?;
    let mut ver = [0u8; 12];
    sock.read_exact(&mut ver).await?;

    // Security: offer only None (type 1).
    sock.write_all(&[1u8, 1u8]).await?;
    let mut chosen = [0u8; 1];
    sock.read_exact(&mut chosen).await?;
    sock.write_all(&0u32.to_be_bytes()).await?; // SecurityResult = OK

    // ClientInit (shared-flag) -> ServerInit
    let mut client_init = [0u8; 1];
    sock.read_exact(&mut client_init).await?;
    let (w, h) = {
        let g = shared.lock().unwrap();
        (g.fb.width as u16, g.fb.height as u16)
    };
    sock.write_all(&server_init(w, h)).await?;

    let mut last_gen = u64::MAX;
    let mut ty = [0u8; 1];
    loop {
        sock.read_exact(&mut ty).await?;
        match ty[0] {
            0 => {
                let mut b = [0u8; 19]; // SetPixelFormat
                sock.read_exact(&mut b).await?;
            }
            2 => {
                let mut b = [0u8; 3]; // SetEncodings: pad + count
                sock.read_exact(&mut b).await?;
                let n = u16::from_be_bytes([b[1], b[2]]) as usize;
                let mut enc = vec![0u8; n * 4];
                sock.read_exact(&mut enc).await?;
            }
            3 => {
                let mut b = [0u8; 9]; // FramebufferUpdateRequest
                sock.read_exact(&mut b).await?;
                send_update(&mut sock, &shared, &mut last_gen).await?;
            }
            4 => {
                let mut b = [0u8; 7]; // KeyEvent: down(1)+pad(2)+keysym(4)
                sock.read_exact(&mut b).await?;
                let down = b[0] != 0;
                let keysym = u32::from_be_bytes([b[3], b[4], b[5], b[6]]);
                // send (not try_send): never drop a key event — a lost key-up sticks a key.
                let _ = input.send(Input::Key { down, keysym }).await;
            }
            5 => {
                let mut b = [0u8; 5]; // PointerEvent: buttons(1)+x(2)+y(2)
                sock.read_exact(&mut b).await?;
                let _ = input
                    .send(Input::Pointer {
                        buttons: b[0],
                        x: u16::from_be_bytes([b[1], b[2]]),
                        y: u16::from_be_bytes([b[3], b[4]]),
                    })
                    .await;
            }
            6 => {
                let mut b = [0u8; 7]; // ClientCutText: pad(3)+len(4)
                sock.read_exact(&mut b).await?;
                let n = u32::from_be_bytes([b[3], b[4], b[5], b[6]]) as usize;
                let mut skip = vec![0u8; n];
                sock.read_exact(&mut skip).await?;
            }
            other => anyhow::bail!("unknown RFB client message {other}"),
        }
    }
}

fn server_init(w: u16, h: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(24 + 10);
    v.extend_from_slice(&w.to_be_bytes());
    v.extend_from_slice(&h.to_be_bytes());
    // PixelFormat: 32bpp, depth 24, little-endian, true-colour, RGB in shifts 16/8/0.
    v.extend_from_slice(&[32, 24, 0, 1]);
    v.extend_from_slice(&255u16.to_be_bytes()); // red-max
    v.extend_from_slice(&255u16.to_be_bytes()); // green-max
    v.extend_from_slice(&255u16.to_be_bytes()); // blue-max
    v.extend_from_slice(&[16, 8, 0, 0, 0, 0]); // shifts + padding
    let name = b"idrac6-kvm";
    v.extend_from_slice(&(name.len() as u32).to_be_bytes());
    v.extend_from_slice(name);
    v
}

/// Send a FramebufferUpdate. Waits briefly for a new frame; if none, sends an empty update.
async fn send_update(sock: &mut TcpStream, shared: &SharedFb, last_gen: &mut u64) -> Result<()> {
    // Wait up to ~1s for a change so idle clients don't busy-loop.
    let mut waited = 0;
    let (w, h, gen, pixels) = loop {
        let snap = {
            let g = shared.lock().unwrap();
            (g.fb.width, g.fb.height, g.generation, if g.generation != *last_gen { Some(g.fb.pixels.clone()) } else { None })
        };
        if let (w, h, gen, Some(px)) = snap {
            break (w, h, gen, px);
        }
        if waited >= 1000 {
            // no change: empty update (0 rectangles)
            sock.write_all(&[0u8, 0, 0, 0]).await?;
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        waited += 30;
    };
    *last_gen = gen;

    let mut msg = Vec::with_capacity(16 + pixels.len() * 4);
    msg.extend_from_slice(&[0u8, 0]); // message-type 0 + padding
    msg.extend_from_slice(&1u16.to_be_bytes()); // number-of-rectangles
    msg.extend_from_slice(&0u16.to_be_bytes()); // x
    msg.extend_from_slice(&0u16.to_be_bytes()); // y
    msg.extend_from_slice(&(w as u16).to_be_bytes());
    msg.extend_from_slice(&(h as u16).to_be_bytes());
    msg.extend_from_slice(&0i32.to_be_bytes()); // encoding: Raw
    for px in &pixels {
        msg.extend_from_slice(&px.to_le_bytes()); // 0xFFRRGGBB -> [B,G,R,FF]
    }
    sock.write_all(&msg).await?;
    Ok(())
}
