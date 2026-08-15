//! iDRAC 6 KVM proxy library: talk to the appliance's APCP/legacy-TLS console and re-expose it
//! as RFB/VNC (native clients) or a self-serve noVNC web app. The `idrac6-kvm` binary is a thin
//! CLI over these modules.

pub mod apcp;
pub mod auth;
pub mod http;
pub mod input;
pub mod kvm;
pub mod rfb;
pub mod tls;
#[cfg(feature = "web")]
pub mod web;

/// The pure video codec + framebuffer, re-exported so `crate::video` paths keep resolving.
pub use idrac6_video as video;

/// Initialize the tracing subscriber from `RUST_LOG` (default `idrac6_kvm=info,info`).
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "idrac6_kvm=info,info".into()),
        )
        .init();
}

/// Lowercase hex encoding of a byte slice.
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Resolve on Ctrl-C (SIGINT) or SIGTERM, for graceful shutdown.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}
