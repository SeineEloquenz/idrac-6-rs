//! iDRAC 6 KVM proxy library: talk to the appliance's APCP/legacy-TLS console and re-expose it
//! as RFB/VNC (native clients) or a self-serve noVNC web app. The `idrac6-kvm-serve` and
//! `idrac6-kvm-web` binaries are thin CLIs over these modules.

pub mod server;
pub mod session;

/// The pure video codec + framebuffer, re-exported so `crate::video` paths resolve.
pub(crate) use idrac6_video as video;

/// Initialize the tracing subscriber from `RUST_LOG` (default `idrac6_kvm=info,info`).
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "idrac6_kvm=info,info".into()),
        )
        .init();
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
