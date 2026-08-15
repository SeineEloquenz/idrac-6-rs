//! `idrac6-kvm-serve`: connect + authenticate to the iDRAC KVM console and re-expose it as a
//! plain RFB/VNC server for native clients.

use anyhow::{Context, Result};
use clap::{Args, Parser};
use tokio::net::TcpListener;
use tracing::info;

use idrac6_kvm::{appliance::auth, server::rfb, session::kvm};

#[derive(Parser)]
#[command(name = "idrac6-kvm-serve", about = "iDRAC 6 KVM console as an RFB/VNC proxy")]
struct Cli {
    #[command(flatten)]
    conn: ConnArgs,
    /// Address to expose the RFB/VNC server on.
    #[arg(long, env = "IDRAC_LISTEN", default_value = "127.0.0.1:5900")]
    listen: String,
}

#[derive(Args)]
struct ConnArgs {
    /// iDRAC hostname or IP.
    #[arg(long, env = "IDRAC_HOST")]
    host: Option<String>,
    /// iDRAC username (defaults to root).
    #[arg(long, env = "IDRAC_USER")]
    user: Option<String>,
    /// iDRAC account password.
    #[arg(long, env = "IDRAC_PASSWORD")]
    password: Option<String>,
    /// Primary (video) channel port override. Defaults to 5900, the R710's multiplexed port.
    #[arg(long)]
    video_port: Option<u16>,
    /// Keyboard/mouse channel port override. Defaults to 5900.
    #[arg(long)]
    kvm_port: Option<u16>,
}

impl ConnArgs {
    /// Web-login with account credentials to mint a fresh KVM token.
    async fn session(&self) -> Result<auth::Session> {
        let host = self.host.clone().context("--host/IDRAC_HOST required")?;
        let user = self.user.clone().unwrap_or_else(|| "root".into());
        let password = self.password.clone().context("--password/IDRAC_PASSWORD required")?;
        info!(%host, %user, "web login to mint KVM token");
        let mut s = auth::login_and_get_token(&host, &user, &password).await?;
        if let Some(p) = self.video_port {
            s.video_port = p;
        }
        if let Some(p) = self.kvm_port {
            s.kvm_port = p;
        }
        Ok(s)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    idrac6_kvm::init_tracing();
    let cli = Cli::parse();

    let listener = TcpListener::bind(&cli.listen).await.with_context(|| format!("bind {}", cli.listen))?;

    let s = cli.conn.session().await?;
    // Keep the web-session handle for logout on shutdown (the KVM token is bound to it, so we
    // must not log out while streaming).
    let (host, cookies, st1) = (s.host.clone(), s.web_cookies.clone(), s.web_st1.clone());
    // Reconnect by re-minting a KVM token from the same web session.
    let user = cli.conn.user.clone().unwrap_or_else(|| "root".into());
    let refresh = kvm::refresh_from_web(host.clone(), user, cookies.clone(), st1.clone());
    let (shared, input, _task) = kvm::spawn(refresh, s);
    info!(listen = %cli.listen, "RFB server listening — point a VNC client here (Ctrl-C to stop)");

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
