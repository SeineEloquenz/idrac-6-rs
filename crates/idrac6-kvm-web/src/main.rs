//! `idrac6-kvm-web`, the self-serve browser console. Login is entered in the browser and no
//! secret is stored on the server. The app itself lives in [`app`].

mod app;

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "idrac6-kvm-web",
    about = "iDRAC 6 self-serve noVNC web console"
)]
struct Cli {
    /// iDRAC hostname or IP. Credentials are entered in the browser, never stored here.
    #[arg(long, env = "IDRAC_HOST")]
    host: String,
    /// Username pre-filled on the login form.
    #[arg(long, default_value = "root")]
    user: String,
    /// Address to expose the web UI on (plain HTTP, front it with a TLS reverse proxy).
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
    idrac6_kvm::init_tracing();
    let cli = Cli::parse();
    app::run(
        cli.host,
        cli.user,
        cli.listen,
        cli.novnc_root,
        cli.idle_timeout,
    )
    .await
}
