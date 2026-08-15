//! Self-serve web mode. A login page authenticates with the iDRAC account credentials, opens
//! the KVM backend, and serves noVNC over an in-process RFB-over-WebSocket bridge. No secret is
//! stored on the server. The iDRAC credentials entered in the browser are the only credential.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Form, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tower_http::services::ServeDir;
use tracing::{info, warn};

use idrac6_kvm::server::rfb;
use idrac6_kvm::session::{input, kvm};
use idrac6_proto::auth;

const COOKIE: &str = "idrac6_session";
// noVNC resolves its `path` relative to the page URL, so the viewer must sit at the web root
// for `path=websockify` to reach `/websockify` (works with no explicit host and behind a proxy).
const VIEWER_URL: &str = "/vnc.html?path=websockify&autoconnect=true&resize=scale&reconnect=true";

/// A live KVM backend plus the web-session handle needed to release it on the iDRAC.
struct Backend {
    token: String,
    shared: kvm::SharedFb,
    input: mpsc::Sender<input::Input>,
    task: JoinHandle<()>,
    host: String,
    cookies: Vec<(String, String)>,
    st1: Option<String>,
    viewers: AtomicUsize,
    last_active: Mutex<Instant>,
}

impl Backend {
    async fn teardown(&self) {
        self.task.abort();
        if !self.cookies.is_empty() {
            let _ = auth::web_logout(&self.host, &self.cookies, self.st1.as_deref()).await;
        }
    }
}

struct AppState {
    host: String,
    default_user: String,
    idle_timeout: Duration,
    backend: Mutex<Option<Arc<Backend>>>,
}

impl AppState {
    /// Return the live backend iff the request carries its session cookie.
    async fn authed(&self, headers: &HeaderMap) -> Option<Arc<Backend>> {
        let token = cookie_value(headers, COOKIE)?;
        let guard = self.backend.lock().await;
        let b = guard.as_ref()?;
        (b.token == token).then(|| b.clone())
    }
}

pub(crate) async fn run(
    host: String,
    user: String,
    listen: String,
    novnc_root: PathBuf,
    idle_secs: u64,
) -> Result<()> {
    if !novnc_root.join("vnc.html").is_file() {
        warn!(root = %novnc_root.display(), "noVNC vnc.html not found under --novnc-root; the viewer will 404");
    }
    let state = Arc::new(AppState {
        host,
        default_user: user,
        idle_timeout: Duration::from_secs(idle_secs),
        backend: Mutex::new(None),
    });
    tokio::spawn(reaper(state.clone()));

    let app = Router::new()
        .route("/", get(root))
        .route("/login", post(login))
        .route("/logout", get(logout).post(logout))
        .route("/websockify", get(websockify))
        .fallback_service(ServeDir::new(&novnc_root))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("bind {listen}"))?;
    info!(%listen, host = %state.host, "web UI listening (plain HTTP — front with a TLS reverse proxy)");
    axum::serve(listener, app)
        .with_graceful_shutdown(idrac6_kvm::shutdown_signal())
        .await?;

    if let Some(b) = state.backend.lock().await.take() {
        info!("shutting down; releasing KVM session");
        b.teardown().await;
    }
    Ok(())
}

async fn root(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if st.authed(&headers).await.is_some() {
        Redirect::to(VIEWER_URL).into_response()
    } else {
        Html(login_page(&st.host, &st.default_user, None)).into_response()
    }
}

#[derive(Deserialize)]
struct LoginForm {
    #[serde(default)]
    user: String,
    #[serde(default)]
    password: String,
}

async fn login(State(st): State<Arc<AppState>>, Form(form): Form<LoginForm>) -> Response {
    let user = if form.user.is_empty() {
        st.default_user.clone()
    } else {
        form.user
    };
    let password = form.password;

    let session = match auth::login_and_get_token(&st.host, &user, &password).await {
        Ok(s) => s,
        Err(e) => {
            let status = match &e {
                auth::AuthError::BadCredentials => StatusCode::UNAUTHORIZED,
                auth::AuthError::NoPrivilege => StatusCode::FORBIDDEN,
                auth::AuthError::MaxSessions => StatusCode::SERVICE_UNAVAILABLE,
                auth::AuthError::Other(_) => StatusCode::BAD_GATEWAY,
            };
            warn!("web login rejected ({status}): {e:#}");
            return (
                status,
                Html(login_page(&st.host, &st.default_user, Some(&e.to_string()))),
            )
                .into_response();
        }
    };

    let token = random_token();
    let (host, cookies, st1) = (
        session.host.clone(),
        session.web_cookies.clone(),
        session.web_st1.clone(),
    );
    let refresh = kvm::refresh_from_web(host.clone(), user.clone(), cookies.clone(), st1.clone());
    let (shared, input, task) = kvm::spawn(refresh, session);
    let backend = Arc::new(Backend {
        token: token.clone(),
        shared,
        input,
        task,
        host,
        cookies,
        st1,
        viewers: AtomicUsize::new(0),
        last_active: Mutex::new(Instant::now()),
    });

    // The appliance gives keyboard and mouse to one session only, so a new login takes over and
    // releases the previous one.
    if let Some(old) = st.backend.lock().await.replace(backend) {
        tokio::spawn(async move { old.teardown().await });
    }
    info!(%user, "web login ok; KVM session started");

    let cookie = format!("{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/");
    ([(header::SET_COOKIE, cookie)], Redirect::to(VIEWER_URL)).into_response()
}

async fn logout(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(b) = st.authed(&headers).await {
        if st
            .backend
            .lock()
            .await
            .as_ref()
            .is_some_and(|c| c.token == b.token)
        {
            if let Some(cur) = st.backend.lock().await.take() {
                tokio::spawn(async move { cur.teardown().await });
            }
        }
    }
    let clear = format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    ([(header::SET_COOKIE, clear)], Redirect::to("/")).into_response()
}

async fn websockify(
    ws: WebSocketUpgrade,
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    match st.authed(&headers).await {
        Some(backend) => {
            info!("websocket upgrade for authenticated viewer");
            ws.on_upgrade(move |socket| bridge(socket, backend))
        }
        None => {
            warn!("websocket rejected: no valid session cookie");
            (StatusCode::UNAUTHORIZED, "not authenticated").into_response()
        }
    }
}

/// Pump RFB bytes between the browser WebSocket and an in-process RFB server over a duplex pipe.
async fn bridge(mut socket: WebSocket, backend: Arc<Backend>) {
    backend.viewers.fetch_add(1, Ordering::SeqCst);

    let (rfb_side, ws_side) = tokio::io::duplex(1 << 16);
    let shared = backend.shared.clone();
    let input = backend.input.clone();
    let rfb_task = tokio::spawn(async move {
        if let Err(e) = rfb::serve_conn(rfb_side, shared, input).await {
            warn!("RFB-over-WebSocket ended: {e:#}");
        }
    });

    let (mut rd, mut wr) = tokio::io::split(ws_side);
    let mut buf = vec![0u8; 1 << 15];
    loop {
        tokio::select! {
            msg = socket.recv() => match msg {
                Some(Ok(Message::Binary(b))) => { if wr.write_all(&b).await.is_err() { break; } }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {} // ignore text/ping/pong (axum auto-replies to pings)
            },
            r = rd.read(&mut buf) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if socket.send(Message::Binary(Bytes::copy_from_slice(&buf[..n]))).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    rfb_task.abort();
    backend.viewers.fetch_sub(1, Ordering::SeqCst);
    *backend.last_active.lock().await = Instant::now();
}

/// Release a backend that has had no viewers for longer than the idle timeout, so leaked iDRAC
/// sessions do not accumulate toward the appliance's session limit.
async fn reaper(st: Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        let idle = {
            let guard = st.backend.lock().await;
            match guard.as_ref() {
                Some(b) if b.viewers.load(Ordering::SeqCst) == 0 => {
                    b.last_active.lock().await.elapsed() > st.idle_timeout
                }
                _ => false,
            }
        };
        if idle {
            if let Some(b) = st.backend.lock().await.take() {
                info!("idle timeout: releasing KVM session");
                b.teardown().await;
            }
        }
    }
}

fn login_page(host: &str, default_user: &str, error: Option<&str>) -> String {
    let err = error
        .map(|e| format!("<p class=\"err\">{}</p>", html_escape(e)))
        .unwrap_or_default();
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>iDRAC 6 KVM</title>
<style>
:root {{ color-scheme: light dark; --bg:#0b0d12; --card:#151922; --line:#2a3140; --fg:#e6e9ef; --muted:#9aa4b2; --accent:#2563eb; --err:#f87171; }}
@media (prefers-color-scheme: light) {{ :root {{ --bg:#f3f4f6; --card:#fff; --line:#d1d5db; --fg:#111827; --muted:#6b7280; }} }}
* {{ box-sizing: border-box; }}
body {{ font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--fg); display: grid; place-items: center; min-height: 100vh; margin: 0; }}
form {{ display: grid; gap: 1rem; width: min(22rem, 92vw); padding: 2rem; background: var(--card); border: 1px solid var(--line); border-radius: .75rem; box-shadow: 0 10px 30px #0006; }}
.title {{ margin: 0; font-size: 1.25rem; font-weight: 650; }}
.sub {{ margin: -.6rem 0 .2rem; font-size: .8rem; color: var(--muted); }}
label {{ display: grid; gap: .35rem; font-size: .8rem; color: var(--muted); }}
input {{ padding: .6rem .7rem; font: inherit; color: var(--fg); background: var(--bg); border: 1px solid var(--line); border-radius: .45rem; }}
input:focus {{ outline: 2px solid var(--accent); outline-offset: 1px; border-color: transparent; }}
button {{ margin-top: .3rem; padding: .65rem; font: inherit; font-weight: 600; cursor: pointer; border: 0; border-radius: .45rem; background: var(--accent); color: #fff; display: flex; align-items: center; justify-content: center; gap: .5rem; }}
button[disabled] {{ opacity: .8; cursor: progress; }}
.spin {{ width: 1em; height: 1em; border: 2px solid #fff8; border-top-color: #fff; border-radius: 50%; animation: r .7s linear infinite; display: none; }}
@keyframes r {{ to {{ transform: rotate(360deg); }} }}
.err {{ margin: 0; padding: .6rem .7rem; font-size: .82rem; color: var(--err); background: #f871711a; border: 1px solid #f8717155; border-radius: .45rem; }}
</style></head><body>
<form method="post" action="/login" onsubmit="this.querySelector('button').disabled=true;this.querySelector('.spin').style.display='inline-block';this.querySelector('.lbl').textContent='Connecting…'">
<h1 class="title">iDRAC 6 KVM console</h1>
<p class="sub">{host}</p>
{err}
<label>Username<input name="user" value="{user}" autocomplete="username" autofocus></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit"><span class="spin"></span><span class="lbl">Connect</span></button>
</form></body></html>"#,
        host = html_escape(host),
        user = html_escape(default_user),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for h in headers.get_all(header::COOKIE) {
        let Ok(s) = h.to_str() else { continue };
        for pair in s.split(';') {
            if let Some((k, v)) = pair.trim().split_once('=') {
                if k == name {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

fn random_token() -> String {
    let mut b = [0u8; 32];
    openssl::rand::rand_bytes(&mut b).ok();
    to_hex(&b)
}

/// Lowercase hex encoding of a byte slice.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
