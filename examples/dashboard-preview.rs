//! Local preview server for the aa-proxy-rs web dashboard.
//!
//! Run with:
//!     cargo run --example dashboard-preview
//!
//! Then browse http://localhost:8088
//!
//! Unlike the real `aa-proxy-rs` binary, this preview:
//!   * reads `static/index.html`, `static/styles.css`, `static/pico.min.css`,
//!     `static/config.json`, and `static/aa-proxy-rs.webp` at REQUEST time (no
//!     `include_str!`), so HTML / CSS / config-schema edits show up on a
//!     browser refresh with no rebuild.
//!   * needs no Bluetooth, USB, or kernel features — every aa-proxy-rs side
//!     effect (restart, reboot, key tap, toll-card, etc.) is logged to stdout
//!     and returns 200.
//!   * loads its starting config from `WebUI/web-dev/config.toml` if present,
//!     otherwise falls back to `AppConfig::default()`. Saves are kept in
//!     memory only.
//!
//! When you change the renderer in `src/web.rs`, run `cargo run --example
//! dashboard-preview` again — only the renderer module recompiles.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aa_proxy_rs::config::{AppConfig, ConfigJson};
use aa_proxy_rs::web::{render_config_values, render_config_ids};

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use serde_json::{json, Value};
use tokio::sync::RwLock;

const STATIC_DIR: &str = "static";
const PREVIEW_CONFIG_TOML: &str = "../WebUI/web-dev/config.toml";
const BIND_ADDR: &str = "127.0.0.1:8088";

struct AppState {
    config: RwLock<AppConfig>,
}

#[tokio::main]
async fn main() {
    let cfg = match AppConfig::load(PathBuf::from(PREVIEW_CONFIG_TOML)) {
        Ok(c) => {
            eprintln!("[preview] loaded starting config from {PREVIEW_CONFIG_TOML}");
            c
        }
        Err(e) => {
            eprintln!(
                "[preview] {PREVIEW_CONFIG_TOML} not loadable ({e}); using AppConfig::default()"
            );
            AppConfig::default()
        }
    };

    let state = Arc::new(AppState {
        config: RwLock::new(cfg),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/aa-proxy-rs.webp", get(logo))
        .route("/config", get(get_config).post(set_config))
        // Endpoints the dashboard JS hits. We log + return 200 so the UI
        // doesn't surface errors during preview.
        .route("/restart", post(noop_action))
        .route("/reboot", post(noop_action))
        .route("/disconnect", post(noop_action))
        .route("/factory-reset", post(noop_action))
        .route("/input/key", post(noop_action))
        .route("/toll-card/add", post(noop_action))
        .route("/toll-card/remove", post(noop_action))
        .route("/bt/known-devices", any(noop_action))
        .route("/upload-certs", post(noop_action))
        .route("/userdata-restore", post(noop_action))
        // Catch-all: log and return 200 for any other dashboard action that
        // might exist now or later.
        .fallback(unhandled)
        .with_state(state);

    let addr: SocketAddr = BIND_ADDR.parse().expect("valid bind address");
    eprintln!("[preview] serving dashboard on http://{addr}");
    eprintln!("[preview] static files read from ./{STATIC_DIR}/ at request time");
    eprintln!("[preview] refresh the page after editing HTML/CSS/config.json");

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn index() -> impl IntoResponse {
    let template = match read_static("index.html") {
        Ok(s) => s,
        Err(e) => return preview_error("read static/index.html", e.into()),
    };
    let pico = read_static("pico.min.css").unwrap_or_default();
    let styles = read_static("styles.css").unwrap_or_default();
    let config_json_raw = match read_static("config.json") {
        Ok(s) => s,
        Err(e) => return preview_error("read static/config.json", e.into()),
    };
    let cfg: ConfigJson = match serde_json::from_str(&config_json_raw) {
        Ok(c) => c,
        Err(e) => return preview_error("parse static/config.json", e.into()),
    };

    let html = template
        .replace("{BUILD_DATE}", "preview")
        .replace("{GIT_INFO}", "dashboard-preview")
        .replace("{PICO_CSS}", &pico)
        .replace("{STYLES_CSS}", &styles)
        .replace("{CONFIG_VALUES}", &render_config_values(&cfg))
        .replace("{CONFIG_IDS}", &render_config_ids(&cfg))
        .replace("{LOGO_URL}", "/aa-proxy-rs.webp");

    Html(html).into_response()
}

async fn logo() -> Response {
    match std::fs::read(static_path("aa-proxy-rs.webp")) {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "image/webp"),
                (header::CACHE_CONTROL, "no-cache"),
            ],
            bytes,
        )
            .into_response(),
        Err(e) => preview_error("read static/aa-proxy-rs.webp", e.into()),
    }
}

async fn get_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cfg = state.config.read().await.clone();
    let val = serde_json::to_value(cfg).unwrap_or_else(|_| json!({}));
    Json(val)
}

async fn set_config(
    State(state): State<Arc<AppState>>,
    Json(raw): Json<Value>,
) -> impl IntoResponse {
    eprintln!(
        "[preview] /config POST received ({} keys)",
        raw.as_object().map(|o| o.len()).unwrap_or(0)
    );
    match serde_json::from_value::<AppConfig>(raw.clone()) {
        Ok(new_cfg) => {
            *state.config.write().await = new_cfg;
            (StatusCode::OK, Json(raw)).into_response()
        }
        Err(e) => {
            eprintln!("[preview] /config POST rejected: {e}");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "status": "error", "message": e.to_string() })),
            )
                .into_response()
        }
    }
}

async fn noop_action() -> impl IntoResponse {
    eprintln!("[preview] action endpoint hit (no-op)");
    (StatusCode::OK, "OK")
}

async fn unhandled(method: axum::http::Method, uri: axum::http::Uri) -> impl IntoResponse {
    eprintln!("[preview] unhandled {method} {uri} -> 200 OK no-op");
    (StatusCode::OK, "OK (preview no-op)")
}

fn read_static(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(static_path(name))
}

fn static_path(name: &str) -> PathBuf {
    Path::new(STATIC_DIR).join(name)
}

fn preview_error(context: &str, err: Box<dyn std::error::Error>) -> Response {
    let msg = format!("[preview] failed to {context}: {err}");
    eprintln!("{msg}");
    (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
}
