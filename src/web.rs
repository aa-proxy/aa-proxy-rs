use crate::bluetooth::{load_known_devices, KNOWN_DEVICES_FILE};
use crate::bt_helper;
#[cfg(feature = "wasm-scripting")]
use crate::config::wasm_script_limits_config_section;
use crate::config::Action;
use crate::config::AppConfig;
use crate::config::ConfigJson;
use crate::config::ConfigValue;
use crate::config::ConfigValues;
use crate::config::SharedConfig;
use crate::config::SharedConfigJson;
use crate::config::BASE_CONFIG_DIR;
use crate::crash;
use crate::device_info;
use crate::ev::send_ev_data;
use crate::ev::BatteryData;
use crate::ev::EV_MODEL_FILE;
use crate::inject_displays;
use crate::map_album_art::{
    global_album_art_store, replacement_png_for_config, status_for_config, validate_png,
};
use crate::mitm::protos::KeyCode;
use crate::mitm::send_byebye;
use crate::mitm::send_input_key;
use crate::mitm::send_key_event;
use crate::mitm::send_rotary_event;
use crate::mitm::send_toll_card;
use crate::mitm::Packet;
use crate::mitm::Result;
use crate::mitm::SharedServiceDiscoveryResponse;
use crate::mitm::{send_odometer_data, OdometerData};
use crate::mitm::{send_tire_pressure_data, TirePressureData};
use crate::mitm::{SharedCompanionIp, SharedMediaChannels, SharedMediaTapEndpoints};
use crate::proxy::media_tap_reverse_bridge_once;
#[cfg(feature = "wasm-scripting")]
use crate::script_wasm::{LoadedScript, ScriptRegistry};
use crate::sdr_ui;
use crate::sdr_ui_preview;
#[cfg(not(feature = "wasm-scripting"))]
type ScriptRegistry = ();
use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, RawBody, State,
    },
    http::{header, HeaderMap, Response, StatusCode},
    response::{Html, IntoResponse},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::Local;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use futures::{SinkExt, StreamExt};
use glob::glob;
use hyper::body::to_bytes;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use simplelog::*;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::{io::Cursor, path::Path, sync::Arc};
use tar::Archive;
use tar::Builder;
use time::OffsetDateTime;
use tokio::fs;
use tokio::fs::File;
use tokio::io::duplex;
use tokio::io::AsyncWriteExt;
use tokio::io::DuplexStream;
use tokio::sync::broadcast;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio_util::io::ReaderStream;
use toml_edit::{value, DocumentMut};

const TEMPLATE: &str = include_str!("../static/index.html");
const PICO_CSS: &str = include_str!("../static/pico.min.css");
const STYLES_CSS: &str = include_str!("../static/styles.css");
const LOGO_WEBP: &[u8] = include_bytes!("../static/aa-proxy-rs.webp");
const AA_PROXY_RS_URL: &str = "https://github.com/aa-proxy/aa-proxy-rs";
const BUILDROOT_URL: &str = "https://github.com/aa-proxy/buildroot";
const CERT_SHA_FILENAME: &str = "cert-bundle.sha";

// module name for logging engine
const NAME: &str = "<i><bright-black> web: </>";

#[derive(Debug, Deserialize)]
pub struct InjectEventData {
    /// eg. "KEYCODE_HOME", "KEYCODE_BACK", "KEYCODE_SEARCH"
    pub keycode: String,
}

#[derive(Debug, Deserialize)]
pub struct InjectRotaryData {
    /// Positive = clockwise, negative = counterclockwise.
    /// Absolute value of 1 = single UI step (scales linearly).
    pub delta: i32,
}

#[derive(Debug, Deserialize)]
pub struct UpdateConfigEntry {
    /// Configuration key name (e.g., "dpi", "ssid", "mitm")
    pub key: String,
    /// New value for the configuration key
    pub value: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerEvent {
    pub topic: String,
    pub payload: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientWsMessage {
    Subscribe { topic: String },
    Unsubscribe { topic: String },
    ScriptEvent { topic: String, payload: String },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerWsMessage {
    Event { topic: String, payload: String },
    Subscribed { topic: String },
    Unsubscribed { topic: String },
    Error { message: String },
}

#[derive(Clone)]
pub struct AppState {
    pub config: SharedConfig,
    pub config_json: SharedConfigJson,
    pub config_file: Arc<PathBuf>,
    pub tx: Arc<Mutex<Option<Sender<Packet>>>>,
    pub sensor_channel: Arc<Mutex<Option<u8>>>,
    pub input_channel: Arc<Mutex<Option<u8>>>,
    pub last_battery_data: Arc<RwLock<Option<BatteryData>>>,
    pub last_odometer_data: Arc<RwLock<Option<OdometerData>>>,
    pub last_speed: Arc<RwLock<Option<i32>>>,
    pub last_service_discovery_response: SharedServiceDiscoveryResponse,
    pub media_tap_endpoints: SharedMediaTapEndpoints,
    pub shared_media_channels: SharedMediaChannels,
    pub companion_ip: SharedCompanionIp,
    pub last_tire_pressure_data: Arc<RwLock<Option<TirePressureData>>>,
    pub ws_event_tx: broadcast::Sender<ServerEvent>,
    pub script_registry: Option<Arc<ScriptRegistry>>,
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/config", get(get_config).post(set_config))
        .route("/config-entry", post(update_config_entry))
        .route("/config-data", get(get_config_data))
        .route("/config-data-tree", get(get_config_data_tree))
        .route(
            "/map-album-art",
            post(map_album_art_upload_handler)
                .get(map_album_art_get_handler)
                .delete(map_album_art_delete_handler),
        )
        .route("/map-album-art-status", get(map_album_art_status_handler))
        .route("/download", get(download_handler))
        .route(
            "/crashes",
            get(crashes_list_handler).delete(crashes_clear_handler),
        )
        .route(
            "/crashes/:filename",
            get(crashes_read_handler).delete(crashes_delete_handler),
        )
        .route("/restart", post(restart_handler))
        .route("/reboot", post(reboot_handler))
        .route("/upload-hex-model", post(upload_hex_model_handler))
        .route("/upload-certs", post(upload_cert_bundle_handler))
        .route("/certs-info", get(certs_info_handler))
        .route("/battery", post(battery_handler))
        .route("/battery-status", get(battery_status_handler))
        .route("/odometer", post(odometer_handler))
        .route("/odometer-status", get(odometer_status_handler))
        .route("/tire-pressure", post(tire_pressure_handler))
        .route("/tire-pressure-status", get(tire_pressure_status_handler))
        .route("/inject_event", post(inject_event_handler))
        .route("/inject_rotary", post(inject_rotary_handler))
        .route("/toll-card/add", post(toll_card_add_handler))
        .route("/toll-card/remove", post(toll_card_remove_handler))
        .route("/input/key", post(input_key_handler))
        .route("/userdata-backup", get(userdata_backup_handler))
        .route("/userdata-restore", post(userdata_restore_handler))
        .route("/factory-reset", post(factory_reset_handler))
        .route("/set-time", post(set_time_handler))
        .route("/speed", get(speed_handler))
        .route("/sdr-ui/current", get(sdr_ui_current_handler))
        .route("/sdr-ui/preview/:channel", get(sdr_ui_preview_handler))
        .route("/sdr-ui/profiles", get(sdr_ui_profiles_list_handler))
        .route(
            "/sdr-ui/profiles/:vehicle_id",
            get(sdr_ui_profile_get_handler)
                .put(sdr_ui_profile_put_handler)
                .delete(sdr_ui_profile_delete_handler),
        )
        .route(
            "/service-discovery-response",
            get(service_discovery_response_handler),
        )
        .route("/media-taps", get(media_taps_handler))
        .route(
            "/media-taps/:endpoint_id/open",
            post(media_tap_open_handler),
        )
        .route(
            "/display-injection",
            get(display_injection_get_handler).put(display_injection_put_handler),
        )
        .route(
            "/display-injection/displays",
            post(display_injection_display_post_handler),
        )
        .route(
            "/display-injection/displays/:id",
            get(display_injection_display_get_handler)
                .put(display_injection_display_put_handler)
                .delete(display_injection_display_delete_handler),
        )
        .route("/version", get(version_handler))
        .route("/ws", get(ws_handler))
        .route("/raw-topic-data", post(raw_topic_data_handler))
        .route("/bt/devices", get(bt_helper::bt_devices_handler))
        .route(
            "/bt/devices/paired",
            get(bt_helper::bt_paired_devices_handler),
        )
        .route(
            "/bt/devices/:id",
            delete(bt_helper::bt_remove_device_handler),
        )
        .route(
            "/bt/known-devices",
            get(bt_known_devices_handler).delete(bt_forget_known_devices_handler),
        )
        .route("/disconnect", post(disconnect_handler))
        .route("/aa-proxy-rs.webp", get(logo_handler))
        .with_state(state)
}

fn linkify_git_info(git_date: &str, git_hash: &str) -> String {
    // check if git_date is really a YYYYMMDD date
    let is_date = git_date.len() == 8 && git_date.chars().all(|c| c.is_ascii_digit());

    if is_date {
        let clean_hash = git_hash.trim_end_matches("-dirty");
        let url = format!(
            "<a href=\"{}/commit/{}\" target=\"_blank\">{}</a>{}",
            AA_PROXY_RS_URL,
            clean_hash,
            clean_hash,
            {
                if clean_hash == git_hash {
                    ""
                } else {
                    "-dirty"
                }
            }
        );
        format!("{}-{}", git_date, url)
    } else if git_hash.starts_with("br#") {
        let url_aaproxy = format!(
            "<a href=\"{}/commit/{}\" target=\"_blank\">{}</a>",
            AA_PROXY_RS_URL, git_date, git_date,
        );

        let clean_hash = git_date.trim_start_matches("br#");
        let url_br = format!(
            "br#<a href=\"{}/commit/{}\" target=\"_blank\">{}</a>",
            BUILDROOT_URL, clean_hash, clean_hash,
        );
        format!("{}-{}", url_aaproxy, url_br)
    } else {
        // format not recognized, use without links
        format!("{}-{}", git_date, git_hash)
    }
}

fn replace_backticks(s: String) -> String {
    let re = Regex::new(r"`([^`]*)`").unwrap();
    re.replace_all(&s, "<code>$1</code>").to_string()
}

pub fn render_config_values(config: &ConfigJson) -> String {
    let mut html = String::new();
    for section in &config.titles {
        render_section(section, 0, &mut html);
    }
    html
}

/// Render one section, recursing into subsections. `depth` 0 selects the
/// top-level `.config-card` class; deeper sections use `.config-card.sub-card`.
fn render_section(section: &ConfigValues, depth: usize, html: &mut String) {
    // Split off a leading emoji so it renders in its own span. Convention in
    // config.json is "<emoji> TITLE".
    let (emoji, title_text) = match section.title.split_once(' ') {
        Some((head, rest)) if !head.chars().all(|c| c.is_ascii()) => (head, rest),
        _ => ("", section.title.as_str()),
    };

    let card_class = if depth == 0 {
        "config-card"
    } else {
        "config-card sub-card"
    };
    let advanced_attr = if section.advanced {
        r#" data-advanced="true""#
    } else {
        ""
    };
    let requires_attrs = requires_data_attrs(&section.requires);
    // `requires`-gated sections render closed by default; client-side
    // `evaluateRequires` opens them on met predicates and closes them again
    // when the dependency turns off.
    let has_requires = !matches!(section.requires, crate::config::Requires::None);
    let open_attr = if section.collapsed_by_default || has_requires {
        ""
    } else {
        " open"
    };

    html.push_str(&format!(
        r#"<div class="config-card-wrapper"{advanced_attr}{requires_attrs}>
  <div class="card-glass-bg"></div>
  <details class="{card_class}"{open_attr}>
  <summary class="card-header">
    <span class="card-header-title"><span>{emoji}</span> <span>{title_text}</span></span>
  </summary>
  <div class="card-content">
"#
    ));

    for (key, val) in &section.values {
        render_field(key, val, html);
    }

    for sub in &section.subsections {
        html.push_str(r#"<div class="sub-section-host">"#);
        render_section(sub, depth + 1, html);
        html.push_str("</div>\n");
    }

    html.push_str("  </div>\n</details>\n</div>\n");
}

fn render_field(key: &str, val: &ConfigValue, html: &mut String) {
    let desc = replace_backticks(val.description.replace('\n', "<br>"));

    // Any non-multiselect field with a `values` list renders as a
    // single-select dropdown, regardless of typ. `data-typ` is recorded so
    // the client can coerce the chosen string back to the right type on save.
    let has_options = val.values.as_ref().map(|v| !v.is_empty()).unwrap_or(false);

    let control_html = match val.typ.as_str() {
        // Accept both `multi-select` and `multiselect` typ spellings.
        "multi-select" | "multiselect" => render_multi_select(key, val.values.as_deref()),
        "select" => render_single_select(key, val.typ.as_str(), val.values.as_deref()),
        "boolean" => format!(r#"<input type="checkbox" role="switch" id="{key}" />"#),
        t if has_options => render_single_select(key, t, val.values.as_deref()),
        "integer" => format!(r#"<input type="number" id="{key}" />"#),
        "float" => format!(r#"<input type="number" step="any" id="{key}" />"#),
        "string" => format!(r#"<input type="text" id="{key}" />"#),
        _ => format!(r#"<input type="text" id="{key}" />"#),
    };

    let advanced_attr = if val.advanced {
        r#" data-advanced="true""#
    } else {
        ""
    };
    let requires_attrs = requires_data_attrs(&val.requires);

    html.push_str(&format!(
        r#"    <div class="config-field" data-field="{key}"{advanced_attr}{requires_attrs}>
      <div class="field-info">
        <div class="field-label">{key}</div>
        <div class="field-desc">{desc}</div>
      </div>
      <div class="control-wrap">{control_html}</div>
    </div>
"#
    ));
}

/// Build a leading-space-prefixed attribute string from a Requires.
/// JS reads `data-requires` (comma-separated truthy fields),
/// `data-requires-equals` (field=value), and `data-requires-contains`
/// (field=value for multiselect). All three combine with AND.
fn requires_data_attrs(req: &crate::config::Requires) -> String {
    use crate::config::Requires;
    match req {
        Requires::None => String::new(),
        Requires::Single(field) => format!(r#" data-requires="{field}""#),
        Requires::All(fields) => format!(r#" data-requires="{}""#, fields.join(",")),
        Requires::Predicate(p) => {
            let mut out = String::new();
            if let Some(v) = &p.equals {
                out.push_str(&format!(r#" data-requires-equals="{}={}""#, p.field, v));
            }
            if let Some(v) = &p.contains {
                out.push_str(&format!(r#" data-requires-contains="{}={}""#, p.field, v));
            }
            out
        }
    }
}

fn render_single_select(key: &str, typ: &str, options: Option<&[String]>) -> String {
    let opts = options.unwrap_or(&[]);
    let options_html = opts
        .iter()
        .map(|opt| format!(r#"<div class="single-select-option" data-value="{opt}">{opt}</div>"#))
        .collect::<Vec<_>>()
        .join("\n        ");

    format!(
        r#"<details class="single-select" id="{key}_details">
      <summary><span class="select-text"></span></summary>
      <div class="single-select-dropdown">
        {options_html}
      </div>
    </details>
    <input type="hidden" id="{key}" data-typ="{typ}" />"#
    )
}

fn render_multi_select(key: &str, options: Option<&[String]>) -> String {
    let opts = options.unwrap_or(&[]);
    let options_html = opts
        .iter()
        .map(|opt| format!(r#"<option value="{opt}">{opt}</option>"#))
        .collect::<Vec<_>>()
        .join("\n        ");

    // Native `<select multiple>` markup; the chip widget in
    // static/index.html progressively enhances it into a tag/chip UI.
    // `size` is clamped to 2..=8 so long lists don't overwhelm the row.
    format!(
        r#"<select id="{key}" multiple size="{}">
        {options_html}
    </select>"#,
        opts.len().clamp(2, 8)
    )
}

pub fn render_config_ids(config: &ConfigJson) -> String {
    let mut all_keys = Vec::new();
    for section in &config.titles {
        collect_keys(section, &mut all_keys);
    }
    all_keys.join(", ")
}

/// Recursively collect every field key in a section and its subsections
/// into the JS `CONFIG_IDS` array so `loadConfig` / `saveConfig` cover
/// nested fields too.
fn collect_keys(section: &ConfigValues, out: &mut Vec<String>) {
    for key in section.values.keys() {
        out.push(format!(r#""{key}""#));
    }
    for sub in &section.subsections {
        collect_keys(sub, out);
    }
}

async fn merged_config_json(state: &Arc<AppState>) -> ConfigJson {
    let mut cfg = state.config_json.read().await.clone();

    #[cfg(feature = "wasm-scripting")]
    {
        cfg.titles.push(wasm_script_limits_config_section());

        if let Some(registry) = &state.script_registry {
            registry.append_custom_config_sections(&mut cfg).await;
        }
    }

    cfg
}

async fn index(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config_json = merged_config_json(&state).await;

    let html = TEMPLATE
        .replace("{BUILD_DATE}", env!("BUILD_DATE"))
        .replace(
            "{GIT_INFO}",
            &linkify_git_info(env!("GIT_DATE"), env!("GIT_HASH")),
        )
        .replace("{PICO_CSS}", PICO_CSS)
        .replace("{STYLES_CSS}", STYLES_CSS)
        .replace("{CONFIG_VALUES}", &render_config_values(&config_json))
        .replace("{CONFIG_IDS}", &render_config_ids(&config_json))
        .replace("{LOGO_URL}", "/aa-proxy-rs.webp");
    Html(html)
}

async fn map_album_art_upload_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: RawBody,
) -> impl IntoResponse {
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        if let Ok(content_type) = content_type.to_str() {
            if !content_type
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("image/png")
            {
                return (
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Content-Type must be image/png",
                )
                    .into_response();
            }
        }
    }

    let cfg = state.config.read().await.clone();
    let max_bytes = cfg.map_album_art_max_bytes;

    if max_bytes > 0 {
        if let Some(len) = headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
        {
            if len > max_bytes {
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!(
                        "PNG is larger than map_album_art_max_bytes ({} > {})",
                        len, max_bytes
                    ),
                )
                    .into_response();
            }
        }
    }

    let bytes = match hyper::body::to_bytes(body.0).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("failed to read request body: {}", e),
            )
                .into_response();
        }
    };

    if let Err(e) = validate_png(&bytes, max_bytes) {
        let status = if max_bytes > 0 && bytes.len() > max_bytes {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        };
        return (status, e).into_response();
    }

    let version = global_album_art_store().set_png("rest", bytes.to_vec());
    info!(
        "{} map album art: accepted REST PNG upload ({} bytes, RAM only, version={})",
        NAME,
        bytes.len(),
        version
    );

    Json(serde_json::json!({
        "status": "ok",
        "source": "rest",
        "bytes": bytes.len(),
        "stored": "memory",
        "version": version
    }))
    .into_response()
}

async fn map_album_art_get_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cfg = state.config.read().await.clone();
    let Some(resolved) = replacement_png_for_config(&cfg) else {
        return (
            StatusCode::NOT_FOUND,
            "no map album art is available for the selected source",
        )
            .into_response();
    };

    match Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/png")
        .header("x-aa-proxy-album-art-source", resolved.source)
        .body(Body::from(resolved.png))
    {
        Ok(response) => response.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to build response: {}", e),
        )
            .into_response(),
    }
}

async fn map_album_art_status_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cfg = state.config.read().await.clone();
    Json(status_for_config(&cfg)).into_response()
}

async fn map_album_art_delete_handler() -> impl IntoResponse {
    let version = global_album_art_store().clear();
    Json(serde_json::json!({
        "status": "ok",
        "cleared": true,
        "version": version
    }))
    .into_response()
}

pub async fn battery_handler(
    State(state): State<Arc<AppState>>,
    Json(data): Json<BatteryData>,
) -> impl IntoResponse {
    match data.battery_level_percentage {
        Some(level) => {
            if level < 0.0 || level > 100.0 {
                let msg = format!(
                    "battery_level_percentage out of range: {} (expected 0.0–100.0)",
                    level
                );
                return (StatusCode::BAD_REQUEST, msg).into_response();
            }
        }
        None => {
            if data.battery_level_wh.is_none() {
                let msg = format!(
                    "Either `battery_level_percentage` or `battery_level_wh` has to be set",
                );
                return (StatusCode::BAD_REQUEST, msg).into_response();
            }
        }
    }

    info!("{} Received battery data: {:?}", NAME, data);

    if let Some(ch) = *state.sensor_channel.lock().await {
        if let Some(tx) = state.tx.lock().await.clone() {
            if let Err(e) =
                send_ev_data(tx.clone(), ch, data, state.last_battery_data.clone()).await
            {
                error!("{} EV model error: {}", NAME, e);
            }
        }
    } else {
        warn!("{} Not sending packet because no sensor channel yet", NAME);
    }

    (StatusCode::OK, "OK").into_response()
}

async fn battery_status_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let data = state.last_battery_data.read().await;
    match &*data {
        Some(d) => Json(serde_json::to_value(d).unwrap()).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

pub async fn odometer_handler(
    State(state): State<Arc<AppState>>,
    Json(data): Json<OdometerData>,
) -> impl IntoResponse {
    if data.odometer_km < 0.0 {
        return (StatusCode::BAD_REQUEST, "odometer_km must be >= 0.0").into_response();
    }

    info!("{} Received odometer data: {:?}", NAME, data);

    if let Some(ch) = *state.sensor_channel.lock().await {
        if let Some(tx) = state.tx.lock().await.clone() {
            if let Err(e) = send_odometer_data(
                tx,
                ch,
                data,
                state.last_odometer_data.clone(),
                state.ws_event_tx.clone(),
            )
            .await
            {
                error!("{} Odometer error: {}", NAME, e);
            }
        }
    } else {
        warn!(
            "{} Not sending odometer because no sensor channel yet",
            NAME
        );
    }

    (StatusCode::OK, "OK").into_response()
}

async fn odometer_status_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let data = state.last_odometer_data.read().await;
    match &*data {
        Some(d) => Json(serde_json::to_value(d).unwrap()).into_response(),
        None => (StatusCode::NO_CONTENT, "No odometer data yet").into_response(),
    }
}

pub async fn tire_pressure_handler(
    State(state): State<Arc<AppState>>,
    Json(data): Json<TirePressureData>,
) -> impl IntoResponse {
    if data.pressures_kpa.is_empty() || data.pressures_kpa.len() > 4 {
        return (
            StatusCode::BAD_REQUEST,
            "pressures_kpa must contain 1 to 4 values",
        )
            .into_response();
    }

    info!("{} Received tire pressure data: {:?}", NAME, data);

    if let Some(ch) = *state.sensor_channel.lock().await {
        if let Some(tx) = state.tx.lock().await.clone() {
            if let Err(e) = send_tire_pressure_data(
                tx,
                ch,
                data,
                state.last_tire_pressure_data.clone(),
                state.ws_event_tx.clone(),
            )
            .await
            {
                error!("{} Tire pressure error: {}", NAME, e);
            }
        }
    } else {
        warn!(
            "{} Not sending tire pressure because no sensor channel yet",
            NAME
        );
    }

    (StatusCode::OK, "OK").into_response()
}

async fn tire_pressure_status_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let data = state.last_tire_pressure_data.read().await;
    match &*data {
        Some(d) => Json(serde_json::to_value(d).unwrap()).into_response(),
        None => (StatusCode::NO_CONTENT, "No tire pressure data yet").into_response(),
    }
}

pub async fn inject_event_handler(
    State(state): State<Arc<AppState>>,
    Json(data): Json<InjectEventData>,
) -> impl IntoResponse {
    let keycode = match <KeyCode as protobuf::Enum>::from_str(&data.keycode) {
        Some(k) => k as u32,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Unknown keycode: {}", data.keycode),
            )
                .into_response();
        }
    };

    info!("{} Received inject_event: {:?}", NAME, data.keycode);

    if let Some(ch) = *state.input_channel.lock().await {
        if let Some(tx) = state.tx.lock().await.clone() {
            if let Err(e) = send_key_event(tx, ch, keycode).await {
                error!("{} inject_event error: {}", NAME, e);
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
        }
    } else {
        warn!(
            "{} Not sending key event because no input channel yet",
            NAME
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "No input channel available yet",
        )
            .into_response();
    }

    (StatusCode::OK, "OK").into_response()
}

pub async fn inject_rotary_handler(
    State(state): State<Arc<AppState>>,
    Json(data): Json<InjectRotaryData>,
) -> impl IntoResponse {
    if data.delta == 0 {
        return (StatusCode::BAD_REQUEST, "delta must be non-zero").into_response();
    }

    info!("{} Received inject_rotary: delta={}", NAME, data.delta);

    if let Some(ch) = *state.input_channel.lock().await {
        if let Some(tx) = state.tx.lock().await.clone() {
            if let Err(e) = send_rotary_event(tx, ch, data.delta).await {
                error!("{} inject_rotary error: {}", NAME, e);
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
        }
    } else {
        warn!(
            "{} Not sending rotary event because no input channel yet",
            NAME
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "No input channel available yet",
        )
            .into_response();
    }

    (StatusCode::OK, "OK").into_response()
}

async fn send_toll_card_from_web(state: Arc<AppState>, is_card_present: bool) -> impl IntoResponse {
    if let Some(ch) = *state.sensor_channel.lock().await {
        if let Some(tx) = state.tx.lock().await.clone() {
            if let Err(e) = send_toll_card(tx.clone(), ch, is_card_present).await {
                error!("{} Toll card send error: {}", NAME, e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to send toll card data",
                )
                    .into_response();
            }
            return (StatusCode::OK, "OK").into_response();
        }
        warn!(
            "{} Not sending toll card packet because tx is unavailable",
            NAME
        );
        return (StatusCode::SERVICE_UNAVAILABLE, "No active session tx").into_response();
    }

    warn!(
        "{} Not sending toll card packet because no sensor channel yet",
        NAME
    );
    (StatusCode::SERVICE_UNAVAILABLE, "No sensor channel yet").into_response()
}

pub async fn toll_card_add_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    send_toll_card_from_web(state, true).await
}

pub async fn toll_card_remove_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    send_toll_card_from_web(state, false).await
}

#[derive(Debug, Deserialize)]
pub struct InputKeyRequest {
    pub keycode: u32,
    pub down: Option<bool>,
    pub longpress: Option<bool>,
}

pub async fn input_key_handler(
    State(state): State<Arc<AppState>>,
    Json(data): Json<InputKeyRequest>,
) -> impl IntoResponse {
    let Some(input_ch) = *state.input_channel.lock().await else {
        warn!(
            "{} Not sending key packet because no input channel yet",
            NAME
        );
        return (StatusCode::SERVICE_UNAVAILABLE, "No input channel yet").into_response();
    };

    let Some(tx) = state.tx.lock().await.clone() else {
        warn!("{} Not sending key packet because tx is unavailable", NAME);
        return (StatusCode::SERVICE_UNAVAILABLE, "No active session tx").into_response();
    };

    let down = data.down.unwrap_or(true);
    let longpress = data.longpress.unwrap_or(false);

    if data.down.is_none() {
        // Default behavior is a tap: press and release.
        if let Err(e) = send_input_key(tx.clone(), input_ch, data.keycode, true, longpress).await {
            error!("{} Input key send (down) error: {}", NAME, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to send key event",
            )
                .into_response();
        }
        if let Err(e) = send_input_key(tx.clone(), input_ch, data.keycode, false, longpress).await {
            error!("{} Input key send (up) error: {}", NAME, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to send key event",
            )
                .into_response();
        }
    } else if let Err(e) = send_input_key(tx.clone(), input_ch, data.keycode, down, longpress).await
    {
        error!("{} Input key send error: {}", NAME, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to send key event",
        )
            .into_response();
    }

    (StatusCode::OK, "OK").into_response()
}

fn generate_filename(kind: &str) -> String {
    let now = Local::now();
    now.format(&format!("%Y%m%d%H%M%S_aa-proxy-rs_{}.tar.gz", kind))
        .to_string()
}

async fn disconnect_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if let Some(tx) = state.tx.lock().await.clone() {
        if let Err(e) = send_byebye(tx).await {
            error!("{} ByeBye send error: {}", NAME, e);
        }
    } else {
        warn!("{} disconnect requested but no active session", NAME);
    }
    state.config.write().await.action_requested = Some(Action::Reconnect);

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("Disconnect has been requested"))
        .unwrap()
}

async fn restart_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.config.write().await.action_requested = Some(Action::Reconnect);

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("Restart has been requested"))
        .unwrap()
}

async fn reboot_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.config.write().await.action_requested = Some(Action::Reboot);

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("Reboot has been requested"))
        .unwrap()
}

async fn crashes_list_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cfg = state.config.read().await;
    let crash_dir = cfg.crash_dir.clone();
    let enabled = cfg.crash_handler_enabled;
    drop(cfg);

    match crash::list_crashes(&crash_dir) {
        Ok(files) => Json(json!({
            "crash_handler_enabled": enabled,
            "crash_dir": crash_dir.display().to_string(),
            "files": files,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": format!("Failed to list crash files: {}", e),
            })),
        )
            .into_response(),
    }
}

async fn crashes_read_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(filename): axum::extract::Path<String>,
) -> impl IntoResponse {
    let crash_dir = state.config.read().await.crash_dir.clone();

    match crash::read_crash_file(&crash_dir, &filename) {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from(body))
            .unwrap()
            .into_response(),
        Err(e) => crash_file_error_response(e, &filename, "read"),
    }
}

async fn crashes_delete_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(filename): axum::extract::Path<String>,
) -> impl IntoResponse {
    let crash_dir = state.config.read().await.crash_dir.clone();

    match crash::delete_crash_file(&crash_dir, &filename) {
        Ok(()) => Json(json!({
            "status": "success",
            "deleted": 1,
            "filename": filename,
        }))
        .into_response(),
        Err(e) => crash_file_error_response(e, &filename, "delete"),
    }
}

async fn crashes_clear_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let crash_dir = state.config.read().await.crash_dir.clone();

    match crash::clear_crashes(&crash_dir) {
        Ok(deleted) => Json(json!({
            "status": "success",
            "deleted": deleted,
            "crash_dir": crash_dir.display().to_string(),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": format!("Failed to clear crash files: {}", e),
            })),
        )
            .into_response(),
    }
}

fn crash_file_error_response(
    e: std::io::Error,
    filename: &str,
    action: &str,
) -> axum::response::Response {
    match e.kind() {
        std::io::ErrorKind::InvalidInput => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "error",
                "message": e.to_string(),
            })),
        )
            .into_response(),
        std::io::ErrorKind::NotFound => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "status": "error",
                "message": format!("Crash file not found: {}", filename),
            })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": format!("Failed to {} crash file: {}", action, e),
            })),
        )
            .into_response(),
    }
}

async fn download_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let file_path = state.config.read().await.logfile.clone();
    // if we have filename parameter, use it; default otherwise
    let filename = params
        .get("filename")
        .cloned()
        .unwrap_or_else(|| generate_filename("logs"));

    // Create an in-memory duplex stream (reader/writer pipe)
    let (mut writer, reader): (DuplexStream, DuplexStream) = duplex(16 * 1024);

    // Spawn background task to write tar.gz into the writer
    tokio::spawn(async move {
        let gz_encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar_builder = Builder::new(gz_encoder);

        // Create a set to track which absolute paths have been added
        let mut added_paths: HashSet<PathBuf> = HashSet::new();

        // Use glob to find matching files
        let glob_patterns = vec!["/var/log/aa-proxy-*log", "/var/log/messages"];
        for pattern in glob_patterns {
            match glob(pattern) {
                Ok(paths) => {
                    for entry in paths.flatten() {
                        if entry.is_file() && added_paths.insert(entry.clone()) {
                            let _ = tar_builder
                                .append_path_with_name(&entry, entry.file_name().unwrap());
                        }
                    }
                }
                Err(e) => {
                    error!("{} Invalid glob pattern '{}': {}", NAME, pattern, e);
                }
            }
        }
        // Add the configured log file unless it's already been added (e.g., via glob match)
        if file_path.is_file() && added_paths.insert(file_path.clone()) {
            let _ = tar_builder.append_path_with_name(&file_path, file_path.file_name().unwrap());
        }

        // Finalize the tar archive and retrieve the compressed byte buffer
        match tar_builder.into_inner() {
            Ok(gz_encoder) => match gz_encoder.finish() {
                Ok(tar_gz_bytes) => {
                    // Write the tar.gz bytes into the duplex writer
                    if let Err(e) = writer.write_all(&tar_gz_bytes).await {
                        error!("{} Failed to write tar.gz data: {}", NAME, e);
                    }
                }
                Err(e) => {
                    error!("{} Failed to finish gzip encoding: {}", NAME, e);
                }
            },
            Err(e) => {
                error!("{} Failed to finalize tar archive: {}", NAME, e);
            }
        }

        // Shutdown the writer when done
        let _ = writer.shutdown().await;
    });

    // Wrap the duplex reader in a stream for the response body
    let stream = ReaderStream::new(reader);
    let body = Body::wrap_stream(stream);

    // Build HTTP response with appropriate headers
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/gzip")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(body)
        .unwrap()
}

async fn upload_hex_model_handler(
    State(_state): State<Arc<AppState>>,
    _headers: HeaderMap,
    RawBody(body): RawBody,
) -> impl IntoResponse {
    // read body as bytes
    let body_bytes = match to_bytes(body).await {
        Ok(bytes) => bytes,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Unable to read body: {}", err),
            )
        }
    };

    // convert to UTF-8 string
    let hex_str = match std::str::from_utf8(&body_bytes) {
        Ok(s) => s.trim(), // remove whitespaces
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Unable to parse body to UTF-8: {}", err),
            )
        }
    };

    // decode into Vec<u8>
    let binary_data = match hex::decode(hex_str) {
        Ok(data) => data,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid hex data: {}", err),
            )
        }
    };

    // save to model file
    let path: PathBuf = PathBuf::from(EV_MODEL_FILE);
    match fs::File::create(&path).await {
        Ok(mut file) => {
            if let Err(err) = file.write_all(&binary_data).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Error saving model file: {}", err),
                );
            }
            (
                StatusCode::OK,
                format!("File saved correctly as {:?}", path),
            )
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("File create error: {}", err),
        ),
    }
}

pub async fn upload_cert_bundle_handler(
    State(_state): State<Arc<AppState>>,
    headers: HeaderMap,
    RawBody(body): RawBody,
) -> impl IntoResponse {
    // Validate Content-Type header
    let content_type = headers
        .get("content-type")
        .and_then(|ct| ct.to_str().ok())
        .unwrap_or("");

    if content_type != "application/gzip" && content_type != "application/x-gzip" {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("Unsupported Content-Type: {}", content_type),
        );
    }

    // Read request body into bytes
    let body_bytes = match hyper::body::to_bytes(body).await {
        Ok(bytes) => bytes,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Unable to read body: {}", err),
            );
        }
    };

    // Compute sha256 for the tarball
    let hash = Sha256::digest(&body_bytes); // [u8; 32]
    let hash_hex = hex::encode(hash); // hex hash String

    // temp dir
    let extract_to = Path::new("/tmp");

    // Clean up previous unpack (optional but clean)
    let old_path = extract_to.join("aa-proxy-rs");
    if fs::metadata(&old_path).await.is_ok() {
        if let Err(err) = fs::remove_dir_all(&old_path).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to clean old extracted dir: {}", err),
            );
        }
    }

    // Prepare GZIP decoder over the byte buffer
    let decompressed = GzDecoder::new(Cursor::new(body_bytes));
    let mut archive = Archive::new(decompressed);

    // Unpack archive directly into /tmp
    if let Err(err) = archive.unpack(extract_to) {
        return (
            StatusCode::BAD_REQUEST,
            format!("Failed to unpack archive: {}", err),
        );
    }

    // Iterate over extracted files
    let mut valid_files = vec![];
    let certs_dir = Path::new("/tmp/aa-proxy-rs");

    let mut entries = match fs::read_dir(&certs_dir).await {
        Ok(e) => e,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "Missing expected 'aa-proxy-rs/' directory in archive: {}",
                    err
                ),
            );
        }
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let filename = match path.file_name().and_then(|f| f.to_str()) {
            Some(name) => name,
            None => continue,
        };

        // Accept only .pem files
        if filename.ends_with(".pem") {
            valid_files.push((path.clone(), filename.to_string()));
        }
    }

    if valid_files.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "No valid .pem files found in archive".to_string(),
        );
    }

    // Copy valid .pem files to destination
    for (src_path, filename) in valid_files {
        let dest_path = Path::new(BASE_CONFIG_DIR).join(filename);
        match fs::copy(&src_path, &dest_path).await {
            Ok(_) => {}
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to copy file: {}", err),
                );
            }
        }
    }

    // finally: save the hash of the new bundle to sha file
    let hash_path = Path::new(BASE_CONFIG_DIR).join(CERT_SHA_FILENAME);
    if let Err(err) = fs::write(&hash_path, &hash_hex).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to write hash file: {}", err),
        );
    }

    (
        StatusCode::OK,
        format!("Certificates uploaded to {}", BASE_CONFIG_DIR),
    )
}

async fn certs_info_handler(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    let hash_path = Path::new(BASE_CONFIG_DIR).join(CERT_SHA_FILENAME);

    let sha = match fs::read_to_string(hash_path).await {
        Ok(content) => content.trim().to_string(),
        Err(_) => String::new(),
    };

    let json_body = json!({
        "sha": sha
    });

    Json(json_body)
}

async fn userdata_backup_handler(
    State(_state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // if we have filename parameter, use it; default otherwise
    let filename = params
        .get("filename")
        .cloned()
        .unwrap_or_else(|| generate_filename("backup"));

    let (mut writer, reader): (DuplexStream, DuplexStream) = duplex(32 * 1024);

    let backup_dir = Path::new("/data");

    tokio::spawn(async move {
        let gz_encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar_builder = Builder::new(gz_encoder);
        // preserve symlinks
        tar_builder.follow_symlinks(false);

        // Append everything in /data, recursively
        if let Err(e) = tar_builder.append_dir_all(".", backup_dir) {
            error!("{} Error archiving backup dir: {}", NAME, e);
        }

        // Finish and write to pipe
        match tar_builder.into_inner() {
            Ok(gz_encoder) => match gz_encoder.finish() {
                Ok(tar_gz_bytes) => {
                    if let Err(e) = writer.write_all(&tar_gz_bytes).await {
                        error!("{} Failed to write tar.gz to stream: {}", NAME, e);
                    }
                }
                Err(e) => {
                    error!("{} Failed to finish gzip: {}", NAME, e);
                }
            },
            Err(e) => {
                error!("{} Failed to finalize tar archive: {}", NAME, e);
            }
        }

        let _ = writer.shutdown().await;
    });

    let stream = ReaderStream::new(reader);
    let body = Body::wrap_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/gzip")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(body)
        .unwrap()
}

pub async fn userdata_restore_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    RawBody(body): RawBody,
) -> impl IntoResponse {
    // Validate Content-Type header
    let content_type = headers
        .get("content-type")
        .and_then(|ct| ct.to_str().ok())
        .unwrap_or("");

    if content_type != "application/gzip" && content_type != "application/x-gzip" {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("Unsupported Content-Type: {}", content_type),
        );
    }

    // Create the file for writing
    let save_path = Path::new("/data/pending_restore.tar.gz");
    let mut file = match File::create(&save_path).await {
        Ok(f) => f,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create file: {}", err),
            );
        }
    };

    // Convert body to stream and write to file in chunks
    let mut stream = body;
    while let Some(chunk_result) = stream.next().await {
        match chunk_result {
            Ok(chunk) => {
                if let Err(err) = file.write_all(&chunk).await {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to write to file: {}", err),
                    );
                }
            }
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Error reading body chunk: {}", err),
                );
            }
        }
    }

    // request reboot
    state.config.write().await.action_requested = Some(Action::Reboot);

    (
        StatusCode::OK,
        format!(
            "Backup data uploaded to {}\nDevice will now reboot!",
            save_path.display()
        ),
    )
}

pub async fn factory_reset_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let save_path = Path::new("/data/factory-reset");

    // Create an empty file to signal a factory reset
    if let Err(err) = File::create(&save_path).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create factory reset file: {}", err),
        );
    }

    // request reboot
    state.config.write().await.action_requested = Some(Action::Reboot);

    (
        StatusCode::OK,
        "Factory reset requested. Device will now reboot.".to_string(),
    )
}

async fn bt_known_devices_handler() -> impl IntoResponse {
    let devices: Vec<String> = load_known_devices()
        .into_iter()
        .map(|addr| addr.to_string())
        .collect();
    Json(devices).into_response()
}

async fn bt_forget_known_devices_handler() -> impl IntoResponse {
    let path = std::path::Path::new(KNOWN_DEVICES_FILE);
    if !path.exists() {
        info!(
            "{} 🗑️ Known devices file already empty or does not exist",
            NAME
        );
        return (
            StatusCode::OK,
            "No known devices file to remove".to_string(),
        );
    }
    match fs::remove_file(path).await {
        Ok(_) => {
            info!("{} 🗑️ Known devices file deleted", NAME);
            (StatusCode::OK, "Known devices cleared".to_string())
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to delete known devices file: {}", e),
        ),
    }
}

async fn speed_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let data = state.last_speed.read().await;
    if let Some(d) = *data {
        Json(serde_json::json!({ "speed": d })).into_response()
    } else {
        (StatusCode::NO_CONTENT, "No speed data yet").into_response()
    }
}

/// Renders a still-frame PNG preview of a video channel's current IDR burst
/// (the cached IDR plus a short contiguous run of frames after it -- see
/// MediaSink::get_idr_burst), for the Display Margins web panel. Requires
/// media_dump_base_port to be configured (media tap), since that's what
/// populates the per-channel MediaSink registry this reads from. Returns 404
/// if no sink/IDR is cached yet for the requested channel. The response
/// carries an `X-Frame-Age-Secs` header (seconds since the burst's IDR was
/// cached) so the UI can show how current the frame actually is, rather than
/// presenting a possibly-stale frame as if it were live.
async fn sdr_ui_preview_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(channel): axum::extract::Path<u8>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let sink = state
        .shared_media_channels
        .lock()
        .await
        .get(&channel)
        .cloned();
    let Some(sink) = sink else {
        return (
            StatusCode::NOT_FOUND,
            "no media sink for this channel yet (is media_dump_base_port configured?)",
        )
            .into_response();
    };

    // Cheap identity check (no decode) so a conditional request for a burst
    // that hasn't changed since the browser last fetched it can be answered
    // with 304 instead of paying the multi-second decode again.
    if let Some((first_pts, unit_count)) = sink.get_idr_burst_version().await {
        let etag = format!("\"{channel:x}-{first_pts:x}-{unit_count:x}\"");
        let if_none_match = headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok());
        if if_none_match == Some(etag.as_str()) {
            return (
                StatusCode::NOT_MODIFIED,
                [(header::CACHE_CONTROL, "no-cache"), (header::ETAG, &etag)],
            )
                .into_response();
        }
    }

    match sdr_ui_preview::render_last_idr_burst_png(&sink, channel, 960).await {
        Ok(rendered) => {
            let (first_pts, unit_count) = rendered.burst_version;
            let etag = format!("\"{channel:x}-{first_pts:x}-{unit_count:x}\"");
            let response = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "image/png")
                .header(header::CACHE_CONTROL, "no-cache")
                .header(header::ETAG, etag)
                .header("x-frame-age-secs", rendered.age.as_secs().to_string())
                .body(Body::from(rendered.png));
            match response {
                Ok(response) => response.into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to build response: {}", e),
                )
                    .into_response(),
            }
        }
        Err(e) => (
            StatusCode::NOT_FOUND,
            format!("no preview frame available yet: {e}"),
        )
            .into_response(),
    }
}

async fn sdr_ui_current_handler() -> impl IntoResponse {
    if let Some(current) = sdr_ui::current_sdr_ui() {
        Json(current).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "sdr_ui_current_not_available",
                "message": "No ServiceDiscoveryResponse has been observed yet"
            })),
        )
            .into_response()
    }
}

async fn sdr_ui_profiles_list_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let path = state.config.read().await.sdr_ui_override_file.clone();
    match sdr_ui::list_profiles(path.clone()).await {
        Ok(profiles) => Json(json!({
            "profile_file": path.display().to_string(),
            "profiles": profiles,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": format!("Failed to list SDR UI profiles: {:#}", e),
            })),
        )
            .into_response(),
    }
}

async fn sdr_ui_profile_get_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(vehicle_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let path = state.config.read().await.sdr_ui_override_file.clone();
    match sdr_ui::get_vehicle_profile(path, &vehicle_id).await {
        Ok(Some(profile)) => Json(profile).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "status": "error",
                "message": format!("SDR UI vehicle profile not found: {}", vehicle_id),
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": format!("Failed to read SDR UI profile: {:#}", e),
            })),
        )
            .into_response(),
    }
}

async fn sdr_ui_profile_put_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(vehicle_id): axum::extract::Path<String>,
    Json(profile): Json<sdr_ui::SdrUiVehicleProfile>,
) -> impl IntoResponse {
    let path = state.config.read().await.sdr_ui_override_file.clone();
    match sdr_ui::upsert_vehicle_profile(path, &vehicle_id, profile).await {
        Ok(saved) => {
            let live_push_channels = if let Some(tx) = state.tx.lock().await.clone() {
                sdr_ui::push_live_margin_updates(tx, &saved).await
            } else {
                0
            };
            Json(json!({
                "status": "success",
                "profile": saved,
                "live_push_channels": live_push_channels,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": format!("Failed to save SDR UI profile: {:#}", e),
            })),
        )
            .into_response(),
    }
}

async fn sdr_ui_profile_delete_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(vehicle_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let path = state.config.read().await.sdr_ui_override_file.clone();
    match sdr_ui::delete_vehicle_profile(path, &vehicle_id).await {
        Ok(true) => Json(json!({
            "status": "success",
            "deleted": true,
            "vehicle_id": vehicle_id,
        }))
        .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "status": "error",
                "message": format!("SDR UI vehicle profile not found: {}", vehicle_id),
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": format!("Failed to delete SDR UI profile: {:#}", e),
            })),
        )
            .into_response(),
    }
}

fn display_injection_error_response(error: anyhow::Error) -> axum::response::Response {
    let message = format!("{:#}", error);
    let status = if message.contains("failed to read")
        || message.contains("failed to write")
        || message.contains("failed to create")
        || message.contains("failed to serialize")
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    };

    (
        status,
        Json(json!({
            "status": "error",
            "message": message,
        })),
    )
        .into_response()
}

async fn display_injection_get_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let path = state.config.read().await.inject_displays_file.clone();
    match inject_displays::list_displays(path).await {
        Ok(response) => Json(response).into_response(),
        Err(e) => display_injection_error_response(e),
    }
}

async fn display_injection_put_handler(
    State(state): State<Arc<AppState>>,
    Json(update): Json<inject_displays::InjectDisplaysSettingsUpdate>,
) -> impl IntoResponse {
    let path = state.config.read().await.inject_displays_file.clone();
    match inject_displays::update_settings(path, update).await {
        Ok(response) => Json(response).into_response(),
        Err(e) => display_injection_error_response(e),
    }
}

async fn display_injection_display_get_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let path = state.config.read().await.inject_displays_file.clone();
    match inject_displays::list_displays(path).await {
        Ok(response) => {
            if let Some(display) = response
                .displays
                .iter()
                .find(|display| display.id == id)
                .cloned()
            {
                Json(display).into_response()
            } else {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({
                        "status": "error",
                        "message": format!("Injected display not found: {}", id),
                    })),
                )
                    .into_response()
            }
        }
        Err(e) => display_injection_error_response(e),
    }
}

async fn display_injection_display_post_handler(
    State(state): State<Arc<AppState>>,
    Json(profile): Json<inject_displays::InjectDisplayProfile>,
) -> impl IntoResponse {
    let path = state.config.read().await.inject_displays_file.clone();
    match inject_displays::add_display(path, profile).await {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(e) => display_injection_error_response(e),
    }
}

async fn display_injection_display_put_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(profile): Json<inject_displays::InjectDisplayProfile>,
) -> impl IntoResponse {
    let path = state.config.read().await.inject_displays_file.clone();
    match inject_displays::upsert_display(path, &id, profile).await {
        Ok(response) => Json(response).into_response(),
        Err(e) => display_injection_error_response(e),
    }
}

async fn display_injection_display_delete_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let path = state.config.read().await.inject_displays_file.clone();
    match inject_displays::delete_display(path, &id).await {
        Ok(Some(response)) => Json(response).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "status": "error",
                "message": format!("Injected display not found: {}", id),
            })),
        )
            .into_response(),
        Err(e) => display_injection_error_response(e),
    }
}

async fn media_taps_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let endpoints = state.media_tap_endpoints.read().await.clone();
    if endpoints.is_empty() {
        Json(json!({
            "available": false,
            "reason": "No injected media taps are available yet. Connect Android Auto first.",
            "endpoints": []
        }))
        .into_response()
    } else {
        Json(json!({
            "available": true,
            "endpoints": endpoints
        }))
        .into_response()
    }
}

async fn media_tap_open_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(endpoint_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let endpoint = {
        let endpoints = state.media_tap_endpoints.read().await;
        endpoints
            .iter()
            .find(|endpoint| endpoint.endpoint_id == endpoint_id)
            .cloned()
    };

    let Some(endpoint) = endpoint else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "status": "error",
                "message": format!("Media tap endpoint not found: {}", endpoint_id),
            })),
        )
            .into_response();
    };

    let android_ip = state.companion_ip.read().await.clone();
    let Some(android_ip) = android_ip else {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "status": "error",
                "message": "No companion Android IP is known yet. Connect Android Auto first.",
            })),
        )
            .into_response();
    };

    let endpoint_for_task = endpoint.clone();
    tokio::spawn(async move {
        if let Err(e) = media_tap_reverse_bridge_once(android_ip, endpoint_for_task).await {
            error!("{} media tap open bridge failed: {}", NAME, e);
        }
    });

    Json(json!({
        "status": "success",
        "message": "Media tap reverse bridge is opening.",
        "endpoint": endpoint,
    }))
    .into_response()
}

async fn service_discovery_response_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let data = state.last_service_discovery_response.read().await;
    if let Some(value) = data.clone() {
        Json(value).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "service_discovery_response_not_available",
                "message": "No ServiceDiscoveryResponse has been observed yet"
            })),
        )
            .into_response()
    }
}

pub async fn version_handler() -> impl IntoResponse {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "board": device_info::board_prefix(),
        "model": device_info::get_sbc_model().ok()
    }))
}

async fn logo_handler() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/webp")
        .header(header::CACHE_CONTROL, "public, max-age=604800, immutable")
        .body(Body::from(LOGO_WEBP))
        .unwrap()
}

async fn get_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cfg = state.config.read().await.clone();
    let mut cfg_json: Value = serde_json::to_value(cfg).unwrap_or_else(|_| json!({}));

    #[cfg(feature = "wasm-scripting")]
    if let Some(registry) = &state.script_registry {
        registry.append_custom_config_values(&mut cfg_json).await;
    }

    Json(cfg_json)
}

async fn get_config_data(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cfg = merged_config_json(&state).await;
    Json(cfg.to_flat_config_data())
}

async fn get_config_data_tree(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cfg = merged_config_json(&state).await;
    Json(cfg)
}

/// POST /set-time
/// Body: plain text, e.g. "2025-10-15T16:20:22+02:00"
pub async fn set_time_handler(body: RawBody) -> impl IntoResponse {
    // Read the whole body as bytes
    let bytes = match to_bytes(body.0).await {
        Ok(b) => b,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Failed to read body: {e}")).into_response()
        }
    };

    let time_str = match std::str::from_utf8(&bytes) {
        Ok(s) => s.trim(),
        Err(_) => return (StatusCode::BAD_REQUEST, "Body must be UTF-8").into_response(),
    };

    // Parse time using RFC3339
    let parsed =
        match OffsetDateTime::parse(time_str, &time::format_description::well_known::Rfc3339) {
            Ok(t) => t,
            Err(e) => {
                return (StatusCode::BAD_REQUEST, format!("Invalid time format: {e}"))
                    .into_response()
            }
        };

    // Convert to UTC
    let utc = parsed.to_offset(time::UtcOffset::UTC);

    // Set system time via libc::clock_settime()
    // Requires CAP_SYS_TIME or root privileges
    let ts = libc::timespec {
        tv_sec: utc.unix_timestamp() as _,
        tv_nsec: utc.nanosecond() as _,
    };
    let result = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };
    if result != 0 {
        let err = std::io::Error::last_os_error();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to set clock: {err}"),
        )
            .into_response();
    }

    info!("{} 🕰️ system time set to: <b>{}</>", NAME, utc);
    (StatusCode::OK, format!("System time set to {utc}")).into_response()
}

async fn update_config_entry(
    State(state): State<Arc<AppState>>,
    Json(entry): Json<UpdateConfigEntry>,
) -> impl IntoResponse {
    #[cfg(feature = "wasm-scripting")]
    if entry
        .key
        .starts_with(crate::wasm_config::WASM_CONFIG_KEY_PREFIX)
    {
        let Some(registry) = state.script_registry.clone() else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "error",
                    "key": entry.key,
                    "message": "WASM scripting is not initialized"
                })),
            )
                .into_response();
        };

        return match registry
            .update_custom_config_entry(&entry.key, entry.value.clone())
            .await
        {
            Ok(()) => {
                info!(
                    "{} WASM config entry updated: {} = {}",
                    NAME, entry.key, entry.value
                );
                (
                    StatusCode::OK,
                    Json(json!({
                        "status": "success",
                        "key": entry.key,
                        "value": entry.value
                    })),
                )
                    .into_response()
            }
            Err(err) => (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "error",
                    "key": entry.key,
                    "message": format!("{}", err)
                })),
            )
                .into_response(),
        };
    }

    let mut cfg = state.config.write().await;

    let config_path = state.config_file.to_path_buf();
    let raw = fs::read_to_string(&config_path).await.unwrap_or_default();
    let mut doc = raw
        .parse::<DocumentMut>()
        .unwrap_or_else(|_| DocumentMut::new());

    // Check if the key exists in the TOML document
    if doc.get(&entry.key).is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "error",
                "key": entry.key,
                "message": format!("Unknown configuration key: '{}'", entry.key)
            })),
        )
            .into_response();
    }

    // Convert serde_json::Value to toml_edit value
    let toml_val = match &entry.value {
        serde_json::Value::Bool(b) => value(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                value(i)
            } else if let Some(f) = n.as_f64() {
                value(f)
            } else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "status": "error",
                        "key": entry.key,
                        "message": "Unsupported number type"
                    })),
                )
                    .into_response();
            }
        }
        serde_json::Value::String(s) => value(s.as_str()),
        serde_json::Value::Null => value(""),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "error",
                    "key": entry.key,
                    "message": "Unsupported value type (arrays/objects not allowed)"
                })),
            )
                .into_response();
        }
    };

    doc[&entry.key] = toml_val;

    if let Err(e) = fs::write(&config_path, doc.to_string()).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": format!("Failed to write config file: {}", e)
            })),
        )
            .into_response();
    }

    match AppConfig::load(config_path) {
        Ok(new_cfg) => {
            crash::set_crash_handler_enabled(new_cfg.crash_handler_enabled);
            crash::set_crash_dir(new_cfg.crash_dir.clone());
            *cfg = new_cfg;
            info!(
                "{} Config entry updated: {} = {}",
                NAME, entry.key, entry.value
            );
            (
                StatusCode::OK,
                Json(json!({
                    "status": "success",
                    "key": entry.key,
                    "value": entry.value
                })),
            )
                .into_response()
        }
        Err(e) => {
            warn!("{} Config reload failed after update: {}", NAME, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "error",
                    "message": format!("Config written but reload failed: {}", e)
                })),
            )
                .into_response()
        }
    }
}

#[cfg(feature = "wasm-scripting")]
async fn apply_wasm_config_values_from_root(
    state: &Arc<AppState>,
    root: &mut Value,
) -> std::result::Result<(), String> {
    let Some(obj) = root.as_object_mut() else {
        return Ok(());
    };

    let wasm_keys: Vec<String> = obj
        .keys()
        .filter(|key| key.starts_with(crate::wasm_config::WASM_CONFIG_KEY_PREFIX))
        .cloned()
        .collect();

    if wasm_keys.is_empty() {
        return Ok(());
    }

    let Some(registry) = state.script_registry.clone() else {
        return Err("WASM scripting is not initialized".to_string());
    };

    for key in wasm_keys {
        let Some(value) = obj.remove(&key) else {
            continue;
        };

        registry
            .update_custom_config_entry(&key, value.clone())
            .await
            .map_err(|err| format!("failed to update {key}: {err}"))?;

        info!("{} WASM config entry updated: {} = {}", NAME, key, value);
    }

    Ok(())
}

async fn set_config(
    State(state): State<Arc<AppState>>,
    Json(mut raw_cfg): Json<Value>,
) -> impl IntoResponse {
    #[cfg(feature = "wasm-scripting")]
    if let Err(err) = apply_wasm_config_values_from_root(&state, &mut raw_cfg).await {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "error",
                "message": err
            })),
        )
            .into_response();
    }

    let new_cfg: AppConfig = match serde_json::from_value(raw_cfg) {
        Ok(cfg) => cfg,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "error",
                    "message": format!("Invalid config payload: {}", err)
                })),
            )
                .into_response();
        }
    };

    {
        crash::set_crash_handler_enabled(new_cfg.crash_handler_enabled);
        crash::set_crash_dir(new_cfg.crash_dir.clone());
        let mut cfg = state.config.write().await;
        *cfg = new_cfg.clone();
        cfg.save((&state.config_file).to_path_buf());
    }

    let mut response_json = serde_json::to_value(new_cfg).unwrap_or_else(|_| json!({}));

    #[cfg(feature = "wasm-scripting")]
    if let Some(registry) = &state.script_registry {
        registry
            .append_custom_config_values(&mut response_json)
            .await;
    }

    Json(response_json).into_response()
}

pub async fn raw_topic_data_handler(
    State(state): State<Arc<AppState>>,
    Json(data): Json<ServerEvent>,
) -> impl IntoResponse {
    info!("{} Received raw event data: {:?}", NAME, data);

    let _ = state.ws_event_tx.send(data);

    (StatusCode::OK, "OK").into_response()
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    debug!("WS Handler called");
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

#[cfg(not(feature = "wasm-scripting"))]
async fn run_wasm_ws_hooks(
    _topic: String,
    _payload: String,
    _state: Arc<AppState>,
) -> Result<Option<bool>> {
    Ok(None)
}

#[cfg(feature = "wasm-scripting")]
async fn run_wasm_ws_hooks(
    topic: String,
    payload: String,
    state: Arc<AppState>,
) -> Result<Option<bool>> {
    let Some(registry) = state.script_registry.clone() else {
        return Ok(None);
    };

    let loaded: Vec<LoadedScript> = registry.list_scripts();
    if loaded.is_empty() {
        return Ok(None);
    }

    for script in loaded {
        match script
            .engine
            .ws_script_handler(topic.clone(), payload.clone())
            .await
        {
            Ok((result_payload, _effects)) => {
                if !result_payload.is_empty() {
                    let _ = state.ws_event_tx.send(ServerEvent {
                        topic: topic.clone(),
                        payload: result_payload,
                    });

                    return Ok(Some(true));
                }
            }
            Err(err) => {
                log::warn!(
                    "wasm script runtime error [{}], forwarding original packet: {err:#}",
                    script.path.display()
                );
            }
        }
    }

    Ok(Some(false))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut ws_event_rx = state.ws_event_tx.subscribe();
    let mut subscriptions: HashSet<String> = HashSet::new();

    let hello = ServerWsMessage::Event {
        topic: "system".to_string(),
        payload: "connected".to_string(),
    };

    if sender
        .send(Message::Text(serde_json::to_string(&hello).unwrap()))
        .await
        .is_err()
    {
        return;
    }

    loop {
        tokio::select! {
            incoming = receiver.next() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        info!("[ws] incoming ws message {}", &text);
                        match serde_json::from_str::<ClientWsMessage>(&text) {
                            Ok(ClientWsMessage::Subscribe { topic }) => {
                                subscriptions.insert(topic.clone());
                                let msg = ServerWsMessage::Subscribed { topic };
                                if sender.send(Message::Text(serde_json::to_string(&msg).unwrap())).await.is_err() {
                                    break;
                                }
                            }
                            Ok(ClientWsMessage::Unsubscribe { topic }) => {
                                subscriptions.remove(&topic);
                                let msg = ServerWsMessage::Unsubscribed { topic };
                                if sender.send(Message::Text(serde_json::to_string(&msg).unwrap())).await.is_err() {
                                    break;
                                }
                            }
                            Ok(ClientWsMessage::ScriptEvent { topic, payload }) => {
                                match run_wasm_ws_hooks(topic.clone(), payload.clone(), state.clone()).await {
                                    Ok(Some(true)) => {
                                        // wasm handled it and already emitted replacement event
                                    }
                                    Ok(Some(false)) | Ok(None) => {
                                        // wasm did not handle it, forward original event
                                        let _ = state.ws_event_tx.send(ServerEvent {
                                            topic,
                                            payload,
                                        });
                                    }
                                    Err(err) => {
                                        log::warn!("wasm ws hook failed, forwarding original packet: {err:#}");

                                        let _ = state.ws_event_tx.send(ServerEvent {
                                            topic,
                                            payload,
                                        });
                                    }
                                }
                            }
                            Err(_) => {
                                let msg = ServerWsMessage::Error {
                                    message: "invalid json message".to_string(),
                                };
                                if sender.send(Message::Text(serde_json::to_string(&msg).unwrap())).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Binary(_))) => {}
                    Some(Ok(Message::Ping(payload))) => {
                        if sender.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) => break,
                    Some(Err(_)) => break,
                    None => break,
                }
            }

            event = ws_event_rx.recv() => {
                match event {
                    Ok(ev) => {
                        info!("Received event {}, payload {}", &ev.topic, &ev.payload);
                        if subscriptions.contains(&ev.topic) {
                            match run_wasm_ws_hooks(ev.topic.clone(), ev.payload.clone(), state.clone()).await {
                                Ok(Some(true)) => {
                                    // wasm handled it and already emitted replacement event
                                }
                                Ok(Some(false)) | Ok(None) => {
                                    // wasm did not handle it, forward original event
                                    let msg = ServerWsMessage::Event {
                                        topic: ev.topic,
                                        payload: ev.payload,
                                    };

                                    if sender.send(Message::Text(serde_json::to_string(&msg).unwrap())).await.is_err() {
                                        break;
                                    }
                                }
                                Err(err) => {
                                    log::warn!("wasm ws hook failed, forwarding original packet: {err:#}");

                                    let msg = ServerWsMessage::Event {
                                        topic: ev.topic,
                                        payload: ev.payload,
                                    };

                                    if sender.send(Message::Text(serde_json::to_string(&msg).unwrap())).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let msg = ServerWsMessage::Error {
                            message: "event stream lagged".to_string(),
                        };
                        if sender.send(Message::Text(serde_json::to_string(&msg).unwrap())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitm::protos::{
        DisplayType, MediaSinkService, Service, ServiceDiscoveryResponse, VideoCodecResolutionType,
        VideoConfiguration,
    };

    async fn test_state() -> Arc<AppState> {
        let mut cfg = AppConfig::default();
        cfg.sdr_ui_override_file = std::env::temp_dir().join(format!(
            "aa-proxy-rs-test-sdr-ui-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let (ws_event_tx, _rx) = broadcast::channel(16);

        Arc::new(AppState {
            config: Arc::new(RwLock::new(cfg)),
            config_json: Arc::new(RwLock::new(ConfigJson::default())),
            config_file: Arc::new(PathBuf::from("/tmp/aa-proxy-rs-test-config.toml")),
            tx: Arc::new(Mutex::new(None)),
            sensor_channel: Arc::new(Mutex::new(None)),
            input_channel: Arc::new(Mutex::new(None)),
            last_battery_data: Arc::new(RwLock::new(None)),
            last_odometer_data: Arc::new(RwLock::new(None)),
            last_speed: Arc::new(RwLock::new(None)),
            last_service_discovery_response: Arc::new(RwLock::new(None)),
            media_tap_endpoints: Arc::new(RwLock::new(Vec::new())),
            shared_media_channels: Arc::new(Mutex::new(std::collections::HashMap::new())),
            companion_ip: Arc::new(RwLock::new(None)),
            last_tire_pressure_data: Arc::new(RwLock::new(None)),
            ws_event_tx,
            script_registry: None,
        })
    }

    fn sample_sdr_with_main_display() -> ServiceDiscoveryResponse {
        let mut video_cfg = VideoConfiguration::new();
        video_cfg.set_codec_resolution(VideoCodecResolutionType::VIDEO_800x480);

        let mut sink = MediaSinkService::new();
        sink.video_configs.push(video_cfg);
        sink.set_display_id(0);
        sink.set_display_type(DisplayType::DISPLAY_TYPE_MAIN);

        let mut svc = Service::new();
        svc.set_id(3);
        svc.media_sink_service = Some(sink).into();

        let mut msg = ServiceDiscoveryResponse::new();
        msg.services.push(svc);
        msg
    }

    /// Exercises the exact HTTP surface the new Display Margins web panel
    /// drives: GET /sdr-ui/current (to discover displays/baseline margins)
    /// and PUT /sdr-ui/profiles/:vehicle_id (the "Apply & push live" button),
    /// confirming the JSON shapes the frontend JS assumes actually hold.
    #[tokio::test]
    async fn margins_panel_endpoints_round_trip() {
        let state = test_state().await;

        // Populate the live SDR-UI snapshot the same way a real connection
        // would, via the real process_service_discovery_response path.
        let mut sdr = sample_sdr_with_main_display();
        let cfg_snapshot = state.config.read().await.clone();
        sdr_ui::process_service_discovery_response(&mut sdr, &cfg_snapshot)
            .await
            .expect("process_service_discovery_response");

        let app = app(state.clone());
        let server =
            hyper::Server::bind(&"127.0.0.1:0".parse().unwrap()).serve(app.into_make_service());
        let addr = server.local_addr();
        tokio::spawn(server);
        let base = format!("http://{addr}");

        let current_url = format!("{base}/sdr-ui/current");
        let current: serde_json::Value = tokio::task::spawn_blocking(move || {
            let body = ureq::get(&current_url)
                .call()
                .expect("GET /sdr-ui/current")
                .into_string()
                .expect("read body");
            serde_json::from_str(&body).expect("parse current json")
        })
        .await
        .unwrap();

        assert_eq!(current["displays"].as_array().unwrap().len(), 1);
        let display = &current["displays"][0];
        assert_eq!(display["display_type"], "DISPLAY_TYPE_MAIN");
        assert_eq!(display["service_id"], 3);
        let video = &display["video_configs"][0];
        assert_eq!(video["codec_resolution"], "VIDEO_800x480");
        assert!(video["margins"].is_object());

        let vehicle_id = current["vehicle_id"].as_str().unwrap().to_string();

        // Simulate the "Apply & push live" button: PUT a profile with new
        // margins for that display/video config, exactly as the panel's JS
        // constructs it.
        let profile = json!({
            "id": vehicle_id,
            "name": "Test Vehicle",
            "enabled": true,
            "info": {},
            "displays": [{
                "service_id": 3,
                "display_id": 0,
                "display_type": "DISPLAY_TYPE_MAIN",
                "video_configs": [{
                    "codec_resolution": "VIDEO_800x480",
                    "enabled": true,
                    "margins": {"top": 12, "bottom": 8, "left": 4, "right": 4},
                }],
            }],
            "phones": [],
        });

        let put_url = format!("{base}/sdr-ui/profiles/{vehicle_id}");
        let put_resp: serde_json::Value = tokio::task::spawn_blocking(move || {
            let body = ureq::put(&put_url)
                .set("content-type", "application/json")
                .send_string(&profile.to_string())
                .expect("PUT /sdr-ui/profiles")
                .into_string()
                .expect("read body");
            serde_json::from_str(&body).expect("parse put response")
        })
        .await
        .unwrap();

        assert_eq!(put_resp["status"], "success");
        // No phone tx is wired up in this test, so nothing was pushed live --
        // this also confirms the "no active session" branch the web UI
        // handles (it shows "Saved -- will apply on next reconnect").
        assert_eq!(put_resp["live_push_channels"], 0);

        let saved_margins = &put_resp["profile"]["displays"][0]["video_configs"][0]["margins"];
        assert_eq!(saved_margins["top"], 12);
        assert_eq!(saved_margins["right"], 4);

        let _ = std::fs::remove_file(&cfg_snapshot.sdr_ui_override_file);
    }
}
