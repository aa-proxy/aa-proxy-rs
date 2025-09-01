use crate::config::Action;
use crate::config::AppConfig;
use crate::config::ConfigJson;
use crate::config::SharedConfig;
use crate::config::SharedConfigJson;
use crate::ev::send_ev_data;
use crate::ev::BatteryData;
use crate::ev::EV_MODEL_FILE;
use crate::mitm::Packet;
use axum::{
    body::Body,
    extract::{Query, RawBody, State},
    http::{header, HeaderMap, Response, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use chrono::Local;
use hyper::body::to_bytes;
use regex::Regex;
use simplelog::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

const TEMPLATE: &str = include_str!("../static/index.html");
const PICO_CSS: &str = include_str!("../static/pico.min.css");
const AA_PROXY_RS_URL: &str = "https://github.com/aa-proxy/aa-proxy-rs";
const BUILDROOT_URL: &str = "https://github.com/aa-proxy/buildroot";

// module name for logging engine
const NAME: &str = "<i><bright-black> web: </>";

#[derive(Clone)]
pub struct AppState {
    pub config: SharedConfig,
    pub config_json: SharedConfigJson,
    pub config_file: Arc<PathBuf>,
    pub tx: Arc<Mutex<Option<Sender<Packet>>>>,
    pub sensor_channel: Arc<Mutex<Option<u8>>>,
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/config", get(get_config).post(set_config))
        .route("/config-data", get(get_config_data))
        .route("/download", get(download_handler))
        .route("/restart", get(restart_handler))
        .route("/reboot", get(reboot_handler))
        .route("/upload-hex-model", post(upload_hex_model_handler))
        .route("/battery", post(battery_handler))
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
        // Section header row
        html.push_str(&format!(
            r#"
            <fieldset>
                <legend class="section-title">{}</legend>
                <div class="grid grid-cols-1 section-body">
            "#,
            section.title,
        ));

        let len = section.values.len();
        for (i, (key, val)) in section.values.iter().enumerate() {
            let input_html = match val.typ.as_str() {
                "string" => format!(r#"<input type="text" id="{key}" />"#),
                "integer" => format!(r#"<input type="number" id="{key}" />"#),
                "boolean" => format!(r#"<input type="checkbox" role="switch" id="{key}" />"#),
                "select" => {
                    // Render a <select> with options if they exist
                    if let Some(options) = &val.values {
                        let options_html = options
                            .iter()
                            .map(|opt| format!(r#"<option value="{opt}">{opt}</option>"#))
                            .collect::<Vec<_>>()
                            .join("\n");
                        format!(r#"<select id="{key}">{options_html}</select>"#)
                    } else {
                        // fallback to text input if no options provided
                        format!(r#"<input type="text" id="{key}" />"#)
                    }
                }
                _ => format!(r#"<input type="text" id="{key}" />"#),
            };

            let desc = replace_backticks(val.description.replace("\n", "<br>"));
            html.push_str(&format!(
                r#"
                <div class="grid grid-cols-2">
                    <label for="{key}">{key}</label>
                    <div>
                        {input_html}
                        <div><small>{desc}</small></div>
                    </div>
                </div>
                "#
            ));

            // nice line break
            if i + 1 != len {
                html.push_str("<hr>")
            }
        }

        // Close section
        html.push_str("</div></fieldset>");
    }

    html
}

pub fn render_config_ids(config: &ConfigJson) -> String {
    let mut all_keys = Vec::new();

    for section in &config.titles {
        for key in section.values.keys() {
            all_keys.push(format!(r#""{key}""#));
        }
    }

    format!("{}", all_keys.join(", "))
}

async fn index(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config_json_guard = state.config_json.read().await;
    let config_json = &*config_json_guard;

    let html = TEMPLATE
        .replace("{BUILD_DATE}", env!("BUILD_DATE"))
        .replace(
            "{GIT_INFO}",
            &linkify_git_info(env!("GIT_DATE"), env!("GIT_HASH")),
        )
        .replace("{PICO_CSS}", PICO_CSS)
        .replace("{CONFIG_VALUES}", &render_config_values(config_json))
        .replace("{CONFIG_IDS}", &render_config_ids(config_json));
    Html(html)
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
            if let Err(e) = send_ev_data(tx.clone(), ch, data).await {
                error!("{} EV model error: {}", NAME, e);
            }
        }
    } else {
        warn!("{} Not sending packet because no sensor channel yet", NAME);
    }

    (StatusCode::OK, "OK").into_response()
}

fn generate_filename() -> String {
    let now = Local::now();
    now.format("%Y%m%d%H%M%S_aa-proxy-rs.log").to_string()
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

async fn download_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let file_path = state.config.read().await.logfile.clone();
    // if we have filename parameter, use it; default otherwise
    let filename = params
        .get("filename")
        .cloned()
        .unwrap_or_else(generate_filename);

    match fs::read(file_path).await {
        Ok(content) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename),
            )
            .body(Body::from(content))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Cannot access log file"))
            .unwrap(),
    }
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

async fn get_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cfg = state.config.read().await.clone();
    Json(cfg)
}

async fn get_config_data(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cfg = state.config_json.read().await.clone();
    Json(cfg)
}

async fn set_config(
    State(state): State<Arc<AppState>>,
    Json(new_cfg): Json<AppConfig>,
) -> impl IntoResponse {
    {
        let mut cfg = state.config.write().await;
        *cfg = new_cfg.clone();
        cfg.save((&state.config_file).to_path_buf());
    }
    Json(new_cfg)
}
