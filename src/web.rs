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
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use futures::StreamExt;
use glob::glob;
use hyper::body::to_bytes;
use regex::Regex;
use serde_json::json;
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
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio_util::io::ReaderStream;

const TEMPLATE: &str = include_str!("../static/index.html");
const PICO_CSS: &str = include_str!("../static/pico.min.css");
const AA_PROXY_RS_URL: &str = "https://github.com/aa-proxy/aa-proxy-rs";
const BUILDROOT_URL: &str = "https://github.com/aa-proxy/buildroot";
pub const CERT_DEST_DIR: &str = "/etc/aa-proxy-rs/";
const CERT_SHA_FILENAME: &str = "cert-bundle.sha";

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
        .route("/restart", post(restart_handler))
        .route("/reboot", post(reboot_handler))
        .route("/upload-hex-model", post(upload_hex_model_handler))
        .route("/upload-certs", post(upload_cert_bundle_handler))
        .route("/certs-info", get(certs_info_handler))
        .route("/battery", post(battery_handler))
        .route("/userdata-backup", get(userdata_backup_handler))
        .route("/userdata-restore", post(userdata_restore_handler))
        .route("/factory-reset", post(factory_reset_handler))
        .route("/set-time", post(set_time_handler))
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
                "float" => format!(r#"<input type="number" step="any" id="{key}" />"#),
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

fn generate_filename(kind: &str) -> String {
    let now = Local::now();
    now.format(&format!("%Y%m%d%H%M%S_aa-proxy-rs_{}.tar.gz", kind))
        .to_string()
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
        let dest_path = Path::new(CERT_DEST_DIR).join(filename);
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
    let hash_path = Path::new(CERT_DEST_DIR).join(CERT_SHA_FILENAME);
    if let Err(err) = fs::write(&hash_path, &hash_hex).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to write hash file: {}", err),
        );
    }

    (
        StatusCode::OK,
        format!("Certificates uploaded to {}", CERT_DEST_DIR),
    )
}

async fn certs_info_handler(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    let hash_path = Path::new(CERT_DEST_DIR).join(CERT_SHA_FILENAME);

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

async fn get_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cfg = state.config.read().await.clone();
    Json(cfg)
}

async fn get_config_data(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cfg = state.config_json.read().await.clone();
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
