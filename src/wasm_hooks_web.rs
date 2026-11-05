//! Upload complete hook files into the active watch directory.

use crate::script_wasm::ScriptRegistry;
use crate::web::AppState;
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

const MAX_WASM_BYTES: usize = 16 * 1024 * 1024;
type ApiError = (StatusCode, String);

pub fn routes(router: Router<Arc<AppState>>) -> Router<Arc<AppState>> {
    router
        .route(
            "/wasm-hooks",
            get(list)
                .post(upload)
                .layer(DefaultBodyLimit::max(MAX_WASM_BYTES + 16 * 1024)),
        )
        .route("/wasm-hooks/:name", delete(remove))
}

fn validate_name(name: &str) -> Result<(), ApiError> {
    if name.len() > 128
        || !name.ends_with(".wasm")
        || !name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Use a plain .wasm file name with ASCII letters, digits, dots, hyphens or underscores"
                .into(),
        ));
    }
    Ok(())
}

fn validate_magic(header: &[u8]) -> Result<(), ApiError> {
    if header.len() < 8 || !header.starts_with(b"\0asm") {
        return Err((
            StatusCode::BAD_REQUEST,
            "The file has no WebAssembly header".into(),
        ));
    }
    Ok(())
}

fn registry(state: &AppState) -> Result<&ScriptRegistry, ApiError> {
    state.script_registry.as_deref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "The WASM hooks engine is not running".into(),
        )
    })
}

fn io_error(error: std::io::Error) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

// Also removes incomplete uploads if the client disconnects or the request is cancelled.
struct PendingUpload(PathBuf);
impl Drop for PendingUpload {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn upload(
    State(state): State<Arc<AppState>>,
    multipart: Multipart,
) -> Result<Json<serde_json::Value>, ApiError> {
    store_upload(registry(&state)?.hook_dir().to_path_buf(), multipart).await
}

async fn store_upload(
    directory: PathBuf,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut field = multipart
        .next_field()
        .await
        .map_err(|e| (e.status(), e.body_text()))?
        .ok_or((StatusCode::BAD_REQUEST, "Expected one file field".into()))?;
    if field.name() != Some("file") {
        return Err((
            StatusCode::BAD_REQUEST,
            "Expected a field named file".into(),
        ));
    }
    let name = field
        .file_name()
        .ok_or((StatusCode::BAD_REQUEST, "Missing file name".into()))?
        .to_string();
    validate_name(&name)?;
    let temporary = directory.join(format!(".{}.upload", Uuid::new_v4()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .await
        .map_err(io_error)?;
    let pending = PendingUpload(temporary);
    let mut size = 0usize;
    let mut header = Vec::with_capacity(8);
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|e| (e.status(), e.body_text()))?
    {
        if chunk.len() > MAX_WASM_BYTES - size {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "The hook exceeds 16 MiB".into(),
            ));
        }
        size += chunk.len();
        let needed = 8 - header.len();
        header.extend_from_slice(&chunk[..needed.min(chunk.len())]);
        file.write_all(&chunk).await.map_err(io_error)?;
    }
    validate_magic(&header)?;
    drop(field);
    if multipart
        .next_field()
        .await
        .map_err(|e| (e.status(), e.body_text()))?
        .is_some()
    {
        return Err((StatusCode::BAD_REQUEST, "Expected exactly one file".into()));
    }
    file.flush().await.map_err(io_error)?;
    file.sync_all().await.map_err(io_error)?;
    drop(file);
    fs::rename(&pending.0, directory.join(&name))
        .await
        .map_err(io_error)?;
    Ok(Json(
        serde_json::json!({"name": name, "size": size, "status": "pending"}),
    ))
}

#[derive(Serialize)]
struct HookInfo {
    name: String,
    size: u64,
    loaded: bool,
    error: Option<String>,
}

async fn list(State(state): State<Arc<AppState>>) -> Result<Json<Vec<HookInfo>>, ApiError> {
    let registry = registry(&state)?;
    let loaded: HashSet<_> = registry
        .list_scripts()
        .into_iter()
        .map(|s| s.path)
        .collect();
    let errors: HashMap<_, _> = registry.list_errors().into_iter().collect();
    let mut entries = fs::read_dir(registry.hook_dir()).await.map_err(io_error)?;
    let mut hooks = Vec::new();
    while let Some(entry) = entries.next_entry().await.map_err(io_error)? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if validate_name(&name).is_err() || !entry.file_type().await.map_err(io_error)?.is_file() {
            continue;
        }
        let path = entry.path();
        let metadata = match entry.metadata().await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_error(error)),
        };
        hooks.push(HookInfo {
            name,
            size: metadata.len(),
            loaded: loaded.contains(&path),
            error: errors.get(&path).cloned(),
        });
    }
    hooks.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Json(hooks))
}

async fn remove(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    validate_name(&name)?;
    let path = registry(&state)?.hook_dir().join(name);
    let metadata = fs::symlink_metadata(&path).await.map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            (StatusCode::NOT_FOUND, "Hook not found".into())
        } else {
            io_error(error)
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err((
            StatusCode::BAD_REQUEST,
            "The hook is not a regular file".into(),
        ));
    }
    fs::remove_file(path).await.map_err(io_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_plain_wasm_files() {
        for name in ["exlap_hook.wasm", "hook-2.wasm", "a.b.wasm"] {
            assert!(validate_name(name).is_ok(), "{name}");
        }
        for name in [
            "",
            ".wasm",
            "../a.wasm",
            "/a.wasm",
            "a/b.wasm",
            "a\\b.wasm",
            "a.WASM",
            "a.wasm\0",
            "a:hook.wasm",
            "a\n.wasm",
            "\u{e4}.wasm",
        ] {
            assert!(validate_name(name).is_err(), "{name:?}");
        }
        assert!(validate_name(&format!("{}.wasm", "a".repeat(128))).is_err());
    }

    #[tokio::test]
    async fn upload_releases_its_field_before_checking_the_next_part() {
        use axum::body::Body;
        use axum::extract::FromRequest;
        use hyper::Request;

        let directory = std::env::temp_dir().join(format!("aa-proxy-upload-{}", Uuid::new_v4()));
        fs::create_dir(&directory).await.unwrap();
        let mut body = b"--test-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"hook.wasm\"\r\n\r\n".to_vec();
        body.extend_from_slice(b"\0asm\x01\0\0\0");
        body.extend_from_slice(b"\r\n--test-boundary--\r\n");
        let request = Request::builder()
            .header(
                "content-type",
                "multipart/form-data; boundary=test-boundary",
            )
            .body(Body::from(body))
            .unwrap();
        let multipart = Multipart::from_request(request, &()).await.unwrap();
        let response = store_upload(directory.clone(), multipart).await.unwrap();
        assert_eq!(response.0["name"], "hook.wasm");
        assert_eq!(
            fs::read(directory.join("hook.wasm")).await.unwrap(),
            b"\0asm\x01\0\0\0"
        );
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_file(directory.join("hook.wasm")).await.unwrap();
        fs::remove_dir(directory).await.unwrap();
    }

    #[test]
    fn magic_requires_a_complete_wasm_header() {
        assert!(validate_magic(b"\0asm\x01\0\0\0").is_ok());
        assert!(validate_magic(b"\0asm\x0d\0\x01\0").is_ok());
        for bytes in [b"".as_slice(), b"\0asm", b"not wasm"] {
            assert!(validate_magic(bytes).is_err());
        }
    }
}
