//! Last observed ServiceDiscoveryResponse, persisted as protobuf JSON.
//! This is a diagnostic *snapshot*, not a live connection indicator.
use serde_json::Value;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Persistent location; deliberately not /dev/shm (lost after a reboot).
/// The containing directory must be writable by the aa-proxy-rs process.
pub const LAST_SDR_PATH: &str = "/data/aa-proxy-rs/last-service-discovery-response.json";
const MAX_SDR_BYTES: usize = 1024 * 1024;
static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

pub async fn save(value: &Value) -> io::Result<()> {
    save_at(Path::new(LAST_SDR_PATH), value).await
}

async fn save_at(path: &Path, value: &Value) -> io::Result<()> {
    if !value.is_object() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "SDR must be a JSON object"));
    }
    let bytes = serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if bytes.len() > MAX_SDR_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "SDR snapshot exceeds 1 MiB"));
    }
    let parent = path.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "SDR path has no parent"))?;
    fs::create_dir_all(parent).await?;
    // Unique temporary file and atomic rename: readers never see half a JSON document.
    let serial = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("json.tmp.{}.{}", std::process::id(), serial));
    let result: io::Result<()> = async {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600); // Raw SDR can contain phone/head-unit identity data.
        let mut file = options.open(&tmp).await?;
        file.write_all(&bytes).await?;
        file.sync_all().await?;
        drop(file);
        fs::rename(&tmp, path).await
    }.await;
    if result.is_err() {
        let _ = fs::remove_file(&tmp).await;
    }
    result
}

pub async fn load() -> io::Result<Option<Value>> {
    load_at(Path::new(LAST_SDR_PATH)).await
}

async fn load_at(path: &Path) -> io::Result<Option<Value>> {
    let meta = match fs::metadata(path).await {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if meta.len() > MAX_SDR_BYTES as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Saved SDR exceeds 1 MiB"));
    }
    let bytes = fs::read(path).await?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if !value.is_object() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Saved SDR is not a JSON object"));
    }
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn save_load_replace_and_missing() {
        let path = std::env::temp_dir().join(format!(
            "aa-proxy-sdr-test-{}-{}.json",
            std::process::id(), TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(load_at(&path).await.unwrap().is_none());
        let old = json!({"services": [{"id": 1}], "headUnitMake": "Google"});
        save_at(&path, &old).await.unwrap();
        assert_eq!(load_at(&path).await.unwrap(), Some(old));
        let next = json!({"services": [{"id": 2}]});
        save_at(&path, &next).await.unwrap();
        assert_eq!(load_at(&path).await.unwrap(), Some(next));
        fs::remove_file(path).await.unwrap();
    }

    #[tokio::test]
    async fn invalid_json_is_not_accepted() {
        let path = std::env::temp_dir().join(format!(
            "aa-proxy-sdr-bad-{}-{}.json",
            std::process::id(), TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, b"{broken").await.unwrap();
        assert_eq!(load_at(&path).await.unwrap_err().kind(), io::ErrorKind::InvalidData);
        fs::remove_file(path).await.unwrap();
    }
}
