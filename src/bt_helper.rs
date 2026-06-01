use crate::bluetooth::remove_known_device_entry;

use axum::{extract::Path, http::StatusCode, response::IntoResponse, Json};

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

#[derive(Debug, Serialize)]
pub struct BtCommandResponse {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BtDevice {
    pub mac: String,
    pub name: String,
    pub paired: bool,
}

#[derive(Debug, Deserialize)]
pub struct BtDeviceRequest {
    pub mac: String,
}

pub fn validate_bt_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();

    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

pub async fn run_bluetoothctl(args: &[&str]) -> Result<BtCommandResponse, String> {
    let fut = Command::new("bluetoothctl").args(args).output();

    let output = timeout(Duration::from_secs(20), fut)
        .await
        .map_err(|_| "bluetoothctl timed out".to_string())?
        .map_err(|e| format!("failed to run bluetoothctl: {e}"))?;

    Ok(BtCommandResponse {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

pub fn parse_bluetoothctl_devices(output: &str, paired: bool) -> Vec<BtDevice> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();

            let rest = line.strip_prefix("Device ")?;
            let mut parts = rest.splitn(2, char::is_whitespace);

            let mac = parts.next()?.trim();
            let name = parts.next().unwrap_or("").trim();

            if !validate_bt_mac(mac) {
                return None;
            }

            Some(BtDevice {
                mac: mac.to_string(),
                name: name.to_string(),
                paired: paired,
            })
        })
        .collect()
}

pub async fn bt_devices_handler() -> impl IntoResponse {
    match run_bluetoothctl(&["devices"]).await {
        Ok(result) => {
            let devices = if result.ok {
                parse_bluetoothctl_devices(&result.stdout, false)
            } else {
                Vec::new()
            };

            let status = if result.ok {
                StatusCode::OK
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };

            (
                status,
                Json(json!({
                    "ok": result.ok,
                    "devices": devices,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "ok": false,
                "devices": [],
                "error": e
            })),
        )
            .into_response(),
    }
}

pub async fn bt_paired_devices_handler() -> impl IntoResponse {
    match run_bluetoothctl(&["devices Paired"]).await {
        Ok(result) => {
            let devices = if result.ok {
                parse_bluetoothctl_devices(&result.stdout, true)
            } else {
                Vec::new()
            };

            let status = if result.ok {
                StatusCode::OK
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };

            (
                status,
                Json(json!({
                    "ok": result.ok,
                    "devices": devices,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "ok": false,
                "devices": [],
                "error": e
            })),
        )
            .into_response(),
    }
}

pub async fn bt_remove_device_handler(Path(mac): Path<String>) -> impl IntoResponse {
    if !validate_bt_mac(&mac) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "Invalid Bluetooth MAC address",
                "mac": mac
            })),
        )
            .into_response();
    }

    let known_device_result = remove_known_device_entry(&mac);

    match run_bluetoothctl(&["remove", &mac]).await {
        Ok(result) => {
            let known_device_removed = known_device_result.as_ref().copied().unwrap_or(false);
            let ok = result.ok || known_device_removed;
            let status = if ok {
                StatusCode::OK
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };

            (
                status,
                Json(json!({
                    "ok": ok,
                    "bluez_ok": result.ok,
                    "known_device_removed": known_device_removed,
                    "known_device_error": known_device_result.err().map(|e| e.to_string()),
                    "mac": mac,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                })),
            )
                .into_response()
        }
        Err(e) => {
            let known_device_removed = known_device_result.as_ref().copied().unwrap_or(false);
            let ok = known_device_removed;
            let status = if ok {
                StatusCode::OK
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };

            (
                status,
                Json(json!({
                    "ok": ok,
                    "bluez_ok": false,
                    "known_device_removed": known_device_removed,
                    "known_device_error": known_device_result.err().map(|e| e.to_string()),
                    "mac": mac,
                    "error": e
                })),
            )
                .into_response()
        }
    }
}

pub async fn bt_pair_device_handler(Json(req): Json<BtDeviceRequest>) -> impl IntoResponse {
    if !validate_bt_mac(&req.mac) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "Invalid Bluetooth MAC address"
            })),
        )
            .into_response();
    }

    let pair = match run_bluetoothctl(&["pair", &req.mac]).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "step": "pair", "error": e })),
            )
                .into_response();
        }
    };

    if !pair.ok {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "ok": false,
                "step": "pair",
                "mac": req.mac,
                "stdout": pair.stdout,
                "stderr": pair.stderr,
            })),
        )
            .into_response();
    }

    let trust = run_bluetoothctl(&["trust", &req.mac]).await.ok();
    let connect = run_bluetoothctl(&["connect", &req.mac]).await.ok();

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "mac": req.mac,
            "pair": pair,
            "trust": trust,
            "connect": connect,
        })),
    )
        .into_response()
}
