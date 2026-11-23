//! Opt-in authenticated REST/WebSocket ingestion for Dynamic Overlay Builder.
//!
//! Legacy /raw-topic-data, /ws and `/dev/shm/overlay.json` are untouched.
//! Set `OVERLAY_DATA_TOKEN` (minimum 16 bytes) in the aa-proxy-rs environment
//! before exposing these endpoints. Never embed the token into web assets.

use crate::overlay_vars;
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::time::Duration;
use tokio::time::timeout;

const MAX_FIELDS: usize = 32;
const MAX_TTL_MS: u64 = 60_000;
const MIN_TTL_MS: u64 = 250;
const DEFAULT_TTL_MS: u64 = 3_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DataUpdate {
    source: String,
    values: Map<String, Value>,
    #[serde(default)]
    ttl_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WsRequest {
    Auth {
        token: String,
    },
    Update {
        source: String,
        values: Map<String, Value>,
        #[serde(default)]
        ttl_ms: Option<u64>,
    },
}

#[derive(Debug, Serialize)]
struct WriteAck {
    ok: bool,
    source: String,
    ttl_ms: u64,
}

fn configured_token() -> Result<String, (StatusCode, &'static str)> {
    match std::env::var("OVERLAY_DATA_TOKEN") {
        Ok(s) if s.len() >= 16 && s.len() <= 256 => Ok(s),
        _ => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "OVERLAY_DATA_TOKEN is not configured (minimum 16 characters)",
        )),
    }
}

// Constant-time byte comparison for fixed-size tokens.
fn token_matches(actual: &str, expected: &str) -> bool {
    let a = actual.as_bytes();
    let b = expected.as_bytes();
    let mut diff = a.len() ^ b.len();
    for (i, byte) in a.iter().enumerate() {
        diff |= (byte ^ b.get(i).copied().unwrap_or(0)) as usize;
    }
    diff == 0
}

fn verify_http(headers: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    let configured = configured_token()?;
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match given {
        Some(token) if token_matches(token, &configured) => Ok(()),
        _ => Err((StatusCode::UNAUTHORIZED, "Bearer token required or invalid")),
    }
}

fn valid_identifier(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn validate_and_update(update: DataUpdate) -> Result<WriteAck, (StatusCode, &'static str)> {
    if !valid_identifier(&update.source, 48) {
        return Err((
            StatusCode::BAD_REQUEST,
            "source must be 1-48 characters: lowercase letters, digits, _ or -",
        ));
    }
    if update.values.is_empty() || update.values.len() > MAX_FIELDS {
        return Err((StatusCode::BAD_REQUEST, "values must contain 1-32 fields"));
    }
    for (key, val) in &update.values {
        if !valid_identifier(key, 48)
            || matches!(val, Value::Array(_) | Value::Object(_))
            || val.as_str().map(|v| v.len() > 256).unwrap_or(false)
        {
            return Err((StatusCode::BAD_REQUEST, "field keys must be simple identifiers and values must be scalar (string max 256 bytes)"));
        }
    }
    let ttl = update.ttl_ms.unwrap_or(DEFAULT_TTL_MS);
    if !(MIN_TTL_MS..=MAX_TTL_MS).contains(&ttl) {
        return Err((StatusCode::BAD_REQUEST, "ttl_ms must be 250..60000"));
    }
    overlay_vars::update_overlay_source(&update.source, update.values, Duration::from_millis(ttl))
        .map_err(|_| {
            (
                StatusCode::TOO_MANY_REQUESTS,
                "Overlay source limit reached",
            )
        })?;
    Ok(WriteAck {
        ok: true,
        source: update.source,
        ttl_ms: ttl,
    })
}

pub async fn get_data(headers: HeaderMap) -> impl IntoResponse {
    if let Err(error) = verify_http(&headers) {
        return error.into_response();
    }
    (
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({
            "sources": overlay_vars::overlay_sources_status(),
            "namespace": "ws.overlay.<source>.<field>",
            "max_sources": 32
        })),
    )
        .into_response()
}

pub async fn post_data(headers: HeaderMap, Json(update): Json<Value>) -> impl IntoResponse {
    if let Err(error) = verify_http(&headers) {
        return error.into_response();
    }
    let update: DataUpdate = match serde_json::from_value(update) {
        Ok(value) => value,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid overlay data request").into_response(),
    };
    match validate_and_update(update) {
        Ok(ack) => (StatusCode::OK, axum::Json(json!(ack))).into_response(),
        Err(err) => err.into_response(),
    }
}

pub async fn websocket(ws: WebSocketUpgrade) -> impl IntoResponse {
    // Do not provide an unauthenticated message-processing socket when the
    // administrator has not explicitly opted in with a secret.
    let secret = match configured_token() {
        Ok(secret) => secret,
        Err(err) => return err.into_response(),
    };
    ws.max_message_size(16 * 1024)
        .max_frame_size(16 * 1024)
        .on_upgrade(move |socket| handle_socket(socket, secret))
        .into_response()
}

async fn handle_socket(mut socket: WebSocket, secret: String) {
    // The first frame is authentication because browser WebSockets cannot
    // attach custom Authorization headers. Never accept tokens in query URLs.
    let first = timeout(Duration::from_secs(10), socket.next()).await;
    let authenticated = matches!(first,
        Ok(Some(Ok(Message::Text(ref text))))
            if matches!(serde_json::from_str::<WsRequest>(text),
                Ok(WsRequest::Auth { token }) if token_matches(&token, &secret))
    );
    if !authenticated {
        let _ = socket
            .send(Message::Text(
                json!({"type":"error","message":"authentication required"}).to_string(),
            ))
            .await;
        let _ = socket.close().await;
        return;
    }
    if socket
        .send(Message::Text(json!({"type":"authenticated"}).to_string()))
        .await
        .is_err()
    {
        return;
    }
    while let Some(message) = socket.next().await {
        match message {
            Ok(Message::Text(text)) => {
                let response = match serde_json::from_str::<WsRequest>(&text) {
                    Ok(WsRequest::Update {
                        source,
                        values,
                        ttl_ms,
                    }) => {
                        match validate_and_update(DataUpdate {
                            source,
                            values,
                            ttl_ms,
                        }) {
                            Ok(ack) => {
                                json!({"type":"ack", "source":ack.source, "ttl_ms":ack.ttl_ms})
                            }
                            Err((_, error)) => json!({"type":"error", "message":error}),
                        }
                    }
                    _ => json!({"type":"error", "message":"expected update message"}),
                };
                if socket
                    .send(Message::Text(response.to_string()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Ok(Message::Ping(data)) => {
                if socket.send(Message::Pong(data)).await.is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_source_and_nested_values() {
        assert!(!valid_identifier("../../etc", 48));
        assert!(!valid_identifier("MIXED", 48));
        assert!(valid_identifier("obd_reader-1", 48));
        assert!(validate_and_update(DataUpdate {
            source: "obd".to_string(),
            values: serde_json::from_str(r#"{"rpm":{"nested":1}}"#).unwrap(),
            ttl_ms: Some(3000),
        })
        .is_err());
    }
    #[test]
    fn accepts_scalar_values_and_validates_ttl() {
        assert!(validate_and_update(DataUpdate {
            source: "obd".into(),
            values: serde_json::from_str(r#"{"rpm":2500,"temp":87.5}"#).unwrap(),
            ttl_ms: Some(3000)
        })
        .is_ok());
        assert!(validate_and_update(DataUpdate {
            source: "obd".into(),
            values: serde_json::from_str(r#"{"rpm":2500}"#).unwrap(),
            ttl_ms: Some(1)
        })
        .is_err());
    }
    #[test]
    fn token_comparison() {
        assert!(token_matches("1234567890abcdef", "1234567890abcdef"));
        assert!(!token_matches("1234567890abcdef", "1234567890abcdee"));
        assert!(!token_matches("short", "1234567890abcdef"));
    }
}
