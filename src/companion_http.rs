use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;

#[derive(Debug, Deserialize)]
pub struct CompanionHttpRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body_base64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CompanionHttpResponse {
    pub ok: bool,
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body_base64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CompanionHttpResponse {
    pub fn error(status: u16, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            status,
            headers: BTreeMap::new(),
            body_base64: String::new(),
            error: Some(message.into()),
        }
    }
}

pub fn dispatch_companion_http(req: CompanionHttpRequest) -> CompanionHttpResponse {
    let path = req.path.trim();
    if !path.starts_with('/') {
        return CompanionHttpResponse::error(400, "path must start with '/'");
    }

    let body = match req.body_base64.as_deref() {
        Some(body) if !body.is_empty() => match BASE64_STANDARD.decode(body) {
            Ok(bytes) => bytes,
            Err(e) => {
                return CompanionHttpResponse::error(400, format!("invalid body_base64: {e}"))
            }
        },
        _ => Vec::new(),
    };

    let method = req.method.trim().to_ascii_uppercase();
    let url = format!("http://127.0.0.1{}", path);
    let mut request = ureq::request(method.as_str(), &url);

    for (name, value) in req.headers {
        let lower = name.to_ascii_lowercase();
        if lower == "host" || lower == "content-length" || lower == "connection" {
            continue;
        }
        request = request.set(&name, &value);
    }

    let result = if body.is_empty() {
        request.call()
    } else {
        request.send_bytes(&body)
    };

    match result {
        Ok(response) => response_to_companion(response, true, None),
        Err(ureq::Error::Status(_, response)) => response_to_companion(response, false, None),
        Err(err) => {
            log::warn!("companion BT REST call failed: {err}");
            CompanionHttpResponse::error(500, err.to_string())
        }
    }
}

fn response_to_companion(
    response: ureq::Response,
    transport_ok: bool,
    error: Option<String>,
) -> CompanionHttpResponse {
    let status = response.status();
    let mut headers = BTreeMap::new();
    for name in response.headers_names() {
        if let Some(value) = response.header(&name) {
            headers.insert(name, value.to_string());
        }
    }

    let mut reader = response.into_reader();
    let mut body = Vec::new();
    if let Err(e) = reader.read_to_end(&mut body) {
        return CompanionHttpResponse::error(500, format!("failed to read response body: {e}"));
    }

    CompanionHttpResponse {
        ok: transport_ok,
        status,
        headers,
        body_base64: BASE64_STANDARD.encode(body),
        error,
    }
}
