use crate::config::AppConfig;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use hyper::body::HttpBody;
use hyper::header::{
    HeaderValue, ALLOW, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, LAST_MODIFIED,
    WWW_AUTHENTICATE,
};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use log::{error, info, warn};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

const NAME: &str = "<i><bright-black> webdav: </>";
const ALLOW_METHODS: &str = "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, MOVE, LOCK, UNLOCK";
const DAV_HEADER_VALUE: &str = "1, 2";

#[derive(Debug, Clone)]
pub struct WebDavOptions {
    pub bind_addr: String,
    pub root_dir: PathBuf,
    pub username: String,
    pub password: String,
    pub read_only: bool,
}

impl WebDavOptions {
    pub fn from_config(cfg: &AppConfig) -> Self {
        Self {
            bind_addr: cfg.webdav_bind_addr.clone(),
            root_dir: cfg.webdav_root_dir.clone(),
            username: cfg.webdav_username.clone(),
            password: cfg.webdav_password.clone(),
            read_only: cfg.webdav_read_only,
        }
    }
}

#[derive(Clone)]
struct WebDavState {
    root: Arc<PathBuf>,
    username: Arc<String>,
    password: Arc<String>,
    read_only: bool,
}

pub async fn spawn(options: WebDavOptions) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if options.username.is_empty() || options.password.is_empty() {
        return Err(invalid_config(
            "webdav_username/webdav_password must be non-empty when WebDAV is enabled",
        ));
    }

    if !options.root_dir.exists() {
        fs::create_dir_all(&options.root_dir).await?;
    }

    let root = fs::canonicalize(&options.root_dir).await?;
    if !root.is_dir() {
        return Err(invalid_config(format!(
            "webdav_root_dir is not a directory: {}",
            root.display()
        )));
    }

    let addr: SocketAddr = options.bind_addr.parse()?;
    let state = WebDavState {
        root: Arc::new(root.clone()),
        username: Arc::new(options.username),
        password: Arc::new(options.password),
        read_only: options.read_only,
    };

    let make_svc = make_service_fn(move |_| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle_request(req, state).await) }
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);
    tokio::spawn(async move {
        info!(
            "{} WebDAV server running at http://{}/ with root {}",
            NAME,
            addr,
            root.display()
        );
        if let Err(e) = server.await {
            error!("{} WebDAV server error: {}", NAME, e);
        }
    });

    Ok(())
}

fn invalid_config(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

async fn handle_request(mut req: Request<Body>, state: WebDavState) -> Response<Body> {
    if !authorized(&req, &state) {
        return unauthorized();
    }

    let method = req.method().clone();
    match method.as_str() {
        "OPTIONS" => options_response(),
        "PROPFIND" => propfind_handler(req, state).await,
        "GET" => get_handler(req, state, false).await,
        "HEAD" => get_handler(req, state, true).await,
        "PUT" => {
            if state.read_only {
                forbidden("WebDAV is read-only")
            } else {
                put_handler(&mut req, state).await
            }
        }
        "DELETE" => {
            if state.read_only {
                forbidden("WebDAV is read-only")
            } else {
                delete_handler(req, state).await
            }
        }
        "MKCOL" => {
            if state.read_only {
                forbidden("WebDAV is read-only")
            } else {
                mkcol_handler(req, state).await
            }
        }
        "MOVE" => {
            if state.read_only {
                forbidden("WebDAV is read-only")
            } else {
                move_handler(req, state).await
            }
        }
        "LOCK" => lock_handler(req),
        "UNLOCK" => status_response(StatusCode::NO_CONTENT),
        _ => method_not_allowed(),
    }
}

fn authorized(req: &Request<Body>, state: &WebDavState) -> bool {
    let Some(value) = req.headers().get(AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some((scheme, encoded)) = value.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("Basic") {
        return false;
    }
    let Ok(decoded) = BASE64_STANDARD.decode(encoded.trim()) else {
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return false;
    };

    decoded == format!("{}:{}", state.username.as_ref(), state.password.as_ref())
}

async fn propfind_handler(req: Request<Body>, state: WebDavState) -> Response<Body> {
    let request_path = req.uri().path().to_string();
    let depth = req
        .headers()
        .get("Depth")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("infinity");

    let target = match resolve_existing_path(&state, &request_path).await {
        Ok(path) => path,
        Err(response) => return response,
    };

    let metadata = match fs::metadata(&target).await {
        Ok(metadata) => metadata,
        Err(e) => return io_error_response(e),
    };

    let mut entries = Vec::new();
    entries.push(DavEntry {
        href: href_for_path(&request_path, metadata.is_dir()),
        path: target.clone(),
        metadata,
    });

    if depth != "0" {
        if let Ok(metadata) = fs::metadata(&target).await {
            if metadata.is_dir() {
                let mut read_dir = match fs::read_dir(&target).await {
                    Ok(read_dir) => read_dir,
                    Err(e) => return io_error_response(e),
                };

                loop {
                    match read_dir.next_entry().await {
                        Ok(Some(entry)) => {
                            let child_path = entry.path();
                            let child_metadata = match entry.metadata().await {
                                Ok(metadata) => metadata,
                                Err(e) => {
                                    warn!("{} failed to read WebDAV child metadata: {}", NAME, e);
                                    continue;
                                }
                            };
                            let name = entry.file_name().to_string_lossy().into_owned();
                            let child_href =
                                join_href(&request_path, &name, child_metadata.is_dir());
                            entries.push(DavEntry {
                                href: child_href,
                                path: child_path,
                                metadata: child_metadata,
                            });
                        }
                        Ok(None) => break,
                        Err(e) => return io_error_response(e),
                    }
                }
            }
        }
    }

    let xml = multistatus_xml(&entries);
    response_with_body(
        StatusCode::MULTI_STATUS,
        Body::from(xml),
        Some("application/xml; charset=utf-8"),
    )
}

async fn get_handler(req: Request<Body>, state: WebDavState, head_only: bool) -> Response<Body> {
    let target = match resolve_existing_path(&state, req.uri().path()).await {
        Ok(path) => path,
        Err(response) => return response,
    };

    let metadata = match fs::metadata(&target).await {
        Ok(metadata) => metadata,
        Err(e) => return io_error_response(e),
    };

    if metadata.is_dir() {
        return forbidden("directory download is not supported; use PROPFIND to list directories");
    }

    let mut response = if head_only {
        response_with_body(StatusCode::OK, Body::empty(), None)
    } else {
        match File::open(&target).await {
            Ok(file) => {
                let stream = ReaderStream::new(file);
                response_with_body(StatusCode::OK, Body::wrap_stream(stream), None)
            }
            Err(e) => return io_error_response(e),
        }
    };

    insert_header(&mut response, CONTENT_LENGTH, &metadata.len().to_string());
    if let Ok(modified) = metadata.modified() {
        insert_header(&mut response, LAST_MODIFIED, &http_date(modified));
    }
    response
}

async fn put_handler(req: &mut Request<Body>, state: WebDavState) -> Response<Body> {
    let target = match resolve_write_path(&state, req.uri().path()).await {
        Ok(path) => path,
        Err(response) => return response,
    };

    if let Ok(metadata) = fs::metadata(&target).await {
        if metadata.is_dir() {
            return forbidden("cannot overwrite directory with file");
        }
    }

    let existed = target.exists();
    let mut file = match File::create(&target).await {
        Ok(file) => file,
        Err(e) => return io_error_response(e),
    };

    while let Some(chunk) = req.body_mut().data().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(e) => {
                return text_response(
                    StatusCode::BAD_REQUEST,
                    format!("failed to read request body: {e}"),
                )
            }
        };
        if let Err(e) = file.write_all(&chunk).await {
            return io_error_response(e);
        }
    }

    if let Err(e) = file.flush().await {
        return io_error_response(e);
    }

    status_response(if existed {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    })
}

async fn delete_handler(req: Request<Body>, state: WebDavState) -> Response<Body> {
    let target = match resolve_existing_path(&state, req.uri().path()).await {
        Ok(path) => path,
        Err(response) => return response,
    };

    let metadata = match fs::metadata(&target).await {
        Ok(metadata) => metadata,
        Err(e) => return io_error_response(e),
    };

    let result = if metadata.is_dir() {
        fs::remove_dir_all(&target).await
    } else {
        fs::remove_file(&target).await
    };

    match result {
        Ok(()) => status_response(StatusCode::NO_CONTENT),
        Err(e) => io_error_response(e),
    }
}

async fn mkcol_handler(req: Request<Body>, state: WebDavState) -> Response<Body> {
    let target = match resolve_write_path(&state, req.uri().path()).await {
        Ok(path) => path,
        Err(response) => return response,
    };

    if target.exists() {
        return text_response(StatusCode::METHOD_NOT_ALLOWED, "collection already exists");
    }

    match fs::create_dir(&target).await {
        Ok(()) => status_response(StatusCode::CREATED),
        Err(e) => io_error_response(e),
    }
}

async fn move_handler(req: Request<Body>, state: WebDavState) -> Response<Body> {
    let source = match resolve_existing_path(&state, req.uri().path()).await {
        Ok(path) => path,
        Err(response) => return response,
    };

    let destination = match req
        .headers()
        .get("Destination")
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => value,
        None => return text_response(StatusCode::BAD_REQUEST, "missing Destination header"),
    };

    let destination_path = match destination_to_path(destination) {
        Some(path) => path,
        None => return text_response(StatusCode::BAD_REQUEST, "invalid Destination header"),
    };

    let target = match resolve_write_path(&state, &destination_path).await {
        Ok(path) => path,
        Err(response) => return response,
    };

    let overwrite = req
        .headers()
        .get("Overwrite")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("T"))
        .unwrap_or(true);

    let target_exists = target.exists();
    if target_exists {
        if !overwrite {
            return text_response(StatusCode::PRECONDITION_FAILED, "destination exists");
        }
        let metadata = match fs::metadata(&target).await {
            Ok(metadata) => metadata,
            Err(e) => return io_error_response(e),
        };
        let remove_result = if metadata.is_dir() {
            fs::remove_dir_all(&target).await
        } else {
            fs::remove_file(&target).await
        };
        if let Err(e) = remove_result {
            return io_error_response(e);
        }
    }

    match fs::rename(&source, &target).await {
        Ok(()) => status_response(if target_exists {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::CREATED
        }),
        Err(e) => io_error_response(e),
    }
}

fn lock_handler(req: Request<Body>) -> Response<Body> {
    let token = format!(
        "opaquelocktoken:aa-proxy-rs-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let path = xml_escape(req.uri().path());
    let body = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:">
  <D:lockdiscovery>
    <D:activelock>
      <D:locktype><D:write/></D:locktype>
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:depth>infinity</D:depth>
      <D:owner>{}</D:owner>
      <D:timeout>Second-3600</D:timeout>
      <D:locktoken><D:href>{}</D:href></D:locktoken>
    </D:activelock>
  </D:lockdiscovery>
</D:prop>"#,
        path,
        xml_escape(&token)
    );
    let mut response = response_with_body(
        StatusCode::OK,
        Body::from(body),
        Some("application/xml; charset=utf-8"),
    );
    insert_header(&mut response, "Lock-Token", &format!("<{}>", token));
    response
}

fn options_response() -> Response<Body> {
    let mut response = status_response(StatusCode::NO_CONTENT);
    insert_common_headers(&mut response);
    response
}

fn method_not_allowed() -> Response<Body> {
    let mut response = text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    insert_common_headers(&mut response);
    response
}

fn unauthorized() -> Response<Body> {
    let mut response = text_response(StatusCode::UNAUTHORIZED, "authentication required");
    insert_header(
        &mut response,
        WWW_AUTHENTICATE,
        "Basic realm=\"aa-proxy-rs WebDAV\"",
    );
    response
}

fn forbidden(message: impl Into<String>) -> Response<Body> {
    text_response(StatusCode::FORBIDDEN, message)
}

fn status_response(status: StatusCode) -> Response<Body> {
    response_with_body(status, Body::empty(), None)
}

fn text_response(status: StatusCode, message: impl Into<String>) -> Response<Body> {
    response_with_body(
        status,
        Body::from(message.into()),
        Some("text/plain; charset=utf-8"),
    )
}

fn io_error_response(e: std::io::Error) -> Response<Body> {
    match e.kind() {
        std::io::ErrorKind::NotFound => text_response(StatusCode::NOT_FOUND, e.to_string()),
        std::io::ErrorKind::PermissionDenied => text_response(StatusCode::FORBIDDEN, e.to_string()),
        _ => text_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

fn response_with_body(
    status: StatusCode,
    body: Body,
    content_type: Option<&str>,
) -> Response<Body> {
    let mut response = Response::builder()
        .status(status)
        .body(body)
        .unwrap_or_else(|_| Response::new(Body::empty()));
    insert_common_headers(&mut response);
    if let Some(content_type) = content_type {
        insert_header(&mut response, CONTENT_TYPE, content_type);
    }
    response
}

fn insert_common_headers(response: &mut Response<Body>) {
    insert_header(response, "DAV", DAV_HEADER_VALUE);
    insert_header(response, ALLOW, ALLOW_METHODS);
}

fn insert_header<K>(response: &mut Response<Body>, key: K, value: &str)
where
    K: hyper::header::IntoHeaderName,
{
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().insert(key, value);
    }
}

async fn resolve_existing_path(
    state: &WebDavState,
    uri_path: &str,
) -> Result<PathBuf, Response<Body>> {
    let candidate = resolve_logical_path(state, uri_path)?;
    let canonical = match fs::canonicalize(&candidate).await {
        Ok(path) => path,
        Err(e) => return Err(io_error_response(e)),
    };

    if !canonical.starts_with(state.root.as_ref()) {
        return Err(forbidden("path escapes WebDAV root"));
    }

    Ok(canonical)
}

async fn resolve_write_path(
    state: &WebDavState,
    uri_path: &str,
) -> Result<PathBuf, Response<Body>> {
    let candidate = resolve_logical_path(state, uri_path)?;
    let parent = match candidate.parent() {
        Some(parent) => parent,
        None => {
            return Err(text_response(
                StatusCode::CONFLICT,
                "missing parent directory",
            ))
        }
    };

    let canonical_parent = match fs::canonicalize(parent).await {
        Ok(path) => path,
        Err(e) => return Err(io_error_response(e)),
    };

    if !canonical_parent.starts_with(state.root.as_ref()) {
        return Err(forbidden("path escapes WebDAV root"));
    }

    Ok(candidate)
}

fn resolve_logical_path(state: &WebDavState, uri_path: &str) -> Result<PathBuf, Response<Body>> {
    let decoded = match percent_decode(uri_path) {
        Ok(decoded) => decoded,
        Err(e) => return Err(text_response(StatusCode::BAD_REQUEST, e)),
    };

    let mut relative = PathBuf::new();
    for component in Path::new(&decoded).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => relative.push(part),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(forbidden("parent path components are not allowed"));
            }
        }
    }

    Ok(state.root.join(relative))
}

fn destination_to_path(destination: &str) -> Option<String> {
    if let Ok(uri) = destination.parse::<hyper::Uri>() {
        if let Some(path_and_query) = uri.path_and_query() {
            return Some(path_and_query.path().to_string());
        }
    }

    if destination.starts_with('/') {
        Some(destination.to_string())
    } else {
        None
    }
}

struct DavEntry {
    href: String,
    path: PathBuf,
    metadata: std::fs::Metadata,
}

fn multistatus_xml(entries: &[DavEntry]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">\n",
    );
    for entry in entries {
        xml.push_str(&response_xml(entry));
    }
    xml.push_str("</D:multistatus>\n");
    xml
}

fn response_xml(entry: &DavEntry) -> String {
    let is_dir = entry.metadata.is_dir();
    let display_name = entry
        .path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/".to_string());
    let modified = entry
        .metadata
        .modified()
        .map(http_date)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 GMT".to_string());
    let resource_type = if is_dir {
        "<D:resourcetype><D:collection/></D:resourcetype>"
    } else {
        "<D:resourcetype/>"
    };
    let content_length = if is_dir { 0 } else { entry.metadata.len() };

    format!(
        "  <D:response>\n    <D:href>{}</D:href>\n    <D:propstat>\n      <D:prop>\n        <D:displayname>{}</D:displayname>\n        {}\n        <D:getcontentlength>{}</D:getcontentlength>\n        <D:getlastmodified>{}</D:getlastmodified>\n      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n",
        xml_escape(&entry.href),
        xml_escape(&display_name),
        resource_type,
        content_length,
        xml_escape(&modified)
    )
}

fn href_for_path(path: &str, is_dir: bool) -> String {
    let mut href = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    if !href.starts_with('/') {
        href.insert(0, '/');
    }
    if is_dir && !href.ends_with('/') {
        href.push('/');
    }
    href
}

fn join_href(parent: &str, name: &str, is_dir: bool) -> String {
    let mut href = href_for_path(parent, true);
    href.push_str(&percent_encode_segment(name));
    if is_dir {
        href.push('/');
    }
    href
}

fn percent_decode(input: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("invalid percent encoding".to_string());
            }
            let hi =
                hex_value(bytes[i + 1]).ok_or_else(|| "invalid percent encoding".to_string())?;
            let lo =
                hex_value(bytes[i + 2]).ok_or_else(|| "invalid percent encoding".to_string())?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "path is not valid UTF-8".to_string())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn percent_encode_segment(input: &str) -> String {
    let mut out = String::new();
    for byte in input.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn http_date(time: SystemTime) -> String {
    let datetime: DateTime<Utc> = time.into();
    datetime.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}
