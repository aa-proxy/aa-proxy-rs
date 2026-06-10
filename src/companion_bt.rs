use crate::companion_http::{dispatch_companion_http, CompanionHttpRequest};
use crate::companion_protocol::*;
use crate::web::{AppState, ServerEvent};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bluer::agent::{
    Agent, AgentHandle, AuthorizeService, DisplayPasskey, DisplayPinCode,
    ReqResult as AgentReqResult, RequestAuthorization, RequestConfirmation, RequestPasskey,
    RequestPinCode,
};
use bluer::rfcomm::{Profile, ProfileHandle, Role, Stream};
use bluer::{Address, Session, Uuid};
use futures::{FutureExt, StreamExt};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::WriteHalf;
use tokio::sync::Mutex;

const NAME: &str = "<i><bright-black> companion_bt: </>";
const COMPANION_RFCOMM_CHANNEL: u16 = 23;
const COMPANION_SPP_RFCOMM_CHANNEL: u16 = 24;
const SERIAL_PORT_PROFILE_UUID: &str = "00001101-0000-1000-8000-00805f9b34fb";
const AUTH_HMAC_CONTEXT: &[u8] = b"aa-proxy-companion-bt-auth-v1";
const AUTH_NONCE_LEN: usize = 32;
const AUTH_MIN_TOKEN_LEN: usize = 16;
const AUTH_MAX_TOKEN_LEN: usize = 4096;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

type SharedWriter = Arc<Mutex<WriteHalf<Stream>>>;

#[derive(Debug, Deserialize)]
struct TopicPayload {
    topic: String,
}

#[derive(Debug, Serialize)]
struct StatusPayload {
    ready: bool,
    transport: &'static str,
    version: u8,
}

#[derive(Debug, Serialize)]
struct ErrorPayload {
    error: String,
}

#[derive(Debug, Serialize)]
struct AuthStatusPayload {
    required: bool,
    configured: bool,
    authenticated: bool,
    version: u8,
    algorithm: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_nonce: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuthOkPayload {
    ok: bool,
    message: &'static str,
}

#[derive(Debug, Deserialize)]
struct AuthResponsePayload {
    client_nonce: String,
    response: String,
}

#[derive(Debug, Deserialize)]
struct AuthSetTokenPayload {
    token: String,
}

struct CompanionBtAuthState {
    required: bool,
    token: String,
    server_nonce: Option<Vec<u8>>,
    authenticated: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct TopicEventPayload {
    topic: String,
    payload: String,
}

impl CompanionBtAuthState {
    async fn from_state(state: &AppState) -> Self {
        let cfg = state.config.read().await;
        let required = cfg.companion_bt_auth_required;
        let token = cfg.companion_bt_auth_token.trim().to_string();
        Self {
            required,
            token,
            server_nonce: None,
            authenticated: !required,
        }
    }

    fn configured(&self) -> bool {
        !self.token.trim().is_empty()
    }

    fn status_payload(&mut self) -> Result<AuthStatusPayload> {
        let configured = self.configured();
        if self.required && configured && self.server_nonce.is_none() {
            self.server_nonce = Some(random_bytes(AUTH_NONCE_LEN));
        }
        Ok(AuthStatusPayload {
            required: self.required,
            configured,
            authenticated: self.authenticated,
            version: COMPANION_APP_VERSION,
            algorithm: "HMAC-SHA256",
            server_nonce: self
                .server_nonce
                .as_ref()
                .map(|n| BASE64_STANDARD.encode(n)),
        })
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        if file.read_exact(&mut out).is_ok() {
            return out;
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let pid = std::process::id();
    let mut offset = 0usize;
    let mut counter = 0u64;
    while offset < len {
        let mut hasher = Sha256::new();
        hasher.update(now.to_le_bytes());
        hasher.update(pid.to_le_bytes());
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        let take = std::cmp::min(digest.len(), len - offset);
        out[offset..offset + take].copy_from_slice(&digest[..take]);
        offset += take;
        counter = counter.wrapping_add(1);
    }
    out
}

fn companion_auth_message(server_nonce: &[u8], client_nonce: &[u8]) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(AUTH_HMAC_CONTEXT.len() + server_nonce.len() + client_nonce.len() + 1);
    msg.extend_from_slice(AUTH_HMAC_CONTEXT);
    msg.extend_from_slice(server_nonce);
    msg.extend_from_slice(client_nonce);
    msg.push(COMPANION_APP_VERSION);
    msg
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let digest = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn validate_auth_token(token: &str) -> Result<String> {
    let token = token.trim();
    if token.len() < AUTH_MIN_TOKEN_LEN {
        return Err("auth token is too short".into());
    }
    if token.len() > AUTH_MAX_TOKEN_LEN {
        return Err("auth token is too large".into());
    }
    Ok(token.to_string())
}

async fn companion_trust_device(
    session: Session,
    adapter_name: String,
    device_addr: Address,
) -> AgentReqResult<()> {
    match session.adapter(&adapter_name) {
        Ok(adapter) => match adapter.device(device_addr) {
            Ok(device) => match device.set_trusted(true).await {
                Ok(()) => info!(
                    "{} pairing: trusted companion device {} on adapter {}",
                    NAME, device_addr, adapter_name
                ),
                Err(e) => warn!(
                    "{} pairing: failed to trust companion device {} on adapter {}: {}",
                    NAME, device_addr, adapter_name, e
                ),
            },
            Err(e) => warn!(
                "{} pairing: failed to open companion device {} on adapter {}: {}",
                NAME, device_addr, adapter_name, e
            ),
        },
        Err(e) => warn!(
            "{} pairing: failed to open adapter {} while trusting companion device {}: {}",
            NAME, adapter_name, device_addr, e
        ),
    }
    Ok(())
}

async fn companion_request_pin_code(req: RequestPinCode) -> AgentReqResult<String> {
    info!(
        "{} pairing: replying with fallback PIN 0000 for {}",
        NAME, req.device
    );
    Ok("0000".to_string())
}

async fn companion_display_pin_code(req: DisplayPinCode) -> AgentReqResult<()> {
    info!(
        "{} pairing: display PIN-code request from {}: {}",
        NAME, req.device, req.pincode
    );
    Ok(())
}

async fn companion_request_passkey(req: RequestPasskey) -> AgentReqResult<u32> {
    info!(
        "{} pairing: replying with fallback passkey 000000 for {}",
        NAME, req.device
    );
    Ok(0)
}

async fn companion_display_passkey(req: DisplayPasskey) -> AgentReqResult<()> {
    info!(
        "{} pairing: display passkey request from {}: {:06} entered={}",
        NAME, req.device, req.passkey, req.entered
    );
    Ok(())
}

async fn companion_request_confirmation(
    req: RequestConfirmation,
    session: Session,
) -> AgentReqResult<()> {
    info!(
        "{} pairing: confirming passkey {:06} for {}",
        NAME, req.passkey, req.device
    );
    companion_trust_device(session, req.adapter.clone(), req.device).await
}

async fn companion_request_authorization(
    req: RequestAuthorization,
    session: Session,
) -> AgentReqResult<()> {
    info!(
        "{} pairing: authorizing companion pairing from {}",
        NAME, req.device
    );
    companion_trust_device(session, req.adapter.clone(), req.device).await
}

async fn companion_authorize_service(req: AuthorizeService) -> AgentReqResult<()> {
    info!(
        "{} pairing: authorizing service {} for {}",
        NAME, req.service, req.device
    );
    Ok(())
}

pub async fn register_companion_pairing_agent(session: &Session) -> Result<AgentHandle> {
    let session_for_confirmation = session.clone();
    let session_for_authorization = session.clone();

    let agent = Agent {
        request_default: true,
        request_pin_code: Some(Box::new(|req| companion_request_pin_code(req).boxed())),
        display_pin_code: Some(Box::new(|req| companion_display_pin_code(req).boxed())),
        request_passkey: Some(Box::new(|req| companion_request_passkey(req).boxed())),
        display_passkey: Some(Box::new(|req| companion_display_passkey(req).boxed())),
        request_confirmation: Some(Box::new(move |req| {
            companion_request_confirmation(req, session_for_confirmation.clone()).boxed()
        })),
        request_authorization: Some(Box::new(move |req| {
            companion_request_authorization(req, session_for_authorization.clone()).boxed()
        })),
        authorize_service: Some(Box::new(|req| companion_authorize_service(req).boxed())),
        ..Default::default()
    };

    let handle = session.register_agent(agent).await?;
    info!(
        "{} pairing: registered default Companion Classic BT pairing agent",
        NAME
    );
    Ok(handle)
}

async fn register_companion_profile(
    session: &Session,
    uuid: &str,
    name: &str,
    channel: u16,
) -> Result<ProfileHandle> {
    let profile = Profile {
        uuid: Uuid::parse_str(uuid)?,
        name: Some(name.to_string()),
        channel: Some(channel),
        role: Some(Role::Server),
        require_authentication: Some(false),
        require_authorization: Some(false),
        ..Default::default()
    };

    let handle = session.register_profile(profile).await?;
    info!(
        "{} registered Classic BT companion profile name={} uuid={} channel={}",
        NAME, name, uuid, channel
    );
    Ok(handle)
}

pub async fn register_companion_bt_profile(session: &Session) -> Result<ProfileHandle> {
    register_companion_profile(
        session,
        COMPANION_BT_UUID,
        "AA Proxy Companion Control",
        COMPANION_RFCOMM_CHANNEL,
    )
    .await
}

pub async fn register_companion_spp_profile(session: &Session) -> Result<ProfileHandle> {
    // Android's system Bluetooth settings can be picky when pairing with devices
    // that only expose vendor/custom RFCOMM UUIDs. Exposing an additional standard
    // Serial Port Profile record gives the OS a familiar Classic BT service to
    // pair/connect against, while the companion app can still use the custom UUID.
    register_companion_profile(
        session,
        SERIAL_PORT_PROFILE_UUID,
        "AA Proxy Companion Serial",
        COMPANION_SPP_RFCOMM_CHANNEL,
    )
    .await
}

pub fn spawn_companion_bt_accept_loop(mut handle: ProfileHandle, state: AppState) {
    tokio::spawn(async move {
        while let Some(req) = handle.next().await {
            let device = req.device().clone();
            info!("{} connection request from <b>{}</>", NAME, device);

            match req.accept() {
                Ok(stream) => {
                    info!("{} accepted connection from <b>{}</>", NAME, device);
                    let client_state = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, client_state).await {
                            warn!("{} client <b>{}</> ended: {}", NAME, device, e);
                        }
                    });
                }
                Err(e) => {
                    warn!("{} accept error from <b>{}</>: {}", NAME, device, e);
                }
            }
        }

        warn!("{} no more Classic BT companion connection requests", NAME);
    });
}

async fn handle_client(stream: Stream, state: AppState) -> Result<()> {
    let (mut reader, writer) = tokio::io::split(stream);
    let writer = Arc::new(Mutex::new(writer));
    let subscriptions = Arc::new(Mutex::new(HashSet::<String>::new()));
    let mut auth = CompanionBtAuthState::from_state(&state).await;

    if auth.required {
        if auth.configured() {
            info!(
                "{} auth: required; waiting for HMAC challenge-response before accepting commands",
                NAME
            );
        } else {
            info!(
                "{} auth: required but token is empty; entering provisioning-only mode",
                NAME
            );
        }
    }

    spawn_event_forwarder(writer.clone(), subscriptions.clone(), state.clone());

    loop {
        let frame = read_frame(&mut reader).await?;

        match frame.op {
            COMPANION_OP_AUTH_STATUS => {
                let payload = auth.status_payload()?;
                write_json_frame(
                    writer.clone(),
                    COMPANION_OP_AUTH_STATUS_REPLY,
                    frame.request_id,
                    &payload,
                )
                .await?;
                continue;
            }
            COMPANION_OP_AUTH_RESPONSE => {
                if !auth.required {
                    auth.authenticated = true;
                    write_json_frame(
                        writer.clone(),
                        COMPANION_OP_AUTH_OK,
                        frame.request_id,
                        &AuthOkPayload {
                            ok: true,
                            message: "auth not required",
                        },
                    )
                    .await?;
                    continue;
                }

                if !auth.configured() {
                    write_error(
                        writer.clone(),
                        frame.request_id,
                        "BT auth token is not configured; use AUTH_SET_TOKEN provisioning"
                            .to_string(),
                    )
                    .await?;
                    continue;
                }

                let payload: AuthResponsePayload = match serde_json::from_slice(&frame.payload) {
                    Ok(payload) => payload,
                    Err(e) => {
                        write_error(
                            writer.clone(),
                            frame.request_id,
                            format!("invalid auth response payload: {e}"),
                        )
                        .await?;
                        continue;
                    }
                };

                let Some(server_nonce) = auth.server_nonce.as_ref() else {
                    write_error(
                        writer.clone(),
                        frame.request_id,
                        "auth challenge was not requested".to_string(),
                    )
                    .await?;
                    continue;
                };
                let client_nonce = match BASE64_STANDARD.decode(payload.client_nonce.as_bytes()) {
                    Ok(nonce) => nonce,
                    Err(e) => {
                        write_error(
                            writer.clone(),
                            frame.request_id,
                            format!("invalid client_nonce: {e}"),
                        )
                        .await?;
                        continue;
                    }
                };
                let response = match BASE64_STANDARD.decode(payload.response.as_bytes()) {
                    Ok(response) => response,
                    Err(e) => {
                        write_error(
                            writer.clone(),
                            frame.request_id,
                            format!("invalid auth response: {e}"),
                        )
                        .await?;
                        continue;
                    }
                };
                let expected = hmac_sha256(
                    auth.token.as_bytes(),
                    &companion_auth_message(server_nonce, &client_nonce),
                );

                if constant_time_eq(&response, &expected) {
                    auth.authenticated = true;
                    info!("{} auth: HMAC authentication succeeded", NAME);
                    write_json_frame(
                        writer.clone(),
                        COMPANION_OP_AUTH_OK,
                        frame.request_id,
                        &AuthOkPayload {
                            ok: true,
                            message: "authenticated",
                        },
                    )
                    .await?;
                } else {
                    warn!(
                        "{} auth: HMAC authentication failed; closing connection",
                        NAME
                    );
                    write_error(
                        writer.clone(),
                        frame.request_id,
                        "authentication failed".to_string(),
                    )
                    .await?;
                    return Err("authentication failed".into());
                }
                continue;
            }
            COMPANION_OP_AUTH_SET_TOKEN => {
                if !auth.required {
                    write_error(
                        writer.clone(),
                        frame.request_id,
                        "BT auth is not required".to_string(),
                    )
                    .await?;
                    continue;
                }
                if auth.configured() && !auth.authenticated {
                    write_error(
                        writer.clone(),
                        frame.request_id,
                        "BT auth token is already configured; authenticate before changing it"
                            .to_string(),
                    )
                    .await?;
                    continue;
                }

                let payload: AuthSetTokenPayload = match serde_json::from_slice(&frame.payload) {
                    Ok(payload) => payload,
                    Err(e) => {
                        write_error(
                            writer.clone(),
                            frame.request_id,
                            format!("invalid set-token payload: {e}"),
                        )
                        .await?;
                        continue;
                    }
                };
                let token = match validate_auth_token(&payload.token) {
                    Ok(token) => token,
                    Err(e) => {
                        write_error(
                            writer.clone(),
                            frame.request_id,
                            format!("invalid auth token: {e}"),
                        )
                        .await?;
                        continue;
                    }
                };

                {
                    let mut cfg = state.config.write().await;
                    cfg.companion_bt_auth_token = token.clone();
                    cfg.save(state.config_file.as_ref().clone());
                }
                auth.token = token;
                auth.server_nonce = Some(random_bytes(AUTH_NONCE_LEN));
                auth.authenticated = true;
                info!(
                    "{} auth: companion BT auth token provisioned and saved",
                    NAME
                );
                write_json_frame(
                    writer.clone(),
                    COMPANION_OP_AUTH_OK,
                    frame.request_id,
                    &AuthOkPayload {
                        ok: true,
                        message: "token provisioned",
                    },
                )
                .await?;
                continue;
            }
            _ => {}
        }

        if !auth.authenticated {
            write_error(
                writer.clone(),
                frame.request_id,
                "BT auth required before using companion commands".to_string(),
            )
            .await?;
            continue;
        }

        match frame.op {
            COMPANION_OP_PING => {
                write_json_frame(
                    writer.clone(),
                    COMPANION_OP_PONG,
                    frame.request_id,
                    &StatusPayload {
                        ready: true,
                        transport: "bt",
                        version: COMPANION_APP_VERSION,
                    },
                )
                .await?;
            }
            COMPANION_OP_GET_STATUS => {
                write_json_frame(
                    writer.clone(),
                    COMPANION_OP_STATUS,
                    frame.request_id,
                    &StatusPayload {
                        ready: true,
                        transport: "bt",
                        version: COMPANION_APP_VERSION,
                    },
                )
                .await?;
            }
            COMPANION_OP_ECHO => {
                write_raw_frame(
                    writer.clone(),
                    COMPANION_OP_ECHO_REPLY,
                    frame.request_id,
                    frame.payload,
                )
                .await?;
            }
            COMPANION_OP_REST_CALL | COMPANION_OP_REST_CALL_SYNC => {
                let req: CompanionHttpRequest = match serde_json::from_slice(&frame.payload) {
                    Ok(req) => req,
                    Err(e) => {
                        write_error(
                            writer.clone(),
                            frame.request_id,
                            format!("invalid REST payload: {e}"),
                        )
                        .await?;
                        continue;
                    }
                };

                let response =
                    match tokio::task::spawn_blocking(move || dispatch_companion_http(req)).await {
                        Ok(response) => response,
                        Err(e) => {
                            write_error(
                                writer.clone(),
                                frame.request_id,
                                format!("REST task failed: {e}"),
                            )
                            .await?;
                            continue;
                        }
                    };

                write_json_frame(
                    writer.clone(),
                    COMPANION_OP_REST_CALL_RESULT,
                    frame.request_id,
                    &response,
                )
                .await?;
            }
            COMPANION_OP_SUBSCRIBE_TOPIC_EVENT => {
                let payload: TopicPayload = match serde_json::from_slice(&frame.payload) {
                    Ok(payload) => payload,
                    Err(e) => {
                        write_error(
                            writer.clone(),
                            frame.request_id,
                            format!("invalid subscribe payload: {e}"),
                        )
                        .await?;
                        continue;
                    }
                };
                subscriptions.lock().await.insert(payload.topic.clone());
                write_raw_frame(
                    writer.clone(),
                    COMPANION_OP_STATUS,
                    frame.request_id,
                    b"{\"status\":1}".to_vec(),
                )
                .await?;
            }
            COMPANION_OP_UNSUBSCRIBE_TOPIC_EVENT => {
                let payload: TopicPayload = match serde_json::from_slice(&frame.payload) {
                    Ok(payload) => payload,
                    Err(e) => {
                        write_error(
                            writer.clone(),
                            frame.request_id,
                            format!("invalid unsubscribe payload: {e}"),
                        )
                        .await?;
                        continue;
                    }
                };
                subscriptions.lock().await.remove(&payload.topic);
                write_raw_frame(
                    writer.clone(),
                    COMPANION_OP_STATUS,
                    frame.request_id,
                    b"{\"status\":1}".to_vec(),
                )
                .await?;
            }
            COMPANION_OP_ON_SCRIPT_EVENT => {
                let payload: TopicEventPayload = match serde_json::from_slice(&frame.payload) {
                    Ok(payload) => payload,
                    Err(e) => {
                        write_error(
                            writer.clone(),
                            frame.request_id,
                            format!("invalid script event payload: {e}"),
                        )
                        .await?;
                        continue;
                    }
                };
                let _ = state.ws_event_tx.send(ServerEvent {
                    topic: payload.topic,
                    payload: payload.payload,
                });
                write_raw_frame(
                    writer.clone(),
                    COMPANION_OP_STATUS,
                    frame.request_id,
                    b"{\"status\":1}".to_vec(),
                )
                .await?;
            }
            _ => {
                write_error(
                    writer.clone(),
                    frame.request_id,
                    format!("unknown op 0x{:02x}", frame.op),
                )
                .await?;
            }
        }
    }
}

fn spawn_event_forwarder(
    writer: SharedWriter,
    subscriptions: Arc<Mutex<HashSet<String>>>,
    state: AppState,
) {
    tokio::spawn(async move {
        let mut rx = state.ws_event_tx.subscribe();
        loop {
            let event = match rx.recv().await {
                Ok(event) => event,
                Err(e) => {
                    warn!("{} event receiver ended: {}", NAME, e);
                    break;
                }
            };

            let subscribed = {
                let subscriptions = subscriptions.lock().await;
                subscriptions.contains(&event.topic)
            };
            if !subscribed {
                continue;
            }

            let payload = TopicEventPayload {
                topic: event.topic,
                payload: event.payload,
            };
            if let Err(e) =
                write_json_frame(writer.clone(), COMPANION_OP_ON_TOPIC_EVENT, 0, &payload).await
            {
                warn!("{} failed to forward event over BT: {}", NAME, e);
                break;
            }
        }
    });
}

async fn write_error(writer: SharedWriter, request_id: u64, error: String) -> Result<()> {
    write_json_frame(
        writer,
        COMPANION_OP_ERROR,
        request_id,
        &ErrorPayload { error },
    )
    .await
}

async fn write_json_frame<T: Serialize>(
    writer: SharedWriter,
    op: u8,
    request_id: u64,
    payload: &T,
) -> Result<()> {
    let payload = serde_json::to_vec(payload)?;
    write_raw_frame(writer, op, request_id, payload).await
}

async fn write_raw_frame(
    writer: SharedWriter,
    op: u8,
    request_id: u64,
    payload: Vec<u8>,
) -> Result<()> {
    let mut writer = writer.lock().await;
    write_frame(&mut *writer, &CompanionFrame::new(op, request_id, payload)).await
}
