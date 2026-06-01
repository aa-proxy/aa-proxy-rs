use crate::companion_http::{dispatch_companion_http, CompanionHttpRequest};
use crate::companion_protocol::*;
use crate::web::{AppState, ServerEvent};
use bluer::agent::{
    Agent, AgentHandle, AuthorizeService, DisplayPasskey, DisplayPinCode,
    ReqResult as AgentReqResult, RequestAuthorization, RequestConfirmation,
    RequestPasskey, RequestPinCode,
};
use bluer::rfcomm::{Profile, ProfileHandle, Role, Stream};
use bluer::{Address, Session, Uuid};
use futures::{FutureExt, StreamExt};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::io::WriteHalf;
use tokio::sync::Mutex;

const NAME: &str = "<i><bright-black> companion_bt: </>";
const COMPANION_RFCOMM_CHANNEL: u16 = 23;

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

#[derive(Debug, Serialize, Deserialize)]
struct TopicEventPayload {
    topic: String,
    payload: String,
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
    info!("{} pairing: replying with fallback PIN 0000 for {}", NAME, req.device);
    Ok("0000".to_string())
}

async fn companion_display_pin_code(req: DisplayPinCode) -> AgentReqResult<()> {
    info!("{} pairing: display PIN-code request from {}: {}", NAME, req.device, req.pincode);
    Ok(())
}

async fn companion_request_passkey(req: RequestPasskey) -> AgentReqResult<u32> {
    info!("{} pairing: replying with fallback passkey 000000 for {}", NAME, req.device);
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
    info!("{} pairing: authorizing companion pairing from {}", NAME, req.device);
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
    info!("{} pairing: registered default Companion Classic BT pairing agent", NAME);
    Ok(handle)
}

pub async fn register_companion_bt_profile(session: &Session) -> Result<ProfileHandle> {
    let profile = Profile {
        uuid: Uuid::parse_str(COMPANION_BT_UUID)?,
        name: Some("AA Proxy Companion Control".to_string()),
        channel: Some(COMPANION_RFCOMM_CHANNEL),
        role: Some(Role::Server),
        require_authentication: Some(false),
        require_authorization: Some(false),
        ..Default::default()
    };

    let handle = session.register_profile(profile).await?;
    info!(
        "{} registered Classic BT companion profile uuid={} channel={}",
        NAME,
        COMPANION_BT_UUID,
        COMPANION_RFCOMM_CHANNEL
    );
    Ok(handle)
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

    spawn_event_forwarder(writer.clone(), subscriptions.clone(), state.clone());

    loop {
        let frame = read_frame(&mut reader).await?;
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
                write_raw_frame(writer.clone(), COMPANION_OP_ECHO_REPLY, frame.request_id, frame.payload)
                    .await?;
            }
            COMPANION_OP_REST_CALL | COMPANION_OP_REST_CALL_SYNC => {
                let req: CompanionHttpRequest = match serde_json::from_slice(&frame.payload) {
                    Ok(req) => req,
                    Err(e) => {
                        write_error(writer.clone(), frame.request_id, format!("invalid REST payload: {e}"))
                            .await?;
                        continue;
                    }
                };

                let response = match tokio::task::spawn_blocking(move || dispatch_companion_http(req)).await {
                    Ok(response) => response,
                    Err(e) => {
                        write_error(writer.clone(), frame.request_id, format!("REST task failed: {e}"))
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
                        write_error(writer.clone(), frame.request_id, format!("invalid subscribe payload: {e}"))
                            .await?;
                        continue;
                    }
                };
                subscriptions.lock().await.insert(payload.topic.clone());
                write_raw_frame(writer.clone(), COMPANION_OP_STATUS, frame.request_id, b"{\"status\":1}".to_vec())
                    .await?;
            }
            COMPANION_OP_UNSUBSCRIBE_TOPIC_EVENT => {
                let payload: TopicPayload = match serde_json::from_slice(&frame.payload) {
                    Ok(payload) => payload,
                    Err(e) => {
                        write_error(writer.clone(), frame.request_id, format!("invalid unsubscribe payload: {e}"))
                            .await?;
                        continue;
                    }
                };
                subscriptions.lock().await.remove(&payload.topic);
                write_raw_frame(writer.clone(), COMPANION_OP_STATUS, frame.request_id, b"{\"status\":1}".to_vec())
                    .await?;
            }
            COMPANION_OP_ON_SCRIPT_EVENT => {
                let payload: TopicEventPayload = match serde_json::from_slice(&frame.payload) {
                    Ok(payload) => payload,
                    Err(e) => {
                        write_error(writer.clone(), frame.request_id, format!("invalid script event payload: {e}"))
                            .await?;
                        continue;
                    }
                };
                let _ = state.ws_event_tx.send(ServerEvent {
                    topic: payload.topic,
                    payload: payload.payload,
                });
                write_raw_frame(writer.clone(), COMPANION_OP_STATUS, frame.request_id, b"{\"status\":1}".to_vec())
                    .await?;
            }
            _ => {
                write_error(writer.clone(), frame.request_id, format!("unknown op 0x{:02x}", frame.op))
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
            if let Err(e) = write_json_frame(writer.clone(), COMPANION_OP_ON_TOPIC_EVENT, 0, &payload).await {
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
