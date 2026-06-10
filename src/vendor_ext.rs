use crate::companion_protocol::{
    COMPANION_APP_VERSION, COMPANION_OP_ECHO, COMPANION_OP_ECHO_REPLY, COMPANION_OP_ERROR,
    COMPANION_OP_GET_STATUS, COMPANION_OP_ON_SCRIPT_EVENT, COMPANION_OP_ON_TOPIC_EVENT,
    COMPANION_OP_PING, COMPANION_OP_PONG, COMPANION_OP_REST_CALL, COMPANION_OP_REST_CALL_REPLY,
    COMPANION_OP_REST_CALL_RESULT, COMPANION_OP_REST_CALL_SYNC, COMPANION_OP_STATUS,
    COMPANION_OP_SUBSCRIBE_TOPIC_EVENT, COMPANION_OP_UNSUBSCRIBE_TOPIC_EVENT,
};
use crate::mitm::protos::{Service, ServiceDiscoveryResponse, VendorExtensionService};
use crate::mitm::{
    ModifyContext, Packet, PacketAction, Result, ENCRYPTED, FRAME_TYPE_FIRST, FRAME_TYPE_LAST,
};
#[cfg(feature = "wasm-scripting")]
use crate::script_wasm::{LoadedScript, ScriptRegistry};
use crate::web::ServerEvent;
#[cfg(not(feature = "wasm-scripting"))]
type ScriptRegistry = ();
use log::{debug, info, warn};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc::Sender, RwLock};
use tokio::task::JoinHandle;

pub(crate) const OUR_COMPANION_SERVICE_NAME: &str = "aaproxy_companion";
pub(crate) const OUR_COMPANION_PACKAGE: &str = "com.github.deadknight.aaproxycompanion";

// Keep outbound custom companion app-data packets below the aa-proxy IO buffer
// and below the sizes that some phone/HU stacks appear to tolerate on a
// single vendor-extension channel frame. The AA transport supports FIRST /
// middle / LAST fragmentation, so large REST responses are split here.
const COMPANION_APP_FRAGMENT_CHUNK_SIZE: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VecChannelState {
    Opened,
}

#[derive(Clone)]
pub(crate) struct VecTopicEventRuntime {
    pub(crate) ws_event_tx: broadcast::Sender<ServerEvent>,
    pub(crate) script_registry: Option<Arc<ScriptRegistry>>,
}

pub(crate) fn is_vendor_service_id(ctx: &ModifyContext, service_id: u8) -> bool {
    ctx.vendor_service_ids.contains(&service_id)
}

pub(crate) fn is_vendor_channel(ctx: &ModifyContext, channel: u8) -> bool {
    ctx.vendor_service_ids.contains(&channel) || ctx.vendor_channel_states.contains_key(&channel)
}

pub(crate) fn mark_vendor_channel_open(ctx: &mut ModifyContext, channel: u8) {
    ctx.vendor_channel_states
        .insert(channel, VecChannelState::Opened);
}

pub(crate) fn ensure_vendor_channel_open(ctx: &mut ModifyContext, channel: u8) {
    ctx.vendor_channel_states
        .entry(channel)
        .or_insert(VecChannelState::Opened);
}

pub(crate) struct VecTopicEventBridge {
    pub(crate) subscriptions: Arc<RwLock<HashSet<String>>>,
    task: JoinHandle<()>,
}

impl VecTopicEventBridge {
    fn new(channel: u8, tx: Sender<Packet>, runtime: VecTopicEventRuntime) -> Self {
        let subscriptions = Arc::new(RwLock::new(HashSet::new()));
        let task_subscriptions = subscriptions.clone();
        let mut ws_event_rx = runtime.ws_event_tx.subscribe();

        let task = tokio::spawn(async move {
            loop {
                match ws_event_rx.recv().await {
                    Ok(event) => {
                        let should_send = {
                            let subscriptions = task_subscriptions.read().await;
                            subscriptions.contains(&event.topic)
                        };

                        if !should_send {
                            continue;
                        }

                        let event = match run_wasm_vec_topic_hooks(
                            event.topic.clone(),
                            event.payload.clone(),
                            runtime.clone(),
                        )
                        .await
                        {
                            Ok(Some(true)) => {
                                // wasm handled it and already emitted a replacement event.
                                continue;
                            }
                            Ok(Some(false)) | Ok(None) => event,
                            Err(err) => {
                                warn!(
                                    "wasm VEC topic hook failed, forwarding original event: {:#}",
                                    err
                                );
                                event
                            }
                        };

                        let payload = VecTopicEvent {
                            topic: event.topic,
                            payload: event.payload,
                        };

                        let payload = match serde_json::to_string(&payload) {
                            Ok(payload) => payload.into_bytes(),
                            Err(e) => {
                                warn!("Failed to serialize VEC topic event: {}", e);
                                continue;
                            }
                        };

                        let reply =
                            build_vendor_app_reply(channel, COMPANION_OP_ON_TOPIC_EVENT, payload);

                        if let Err(e) = tx.send(reply).await {
                            warn!("Failed to send VEC topic event to phone: {}", e);
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(
                            "Companion topic event bridge lagged on channel={:#04x}, skipped {} events",
                            channel, skipped
                        );
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!("VEC topic event bus closed for channel={:#04x}", channel);
                        break;
                    }
                }
            }
        });

        Self {
            subscriptions,
            task,
        }
    }
}

impl Drop for VecTopicEventBridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) fn ensure_vendor_topic_event_bridge(
    ctx: &mut ModifyContext,
    channel: u8,
    runtime: VecTopicEventRuntime,
) -> bool {
    if ctx.vendor_topic_event_bridges.contains_key(&channel) {
        return true;
    }

    let Some(tx) = ctx.hu_tx.clone() else {
        warn!(
            "Cannot start Companion topic event bridge for channel={:#04x}: hu_tx is missing",
            channel
        );
        return false;
    };

    info!(
        "Starting Companion topic event bridge channel={:#04x}",
        channel
    );

    ctx.vendor_topic_event_bridges
        .insert(channel, VecTopicEventBridge::new(channel, tx, runtime));

    true
}

pub(crate) fn vendor_extension_service_id(msg: &ServiceDiscoveryResponse) -> Option<u8> {
    msg.services
        .iter()
        .find(|svc| {
            svc.vendor_extension_service
                .as_ref()
                .map(|ves| ves.service_name() == OUR_COMPANION_SERVICE_NAME)
                .unwrap_or(false)
        })
        .map(|svc| svc.id() as u8)
}

pub(crate) fn has_vendor_extension_service(msg: &ServiceDiscoveryResponse) -> bool {
    vendor_extension_service_id(msg).is_some()
}

pub(crate) fn add_vendor_extension_service(
    msg: &mut ServiceDiscoveryResponse,
    ctx: &mut ModifyContext,
) -> Option<u8> {
    if let Some(existing_service_id) = vendor_extension_service_id(msg) {
        ctx.vendor_service_ids.insert(existing_service_id);
        return None;
    }

    let next_service_id = msg.services.iter().map(|svc| svc.id()).max().unwrap_or(0) + 1;

    let mut service = Service::new();
    service.set_id(next_service_id);

    let mut ves = VendorExtensionService::new();
    ves.set_service_name(OUR_COMPANION_SERVICE_NAME.to_string());
    ves.package_white_list
        .push(OUR_COMPANION_PACKAGE.to_string());

    service.vendor_extension_service = protobuf::MessageField::some(ves);
    msg.services.push(service);

    let service_id = next_service_id as u8;
    ctx.vendor_service_ids.insert(service_id);

    Some(service_id)
}

fn build_vendor_app_reply(channel: u8, opcode: u8, payload: Vec<u8>) -> Packet {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(COMPANION_APP_VERSION);
    out.push(opcode);
    out.extend_from_slice(&payload);

    Packet {
        channel,
        // Custom vendor app-data frame. Do not set CONTROL here.
        flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload: out,
    }
}

fn build_vendor_app_reply_fragments(channel: u8, opcode: u8, payload: Vec<u8>) -> Vec<Packet> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(COMPANION_APP_VERSION);
    out.push(opcode);
    out.extend_from_slice(&payload);

    if out.len() <= COMPANION_APP_FRAGMENT_CHUNK_SIZE {
        return vec![Packet {
            channel,
            // Custom vendor app-data frame. Do not set CONTROL here.
            flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
            final_length: None,
            payload: out,
        }];
    }

    let total_len = out.len() as u32;
    let total_chunks =
        (out.len() + COMPANION_APP_FRAGMENT_CHUNK_SIZE - 1) / COMPANION_APP_FRAGMENT_CHUNK_SIZE;

    info!(
        "VEC reply fragmented channel={:#04x} opcode={:#04x} total_len={} chunks={} chunk_size={}",
        channel, opcode, total_len, total_chunks, COMPANION_APP_FRAGMENT_CHUNK_SIZE
    );

    let mut packets = Vec::with_capacity(total_chunks);
    for (index, chunk) in out.chunks(COMPANION_APP_FRAGMENT_CHUNK_SIZE).enumerate() {
        let first = index == 0;
        let last = index + 1 == total_chunks;

        let mut flags = ENCRYPTED;
        if first {
            flags |= FRAME_TYPE_FIRST;
        }
        if last {
            flags |= FRAME_TYPE_LAST;
        }

        packets.push(Packet {
            channel,
            flags,
            final_length: if first { Some(total_len) } else { None },
            payload: chunk.to_vec(),
        });
    }

    packets
}

async fn send_vendor_app_reply_fragments(
    tx: Sender<Packet>,
    channel: u8,
    opcode: u8,
    payload: Vec<u8>,
) -> std::result::Result<(), tokio::sync::mpsc::error::SendError<Packet>> {
    for reply in build_vendor_app_reply_fragments(channel, opcode, payload) {
        tx.send(reply).await?;
    }

    Ok(())
}

fn build_error_reply(channel: u8, message: impl Into<String>) -> Packet {
    let message = message.into();
    warn!("VEC error: {}", message);
    build_vendor_app_reply(channel, COMPANION_OP_ERROR, message.into_bytes())
}

#[derive(Debug, Deserialize, Serialize)]
struct VecRestCall {
    method: String,
    path: String,
    body: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct VecRestCallStatus {
    request_id: String,
    status: i8,
}

#[derive(Debug, Deserialize, Serialize)]
struct VecRestCallResult {
    request_id: String,
    payload: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct VecTopicSubscription {
    topic: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct VecTopicEvent {
    topic: String,
    payload: String,
}

fn parse_json_body<T: DeserializeOwned>(
    body: Vec<u8>,
    op_name: &str,
) -> std::result::Result<T, String> {
    let body_str = String::from_utf8(body)
        .map_err(|e| format!("{} body is not valid UTF-8: {}", op_name, e))?;

    serde_json::from_str(&body_str)
        .map_err(|e| format!("Invalid {} JSON: {}; body={}", op_name, e, body_str))
}

fn build_topic_status_reply(
    channel: u8,
    status: &str,
    topic: String,
    receiver_count: Option<usize>,
) -> Packet {
    let payload = serde_json::json!({
        "ok": true,
        "status": status,
        "topic": topic,
        "receiver_count": receiver_count,
    })
    .to_string();

    build_vendor_app_reply(channel, COMPANION_OP_STATUS, payload.into_bytes())
}

#[cfg(not(feature = "wasm-scripting"))]
async fn run_wasm_vec_topic_hooks(
    _topic: String,
    _payload: String,
    _runtime: VecTopicEventRuntime,
) -> Result<Option<bool>> {
    Ok(None)
}

#[cfg(feature = "wasm-scripting")]
async fn run_wasm_vec_topic_hooks(
    topic: String,
    payload: String,
    runtime: VecTopicEventRuntime,
) -> Result<Option<bool>> {
    let Some(registry) = runtime.script_registry else {
        return Ok(None);
    };

    let loaded: Vec<LoadedScript> = registry.list_scripts();
    if loaded.is_empty() {
        return Ok(None);
    }

    for script in loaded {
        match script
            .engine
            .ws_script_handler(topic.clone(), payload.clone())
            .await
        {
            Ok((result_payload, _effects)) => {
                if !result_payload.is_empty() {
                    let _ = runtime.ws_event_tx.send(ServerEvent {
                        topic: topic.clone(),
                        payload: result_payload,
                    });

                    return Ok(Some(true));
                }
            }
            Err(err) => {
                warn!(
                    "wasm VEC topic hook runtime error [{}], forwarding original event: {:#}",
                    script.path.display(),
                    err
                );
            }
        }
    }

    Ok(Some(false))
}

pub(crate) async fn handle_vendor_channel_packet(
    pkt: &mut Packet,
    ctx: &mut ModifyContext,
    runtime: VecTopicEventRuntime,
) -> Result<PacketAction> {
    let state = ctx.vendor_channel_states.get(&pkt.channel).copied();

    debug!(
        "VEC app packet channel={:#04x} state={:?} flags={:#04x} len={} payload={:02X?}",
        pkt.channel,
        state,
        pkt.flags,
        pkt.payload.len(),
        pkt.payload
    );

    if pkt.payload.len() < 2 {
        warn!(
            "VEC app packet too short channel={:#04x} payload={:02X?}",
            pkt.channel, pkt.payload
        );

        *pkt = build_error_reply(pkt.channel, "short packet");
        return Ok(PacketAction::SendBack);
    }

    let version = pkt.payload[0];
    let opcode = pkt.payload[1];
    let body = pkt.payload[2..].to_vec();

    if version != COMPANION_APP_VERSION {
        warn!(
            "VEC unsupported app version={} opcode={:#04x} channel={:#04x}",
            version, opcode, pkt.channel
        );

        *pkt = build_error_reply(pkt.channel, format!("unsupported version {}", version));
        return Ok(PacketAction::SendBack);
    }

    match opcode {
        COMPANION_OP_PING => {
            info!(
                "VEC PING received channel={:#04x} payload={:02X?}",
                pkt.channel, body
            );

            *pkt = build_vendor_app_reply(pkt.channel, COMPANION_OP_PONG, body);
            Ok(PacketAction::SendBack)
        }
        COMPANION_OP_GET_STATUS => {
            let status = serde_json::json!({
                "ok": true,
                "channel": pkt.channel,
                "sensor_channel": ctx.sensor_channel,
                "input_channel": ctx.input_channel,
                "nav_channel": ctx.nav_channel,
                "audio_channels": &ctx.audio_channels,
            })
            .to_string();

            info!("VEC GET_STATUS received channel={:#04x}", pkt.channel);

            *pkt = build_vendor_app_reply(pkt.channel, COMPANION_OP_STATUS, status.into_bytes());
            Ok(PacketAction::SendBack)
        }
        COMPANION_OP_ECHO => {
            info!(
                "VEC ECHO received channel={:#04x} payload_len={}",
                pkt.channel,
                body.len()
            );

            *pkt = build_vendor_app_reply(pkt.channel, COMPANION_OP_ECHO_REPLY, body);
            Ok(PacketAction::SendBack)
        }
        COMPANION_OP_SUBSCRIBE_TOPIC_EVENT => {
            let subscription: VecTopicSubscription = match parse_json_body(body, "VEC subscribe") {
                Ok(v) => v,
                Err(e) => {
                    warn!("{}", e);
                    *pkt = build_error_reply(pkt.channel, e);
                    return Ok(PacketAction::SendBack);
                }
            };

            let topic = subscription.topic.trim().to_string();
            if topic.is_empty() {
                *pkt = build_error_reply(pkt.channel, "VEC subscribe topic is empty");
                return Ok(PacketAction::SendBack);
            }

            if !ensure_vendor_topic_event_bridge(ctx, pkt.channel, runtime) {
                *pkt = build_error_reply(
                    pkt.channel,
                    "Companion topic event bridge is not available for this channel",
                );
                return Ok(PacketAction::SendBack);
            }

            let Some(subscriptions) = ctx
                .vendor_topic_event_bridges
                .get(&pkt.channel)
                .map(|bridge| bridge.subscriptions.clone())
            else {
                *pkt = build_error_reply(
                    pkt.channel,
                    "Companion topic event bridge was not registered for this channel",
                );
                return Ok(PacketAction::SendBack);
            };

            subscriptions.write().await.insert(topic.clone());
            info!(
                "VEC subscribed channel={:#04x} topic={}",
                pkt.channel, topic
            );

            *pkt = build_topic_status_reply(pkt.channel, "subscribed", topic, None);
            Ok(PacketAction::SendBack)
        }
        COMPANION_OP_UNSUBSCRIBE_TOPIC_EVENT => {
            let subscription: VecTopicSubscription = match parse_json_body(body, "VEC unsubscribe")
            {
                Ok(v) => v,
                Err(e) => {
                    warn!("{}", e);
                    *pkt = build_error_reply(pkt.channel, e);
                    return Ok(PacketAction::SendBack);
                }
            };

            let topic = subscription.topic.trim().to_string();
            if topic.is_empty() {
                *pkt = build_error_reply(pkt.channel, "VEC unsubscribe topic is empty");
                return Ok(PacketAction::SendBack);
            }

            if let Some(subscriptions) = ctx
                .vendor_topic_event_bridges
                .get(&pkt.channel)
                .map(|bridge| bridge.subscriptions.clone())
            {
                subscriptions.write().await.remove(&topic);
            }

            info!(
                "VEC unsubscribed channel={:#04x} topic={}",
                pkt.channel, topic
            );

            *pkt = build_topic_status_reply(pkt.channel, "unsubscribed", topic, None);
            Ok(PacketAction::SendBack)
        }
        COMPANION_OP_ON_SCRIPT_EVENT => {
            let event: VecTopicEvent = match parse_json_body(body, "VEC script event") {
                Ok(v) => v,
                Err(e) => {
                    warn!("{}", e);
                    *pkt = build_error_reply(pkt.channel, e);
                    return Ok(PacketAction::SendBack);
                }
            };

            let topic = event.topic.trim().to_string();
            if topic.is_empty() {
                *pkt = build_error_reply(pkt.channel, "VEC script event topic is empty");
                return Ok(PacketAction::SendBack);
            }

            let payload = event.payload;
            let receiver_count = match run_wasm_vec_topic_hooks(
                topic.clone(),
                payload.clone(),
                runtime.clone(),
            )
            .await
            {
                Ok(Some(true)) => {
                    // wasm handled it and already emitted a replacement event.
                    0
                }
                Ok(Some(false)) | Ok(None) => {
                    match runtime.ws_event_tx.send(ServerEvent {
                        topic: topic.clone(),
                        payload,
                    }) {
                        Ok(receiver_count) => receiver_count,
                        Err(e) => {
                            debug!(
                                "VEC script event had no active receivers channel={:#04x} topic={} error={}",
                                pkt.channel, topic, e
                            );
                            0
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        "wasm VEC script event hook failed, forwarding original event: {:#}",
                        err
                    );

                    match runtime.ws_event_tx.send(ServerEvent {
                        topic: topic.clone(),
                        payload,
                    }) {
                        Ok(receiver_count) => receiver_count,
                        Err(e) => {
                            debug!(
                                "VEC script event had no active receivers channel={:#04x} topic={} error={}",
                                pkt.channel, topic, e
                            );
                            0
                        }
                    }
                }
            };

            info!(
                "VEC published script event channel={:#04x} topic={} receiver_count={}",
                pkt.channel, topic, receiver_count
            );

            *pkt = build_topic_status_reply(pkt.channel, "published", topic, Some(receiver_count));
            Ok(PacketAction::SendBack)
        }
        COMPANION_OP_REST_CALL_SYNC => {
            let body_str = match String::from_utf8(body) {
                Ok(s) => s,
                Err(e) => {
                    warn!("VEC REST body is not valid UTF-8: {}", e);
                    *pkt = build_error_reply(
                        pkt.channel,
                        format!("VEC REST body is not valid UTF-8: {}", e),
                    );
                    return Ok(PacketAction::SendBack);
                }
            };

            let rest_call: VecRestCall = match serde_json::from_str(&body_str) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Invalid VEC REST call JSON: {}; body={}", e, body_str);
                    *pkt = build_error_reply(
                        pkt.channel,
                        format!("Invalid VEC REST call JSON: {}", e),
                    );
                    return Ok(PacketAction::SendBack);
                }
            };

            let _ = match ctx.hu_tx.clone() {
                Some(tx) => tx,
                None => {
                    *pkt = build_error_reply(
                        pkt.channel,
                        "VEC REST call cannot be processed because hu_tx is missing",
                    );
                    return Ok(PacketAction::SendBack);
                }
            };

            let channel = pkt.channel;
            let result_call =
                rest_call_blocking(rest_call.method, rest_call.path, rest_call.body, false);

            *pkt = build_vendor_app_reply(
                channel,
                COMPANION_OP_REST_CALL_RESULT,
                result_call.into_bytes(),
            );

            return Ok(PacketAction::SendBack);
        }
        COMPANION_OP_REST_CALL => {
            let body_str = match String::from_utf8(body) {
                Ok(s) => s,
                Err(e) => {
                    warn!("VEC REST body is not valid UTF-8: {}", e);
                    *pkt = build_error_reply(
                        pkt.channel,
                        format!("VEC REST body is not valid UTF-8: {}", e),
                    );
                    return Ok(PacketAction::SendBack);
                }
            };

            let rest_call: VecRestCall = match serde_json::from_str(&body_str) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Invalid VEC REST call JSON: {}; body={}", e, body_str);
                    *pkt = build_error_reply(
                        pkt.channel,
                        format!("Invalid VEC REST call JSON: {}", e),
                    );
                    return Ok(PacketAction::SendBack);
                }
            };

            let tx = match ctx.hu_tx.clone() {
                Some(tx) => tx,
                None => {
                    *pkt = build_error_reply(
                        pkt.channel,
                        "VEC REST call cannot be processed because hu_tx is missing",
                    );
                    return Ok(PacketAction::SendBack);
                }
            };

            let channel = pkt.channel;
            let request_id = uuid::Uuid::new_v4().to_string();
            let request_id_for_task = request_id.clone();

            tokio::spawn(async move {
                let result_call = match tokio::task::spawn_blocking(move || {
                    rest_call_blocking(rest_call.method, rest_call.path, rest_call.body, false)
                })
                .await
                {
                    Ok(result_call) => result_call,
                    Err(e) => {
                        format!(r#"{{"ok":false,"error":"rest task failed: {}"}}"#, e)
                    }
                };

                let result_payload = VecRestCallResult {
                    request_id: request_id_for_task,
                    payload: result_call,
                };

                let payload = match serde_json::to_string(&result_payload) {
                    Ok(json) => json,
                    Err(e) => {
                        warn!("Failed to serialize VEC REST call result: {}", e);

                        let reply = build_error_reply(
                            channel,
                            format!("Failed to serialize VEC REST call result: {}", e),
                        );

                        if let Err(send_err) = tx.send(reply).await {
                            warn!(
                                "Failed to send async VEC REST serialization error to phone: {}",
                                send_err
                            );
                        }

                        return;
                    }
                };

                if let Err(e) = send_vendor_app_reply_fragments(
                    tx,
                    channel,
                    COMPANION_OP_REST_CALL_RESULT,
                    payload.into_bytes(),
                )
                .await
                {
                    warn!("Failed to send async VEC REST result to phone: {}", e);
                }
            });

            let rest_call_status = VecRestCallStatus {
                request_id,
                status: 1,
            };

            let payload = match serde_json::to_string(&rest_call_status) {
                Ok(json) => json,
                Err(e) => {
                    warn!("Failed to serialize VEC REST call status: {}", e);
                    *pkt = build_error_reply(
                        pkt.channel,
                        format!("Failed to serialize VEC REST call status: {}", e),
                    );
                    return Ok(PacketAction::SendBack);
                }
            };

            *pkt = build_vendor_app_reply(
                pkt.channel,
                COMPANION_OP_REST_CALL_REPLY,
                payload.into_bytes(),
            );

            Ok(PacketAction::SendBack)
        }
        _ => {
            warn!(
                "VEC unknown app opcode={:#04x} channel={:#04x} payload={:02X?}",
                opcode, pkt.channel, body
            );

            *pkt = build_error_reply(pkt.channel, format!("unknown opcode 0x{:02x}", opcode));
            Ok(PacketAction::SendBack)
        }
    }
}

pub fn rest_call_blocking(method: String, path: String, body: String, whitelist: bool) -> String {
    let path = path.trim();

    if whitelist {
        //Whitelist calls
        match (method.as_str(), path) {
            ("POST", "/battery")
            | ("POST", "/odometer")
            | ("POST", "/tire-pressure")
            | ("POST", "/inject_event")
            | ("POST", "/inject_rotary")
            | ("GET", "/speed")
            | ("GET", "/battery-status")
            | ("GET", "/odometer-status")
            | ("GET", "/tire-pressure-status") => {}

            _ => {
                return format!(
                    r#"{{"ok":false,"status":403,"error":"route not allowed from script: {} {}"}}"#,
                    method, path
                );
            }
        }
    }

    let url = format!("http://127.0.0.1{}", path);

    let result = match method.as_str() {
        "GET" => ureq::get(&url).call(),

        "POST" => ureq::post(&url)
            .set("content-type", "application/json")
            .send_string(&body),

        _ => {
            return r#"{"ok":false,"status":405,"error":"unsupported method"}"#.to_string();
        }
    };

    match result {
        Ok(response) => {
            let status = response.status();

            let text = response.into_string().unwrap_or_else(|err| {
                format!(
                    r#"{{"ok":false,"error":"failed to read response: {}"}}"#,
                    err
                )
            });

            format!(
                r#"{{"ok":true,"status":{},"body":{}}}"#,
                status,
                serde_json::to_string(&text).unwrap_or_else(|_| "\"\"".to_string())
            )
        }

        Err(err) => {
            log::warn!("rest_call failed: {err}");

            format!(
                r#"{{"ok":false,"status":500,"error":{}}}"#,
                serde_json::to_string(&err.to_string())
                    .unwrap_or_else(|_| "\"request failed\"".to_string())
            )
        }
    }
}
