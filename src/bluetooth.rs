use crate::config::Action;
use crate::config::WifiConfig;
use crate::config::IDENTITY_NAME;
use crate::config_types::BluetoothAddressList;
use crate::sdr_ui;
use crate::web::AppState;
use anyhow::anyhow;
use backon::{ExponentialBuilder, Retryable};
use bluer::{
    agent::{
        Agent, AgentHandle, AuthorizeService, DisplayPasskey, DisplayPinCode,
        ReqError as AgentReqError, ReqResult as AgentReqResult, RequestAuthorization,
        RequestConfirmation, RequestPasskey, RequestPinCode,
    },
    l2cap::{SocketAddr as L2capSocketAddr, Stream as L2capStream},
    rfcomm::{Profile, ProfileHandle, Role, SocketAddr, Stream},
    Adapter, Address, AddressType, Session, Uuid,
};
use futures::{FutureExt, StreamExt};
use simplelog::*;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::broadcast::Receiver as BroadcastReceiver;
use tokio::sync::broadcast::Sender as BroadcastSender;
use tokio::sync::Notify;
use tokio::time::timeout;

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
use protobuf::Message;
use WifiInfoResponse::AccessPointType;
use WifiInfoResponse::SecurityMode;
const HEADER_LEN: usize = 4;
const STAGES: u8 = 5;
const ATTEMPTS: usize = 3;

// module name for logging engine
const NAME: &str = "<i><bright-black> bluetooth: </>";

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const SDP_PSM: u16 = 0x0001;
const SDP_PDU_SERVICE_SEARCH_ATTRIBUTE_REQUEST: u8 = 0x06;
const SDP_PDU_SERVICE_SEARCH_ATTRIBUTE_RESPONSE: u8 = 0x07;
const SDP_ATTR_PROTOCOL_DESCRIPTOR_LIST: u16 = 0x0004;
const SDP_MAX_ATTRIBUTE_BYTES: u16 = 0xffff;

fn sdp_de_sequence_u8(payload: Vec<u8>) -> Result<Vec<u8>> {
    if payload.len() > u8::MAX as usize {
        return Err(format!("SDP sequence too long for u8 length: {}", payload.len()).into());
    }
    let mut out = Vec::with_capacity(payload.len() + 2);
    out.push(0x35); // Data Element Sequence, next u8 contains length.
    out.push(payload.len() as u8);
    out.extend_from_slice(&payload);
    Ok(out)
}

fn sdp_de_uuid128(uuid: Uuid) -> Vec<u8> {
    let mut out = Vec::with_capacity(17);
    out.push(0x1c); // UUID, 128-bit.
    out.extend_from_slice(&uuid.as_u128().to_be_bytes());
    out
}

fn sdp_de_uint32(value: u32) -> [u8; 5] {
    let bytes = value.to_be_bytes();
    [0x0a, bytes[0], bytes[1], bytes[2], bytes[3]] // Unsigned integer, 32-bit.
}

fn build_sdp_service_search_attribute_request(
    transaction_id: u16,
    service_uuid: Uuid,
    continuation_state: &[u8],
) -> Result<Vec<u8>> {
    if continuation_state.len() > u8::MAX as usize {
        return Err(format!("SDP continuation state too long: {}", continuation_state.len()).into());
    }

    let service_search_pattern = sdp_de_sequence_u8(sdp_de_uuid128(service_uuid))?;

    let attr_range = ((SDP_ATTR_PROTOCOL_DESCRIPTOR_LIST as u32) << 16)
        | SDP_ATTR_PROTOCOL_DESCRIPTOR_LIST as u32;
    let attribute_id_list = sdp_de_sequence_u8(sdp_de_uint32(attr_range).to_vec())?;

    let mut params = Vec::new();
    params.extend_from_slice(&service_search_pattern);
    params.extend_from_slice(&SDP_MAX_ATTRIBUTE_BYTES.to_be_bytes());
    params.extend_from_slice(&attribute_id_list);
    params.push(continuation_state.len() as u8);
    params.extend_from_slice(continuation_state);

    if params.len() > u16::MAX as usize {
        return Err(format!("SDP request parameters too long: {}", params.len()).into());
    }

    let mut pdu = Vec::with_capacity(params.len() + 5);
    pdu.push(SDP_PDU_SERVICE_SEARCH_ATTRIBUTE_REQUEST);
    pdu.extend_from_slice(&transaction_id.to_be_bytes());
    pdu.extend_from_slice(&(params.len() as u16).to_be_bytes());
    pdu.extend_from_slice(&params);
    Ok(pdu)
}

async fn read_sdp_pdu(stream: &mut L2capStream) -> Result<(u8, u16, Vec<u8>)> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let pdu_id = header[0];
    let transaction_id = u16::from_be_bytes([header[1], header[2]]);
    let param_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut params = vec![0u8; param_len];
    stream.read_exact(&mut params).await?;
    Ok((pdu_id, transaction_id, params))
}

fn parse_rfcomm_channel_after_uuid16(bytes: &[u8], pos: usize) -> Option<u8> {
    let tag = *bytes.get(pos)?;
    match tag {
        0x08 => {
            let ch = *bytes.get(pos + 1)?;
            (1..=30).contains(&ch).then_some(ch)
        }
        0x09 => {
            let value = u16::from_be_bytes([*bytes.get(pos + 1)?, *bytes.get(pos + 2)?]);
            if (1..=30).contains(&value) {
                Some(value as u8)
            } else {
                None
            }
        }
        0x0a => {
            let value = u32::from_be_bytes([
                *bytes.get(pos + 1)?,
                *bytes.get(pos + 2)?,
                *bytes.get(pos + 3)?,
                *bytes.get(pos + 4)?,
            ]);
            if (1..=30).contains(&value) {
                Some(value as u8)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn extract_rfcomm_channel_from_sdp_attribute_lists(bytes: &[u8]) -> Option<u8> {
    // Minimal parser for the ProtocolDescriptorList we requested. In SDP data,
    // RFCOMM is normally encoded as UUID16 0x0003 (`19 00 03`) followed by an
    // unsigned integer data element containing the RFCOMM channel.
    let pattern = [0x19, 0x00, 0x03];
    bytes
        .windows(pattern.len())
        .enumerate()
        .find_map(|(idx, window)| {
            if window == pattern {
                parse_rfcomm_channel_after_uuid16(bytes, idx + pattern.len())
            } else {
                None
            }
        })
}

async fn discover_rfcomm_channel_via_internal_sdp_once(hu_addr: Address, settle_delay: Duration) -> Result<u8> {
    let sdp_addr = L2capSocketAddr::new(hu_addr, AddressType::BrEdr, SDP_PSM);
    info!(
        "{} 🧪 bt-wireless-proxy: internal SDP discovery: connecting to HU {} L2CAP PSM 0x{:04x}",
        NAME, hu_addr, SDP_PSM
    );

    let mut stream = timeout(Duration::from_secs(10), L2capStream::connect(sdp_addr)).await??;
    info!(
        "{} 🧪 bt-wireless-proxy: internal SDP discovery: L2CAP connect returned; settling for {:?} before first SDP write",
        NAME, settle_delay
    );
    tokio::time::sleep(settle_delay).await;

    let mut continuation_state = Vec::new();
    let mut attribute_lists = Vec::new();

    for transaction_id in 1u16..=8 {
        let request = build_sdp_service_search_attribute_request(
            transaction_id,
            AAWG_PROFILE_UUID,
            &continuation_state,
        )?;
        debug!(
            "{} 🧪 bt-wireless-proxy: internal SDP discovery: TX tid={} bytes={}",
            NAME,
            transaction_id,
            hex::encode(&request)
        );
        stream.write_all(&request).await?;
        stream.flush().await?;

        let (pdu_id, response_tid, params) = timeout(Duration::from_secs(10), read_sdp_pdu(&mut stream)).await??;
        debug!(
            "{} 🧪 bt-wireless-proxy: internal SDP discovery: RX pdu=0x{:02x} tid={} len={} bytes={}",
            NAME,
            pdu_id,
            response_tid,
            params.len(),
            hex::encode(&params)
        );

        if response_tid != transaction_id {
            warn!(
                "{} 🧪 bt-wireless-proxy: internal SDP discovery: response transaction id {} != request {}",
                NAME, response_tid, transaction_id
            );
        }
        if pdu_id != SDP_PDU_SERVICE_SEARCH_ATTRIBUTE_RESPONSE {
            return Err(format!(
                "unexpected SDP PDU 0x{:02x}; expected ServiceSearchAttributeResponse 0x{:02x}",
                pdu_id, SDP_PDU_SERVICE_SEARCH_ATTRIBUTE_RESPONSE
            ).into());
        }
        if params.len() < 3 {
            return Err(format!("short SDP ServiceSearchAttributeResponse: {} bytes", params.len()).into());
        }

        let attr_count = u16::from_be_bytes([params[0], params[1]]) as usize;
        if params.len() < 2 + attr_count + 1 {
            return Err(format!(
                "truncated SDP response: attr_count={} total_params={}",
                attr_count,
                params.len()
            ).into());
        }

        attribute_lists.extend_from_slice(&params[2..2 + attr_count]);
        let cont_len_pos = 2 + attr_count;
        let cont_len = params[cont_len_pos] as usize;
        if params.len() < cont_len_pos + 1 + cont_len {
            return Err(format!(
                "truncated SDP continuation state: cont_len={} total_params={}",
                cont_len,
                params.len()
            ).into());
        }
        continuation_state = params[cont_len_pos + 1..cont_len_pos + 1 + cont_len].to_vec();
        if continuation_state.is_empty() {
            break;
        }
        debug!(
            "{} 🧪 bt-wireless-proxy: internal SDP discovery: continuing with state={}",
            NAME,
            hex::encode(&continuation_state)
        );
    }

    if attribute_lists.is_empty() {
        return Err(format!(
            "HU {} returned no SDP attributes for AA Wireless UUID {}",
            hu_addr, AAWG_PROFILE_UUID
        ).into());
    }

    if let Some(channel) = extract_rfcomm_channel_from_sdp_attribute_lists(&attribute_lists) {
        info!(
            "{} 🧪 bt-wireless-proxy: internal SDP discovery: HU {} AA Wireless RFCOMM channel={}",
            NAME, hu_addr, channel
        );
        return Ok(channel);
    }

    Err(format!(
        "could not find RFCOMM channel in HU {} SDP ProtocolDescriptorList for AA Wireless UUID {}; attrs={}",
        hu_addr,
        AAWG_PROFILE_UUID,
        hex::encode(&attribute_lists)
    ).into())
}
async fn discover_rfcomm_channel_via_internal_sdp(hu_addr: Address) -> Result<u8> {
    // bluer's classic L2CAP connect may return before the underlying socket is
    // immediately writable on some kernels/adapters. When we write too early,
    // write_all/read_exact can fail with ENOTCONN (os error 107). Keep this
    // retry wrapper local to SDP probing so normal RFCOMM traffic is untouched.
    let delays = [
        Duration::from_millis(1500),
        Duration::from_millis(2200),
        Duration::from_millis(3000),
    ];
    let mut last_error = String::new();

    for (idx, delay) in delays.iter().copied().enumerate() {
        let attempt = idx + 1;
        match discover_rfcomm_channel_via_internal_sdp_once(hu_addr, delay).await {
            Ok(channel) => return Ok(channel),
            Err(err) => {
                last_error = err.to_string();
                warn!(
                    "{} 🧪 bt-wireless-proxy: internal SDP discovery attempt {}/{} failed after settle {:?}: {}",
                    NAME,
                    attempt,
                    delays.len(),
                    delay,
                    last_error
                );
                tokio::time::sleep(Duration::from_millis(350)).await;
            }
        }
    }

    Err(format!(
        "internal SDP discovery failed for HU {} after {} attempts; last error: {}",
        hu_addr,
        delays.len(),
        last_error
    )
    .into())
}


pub const AAWG_PROFILE_UUID: Uuid = Uuid::from_u128(0x4de17a0052cb11e6bdf40800200c9a66);
const HSP_HS_UUID: Uuid = Uuid::from_u128(0x0000110800001000800000805f9b34fb);
const HSP_AG_UUID: Uuid = Uuid::from_u128(0x0000111200001000800000805f9b34fb);
pub const KNOWN_DEVICES_FILE: &str = concat!(crate::base_config_dir!(), "/known_devices");

#[derive(Debug, Clone, PartialEq)]
#[repr(u16)]
#[allow(unused)]
enum MessageId {
    WifiStartRequest = 1,
    WifiInfoRequest = 2,
    WifiInfoResponse = 3,
    WifiVersionRequest = 4,
    WifiVersionResponse = 5,
    WifiConnectStatus = 6,
    WifiStartResponse = 7,
    WifiPingRequest = 8,
    WifiPingResponse = 9,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[allow(unused)]
enum ProxyMessageId {
    WifiStartRequest = 1,
    WifiInfoRequest = 2,
    WifiInfoResponse = 3,
    WifiVersionRequest = 4,
    WifiVersionResponse = 5,
    WifiConnectStatus = 6,
    WifiStartResponse = 7,
    WifiPingRequest = 8,
    WifiPingResponse = 9,
}

impl ProxyMessageId {
    fn name(id: u16) -> &'static str {
        match id {
            1 => "WifiStartRequest",
            2 => "WifiInfoRequest",
            3 => "WifiInfoResponse",
            4 => "WifiVersionRequest",
            5 => "WifiVersionResponse",
            6 => "WifiConnectStatus",
            7 => "WifiStartResponse",
            8 => "WifiPingRequest",
            9 => "WifiPingResponse",
            _ => "Unknown",
        }
    }
}

struct ProxyFrameSniffer {
    direction: &'static str,
    buf: Vec<u8>,
}

impl ProxyFrameSniffer {
    fn new(direction: &'static str) -> Self {
        Self {
            direction,
            buf: Vec::new(),
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
        while self.buf.len() >= HEADER_LEN {
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if self.buf.len() < HEADER_LEN + len {
                break;
            }

            let message_id = u16::from_be_bytes([self.buf[2], self.buf[3]]);
            let payload = self.buf[HEADER_LEN..HEADER_LEN + len].to_vec();
            self.log_frame(message_id, &payload);
            self.buf.drain(..HEADER_LEN + len);
        }

        if self.buf.len() > 1024 * 1024 {
            warn!(
                "{} 🧪 bt-wireless-proxy: {} parser buffer exceeded 1 MiB; clearing partial data",
                NAME, self.direction
            );
            self.buf.clear();
        }
    }

    fn log_frame(&self, message_id: u16, payload: &[u8]) {
        info!(
            "{} 🧪 bt-wireless-proxy: {} frame id={} ({}) len={} payload={}",
            NAME,
            self.direction,
            message_id,
            ProxyMessageId::name(message_id),
            payload.len(),
            if payload.is_empty() {
                "<empty>".to_string()
            } else {
                hex::encode(payload)
            }
        );

        match message_id {
            x if x == ProxyMessageId::WifiStartRequest as u16 => {
                match WifiStartRequest::WifiStartRequest::parse_from_bytes(payload) {
                    Ok(req) => info!(
                        "{} 🧪 bt-wireless-proxy: {} parsed WifiStartRequest ip={} port={}",
                        NAME,
                        self.direction,
                        req.ip_address(),
                        req.port()
                    ),
                    Err(e) => warn!(
                        "{} 🧪 bt-wireless-proxy: {} failed to parse WifiStartRequest: {}",
                        NAME, self.direction, e
                    ),
                }
            }
            x if x == ProxyMessageId::WifiInfoResponse as u16 => {
                match WifiInfoResponse::WifiInfoResponse::parse_from_bytes(payload) {
                    Ok(info_msg) => info!(
                        "{} 🧪 bt-wireless-proxy: {} parsed WifiInfoResponse ssid={} bssid={} security={:?} ap_type={:?} key_len={}",
                        NAME,
                        self.direction,
                        info_msg.ssid(),
                        info_msg.bssid(),
                        info_msg.security_mode(),
                        info_msg.access_point_type(),
                        info_msg.key().len()
                    ),
                    Err(e) => warn!(
                        "{} 🧪 bt-wireless-proxy: {} failed to parse WifiInfoResponse: {}",
                        NAME, self.direction, e
                    ),
                }
            }
            x if x == ProxyMessageId::WifiVersionRequest as u16 => {
                log_wifi_version_request(self.direction, payload);
            }
            x if x == ProxyMessageId::WifiVersionResponse as u16 => {
                log_wifi_version_response(self.direction, payload);
            }
            _ => {}
        }
    }
}

struct ProxyHuConnection {
    stream: Stream,
    endpoint: String,
    _client_profile_session: Option<bluer::Session>,
    _client_profile_handle: Option<ProfileHandle>,
}

#[derive(Debug, Clone)]
pub struct CarWifiMitmProxyOptions {
    pub hu_mac: String,
    pub hu_channel: Option<u8>,
    /// Legacy/default interface. Used as the STA interface when
    /// bt_wireless_proxy_car_wifi_sta_iface is empty.
    pub iface: String,
    pub join_cmd: String,
    pub auto_join: bool,
    /// Automatic Wi-Fi join backend: auto/legacy, wpactrl, wpa_supplicant, wpa_cli, nmcli.
    pub join_control: String,
    /// If true, keep the existing aa-proxy AP interface up and create/use a
    /// separate managed STA interface for the car Wi-Fi. Requires the Wi-Fi
    /// chipset to support concurrent AP+managed mode on the same channel.
    pub keep_ap: bool,
    /// Managed STA interface used to join the HU/car Wi-Fi. Example: wlan0
    /// for takeover mode, sta0 for keep_ap mode.
    pub sta_iface: String,
    /// Existing AP interface to keep when keep_ap=true. Used to discover the
    /// phy for creating sta_iface. Example: wlan0.
    pub ap_iface: String,
    pub rewrite_ip: String,
    pub listen_port: u16,
    /// If HU WifiVersionRequest contains WifiProjectionProtocolInfo(ip/port) and no explicit
    /// WifiStartRequest arrives, synthesize WifiStartRequest from that endpoint.
    pub use_version_projection_fallback: bool,
    /// Timeout for the wpa_supplicant control socket to appear in wpactrl mode.
    pub wpactrl_socket_timeout: Duration,
    /// Timeout for STA association + IPv4 readiness after a Wi-Fi join attempt.
    pub wifi_association_timeout: Duration,
    /// Timeout for DHCP/udhcpc attempts.
    pub dhcp_timeout: Duration,
    pub bt_timeout: Duration,
    pub stopped: bool,
}

async fn relay_with_proxy_logging<R, W>(
    mut reader: R,
    mut writer: W,
    direction: &'static str,
) -> Result<u64>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut sniffer = ProxyFrameSniffer::new(direction);
    let mut total = 0u64;
    let mut buf = vec![0u8; 4096];

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            info!(
                "{} 🧪 bt-wireless-proxy: {} EOF after {} bytes",
                NAME, direction, total
            );
            let _ = writer.shutdown().await;
            return Ok(total);
        }

        let chunk = &buf[..n];
        sniffer.push(chunk);
        writer.write_all(chunk).await?;
        total += n as u64;
    }
}

async fn read_proxy_frame(stream: &mut Stream, direction: &'static str) -> Result<(u16, Vec<u8>)> {
    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[0], header[1]]) as usize;
    let message_id = u16::from_be_bytes([header[2], header[3]]);
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await?;
    }

    let mut full = header.to_vec();
    full.extend_from_slice(&payload);
    let mut sniffer = ProxyFrameSniffer::new(direction);
    sniffer.push(&full);
    Ok((message_id, payload))
}

async fn send_proxy_frame_raw(
    stream: &mut Stream,
    direction: &'static str,
    message_id: u16,
    payload: &[u8],
) -> Result<()> {
    let mut packet = Vec::with_capacity(HEADER_LEN + payload.len());
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(&message_id.to_be_bytes());
    packet.extend_from_slice(payload);

    let mut sniffer = ProxyFrameSniffer::new(direction);
    sniffer.push(&packet);
    stream.write_all(&packet).await?;
    Ok(())
}

async fn send_proxy_frame(
    stream: &mut Stream,
    direction: &'static str,
    message_id: ProxyMessageId,
    payload: &[u8],
) -> Result<()> {
    send_proxy_frame_raw(stream, direction, message_id as u16, payload).await
}

fn success_status_payload() -> &'static [u8] {
    // MessageStatus::OK encoded as proto2 field #1 varint 0.
    &[0x08, 0x00]
}

async fn read_phone_bootstrap_frame(
    phone_stream: &mut Stream,
    expected: ProxyMessageId,
    cached_wifi_info_response: Option<&[u8]>,
    timeout_duration: Duration,
) -> Result<(u16, Vec<u8>)> {
    let start = Instant::now();
    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout_duration {
            return Err(format!(
                "timed out after {:?} waiting for PHONE {} during Wi-Fi bootstrap",
                timeout_duration,
                ProxyMessageId::name(expected as u16)
            )
            .into());
        }
        let remaining = timeout_duration - elapsed;
        let (phone_id, phone_payload) = timeout(
            remaining,
            read_proxy_frame(phone_stream, "PHONE -> POC"),
        )
        .await??;

        if phone_id == expected as u16 {
            return Ok((phone_id, phone_payload));
        }

        if phone_id == ProxyMessageId::WifiPingRequest as u16 {
            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: PHONE sent WifiPingRequest while waiting for {}; replying with WifiPingResponse and keeping state",
                NAME,
                ProxyMessageId::name(expected as u16)
            );
            send_proxy_frame(
                phone_stream,
                "POC -> PHONE",
                ProxyMessageId::WifiPingResponse,
                &phone_payload,
            )
            .await?;
            continue;
        }

        if expected == ProxyMessageId::WifiStartResponse
            && phone_id == ProxyMessageId::WifiInfoRequest as u16
        {
            if let Some(info_payload) = cached_wifi_info_response {
                info!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: PHONE sent another WifiInfoRequest while waiting for WifiStartResponse; re-sending cached HU WifiInfoResponse",
                    NAME
                );
                send_proxy_frame(
                    phone_stream,
                    "POC -> PHONE",
                    ProxyMessageId::WifiInfoResponse,
                    info_payload,
                )
                .await?;
                continue;
            }
        }

        warn!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: expected PHONE {}, got {} ({}); returning unexpected frame to caller",
            NAME,
            ProxyMessageId::name(expected as u16),
            phone_id,
            ProxyMessageId::name(phone_id)
        );
        return Ok((phone_id, phone_payload));
    }
}

#[derive(Debug, Default, Clone)]
struct WifiProjectionProtocolDebugInfo {
    ip_address: Option<String>,
    port: Option<u32>,
}

#[derive(Debug, Default, Clone)]
struct WifiVersionRequestDebugInfo {
    major_version: Option<u64>,
    minor_version: Option<u64>,
    supported_wifi_channels: Vec<i64>,
    car_make: Option<String>,
    car_model: Option<String>,
    car_year: Option<String>,
    vehicle_id: Option<String>,
    head_unit_make: Option<String>,
    head_unit_model: Option<String>,
    head_unit_software_build: Option<String>,
    head_unit_software_version: Option<String>,
    projection: WifiProjectionProtocolDebugInfo,
}

#[derive(Debug, Default, Clone)]
struct WifiVersionResponseDebugInfo {
    major_version: Option<u64>,
    minor_version: Option<u64>,
    device_serial: Option<String>,
    status: Option<i64>,
    selected_wifi_channel_type: Option<u64>,
    device_id: Option<String>,
    connectivity_lifetime_id: Option<String>,
}

fn read_proto_varint(buf: &[u8], offset: &mut usize) -> Option<u64> {
    let mut shift = 0u32;
    let mut value = 0u64;
    while *offset < buf.len() && shift < 64 {
        let b = buf[*offset];
        *offset += 1;
        value |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
    None
}

fn signed_from_proto_varint(value: u64) -> i64 {
    value as i64
}

fn try_utf8(bytes: &[u8]) -> Option<String> {
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

fn skip_proto_value(payload: &[u8], offset: &mut usize, wire: u8) -> bool {
    match wire {
        0 => read_proto_varint(payload, offset).is_some(),
        1 => {
            if *offset + 8 > payload.len() { return false; }
            *offset += 8;
            true
        }
        2 => {
            let Some(len) = read_proto_varint(payload, offset).map(|v| v as usize) else { return false; };
            if *offset + len > payload.len() { return false; }
            *offset += len;
            true
        }
        5 => {
            if *offset + 4 > payload.len() { return false; }
            *offset += 4;
            true
        }
        _ => false,
    }
}

fn inspect_wifi_version_request(payload: &[u8]) -> WifiVersionRequestDebugInfo {
    let mut info = WifiVersionRequestDebugInfo::default();
    let mut offset = 0usize;
    while offset < payload.len() {
        let field_start = offset;
        let Some(key) = read_proto_varint(payload, &mut offset) else { break; };
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        match wire {
            0 => {
                let Some(value) = read_proto_varint(payload, &mut offset) else { break; };
                match field {
                    1 => info.major_version = Some(value),
                    2 => info.minor_version = Some(value),
                    3 => info.supported_wifi_channels.push(signed_from_proto_varint(value)),
                    _ => {}
                }
            }
            2 => {
                let Some(len) = read_proto_varint(payload, &mut offset).map(|v| v as usize) else { break; };
                if offset + len > payload.len() { break; }
                let data = &payload[offset..offset + len];
                match field {
                    // Some encoders may pack repeated int32 supported_wifi_channels.
                    3 => {
                        let mut packed_offset = 0usize;
                        while packed_offset < data.len() {
                            let Some(value) = read_proto_varint(data, &mut packed_offset) else { break; };
                            info.supported_wifi_channels.push(signed_from_proto_varint(value));
                        }
                    }
                    4 => inspect_wifi_version_head_unit_info(data, &mut info),
                    5 => info.projection = inspect_wifi_projection_protocol_info(data),
                    _ => {}
                }
                offset += len;
            }
            1 | 5 => {
                if !skip_proto_value(payload, &mut offset, wire) { break; }
            }
            _ => {
                warn!(
                    "{} 🧪 bt-wireless-proxy: unsupported WifiVersionRequest proto wire type {} at field {} offset {}; stopping debug parse",
                    NAME, wire, field, field_start
                );
                break;
            }
        }
    }
    info
}

fn inspect_wifi_version_head_unit_info(payload: &[u8], info: &mut WifiVersionRequestDebugInfo) {
    let mut offset = 0usize;
    while offset < payload.len() {
        let field_start = offset;
        let Some(key) = read_proto_varint(payload, &mut offset) else { break; };
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        match wire {
            2 => {
                let Some(len) = read_proto_varint(payload, &mut offset).map(|v| v as usize) else { break; };
                if offset + len > payload.len() { break; }
                let value = try_utf8(&payload[offset..offset + len]);
                match field {
                    1 => info.car_make = value,
                    2 => info.car_model = value,
                    3 => info.car_year = value,
                    4 => info.vehicle_id = value,
                    5 => info.head_unit_make = value,
                    6 => info.head_unit_model = value,
                    7 => info.head_unit_software_build = value,
                    8 => info.head_unit_software_version = value,
                    _ => {}
                }
                offset += len;
            }
            _ => {
                if !skip_proto_value(payload, &mut offset, wire) {
                    warn!(
                        "{} 🧪 bt-wireless-proxy: unsupported WifiVersionRequest HeadUnitInfo proto wire type {} at field {} offset {}; stopping debug parse",
                        NAME, wire, field, field_start
                    );
                    break;
                }
            }
        }
    }
}

fn inspect_wifi_projection_protocol_info(payload: &[u8]) -> WifiProjectionProtocolDebugInfo {
    let mut info = WifiProjectionProtocolDebugInfo::default();
    let mut offset = 0usize;
    while offset < payload.len() {
        let field_start = offset;
        let Some(key) = read_proto_varint(payload, &mut offset) else { break; };
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        match wire {
            0 => {
                let Some(value) = read_proto_varint(payload, &mut offset) else { break; };
                if field == 2 {
                    info.port = Some(value as u32);
                }
            }
            2 => {
                let Some(len) = read_proto_varint(payload, &mut offset).map(|v| v as usize) else { break; };
                if offset + len > payload.len() { break; }
                if field == 1 {
                    info.ip_address = try_utf8(&payload[offset..offset + len]);
                }
                offset += len;
            }
            _ => {
                if !skip_proto_value(payload, &mut offset, wire) {
                    warn!(
                        "{} 🧪 bt-wireless-proxy: unsupported WifiProjectionProtocolInfo proto wire type {} at field {} offset {}; stopping debug parse",
                        NAME, wire, field, field_start
                    );
                    break;
                }
            }
        }
    }
    info
}

fn inspect_wifi_version_response(payload: &[u8]) -> WifiVersionResponseDebugInfo {
    let mut info = WifiVersionResponseDebugInfo::default();
    let mut offset = 0usize;
    while offset < payload.len() {
        let field_start = offset;
        let Some(key) = read_proto_varint(payload, &mut offset) else { break; };
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        match wire {
            0 => {
                let Some(value) = read_proto_varint(payload, &mut offset) else { break; };
                match field {
                    1 => info.major_version = Some(value),
                    2 => info.minor_version = Some(value),
                    4 => info.status = Some(signed_from_proto_varint(value)),
                    5 => info.selected_wifi_channel_type = Some(value),
                    _ => {}
                }
            }
            2 => {
                let Some(len) = read_proto_varint(payload, &mut offset).map(|v| v as usize) else { break; };
                if offset + len > payload.len() { break; }
                let data = &payload[offset..offset + len];
                match field {
                    3 => info.device_serial = try_utf8(data),
                    6 => inspect_wifi_version_device_info(data, &mut info),
                    _ => {}
                }
                offset += len;
            }
            1 | 5 => {
                if !skip_proto_value(payload, &mut offset, wire) { break; }
            }
            _ => {
                warn!(
                    "{} 🧪 bt-wireless-proxy: unsupported WifiVersionResponse proto wire type {} at field {} offset {}; stopping debug parse",
                    NAME, wire, field, field_start
                );
                break;
            }
        }
    }
    info
}

fn inspect_wifi_version_device_info(payload: &[u8], info: &mut WifiVersionResponseDebugInfo) {
    let mut offset = 0usize;
    while offset < payload.len() {
        let field_start = offset;
        let Some(key) = read_proto_varint(payload, &mut offset) else { break; };
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        match wire {
            2 => {
                let Some(len) = read_proto_varint(payload, &mut offset).map(|v| v as usize) else { break; };
                if offset + len > payload.len() { break; }
                let value = try_utf8(&payload[offset..offset + len]);
                match field {
                    1 => info.device_id = value,
                    2 => info.connectivity_lifetime_id = value,
                    _ => {}
                }
                offset += len;
            }
            _ => {
                if !skip_proto_value(payload, &mut offset, wire) {
                    warn!(
                        "{} 🧪 bt-wireless-proxy: unsupported WifiVersionResponse WifiDeviceInfo proto wire type {} at field {} offset {}; stopping debug parse",
                        NAME, wire, field, field_start
                    );
                    break;
                }
            }
        }
    }
}

fn log_wifi_version_request(direction: &str, payload: &[u8]) -> WifiVersionRequestDebugInfo {
    let info_msg = inspect_wifi_version_request(payload);
    info!(
        "{} 🧪 bt-wireless-proxy: {} parsed WifiVersionRequest major={:?} minor={:?} channels={:?} car_make={:?} car_model={:?} car_year={:?} hu_make={:?} hu_model={:?} hu_sw_build={:?} hu_sw_version={:?} projection_ip={:?} projection_port={:?}",
        NAME,
        direction,
        info_msg.major_version,
        info_msg.minor_version,
        info_msg.supported_wifi_channels,
        info_msg.car_make,
        info_msg.car_model,
        info_msg.car_year,
        info_msg.head_unit_make,
        info_msg.head_unit_model,
        info_msg.head_unit_software_build,
        info_msg.head_unit_software_version,
        info_msg.projection.ip_address,
        info_msg.projection.port
    );
    info_msg
}

fn log_wifi_version_response(direction: &str, payload: &[u8]) -> WifiVersionResponseDebugInfo {
    let info_msg = inspect_wifi_version_response(payload);
    info!(
        "{} 🧪 bt-wireless-proxy: {} parsed WifiVersionResponse major={:?} minor={:?} serial={:?} status={:?} selected_channel={:?} device_id={:?} connectivity_lifetime_id={:?}",
        NAME,
        direction,
        info_msg.major_version,
        info_msg.minor_version,
        info_msg.device_serial,
        info_msg.status,
        info_msg.selected_wifi_channel_type,
        info_msg.device_id,
        info_msg.connectivity_lifetime_id
    );
    info_msg
}

fn build_wifi_start_request_payload(ip_address: &str, port: u32) -> Result<Vec<u8>> {
    if port > i32::MAX as u32 {
        return Err(format!("WifiStartRequest port is out of range for generated proto setter: {}", port).into());
    }

    let mut req = WifiStartRequest::WifiStartRequest::new();
    req.set_ip_address(ip_address.to_string());
    req.set_port(port as i32);
    Ok(req.write_to_bytes()?)
}

async fn read_hu_wifi_start_with_prebootstrap_passthrough(
    hu_stream: &mut Stream,
    phone_stream: &mut Stream,
    use_version_projection_fallback: bool,
) -> Result<Vec<u8>> {
    // Some HUs start the AA Wireless RFCOMM bootstrap with a version exchange
    // before WifiStartRequest. Keep HU-initiated pre-bootstrap frames flowing
    // until the real WifiStartRequest arrives. Correct Gearhead protos show that
    // WifiVersionRequest can also carry WifiProjectionProtocolInfo(ip/port), so
    // strict HUs may provide the projection endpoint there and then omit
    // WifiStartRequest. When enabled, synthesize WifiStartRequest from that
    // endpoint after a short wait to avoid a deadlock.
    let mut forwarded_frames = 0usize;
    let mut last_projection_endpoint: Option<WifiProjectionProtocolDebugInfo> = None;
    let mut pending_hu_frame: Option<(u16, Vec<u8>)> = None;

    loop {
        let (hu_id, hu_payload) = if let Some(frame) = pending_hu_frame.take() {
            frame
        } else {
            read_proxy_frame(hu_stream, "HU -> POC pre-bootstrap").await?
        };

        if hu_id == ProxyMessageId::WifiStartRequest as u16 {
            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: captured HU WifiStartRequest after forwarding {} pre-bootstrap frame(s)",
                NAME, forwarded_frames
            );
            return Ok(hu_payload);
        }

        if hu_id == ProxyMessageId::WifiVersionRequest as u16 {
            let req_info = inspect_wifi_version_request(&hu_payload);
            if req_info.projection.ip_address.is_some() && req_info.projection.port.is_some() {
                info!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: HU WifiVersionRequest contains projection endpoint {:?}:{:?}; can use as fallback if WifiStartRequest is omitted",
                    NAME,
                    req_info.projection.ip_address,
                    req_info.projection.port
                );
                last_projection_endpoint = Some(req_info.projection.clone());
            }
        }

        forwarded_frames += 1;
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: forwarding HU pre-bootstrap frame id={} ({}) to phone while waiting for WifiStartRequest",
            NAME,
            hu_id,
            ProxyMessageId::name(hu_id)
        );
        send_proxy_frame_raw(
            phone_stream,
            "POC -> PHONE pre-bootstrap",
            hu_id,
            &hu_payload,
        )
        .await?;

        if hu_id == ProxyMessageId::WifiVersionRequest as u16 {
            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: waiting for PHONE WifiVersionResponse to forward back to HU",
                NAME
            );
            let (phone_id, phone_payload) = timeout(
                Duration::from_secs(10),
                read_proxy_frame(phone_stream, "PHONE -> POC pre-bootstrap"),
            )
            .await??;

            if phone_id != ProxyMessageId::WifiVersionResponse as u16 {
                warn!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: expected PHONE WifiVersionResponse during pre-bootstrap, got {} ({})",
                    NAME,
                    phone_id,
                    ProxyMessageId::name(phone_id)
                );
            }

            send_proxy_frame_raw(
                hu_stream,
                "POC -> HU pre-bootstrap",
                phone_id,
                &phone_payload,
            )
            .await?;

            if use_version_projection_fallback {
                if let Some(endpoint) = &last_projection_endpoint {
                    if let (Some(ip), Some(port)) = (&endpoint.ip_address, endpoint.port) {
                        info!(
                            "{} 🧪 bt-wireless-proxy car-wifi-mitm: waiting up to 3s for explicit HU WifiStartRequest before using VersionRequest projection endpoint {}:{}",
                            NAME, ip, port
                        );
                        match timeout(
                            Duration::from_secs(3),
                            read_proxy_frame(hu_stream, "HU -> POC pre-bootstrap"),
                        )
                        .await
                        {
                            Ok(Ok(next_frame)) => {
                                pending_hu_frame = Some(next_frame);
                            }
                            Ok(Err(e)) => return Err(e),
                            Err(_) => {
                                info!(
                                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: no explicit HU WifiStartRequest after VersionResponse; synthesizing WifiStartRequest from VersionRequest projection endpoint {}:{}",
                                    NAME, ip, port
                                );
                                return build_wifi_start_request_payload(ip, port);
                            }
                        }
                    }
                }
            }
        }

        if forwarded_frames > 32 {
            return Err(
                "too many HU pre-bootstrap frames before WifiStartRequest; aborting car-wifi-mitm"
                    .into(),
            );
        }
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn render_wifi_join_cmd(template: &str, iface: &str, info: &WifiInfoResponse::WifiInfoResponse) -> String {
    template
        .replace("{iface}", &shell_quote(iface))
        .replace("{ssid}", &shell_quote(info.ssid()))
        .replace("{bssid}", &shell_quote(info.bssid()))
        .replace("{key}", &shell_quote(info.key()))
        .replace("{security}", &shell_quote(&format!("{:?}", info.security_mode())))
}

async fn command_available(binary: &str) -> bool {
    matches!(
        timeout(Duration::from_secs(2), Command::new(binary).arg("--help").output()).await,
        Ok(Ok(_))
    ) || matches!(
        timeout(Duration::from_secs(2), Command::new("which").arg(binary).output()).await,
        Ok(Ok(output)) if output.status.success()
    )
}

async fn run_wifi_join_custom_cmd(
    template: &str,
    iface: &str,
    info_msg: &WifiInfoResponse::WifiInfoResponse,
) -> Result<()> {
    let rendered = render_wifi_join_cmd(template.trim(), iface, info_msg);
    info!(
        "{} 🧪 bt-wireless-proxy car-wifi-mitm: running configured Wi-Fi join command for ssid={} bssid={} iface={} key_len={}",
        NAME,
        info_msg.ssid(),
        info_msg.bssid(),
        iface,
        info_msg.key().len()
    );

    let output = timeout(
        Duration::from_secs(30),
        Command::new("/bin/sh").arg("-c").arg(rendered).output(),
    )
    .await??;

    if output.status.success() {
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: Wi-Fi join command completed successfully",
            NAME
        );
        Ok(())
    } else {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "Wi-Fi join command failed status={} stdout={} stderr={}",
            output.status,
            stdout.trim(),
            stderr.trim()
        )
        .into())
    }
}

async fn current_iw_ssid(iface: &str) -> Option<String> {
    let output = timeout(
        Duration::from_secs(3),
        Command::new("iw").args(["dev", iface, "link"]).output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(ssid) = line.strip_prefix("SSID:") {
            return Some(ssid.trim().to_string());
        }
    }
    None
}

async fn run_nmcli_wifi_join(
    iface: &str,
    info_msg: &WifiInfoResponse::WifiInfoResponse,
) -> Result<()> {
    let ssid = info_msg.ssid();
    let key = info_msg.key();
    let bssid = info_msg.bssid();

    let mut cmd = Command::new("nmcli");
    cmd.args(["dev", "wifi", "connect", ssid]);
    if !key.is_empty() {
        cmd.args(["password", key]);
    }
    if !iface.trim().is_empty() {
        cmd.args(["ifname", iface.trim()]);
    }
    if !bssid.trim().is_empty() {
        cmd.args(["bssid", bssid.trim()]);
    }

    info!(
        "{} 🧪 bt-wireless-proxy car-wifi-mitm: auto Wi-Fi join using nmcli ssid={} bssid={} iface={} key_len={}",
        NAME,
        ssid,
        bssid,
        iface,
        key.len()
    );

    let output = timeout(Duration::from_secs(35), cmd.output()).await??;
    if output.status.success() {
        Ok(())
    } else {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "nmcli failed status={} stdout={} stderr={}",
            output.status,
            stdout.trim(),
            stderr.trim()
        )
        .into())
    }
}

fn wpa_quote(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

async fn wpa_cli_output(iface: &str, args: &[&str]) -> Result<String> {
    let output = timeout(
        Duration::from_secs(5),
        Command::new("wpa_cli").arg("-i").arg(iface).args(args).output(),
    )
    .await??;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.status.success() && !stdout.eq_ignore_ascii_case("FAIL") {
        Ok(stdout)
    } else {
        Err(format!(
            "wpa_cli {:?} failed status={} stdout={} stderr={}",
            args, output.status, stdout, stderr
        )
        .into())
    }
}

async fn run_wpa_cli_wifi_join(
    iface: &str,
    info_msg: &WifiInfoResponse::WifiInfoResponse,
) -> Result<()> {
    let iface = iface.trim();
    if iface.is_empty() {
        return Err("wpa_cli auto join needs cfg.iface to be set".into());
    }

    let ssid = info_msg.ssid();
    let key = info_msg.key();
    let bssid = info_msg.bssid();

    info!(
        "{} 🧪 bt-wireless-proxy car-wifi-mitm: auto Wi-Fi join using wpa_cli ssid={} bssid={} iface={} key_len={}",
        NAME,
        ssid,
        bssid,
        iface,
        key.len()
    );

    let net_id = wpa_cli_output(iface, &["add_network"]).await?;
    let net_id = net_id.lines().last().unwrap_or(net_id.as_str()).trim().to_string();
    if net_id.is_empty() || net_id.eq_ignore_ascii_case("FAIL") {
        return Err(format!("wpa_cli add_network returned invalid network id: {}", net_id).into());
    }

    wpa_cli_output(iface, &["set_network", &net_id, "ssid", &wpa_quote(ssid)]).await?;
    if !bssid.trim().is_empty() {
        // Best-effort. Some wpa_supplicant builds reject bssid for generated networks.
        if let Err(e) = wpa_cli_output(iface, &["set_network", &net_id, "bssid", bssid.trim()]).await {
            warn!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: wpa_cli could not pin bssid {}: {}",
                NAME, bssid, e
            );
        }
    }

    if key.is_empty() || info_msg.security_mode() == SecurityMode::OPEN {
        wpa_cli_output(iface, &["set_network", &net_id, "key_mgmt", "NONE"]).await?;
    } else {
        wpa_cli_output(iface, &["set_network", &net_id, "psk", &wpa_quote(key)]).await?;
    }

    wpa_cli_output(iface, &["enable_network", &net_id]).await?;
    wpa_cli_output(iface, &["select_network", &net_id]).await?;
    let _ = wpa_cli_output(iface, &["reassociate"]).await;
    let _ = wpa_cli_output(iface, &["save_config"]).await;
    Ok(())
}



fn wpactrl_cmd(client: &mut wpactrl::Client, cmd: &str) -> Result<String> {
    let response = client
        .request(cmd)
        .map_err(|e| format!("wpactrl command {:?} failed: {}", cmd, e))?;
    let trimmed = response.trim();
    if trimmed.eq_ignore_ascii_case("FAIL") {
        Err(format!("wpactrl command {:?} returned FAIL", cmd).into())
    } else {
        Ok(response)
    }
}

async fn wait_for_wpa_ctrl_socket(iface: &str, timeout_duration: Duration) -> Result<String> {
    let ctrl_path = format!("/var/run/wpa_supplicant/{}", iface.trim());
    let start = Instant::now();
    while start.elapsed() < timeout_duration {
        if tokio::fs::metadata(&ctrl_path).await.is_ok() {
            return Ok(ctrl_path);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err(format!(
        "wpa_supplicant control socket did not appear at {} within {:?}",
        ctrl_path, timeout_duration
    )
    .into())
}

async fn cleanup_wpactrl_wpa_supplicant(iface: &str, reason: &str) {
    let iface = iface.trim();
    warn!(
        "{} 🧪 bt-wireless-proxy car-wifi-mitm: cleaning up wpactrl/wpa_supplicant for iface={} after {}",
        NAME,
        iface,
        reason
    );
    let _ = run_shell_for_wifi(
        "cleanup wpactrl wpa_supplicant",
        "killall wpa_supplicant 2>/dev/null || true",
        5,
    )
    .await;
    if !iface.is_empty() {
        let _ = tokio::fs::remove_file(format!("/var/run/wpa_supplicant/{}", iface)).await;
    }
}

async fn run_wpactrl_wifi_join(
    iface: &str,
    info_msg: &WifiInfoResponse::WifiInfoResponse,
    socket_timeout: Duration,
    dhcp_timeout: Duration,
) -> Result<()> {
    let iface = iface.trim();
    if iface.is_empty() {
        return Err("wpactrl auto join needs a non-empty interface".into());
    }
    if !command_available("wpa_supplicant").await {
        return Err("wpactrl auto join needs wpa_supplicant binary".into());
    }

    let ssid = info_msg.ssid().to_string();
    let key = info_msg.key().to_string();
    let bssid = info_msg.bssid().trim().to_string();
    let is_open = key.is_empty() || info_msg.security_mode() == SecurityMode::OPEN;
    let conf_path = format!("/tmp/aa-proxy-car-wifi-{}-wpactrl.conf", iface.replace('/', "_"));
    tokio::fs::write(&conf_path, wpa_supplicant_config(info_msg)).await?;

    info!(
        "{} 🧪 bt-wireless-proxy car-wifi-mitm: auto Wi-Fi join using wpactrl+wpa_supplicant iface={} ssid={} bssid={} key_len={}",
        NAME,
        iface,
        ssid,
        bssid,
        key.len()
    );

    let _ = tokio::fs::create_dir_all("/var/run/wpa_supplicant").await;
    let _ = run_shell_for_wifi(
        "stop old iface wpa_supplicant",
        &format!(
            "pidof wpa_supplicant >/dev/null 2>&1 && killall wpa_supplicant 2>/dev/null || true"
        ),
        5,
    )
    .await;
    let _ = tokio::fs::remove_file(format!("/var/run/wpa_supplicant/{}", iface)).await;

    let output = timeout(
        Duration::from_secs(15),
        Command::new("wpa_supplicant")
            .args([
                "-B",
                "-i",
                iface,
                "-c",
                conf_path.as_str(),
                "-D",
                "nl80211",
                "-C",
                "/var/run/wpa_supplicant",
            ])
            .output(),
    )
    .await??;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "wpa_supplicant for wpactrl failed status={} stdout={} stderr={}",
            output.status,
            stdout.trim(),
            stderr.trim()
        )
        .into());
    }

    let ctrl_path = match wait_for_wpa_ctrl_socket(iface, socket_timeout).await {
        Ok(path) => path,
        Err(e) => {
            cleanup_wpactrl_wpa_supplicant(iface, "control socket timeout").await;
            return Err(e);
        }
    };
    let ssid_cmd = wpa_quote(&ssid);
    let key_cmd = wpa_quote(&key);
    let bssid_cmd = bssid.clone();
    let ctrl_path_for_blocking = ctrl_path.clone();

    let wpactrl_result = tokio::task::spawn_blocking(move || -> Result<()> {
        let mut client = wpactrl::Client::builder()
            .ctrl_path(ctrl_path_for_blocking.as_str())
            .open()
            .map_err(|e| format!("wpactrl open {} failed: {}", ctrl_path_for_blocking, e))?;

        let pong = wpactrl_cmd(&mut client, "PING")?;
        if !pong.trim().eq_ignore_ascii_case("PONG") {
            return Err(format!("wpactrl PING returned unexpected response: {}", pong.trim()).into());
        }

        let _ = wpactrl_cmd(&mut client, "DISCONNECT");
        let _ = wpactrl_cmd(&mut client, "REMOVE_NETWORK all");
        let net_id = wpactrl_cmd(&mut client, "ADD_NETWORK")?;
        let net_id = net_id.lines().last().unwrap_or(net_id.as_str()).trim().to_string();
        if net_id.is_empty() || net_id.eq_ignore_ascii_case("FAIL") {
            return Err(format!("wpactrl ADD_NETWORK returned invalid network id: {}", net_id).into());
        }

        wpactrl_cmd(&mut client, &format!("SET_NETWORK {} ssid {}", net_id, ssid_cmd))?;
        if !bssid_cmd.is_empty() {
            if let Err(e) = wpactrl_cmd(&mut client, &format!("SET_NETWORK {} bssid {}", net_id, bssid_cmd)) {
                warn!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: wpactrl could not pin bssid {}: {}",
                    NAME, bssid_cmd, e
                );
            }
        }
        if is_open {
            wpactrl_cmd(&mut client, &format!("SET_NETWORK {} key_mgmt NONE", net_id))?;
        } else {
            wpactrl_cmd(&mut client, &format!("SET_NETWORK {} key_mgmt WPA-PSK", net_id))?;
            wpactrl_cmd(&mut client, &format!("SET_NETWORK {} psk {}", net_id, key_cmd))?;
        }
        wpactrl_cmd(&mut client, &format!("ENABLE_NETWORK {}", net_id))?;
        wpactrl_cmd(&mut client, &format!("SELECT_NETWORK {}", net_id))?;
        let _ = wpactrl_cmd(&mut client, "RECONNECT");
        Ok(())
    })
    .await;

    match wpactrl_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            cleanup_wpactrl_wpa_supplicant(iface, "wpactrl command failure").await;
            return Err(e);
        }
        Err(e) => {
            cleanup_wpactrl_wpa_supplicant(iface, "wpactrl blocking task failure").await;
            return Err(format!("wpactrl blocking task failed: {}", e).into());
        }
    }

    let _ = run_udhcpc_for_iface(iface, "after wpactrl network selection", dhcp_timeout).await;

    Ok(())
}

async fn iface_exists(iface: &str) -> bool {
    if iface.trim().is_empty() {
        return false;
    }
    matches!(
        timeout(
            Duration::from_secs(2),
            Command::new("ip").args(["link", "show", "dev", iface.trim()]).output(),
        )
        .await,
        Ok(Ok(output)) if output.status.success()
    )
}

async fn run_shell_for_wifi(label: &str, command: &str, timeout_secs: u64) -> Result<()> {
    debug!(
        "{} 🧪 bt-wireless-proxy car-wifi-mitm: running {}: {}",
        NAME, label, command
    );
    let output = timeout(
        Duration::from_secs(timeout_secs),
        Command::new("/bin/sh").arg("-c").arg(command).output(),
    )
    .await??;
    if output.status.success() {
        Ok(())
    } else {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "{} failed status={} stdout={} stderr={}",
            label,
            output.status,
            stdout.trim(),
            stderr.trim()
        )
        .into())
    }
}

async fn iface_ipv4(iface: &str) -> Option<String> {
    let output = timeout(
        Duration::from_secs(3),
        Command::new("ip")
            .args(["-4", "addr", "show", "dev", iface.trim()])
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let tokens: Vec<&str> = stdout.split_whitespace().collect();
    for pair in tokens.windows(2) {
        if pair[0] == "inet" {
            return Some(pair[1].split('/').next().unwrap_or(pair[1]).to_string());
        }
    }
    None
}

async fn run_udhcpc_for_iface(iface: &str, reason: &str, timeout_duration: Duration) -> bool {
    let iface = iface.trim();
    if iface.is_empty() {
        return false;
    }
    if !command_available("udhcpc").await {
        warn!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: udhcpc not available while {}; cannot request DHCP lease for {}",
            NAME, reason, iface
        );
        return false;
    }

    info!(
        "{} 🧪 bt-wireless-proxy car-wifi-mitm: running udhcpc on {} because {}",
        NAME, iface, reason
    );
    match timeout(
        timeout_duration,
        Command::new("udhcpc")
            .args(["-i", iface, "-q", "-n", "-t", "6"])
            .output(),
    )
    .await
    {
        Ok(Ok(output)) if output.status.success() => true,
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: udhcpc on {} did not return success status={} stdout={} stderr={}",
                NAME,
                iface,
                output.status,
                stdout.trim(),
                stderr.trim()
            );
            false
        }
        Ok(Err(e)) => {
            warn!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: failed to run udhcpc on {}: {}",
                NAME, iface, e
            );
            false
        }
        Err(_) => {
            warn!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: timed out running udhcpc on {}",
                NAME, iface
            );
            false
        }
    }
}

async fn wait_for_wifi_ready(iface: &str, ssid: &str, timeout_duration: Duration) -> bool {
    let start = Instant::now();
    let mut logged_associated_without_ip = false;
    while start.elapsed() < timeout_duration {
        let current_ssid = current_iw_ssid(iface).await;
        let associated = if ssid.trim().is_empty() {
            current_ssid.is_some()
        } else {
            current_ssid.as_deref() == Some(ssid)
        };
        let ip = iface_ipv4(iface).await;

        if associated && ip.is_some() {
            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: iface {} is associated to ssid={} and has IPv4 {}",
                NAME,
                iface,
                current_ssid.as_deref().unwrap_or("<unknown>"),
                ip.as_deref().unwrap_or("<none>")
            );
            return true;
        }

        if associated && ip.is_none() && !logged_associated_without_ip {
            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: iface {} is associated to ssid={} but has no IPv4 yet; waiting for DHCP",
                NAME,
                iface,
                current_ssid.as_deref().unwrap_or(ssid)
            );
            logged_associated_without_ip = true;
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    false
}

fn wpa_supplicant_config(info_msg: &WifiInfoResponse::WifiInfoResponse) -> String {
    let ssid = info_msg.ssid();
    let key = info_msg.key();
    if key.is_empty() || info_msg.security_mode() == SecurityMode::OPEN {
        format!(
            "network={{\n    ssid={}\n    key_mgmt=NONE\n}}\n",
            wpa_quote(ssid)
        )
    } else {
        format!(
            "network={{\n    ssid={}\n    psk={}\n    key_mgmt=WPA-PSK\n}}\n",
            wpa_quote(ssid),
            wpa_quote(key)
        )
    }
}

async fn prepare_sta_iface_takeover(iface: &str) -> Result<String> {
    let iface = iface.trim();
    if iface.is_empty() {
        return Err("car Wi-Fi takeover needs a non-empty STA interface".into());
    }

    info!(
        "{} 🧪 bt-wireless-proxy car-wifi-mitm: takeover mode; stopping AP helpers and switching {} to managed mode",
        NAME, iface
    );
    let _ = run_shell_for_wifi(
        "stop AP helpers",
        "killall hostapd dnsmasq udhcpd 2>/dev/null || true",
        5,
    )
    .await;
    let _ = run_shell_for_wifi(
        "stop old wpa_supplicant",
        &format!("killall wpa_supplicant 2>/dev/null || true"),
        5,
    )
    .await;
    run_shell_for_wifi(
        "switch iface to managed",
        &format!(
            "ip link set {i} down && ip addr flush dev {i} && iw dev {i} set type managed && ip link set {i} up",
            i = shell_quote(iface)
        ),
        10,
    )
    .await?;
    Ok(iface.to_string())
}

async fn phy_for_iface(iface: &str) -> Option<String> {
    let iface = iface.trim();
    if iface.is_empty() {
        return None;
    }
    let output = timeout(
        Duration::from_secs(3),
        Command::new("iw").args(["dev", iface, "info"]).output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(wiphy) = line.strip_prefix("wiphy") {
            let wiphy = wiphy.trim();
            if !wiphy.is_empty() {
                return Some(format!("phy{}", wiphy));
            }
        }
    }
    None
}

async fn prepare_sta_iface_keep_ap(sta_iface: &str, ap_iface: &str) -> Result<String> {
    let sta_iface = sta_iface.trim();
    if sta_iface.is_empty() {
        return Err("car Wi-Fi keep_ap mode needs bt_wireless_proxy_car_wifi_sta_iface".into());
    }
    if iface_exists(sta_iface).await {
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: keep_ap mode; reusing existing STA iface {}",
            NAME, sta_iface
        );
        let _ = run_shell_for_wifi(
            "bring STA iface up",
            &format!("ip link set {} up", shell_quote(sta_iface)),
            5,
        )
        .await;
        return Ok(sta_iface.to_string());
    }

    let phy = phy_for_iface(ap_iface).await.unwrap_or_else(|| "phy0".to_string());
    info!(
        "{} 🧪 bt-wireless-proxy car-wifi-mitm: keep_ap mode; creating managed STA iface {} on {} while AP iface {} stays up",
        NAME, sta_iface, phy, ap_iface
    );
    run_shell_for_wifi(
        "create STA iface",
        &format!(
            "iw phy {} interface add {} type managed && ip link set {} up",
            shell_quote(&phy),
            shell_quote(sta_iface),
            shell_quote(sta_iface)
        ),
        10,
    )
    .await?;
    Ok(sta_iface.to_string())
}

async fn run_wpa_supplicant_wifi_join(
    iface: &str,
    info_msg: &WifiInfoResponse::WifiInfoResponse,
    dhcp_timeout: Duration,
) -> Result<()> {
    let iface = iface.trim();
    if iface.is_empty() {
        return Err("wpa_supplicant auto join needs a non-empty interface".into());
    }
    let conf_path = format!("/tmp/aa-proxy-car-wifi-{}.conf", iface.replace('/', "_"));
    tokio::fs::write(&conf_path, wpa_supplicant_config(info_msg)).await?;

    info!(
        "{} 🧪 bt-wireless-proxy car-wifi-mitm: auto Wi-Fi join using wpa_supplicant iface={} ssid={} bssid={} key_len={}",
        NAME,
        iface,
        info_msg.ssid(),
        info_msg.bssid(),
        info_msg.key().len()
    );

    let _ = run_shell_for_wifi(
        "stop old iface wpa_supplicant",
        &format!(
            "pidof wpa_supplicant >/dev/null 2>&1 && killall wpa_supplicant 2>/dev/null || true"
        ),
        5,
    )
    .await;

    let output = timeout(
        Duration::from_secs(15),
        Command::new("wpa_supplicant")
            .args(["-B", "-i", iface, "-c", conf_path.as_str(), "-D", "nl80211"])
            .output(),
    )
    .await??;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "wpa_supplicant failed status={} stdout={} stderr={}",
            output.status,
            stdout.trim(),
            stderr.trim()
        )
        .into());
    }

    tokio::time::sleep(Duration::from_secs(5)).await;

    let _ = run_udhcpc_for_iface(iface, "after wpa_supplicant start", dhcp_timeout).await;

    Ok(())
}

async fn run_car_wifi_join(
    custom_template: &str,
    auto_join: bool,
    join_control: &str,
    base_iface: &str,
    keep_ap: bool,
    sta_iface: &str,
    ap_iface: &str,
    info_msg: &WifiInfoResponse::WifiInfoResponse,
    wpactrl_socket_timeout: Duration,
    wifi_association_timeout: Duration,
    dhcp_timeout: Duration,
) -> Result<String> {
    let ssid = info_msg.ssid().trim();
    let base_iface = base_iface.trim();
    let ap_iface = if ap_iface.trim().is_empty() {
        base_iface
    } else {
        ap_iface.trim()
    };
    let requested_sta_iface = if sta_iface.trim().is_empty() {
        if keep_ap { "sta0" } else { base_iface }
    } else {
        sta_iface.trim()
    };

    if ssid.is_empty() {
        return Err("HU WifiInfoResponse did not include an SSID; cannot auto-join Wi-Fi".into());
    }

    if !requested_sta_iface.is_empty()
        && current_iw_ssid(requested_sta_iface).await.as_deref() == Some(ssid)
    {
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: iface {} is already associated to ssid={}; verifying IPv4 before reusing it",
            NAME, requested_sta_iface, ssid
        );
        if wait_for_wifi_ready(requested_sta_iface, ssid, Duration::from_secs(2)).await {
            return Ok(requested_sta_iface.to_string());
        }
        warn!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: iface {} is associated to ssid={} but IPv4 is not ready; requesting DHCP before deciding to rejoin",
            NAME, requested_sta_iface, ssid
        );
        let _ = run_udhcpc_for_iface(requested_sta_iface, "existing association has no IPv4", dhcp_timeout).await;
        if wait_for_wifi_ready(requested_sta_iface, ssid, wifi_association_timeout).await {
            return Ok(requested_sta_iface.to_string());
        }
        warn!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: existing association on {} still has no IPv4; continuing with configured Wi-Fi join flow",
            NAME, requested_sta_iface
        );
    }

    if !custom_template.trim().is_empty() {
        run_wifi_join_custom_cmd(custom_template, requested_sta_iface, info_msg).await?;
        if requested_sta_iface.is_empty()
            || wait_for_wifi_ready(requested_sta_iface, ssid, wifi_association_timeout).await
        {
            return Ok(requested_sta_iface.to_string());
        }
        warn!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: custom command returned success but iface {} is not associated/IPv4-ready for ssid={} yet",
            NAME, requested_sta_iface, ssid
        );
        return Ok(requested_sta_iface.to_string());
    }

    if !auto_join {
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: auto Wi-Fi join disabled and no join command configured; assuming SBC is already on car Wi-Fi",
            NAME
        );
        return Ok(requested_sta_iface.to_string());
    }

    let join_iface = if keep_ap {
        prepare_sta_iface_keep_ap(requested_sta_iface, ap_iface).await?
    } else {
        prepare_sta_iface_takeover(requested_sta_iface).await?
    };

    let join_control = join_control.trim().to_ascii_lowercase();
    let join_control = if join_control.is_empty() { "auto" } else { join_control.as_str() };
    info!(
        "{} 🧪 bt-wireless-proxy car-wifi-mitm: Wi-Fi join control={} iface={}",
        NAME, join_control, join_iface
    );

    let mut errors = Vec::new();

    if join_control == "wpactrl" {
        match run_wpactrl_wifi_join(&join_iface, info_msg, wpactrl_socket_timeout, dhcp_timeout).await {
            Ok(()) => {
                if wait_for_wifi_ready(&join_iface, ssid, wifi_association_timeout).await {
                    return Ok(join_iface);
                }
                return Err("wpactrl returned success but association/IPv4 was not observed".into());
            }
            Err(e) => return Err(format!("wpactrl: {}", e).into()),
        }
    }

    if join_control == "wpa_supplicant" {
        match run_wpa_supplicant_wifi_join(&join_iface, info_msg, dhcp_timeout).await {
            Ok(()) => {
                if wait_for_wifi_ready(&join_iface, ssid, wifi_association_timeout).await {
                    return Ok(join_iface);
                }
                return Err("wpa_supplicant returned success but association/IPv4 was not observed".into());
            }
            Err(e) => return Err(format!("wpa_supplicant: {}", e).into()),
        }
    }

    if join_control == "wpa_cli" {
        match run_wpa_cli_wifi_join(&join_iface, info_msg).await {
            Ok(()) => {
                if wait_for_wifi_ready(&join_iface, ssid, wifi_association_timeout).await {
                    return Ok(join_iface);
                }
                return Err("wpa_cli returned success but association/IPv4 was not observed".into());
            }
            Err(e) => return Err(format!("wpa_cli: {}", e).into()),
        }
    }

    if join_control == "nmcli" {
        match run_nmcli_wifi_join(&join_iface, info_msg).await {
            Ok(()) => {
                if wait_for_wifi_ready(&join_iface, ssid, wifi_association_timeout).await {
                    return Ok(join_iface);
                }
                return Err("nmcli returned success but association/IPv4 was not observed".into());
            }
            Err(e) => return Err(format!("nmcli: {}", e).into()),
        }
    }

    if join_control != "auto" && join_control != "legacy" {
        warn!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: unknown Wi-Fi join control {}; falling back to auto",
            NAME, join_control
        );
    }

    if command_available("nmcli").await {
        match run_nmcli_wifi_join(&join_iface, info_msg).await {
            Ok(()) => {
                if wait_for_wifi_ready(&join_iface, ssid, wifi_association_timeout).await {
                    return Ok(join_iface);
                }
                errors.push("nmcli returned success but association/IPv4 was not observed".to_string());
            }
            Err(e) => errors.push(format!("nmcli: {}", e)),
        }
    } else {
        debug!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: nmcli not available for auto Wi-Fi join",
            NAME
        );
    }

    if command_available("wpa_cli").await {
        match run_wpa_cli_wifi_join(&join_iface, info_msg).await {
            Ok(()) => {
                if wait_for_wifi_ready(&join_iface, ssid, wifi_association_timeout).await {
                    return Ok(join_iface);
                }
                errors.push("wpa_cli returned success but association/IPv4 was not observed".to_string());
            }
            Err(e) => errors.push(format!("wpa_cli: {}", e)),
        }
    } else {
        debug!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: wpa_cli not available for auto Wi-Fi join",
            NAME
        );
    }

    if command_available("wpa_supplicant").await {
        match run_wpa_supplicant_wifi_join(&join_iface, info_msg, dhcp_timeout).await {
            Ok(()) => {
                if wait_for_wifi_ready(&join_iface, ssid, wifi_association_timeout).await {
                    return Ok(join_iface);
                }
                errors.push("wpa_supplicant returned success but association/IPv4 was not observed".to_string());
            }
            Err(e) => errors.push(format!("wpa_supplicant: {}", e)),
        }
    } else {
        debug!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: wpa_supplicant not available for auto Wi-Fi join",
            NAME
        );
    }

    if errors.is_empty() {
        Err("auto Wi-Fi join requested but nmcli, wpa_cli, and wpa_supplicant were unavailable".into())
    } else {
        Err(format!("auto Wi-Fi join failed: {}", errors.join("; ")).into())
    }
}

fn ipv4_likely_same_lan(src_ip: &str, target_ip: &str) -> bool {
    let Ok(src) = src_ip.parse::<std::net::Ipv4Addr>() else { return true; };
    let Ok(target) = target_ip.parse::<std::net::Ipv4Addr>() else { return true; };
    let s = src.octets();
    let t = target.octets();

    if s[0] == 10 || t[0] == 10 {
        return s[0] == t[0];
    }
    if s[0] == 192 || t[0] == 192 {
        return s[0] == t[0] && s[1] == t[1] && s[2] == t[2];
    }
    if s[0] == 172 || t[0] == 172 {
        return s[0] == 172 && t[0] == 172 && s[1] == t[1];
    }

    s[0] == t[0] && s[1] == t[1]
}

async fn discover_rewrite_ip(target_ip: &str, iface: &str, override_ip: &str, dhcp_timeout: Duration) -> Result<String> {
    let override_ip = override_ip.trim();
    if !override_ip.is_empty() {
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: using configured rewrite IP {}",
            NAME, override_ip
        );
        return Ok(override_ip.to_string());
    }

    if !target_ip.trim().is_empty() {
        if let Ok(Ok(output)) = timeout(
            Duration::from_secs(5),
            Command::new("ip")
                .args(["-4", "route", "get", target_ip.trim()])
                .output(),
        )
        .await
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let tokens: Vec<&str> = stdout.split_whitespace().collect();
            for pair in tokens.windows(2) {
                if pair[0] == "src" {
                    if !ipv4_likely_same_lan(pair[1], target_ip.trim()) {
                        warn!(
                            "{} 🧪 bt-wireless-proxy car-wifi-mitm: ignoring route src {} as rewrite IP because it does not look reachable for HU endpoint {}; will try iface/DHCP fallback",
                            NAME, pair[1], target_ip.trim()
                        );
                        continue;
                    }
                    info!(
                        "{} 🧪 bt-wireless-proxy car-wifi-mitm: discovered rewrite IP {} via route to HU {}",
                        NAME, pair[1], target_ip
                    );
                    return Ok(pair[1].to_string());
                }
            }
            debug!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: ip route get output had no src: {}",
                NAME,
                stdout.trim()
            );
        }
    }

    let iface = iface.trim();
    if !iface.is_empty() {
        if let Ok(Ok(output)) = timeout(
            Duration::from_secs(5),
            Command::new("ip")
                .args(["-4", "addr", "show", "dev", iface])
                .output(),
        )
        .await
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let tokens: Vec<&str> = stdout.split_whitespace().collect();
            for pair in tokens.windows(2) {
                if pair[0] == "inet" {
                    let ip = pair[1].split('/').next().unwrap_or(pair[1]);
                    if !target_ip.trim().is_empty() && !ipv4_likely_same_lan(ip, target_ip.trim()) {
                        warn!(
                            "{} 🧪 bt-wireless-proxy car-wifi-mitm: ignoring iface {} IPv4 {} as rewrite IP because it does not look reachable for HU endpoint {}; set bt_wireless_proxy_rewrite_ip to override",
                            NAME, iface, ip, target_ip.trim()
                        );
                        continue;
                    }
                    info!(
                        "{} 🧪 bt-wireless-proxy car-wifi-mitm: discovered rewrite IP {} from iface {}",
                        NAME, ip, iface
                    );
                    return Ok(ip.to_string());
                }
            }
        }
    }

    if !iface.is_empty() && !target_ip.trim().is_empty() {
        warn!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: no suitable rewrite IP found for HU {}; requesting DHCP on {} and retrying once",
            NAME, target_ip.trim(), iface
        );
        let _ = run_udhcpc_for_iface(iface, "rewrite IP discovery had no suitable source address", dhcp_timeout).await;

        if let Ok(Ok(output)) = timeout(
            Duration::from_secs(5),
            Command::new("ip")
                .args(["-4", "route", "get", target_ip.trim()])
                .output(),
        )
        .await
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let tokens: Vec<&str> = stdout.split_whitespace().collect();
            for pair in tokens.windows(2) {
                if pair[0] == "src" && ipv4_likely_same_lan(pair[1], target_ip.trim()) {
                    info!(
                        "{} 🧪 bt-wireless-proxy car-wifi-mitm: discovered rewrite IP {} via route to HU {} after DHCP retry",
                        NAME, pair[1], target_ip
                    );
                    return Ok(pair[1].to_string());
                }
            }
        }

        if let Some(ip) = iface_ipv4(iface).await {
            if ipv4_likely_same_lan(&ip, target_ip.trim()) {
                info!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: discovered rewrite IP {} from iface {} after DHCP retry",
                    NAME, ip, iface
                );
                return Ok(ip);
            }
            warn!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: iface {} still has non-matching IPv4 {} after DHCP retry for HU {}",
                NAME, iface, ip, target_ip.trim()
            );
        }
    }

    Err("could not discover local rewrite IP; set bt_wireless_proxy_rewrite_ip".into())
}

pub struct Bluetooth {
    session: Session,
    adapter: Adapter,
    handle_aa: Option<ProfileHandle>,
    hu_pairing_agent: Option<AgentHandle>,
    companion_pairing_agent: Option<AgentHandle>,
    current_index: usize,
    dongle_mode: bool,
    adapter_alias: String,
}

// Create and configure the Bluetooth adapter
pub async fn init(
    btalias: Option<String>,
    advertise: bool,
    dongle_mode: bool,
    register_aa_wireless_profile: bool,
) -> Result<Bluetooth> {
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;

    // setting BT alias for further use
    let alias = match btalias {
        None => match get_cpu_serial_number_suffix().await {
            Ok(suffix) => format!("{}-{}", IDENTITY_NAME, suffix),
            Err(_) => String::from(IDENTITY_NAME),
        },
        Some(btalias) => btalias,
    };
    info!("{} 🥏 Bluetooth alias: <bold><green>{}</>", NAME, alias);

    info!(
        "{} 🥏 Opened bluetooth adapter <b>{}</> with address <b>{}</b>",
        NAME,
        adapter.name(),
        adapter.address().await?
    );
    adapter.set_alias(alias.clone()).await?;
    adapter.set_powered(true).await?;
    adapter.set_pairable(true).await?;

    if advertise {
        adapter.set_discoverable(true).await?;
        adapter.set_discoverable_timeout(0).await?;
    }

    // AA Wireless profile. Probe-only Proxy acts as a Bluetooth client toward an HU/fake-HU,
    // so it must not also register the same UUID as a local server profile; BlueZ allows only
    // one local registration for a UUID and would otherwise fail later with "UUID already registered".
    let handle_aa = if register_aa_wireless_profile {
        let profile = Profile {
            uuid: AAWG_PROFILE_UUID,
            name: Some("AA Wireless".to_string()),
            channel: Some(8),
            role: Some(Role::Server),
            require_authentication: Some(false),
            require_authorization: Some(false),
            ..Default::default()
        };
        let handle_aa = session.register_profile(profile).await?;
        info!("{} 📱 AA Wireless Profile: registered", NAME);
        Some(handle_aa)
    } else {
        info!(
            "{} 📱 AA Wireless Profile: not registered locally because bt_wireless_proxy probe mode will use client Profile registration",
            NAME
        );
        None
    };

    Ok(Bluetooth {
        session,
        adapter,
        handle_aa,
        hu_pairing_agent: None,
        companion_pairing_agent: None,
        current_index: 0,
        dongle_mode,
        adapter_alias: alias,
    })
}

pub async fn get_cpu_serial_number_suffix() -> Result<String> {
    let mut serial = String::new();
    let contents = tokio::fs::read_to_string("/sys/firmware/devicetree/base/serial-number").await?;
    let trimmed = contents.trim_end_matches(char::from(0)).trim();
    // check if we read the serial number with correct length
    if trimmed.len() >= 6 {
        serial = trimmed[trimmed.len() - 6..].to_string();
    }
    Ok(serial)
}

/// Load previously successful AA device addresses from persistent file.
pub fn load_known_devices() -> Vec<Address> {
    let path = std::path::Path::new(KNOWN_DEVICES_FILE);
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let addrs: Vec<Address> = contents
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            match trimmed.parse::<Address>() {
                Ok(addr) if addr != Address::any() => Some(addr),
                _ => {
                    warn!("{} known_devices: skipping invalid line: {}", NAME, trimmed);
                    None
                }
            }
        })
        .collect();
    if !addrs.is_empty() {
        info!(
            "{} 📋 Loaded {} known device(s) from {}",
            NAME,
            addrs.len(),
            KNOWN_DEVICES_FILE
        );
    }
    addrs
}

/// Remove a device address from the known-good devices file.
pub fn remove_known_device_entry(mac: &str) -> std::io::Result<bool> {
    let path = std::path::Path::new(KNOWN_DEVICES_FILE);
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };

    let target = mac.trim();
    let mut removed = false;
    let mut remaining: Vec<String> = Vec::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.eq_ignore_ascii_case(target) {
            removed = true;
        } else {
            remaining.push(trimmed.to_string());
        }
    }

    if !removed {
        return Ok(false);
    }

    if remaining.is_empty() {
        match std::fs::remove_file(path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    } else {
        let mut new_contents = remaining.join("\n");
        new_contents.push('\n');
        std::fs::write(path, new_contents)?;
    }

    info!(
        "{} 🗑️ Removed {} from known devices file",
        NAME, target
    );

    Ok(true)
}

/// Append a device address to the known-good devices file (if not already present).
fn save_known_device(addr: Address) {
    if addr == Address::any() {
        return;
    }
    // Read existing entries to avoid duplicates
    let existing = load_known_devices();
    if existing.contains(&addr) {
        debug!("{} known_devices: {} already recorded", NAME, addr);
        return;
    }
    let addr_str = format!("{}\n", addr);
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(KNOWN_DEVICES_FILE)
    {
        Ok(mut file) => {
            use std::io::Write;
            if let Err(e) = file.write_all(addr_str.as_bytes()) {
                warn!("{} known_devices: failed to write {}: {}", NAME, addr, e);
            } else {
                info!("{} 💾 Saved {} to known devices", NAME, addr);
            }
        }
        Err(e) => {
            warn!(
                "{} known_devices: failed to open file for writing: {}",
                NAME, e
            );
        }
    }
}

async fn send_message(
    stream: &mut Stream,
    stage: u8,
    id: MessageId,
    message: impl Message,
) -> Result<usize> {
    let mut packet: Vec<u8> = vec![];
    let mut data = message.write_to_bytes()?;

    // create header: 2 bytes message length (big-endian) + 2 bytes MessageID
    packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
    packet.extend_from_slice(&((id.clone() as u16).to_be_bytes()));

    // append data and send
    packet.append(&mut data);

    info!(
        "{} 📨 stage #{} of {}: Sending <yellow>{:?}</> frame to phone...",
        NAME, stage, STAGES, id
    );

    // Ensure the full packet is written
    stream.write_all(&packet).await?;

    Ok(packet.len())
}

async fn read_message(
    stream: &mut Stream,
    stage: u8,
    id: MessageId,
    started: Instant,
) -> Result<usize> {
    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await?;
    debug!("received header bytes: {:02X?}", header);
    let elapsed = started.elapsed();

    let len: usize = u16::from_be_bytes(header[0..2].try_into()?).into();
    let message_id = u16::from_be_bytes(header[2..4].try_into()?);
    debug!("MessageID = {}, len = {}", message_id, len);

    if message_id != id.clone() as u16 {
        warn!(
            "Received data has invalid MessageID: got: {:?}, expected: {:?}",
            message_id, id
        );
    }
    info!(
        "{} 📨 stage #{} of {}: Received <yellow>{:?}</> frame from phone (⏱️ {} ms)",
        NAME,
        stage,
        STAGES,
        id,
        (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64,
    );

    // read and discard the remaining bytes
    if len > 0 {
        let mut buf = vec![0; len];
        let n = stream.read_exact(&mut buf).await?;
        debug!("remaining {} bytes: {:02X?}", n, buf);

        // analyzing WifiConnectStatus
        // this is a frame where phone cannot connect to WiFi:
        // [08, FD, FF, FF, FF, FF, FF, FF, FF, FF, 01] -> which is -i64::MAX
        // and this is where all is fine:
        // [08, 00]
        if id == MessageId::WifiConnectStatus && n >= 2 {
            if buf[1] != 0 {
                return Err("phone cannot connect to our WiFi AP...".into());
            }
        }
    }

    Ok(HEADER_LEN + len)
}


fn auto_accept_only_configured_hu(device: Address, allowed_hu: Address, action: &str) -> AgentReqResult<()> {
    if device == allowed_hu {
        info!(
            "{} 🧲 bt-wireless-proxy pairing: auto-accepting {} from configured HU {}",
            NAME, action, device
        );
        Ok(())
    } else {
        warn!(
            "{} 🧲 bt-wireless-proxy pairing: rejecting {} from {}; configured HU is {}",
            NAME, action, device, allowed_hu
        );
        Err(AgentReqError::Rejected)
    }
}

async fn trust_hu_after_pairing(
    session: Session,
    adapter_name: String,
    device_addr: Address,
) -> AgentReqResult<()> {
    match session.adapter(&adapter_name) {
        Ok(adapter) => match adapter.device(device_addr) {
            Ok(device) => match device.set_trusted(true).await {
                Ok(()) => info!(
                    "{} 🧲 bt-wireless-proxy pairing: trusted HU {} on adapter {}",
                    NAME, device_addr, adapter_name
                ),
                Err(e) => warn!(
                    "{} 🧲 bt-wireless-proxy pairing: failed to trust HU {} on adapter {}: {}",
                    NAME, device_addr, adapter_name, e
                ),
            },
            Err(e) => warn!(
                "{} 🧲 bt-wireless-proxy pairing: failed to open device {} on adapter {}: {}",
                NAME, device_addr, adapter_name, e
            ),
        },
        Err(e) => warn!(
            "{} 🧲 bt-wireless-proxy pairing: failed to open adapter {} while trusting {}: {}",
            NAME, adapter_name, device_addr, e
        ),
    }
    Ok(())
}

async fn hu_request_pin_code(req: RequestPinCode, allowed_hu: Address) -> AgentReqResult<String> {
    auto_accept_only_configured_hu(req.device, allowed_hu, "legacy PIN-code request")?;
    info!(
        "{} 🧲 bt-wireless-proxy pairing: replying with fallback PIN 0000 for HU {}",
        NAME, req.device
    );
    Ok("0000".to_string())
}

async fn hu_display_pin_code(req: DisplayPinCode, allowed_hu: Address) -> AgentReqResult<()> {
    auto_accept_only_configured_hu(req.device, allowed_hu, "display PIN-code request")?;
    info!(
        "{} 🧲 bt-wireless-proxy pairing: HU {} PIN-code display requested: {}",
        NAME, req.device, req.pincode
    );
    Ok(())
}

async fn hu_request_passkey(req: RequestPasskey, allowed_hu: Address) -> AgentReqResult<u32> {
    auto_accept_only_configured_hu(req.device, allowed_hu, "passkey request")?;
    info!(
        "{} 🧲 bt-wireless-proxy pairing: replying with fallback passkey 000000 for HU {}",
        NAME, req.device
    );
    Ok(0)
}

async fn hu_display_passkey(req: DisplayPasskey, allowed_hu: Address) -> AgentReqResult<()> {
    auto_accept_only_configured_hu(req.device, allowed_hu, "display passkey request")?;
    info!(
        "{} 🧲 bt-wireless-proxy pairing: HU {} passkey display requested: {:06} entered={}",
        NAME, req.device, req.passkey, req.entered
    );
    Ok(())
}

async fn hu_request_confirmation(
    req: RequestConfirmation,
    session: Session,
    allowed_hu: Address,
) -> AgentReqResult<()> {
    auto_accept_only_configured_hu(req.device, allowed_hu, "numeric confirmation")?;
    info!(
        "{} 🧲 bt-wireless-proxy pairing: confirming passkey {:06} for HU {}",
        NAME, req.passkey, req.device
    );
    trust_hu_after_pairing(session, req.adapter.clone(), req.device).await
}

async fn hu_request_authorization(
    req: RequestAuthorization,
    session: Session,
    allowed_hu: Address,
) -> AgentReqResult<()> {
    auto_accept_only_configured_hu(req.device, allowed_hu, "pairing authorization")?;
    trust_hu_after_pairing(session, req.adapter.clone(), req.device).await
}

async fn hu_authorize_service(req: AuthorizeService, allowed_hu: Address) -> AgentReqResult<()> {
    auto_accept_only_configured_hu(req.device, allowed_hu, "service authorization")?;
    info!(
        "{} 🧲 bt-wireless-proxy pairing: authorizing service {} for HU {}",
        NAME, req.service, req.device
    );
    Ok(())
}

impl Bluetooth {
    pub async fn set_adapter_pairable_discoverable(
        &self,
        pairable: bool,
        discoverable: bool,
        timeout_secs: u32,
    ) -> Result<()> {
        self.adapter.set_pairable_timeout(timeout_secs).await?;
        self.adapter.set_discoverable_timeout(timeout_secs).await?;
        self.adapter.set_pairable(pairable).await?;
        self.adapter.set_discoverable(discoverable).await?;
        Ok(())
    }

    async fn register_hu_pairing_agent(&mut self, hu_addr: Address) -> Result<()> {
        if self.hu_pairing_agent.is_some() {
            return Ok(());
        }

        if self.companion_pairing_agent.is_some() {
            info!(
                "{} 🧲 bt-wireless-proxy pairing: using existing Companion Classic BT default agent while pairing configured HU {}",
                NAME, hu_addr
            );
            return Ok(());
        }

        let session_for_confirmation = self.session.clone();
        let session_for_authorization = self.session.clone();
        let allowed_for_pin = hu_addr.clone();
        let allowed_for_display_pin = hu_addr.clone();
        let allowed_for_passkey = hu_addr.clone();
        let allowed_for_display_passkey = hu_addr.clone();
        let allowed_for_confirmation = hu_addr.clone();
        let allowed_for_authorization = hu_addr.clone();
        let allowed_for_service = hu_addr.clone();
        let agent = Agent {
            request_default: true,
            request_pin_code: Some(Box::new(move |req| {
                hu_request_pin_code(req, allowed_for_pin.clone()).boxed()
            })),
            display_pin_code: Some(Box::new(move |req| {
                hu_display_pin_code(req, allowed_for_display_pin.clone()).boxed()
            })),
            request_passkey: Some(Box::new(move |req| {
                hu_request_passkey(req, allowed_for_passkey.clone()).boxed()
            })),
            display_passkey: Some(Box::new(move |req| {
                hu_display_passkey(req, allowed_for_display_passkey.clone()).boxed()
            })),
            request_confirmation: Some(Box::new(move |req| {
                hu_request_confirmation(
                    req,
                    session_for_confirmation.clone(),
                    allowed_for_confirmation.clone(),
                )
                .boxed()
            })),
            request_authorization: Some(Box::new(move |req| {
                hu_request_authorization(
                    req,
                    session_for_authorization.clone(),
                    allowed_for_authorization.clone(),
                )
                .boxed()
            })),
            authorize_service: Some(Box::new(move |req| {
                hu_authorize_service(req, allowed_for_service.clone()).boxed()
            })),
            ..Default::default()
        };

        let handle = self.session.register_agent(agent).await?;
        self.hu_pairing_agent = Some(handle);
        info!(
            "{} 🧲 bt-wireless-proxy pairing: registered BlueZ agent for configured HU {} only",
            NAME, hu_addr
        );
        Ok(())
    }

    async fn cleanup_hu_pairing_window(&mut self) {
        let keep_pairing_open_for_companion = self.companion_pairing_agent.is_some();
        let (pairable, discoverable, timeout_secs) = if keep_pairing_open_for_companion {
            (true, true, 0)
        } else {
            (false, false, 0)
        };

        if let Err(e) = self
            .set_adapter_pairable_discoverable(pairable, discoverable, timeout_secs)
            .await
        {
            warn!(
                "{} 🧲 bt-wireless-proxy pairing: failed to restore pairable/discoverable state after window: {}",
                NAME, e
            );
        }
        if keep_pairing_open_for_companion {
            info!(
                "{} 🧲 bt-wireless-proxy pairing: keeping adapter pairable/discoverable for Companion Classic BT",
                NAME
            );
        }
        if self.hu_pairing_agent.take().is_some() {
            info!(
                "{} 🧲 bt-wireless-proxy pairing: unregistered temporary HU pairing agent",
                NAME
            );
        }
    }

    pub async fn ensure_hu_pairing_agent(
        &mut self,
        hu_mac: &str,
        pairing_window_secs: u64,
    ) -> Result<()> {
        let hu_mac = hu_mac.trim();
        if hu_mac.is_empty() {
            return Ok(());
        }

        let hu_addr: Address = hu_mac.parse()?;
        let already_ready = match self.adapter.device(hu_addr) {
            Ok(device) => {
                let paired = device.is_paired().await.unwrap_or(false);
                let trusted = device.is_trusted().await.unwrap_or(false);
                if paired && !trusted {
                    info!(
                        "{} 🧲 bt-wireless-proxy pairing: HU {} is paired but not trusted; trusting now",
                        NAME, hu_addr
                    );
                    if let Err(e) = device.set_trusted(true).await {
                        warn!(
                            "{} 🧲 bt-wireless-proxy pairing: failed to trust paired HU {}: {}",
                            NAME, hu_addr, e
                        );
                    }
                }
                paired && (trusted || device.is_trusted().await.unwrap_or(false))
            }
            Err(_) => false,
        };

        if already_ready {
            info!(
                "{} 🧲 bt-wireless-proxy pairing: HU {} is already paired and trusted; skipping pairing window",
                NAME, hu_addr
            );
            return Ok(());
        }

        let window_secs = pairing_window_secs.max(10) as u32;
        self.register_hu_pairing_agent(hu_addr).await?;
        self.set_adapter_pairable_discoverable(true, true, window_secs)
            .await?;
        info!(
            "{} 🧲 bt-wireless-proxy pairing: HU {} is not paired/trusted; adapter is pairable/discoverable for {}s before USB/phone flow",
            NAME, hu_addr, window_secs
        );

        let started = Instant::now();
        loop {
            if let Ok(device) = self.adapter.device(hu_addr) {
                let paired = device.is_paired().await.unwrap_or(false);
                if paired {
                    match device.set_trusted(true).await {
                        Ok(()) => info!(
                            "{} 🧲 bt-wireless-proxy pairing: HU {} paired and trusted",
                            NAME, hu_addr
                        ),
                        Err(e) => warn!(
                            "{} 🧲 bt-wireless-proxy pairing: HU {} paired but trust failed: {}",
                            NAME, hu_addr, e
                        ),
                    }
                    self.cleanup_hu_pairing_window().await;
                    return Ok(());
                }
            }

            if started.elapsed() >= Duration::from_secs(window_secs as u64) {
                self.cleanup_hu_pairing_window().await;
                return Err(format!(
                    "timed out waiting {}s for HU {} pairing; select aa-proxy on the HU and pair again",
                    window_secs, hu_addr
                )
                .into());
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn start_companion_bt(&mut self, state: AppState, enable_companion_bt: bool) -> Result<()> {
        if !enable_companion_bt {
            info!("{} 📱 Companion Classic BT profile: disabled", NAME);
            return Ok(());
        }

        if self.companion_pairing_agent.is_none() {
            match crate::companion_bt::register_companion_pairing_agent(&self.session).await {
                Ok(handle) => {
                    info!("{} 📱 Companion Classic BT pairing agent: registered", NAME);
                    self.companion_pairing_agent = Some(handle);
                }
                Err(e) => {
                    warn!("{} 📱 Failed to register Companion Classic BT pairing agent: {}", NAME, e);
                }
            }
        }

        // Keep the adapter pairable/discoverable while Companion BT is enabled.  The HU pairing
        // window is temporary, but the companion app may need to pair after startup or after the
        // user deletes the bond from Android Settings.
        match self.set_adapter_pairable_discoverable(true, true, 0).await {
            Ok(()) => info!(
                "{} 📱 Companion Classic BT: adapter is pairable/discoverable with no timeout",
                NAME
            ),
            Err(e) => warn!(
                "{} 📱 Companion Classic BT: failed to set adapter pairable/discoverable: {}",
                NAME, e
            ),
        }

        match crate::companion_bt::register_companion_bt_profile(&self.session).await {
            Ok(handle) => {
                info!("{} 📱 Companion Classic BT custom profile: registered", NAME);
                crate::companion_bt::spawn_companion_bt_accept_loop(handle, state.clone());
            }
            Err(e) => {
                error!("{} 📱 Failed to register Companion Classic BT custom profile: {}", NAME, e);
            }
        }

        match crate::companion_bt::register_companion_spp_profile(&self.session).await {
            Ok(handle) => {
                info!("{} 📱 Companion Classic BT SPP fallback profile: registered", NAME);
                crate::companion_bt::spawn_companion_bt_accept_loop(handle, state);
            }
            Err(e) => {
                warn!("{} 📱 Failed to register Companion Classic BT SPP fallback profile: {}", NAME, e);
            }
        }

        Ok(())
    }

    async fn get_aa_profile_connection(
        &mut self,
        connect: BluetoothAddressList,
        bt_timeout: Duration,
        stopped: bool,
    ) -> Result<(Address, Stream)> {
        info!("{} ⏳ Waiting for phone to connect via bluetooth...", NAME);

        // try to connect to saved devices or provided one via command line
        if let Some(addresses_to_connect) = connect.0 {
            if !stopped {
                let adapter_cloned = self.adapter.clone();

                let addresses: Vec<Address> = if addresses_to_connect
                    .iter()
                    .any(|addr| *addr == Address::any())
                {
                    // Only use known-good devices, no fallback to all paired devices
                    let known = load_known_devices();
                    if !known.is_empty() {
                        info!("{} 🥏 Using {} known-good device(s)...", NAME, known.len());
                    } else {
                        info!("{} 🥏 No known-good devices, passively waiting for incoming connection...", NAME);
                    }
                    known
                } else {
                    addresses_to_connect
                };
                // exit if we don't have anything to connect to
                if !addresses.is_empty() {
                    info!("{} 🧲 Attempting to start an AndroidAuto session via bluetooth with the following devices, in this order: {:?}", NAME, addresses);
                    if !self.dongle_mode {
                        let try_connect_bluetooth_addresses_retry = || async {
                            let next_index = Bluetooth::try_connect_bluetooth_addresses(
                                &adapter_cloned,
                                &addresses,
                                self.current_index,
                            )
                            .await?;

                            Ok(next_index)
                        };

                        let retry_policy = ExponentialBuilder::default()
                            .with_min_delay(Duration::from_secs(1))
                            .with_max_delay(Duration::from_secs(15))
                            .without_max_times();

                        self.current_index = try_connect_bluetooth_addresses_retry
                            // Retry with exponential backoff
                            .retry(retry_policy)
                            // Sleep implementation, required if no feature has been enabled
                            .sleep(tokio::time::sleep)
                            // Notify when retrying;
                            .notify(
                                |err: &Box<dyn std::error::Error + Send + Sync + 'static>,
                                 dur: Duration| {
                                    debug!(
                                        "{} Retrying due to error: {:?} after {:?}",
                                        NAME, err, dur
                                    );
                                },
                            )
                            .await?;
                    } else {
                        for addr in addresses {
                            if let Ok(device) = adapter_cloned.device(addr) {
                                match device.name().await {
                                    Ok(Some(name)) => {
                                        if name.starts_with("AndroidAuto-") {
                                            let dev_name = format!(" (<b><blue>{}</>)", name);
                                            info!(
                                                "{} 🧲 (dongle_mode) Forcing BR/EDR device.connect() to {} {}",
                                                NAME, addr, dev_name
                                            );
                                            if let Err(e) = device.connect().await {
                                                debug!(
                                                    "{} (dongle_mode) connect() returned {:?} (ignored)",
                                                    NAME, e
                                                );
                                            }
                                        } else {
                                            debug!(
                                                "{} 🧲 (dongle_mode) skipping {} - name doesn't start with AndroidAuto-",
                                                NAME,
                                                addr
                                            );
                                        }
                                    }
                                    _ => {
                                        debug!(
                                            "{} 🧲 (dongle_mode) skipping {} - no device name available",
                                            NAME,
                                            addr
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let handle_aa = self
            .handle_aa
            .as_mut()
            .ok_or("AA Wireless local server profile is not registered in this mode")?;
        let req = timeout(bt_timeout, handle_aa.next())
            .await?
            .expect("received no connect request");
        info!(
            "{} 📱 AA Wireless Profile: connect from: <b>{}</>",
            NAME,
            req.device()
        );
        let addr = req.device().clone();
        let stream = req.accept()?;

        Ok((addr, stream))
    }

    async fn try_connect_bluetooth_addresses(
        adapter: &Adapter,
        addresses: &Vec<Address>,
        start_index: usize,
    ) -> Result<usize> {
        let n = addresses.len();

        // Pre-fetch device handles and names once before the attempt rounds begin.
        // This avoids redundant name lookups on every attempt.
        struct DeviceEntry {
            idx: usize,
            addr: Address,
            dev_name: String,
        }
        let mut entries: Vec<DeviceEntry> = Vec::with_capacity(n);
        for i in 0..n {
            // Calculate the actual index, taking start_index into account
            let idx = (start_index + i) % n;
            let addr = addresses[idx];
            let device = adapter.device(addr)?;

            let dev_name = match device.name().await {
                Ok(Some(name)) => format!(" (<b><blue>{}</>)", name),
                _ => String::new(),
            };
            entries.push(DeviceEntry {
                idx,
                addr,
                dev_name,
            });
        }

        // Connect in an interleaved order:
        // Each device gets one attempt per round before any device is retried,
        // so a user whose phone is device #N does not have to wait through all
        // ATTEMPTS failures on devices #0..N-1 before being tried.
        for j in 1..=ATTEMPTS {
            for entry in &entries {
                let DeviceEntry {
                    idx,
                    addr,
                    dev_name,
                } = entry;
                let device = adapter.device(*addr)?;
                info!(
                    "{} 🧲 Trying to connect to: {}{}, attempt: {}/{}",
                    NAME, addr, dev_name, j, ATTEMPTS
                );
                if let Ok(true) = device.is_paired().await {
                    match device.connect_profile(&HSP_AG_UUID).await {
                        Ok(_) => {
                            info!(
                                "{} 🔗 Successfully connected to device: {}{}",
                                NAME, addr, dev_name
                            );
                            return Ok((*idx + 1) % n);
                        }
                        Err(e) => {
                            warn!("{} 🔇 {}{}: Error connecting: {}", NAME, addr, dev_name, e)
                        }
                    }
                } else {
                    warn!(
                        "{} 🧲 Unable to connect to: {}{} device not paired",
                        NAME, addr, dev_name
                    );
                }
            }
        }
        Err(anyhow!("Unable to connect to the provided addresses").into())
    }

    async fn send_params(wifi_config: WifiConfig, stream: &mut Stream) -> Result<()> {
        use WifiInfoResponse::WifiInfoResponse;
        use WifiStartRequest::WifiStartRequest;
        let mut stage = 1;
        let mut started;

        info!("{} 📲 Sending parameters via bluetooth to phone...", NAME);
        let mut start_req = WifiStartRequest::new();
        info!(
            "{} 🛜 Sending Host IP Address: {}",
            NAME, wifi_config.ip_addr
        );
        start_req.set_ip_address(wifi_config.ip_addr);
        start_req.set_port(wifi_config.port);
        send_message(stream, stage, MessageId::WifiStartRequest, start_req).await?;
        stage += 1;
        started = Instant::now();
        read_message(stream, stage, MessageId::WifiInfoRequest, started).await?;

        let mut info = WifiInfoResponse::new();
        info!(
            "{} 🛜 Sending Host SSID and Password: {}, {}",
            NAME, wifi_config.ssid, wifi_config.wpa_key
        );
        info.set_ssid(wifi_config.ssid);
        info.set_key(wifi_config.wpa_key);
        info.set_bssid(wifi_config.bssid);
        info.set_security_mode(SecurityMode::WPA2_PERSONAL);
        info.set_access_point_type(AccessPointType::DYNAMIC);
        stage += 1;
        send_message(stream, stage, MessageId::WifiInfoResponse, info).await?;
        stage += 1;
        started = Instant::now();
        read_message(stream, stage, MessageId::WifiStartResponse, started).await?;
        stage += 1;
        started = Instant::now();
        read_message(stream, stage, MessageId::WifiConnectStatus, started).await?;

        Ok(())
    }


    async fn register_hsp_trigger_profile(&self, bt_sco: bool) -> Option<bluer::Session> {
        if self.dongle_mode {
            return None;
        }

        let session = match bluer::Session::new().await {
            Ok(session) => session,
            Err(e) => {
                warn!("{} 🎧 Headset Profile (HSP): session error: {}, ignoring", NAME, e);
                return None;
            }
        };
        let profile = Profile {
            uuid: HSP_HS_UUID,
            name: Some("HSP HS".to_string()),
            require_authentication: Some(false),
            require_authorization: Some(false),
            ..Default::default()
        };

        match session.register_profile(profile).await {
            Ok(handle) => {
                info!("{} 🎧 Headset Profile (HSP): registered", NAME);
                tokio::spawn(async move {
                    let mut h = handle;
                    loop {
                        let req = match h.next().await {
                            Some(req) => req,
                            None => {
                                warn!("{} 🎧 Headset Profile (HSP): no more connect requests", NAME);
                                break;
                            }
                        };

                        let device = req.device().clone();
                        info!(
                            "{} 🎧 Headset Profile (HSP): connect from <b>{}</>",
                            NAME, device
                        );

                        match req.accept() {
                            Ok(stream) => {
                                if bt_sco {
                                    info!(
                                        "{} 🎧 Headset Profile (HSP): accepted from <b>{}</>, dropping control stream in SCO mode",
                                        NAME, device
                                    );
                                }
                                drop(stream);
                            }
                            Err(e) => {
                                warn!(
                                    "{} 🎧 Headset Profile (HSP): accept error from <b>{}</>: {}",
                                    NAME, device, e
                                );
                            }
                        }
                    }
                });
                Some(session)
            }
            Err(e) => {
                warn!(
                    "{} 🎧 Headset Profile (HSP) registering error: {}, ignoring",
                    NAME, e
                );
                None
            }
        }
    }

    /// Drop HSP session here - this unregisters the profile from BlueZ.
    /// We do it explicitly with a small delay to give BlueZ time to clean up.
    async fn unregister_hsp(hsp_session: Option<bluer::Session>) {
        if let Some(sess) = hsp_session {
            info!("{} 🎧 Headset Profile (HSP): unregistering ...", NAME);
            drop(sess);
            tokio::time::sleep(Duration::from_millis(80)).await;
            info!("{} 🎧 Headset Profile (HSP): unregistered", NAME);
        }
    }

    async fn connect_hu_aa_wireless_proxy(
        &self,
        hu_mac: &str,
        hu_channel: Option<u8>,
    ) -> Result<ProxyHuConnection> {
        if hu_mac.trim().is_empty() {
            return Err("bt_wireless_proxy_hu_mac must be set".into());
        }

        let hu_addr: Address = hu_mac.trim().parse()?;
        let channel = if let Some(channel) = hu_channel.filter(|channel| *channel > 0) {
            info!(
                "{} 🧪 bt-wireless-proxy: using configured HU RFCOMM channel {} for {}",
                NAME, channel, hu_addr
            );
            channel
        } else {
            info!(
                "{} 🧪 bt-wireless-proxy: HU RFCOMM channel is empty/0; using internal SDP discovery + raw RFCOMM for {}",
                NAME, hu_addr
            );
            discover_rfcomm_channel_via_internal_sdp(hu_addr).await?
        };

        let hu_socket = SocketAddr::new(hu_addr, channel);
        info!(
            "{} 🧪 bt-wireless-proxy: connecting to HU RFCOMM {} without registering a second AA Wireless UUID profile",
            NAME, hu_socket
        );
        let stream = timeout(Duration::from_secs(15), Stream::connect(hu_socket)).await??;
        Ok(ProxyHuConnection {
            stream,
            endpoint: format!("RFCOMM {}", hu_socket),
            _client_profile_session: None,
            _client_profile_handle: None,
        })
    }

    pub async fn aa_wireless_bridge_proxy(
        &mut self,
        connect: BluetoothAddressList,
        hu_mac: String,
        hu_channel: Option<u8>,
        bt_timeout: Duration,
        stopped: bool,
    ) -> Result<()> {
        if hu_mac.trim().is_empty() {
            return Err("bt_wireless_proxy_hu_mac must be set for bridge mode".into());
        }

        let hu_endpoint_hint = match hu_channel.filter(|channel| *channel > 0) {
            Some(channel) => format!("{} RFCOMM channel {}", hu_mac.trim(), channel),
            None => format!("{} AA Wireless SDP auto-discovery", hu_mac.trim()),
        };

        info!(
            "{} 🧪 bt-wireless-proxy bridge: waiting for phone AA RFCOMM, then connecting to HU {}",
            NAME, hu_endpoint_hint
        );

        let (phone_addr, phone_stream) = self
            .get_aa_profile_connection(connect, bt_timeout, stopped)
            .await?;

        info!(
            "{} 🧪 bt-wireless-proxy bridge: phone connected from {}; connecting to HU {}",
            NAME, phone_addr, hu_endpoint_hint
        );

        let hu_conn = self.connect_hu_aa_wireless_proxy(hu_mac.trim(), hu_channel).await?;
        let hu_endpoint = hu_conn.endpoint.clone();
        info!(
            "{} 🧪 bt-wireless-proxy bridge: connected to HU {}; relaying raw AA Wireless BT frames both ways",
            NAME, hu_endpoint
        );

        let ProxyHuConnection {
            stream: hu_stream,
            endpoint: _,
            _client_profile_session: hu_client_profile_session,
            _client_profile_handle: hu_client_profile_handle,
        } = hu_conn;
        let _hu_client_profile_guard = (hu_client_profile_session, hu_client_profile_handle);

        let (phone_read, phone_write) = phone_stream.into_split();
        let (hu_read, hu_write) = hu_stream.into_split();

        let mut phone_to_hu = tokio::spawn(relay_with_proxy_logging(
            phone_read,
            hu_write,
            "PHONE -> HU",
        ));
        let mut hu_to_phone = tokio::spawn(relay_with_proxy_logging(
            hu_read,
            phone_write,
            "HU -> PHONE",
        ));

        tokio::select! {
            res = &mut phone_to_hu => {
                match res {
                    Ok(Ok(bytes)) => info!("{} 🧪 bt-wireless-proxy bridge: PHONE -> HU ended after {} bytes", NAME, bytes),
                    Ok(Err(e)) => warn!("{} 🧪 bt-wireless-proxy bridge: PHONE -> HU error: {}", NAME, e),
                    Err(e) => warn!("{} 🧪 bt-wireless-proxy bridge: PHONE -> HU task error: {}", NAME, e),
                }
                hu_to_phone.abort();
            }
            res = &mut hu_to_phone => {
                match res {
                    Ok(Ok(bytes)) => info!("{} 🧪 bt-wireless-proxy bridge: HU -> PHONE ended after {} bytes", NAME, bytes),
                    Ok(Err(e)) => warn!("{} 🧪 bt-wireless-proxy bridge: HU -> PHONE error: {}", NAME, e),
                    Err(e) => warn!("{} 🧪 bt-wireless-proxy bridge: HU -> PHONE task error: {}", NAME, e),
                }
                phone_to_hu.abort();
            }
        }

        info!("{} 🧪 bt-wireless-proxy bridge: finished", NAME);
        Ok(())
    }

    pub async fn aa_wireless_car_wifi_mitm_proxy(
        &mut self,
        connect: BluetoothAddressList,
        options: CarWifiMitmProxyOptions,
    ) -> Result<()> {
        if options.hu_mac.trim().is_empty() {
            return Err("bt_wireless_proxy_hu_mac must be set for car-wifi-mitm mode".into());
        }

        let listen_port = if options.listen_port == 0 {
            5288
        } else {
            options.listen_port
        };
        let hu_endpoint_hint = match options.hu_channel.filter(|channel| *channel > 0) {
            Some(channel) => format!("{} RFCOMM channel {}", options.hu_mac.trim(), channel),
            None => format!("{} AA Wireless SDP auto-discovery", options.hu_mac.trim()),
        };

        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: waiting for phone AA RFCOMM, then connecting to HU {}",
            NAME, hu_endpoint_hint
        );

        // Keep the same phone-trigger behavior as the normal AA handshake path.
        // Without a local HSP HS profile, BlueZ device.connect_profile(HSP_AG) often
        // fails with br-connection-profile-unavailable and the phone never opens the
        // AA Wireless RFCOMM profile. The HSP control stream is accepted and dropped,
        // exactly like the normal path, only to nudge Android into starting wireless AA.
        let _hsp_session = self.register_hsp_trigger_profile(false).await;

        let (phone_addr, mut phone_stream) = self
            .get_aa_profile_connection(connect, options.bt_timeout, options.stopped)
            .await?;

        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: phone connected from {}; connecting to HU {}",
            NAME, phone_addr, hu_endpoint_hint
        );

        let hu_conn = self
            .connect_hu_aa_wireless_proxy(options.hu_mac.trim(), options.hu_channel)
            .await?;
        let hu_endpoint = hu_conn.endpoint.clone();
        let ProxyHuConnection {
            stream: mut hu_stream,
            endpoint: _,
            _client_profile_session: hu_client_profile_session,
            _client_profile_handle: hu_client_profile_handle,
        } = hu_conn;
        let _hu_client_profile_guard = (hu_client_profile_session, hu_client_profile_handle);

        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: connected to HU {}; starting delayed bootstrap MITM; waiting up to 10s for HU bootstrap frame; version_projection_fallback={}",
            NAME,
            hu_endpoint,
            options.use_version_projection_fallback
        );

        let hu_start_payload = match timeout(
            Duration::from_secs(10),
            read_hu_wifi_start_with_prebootstrap_passthrough(
                &mut hu_stream,
                &mut phone_stream,
                options.use_version_projection_fallback,
            ),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(format!(
                    "timed out waiting 10s for HU bootstrap frame after RFCOMM connect to {}; closing connection and restarting car-wifi-mitm",
                    hu_endpoint
                )
                .into())
            }
        };
        let hu_start_req = WifiStartRequest::WifiStartRequest::parse_from_bytes(&hu_start_payload)?;
        let hu_tcp_ip = hu_start_req.ip_address().to_string();
        let hu_tcp_port = hu_start_req.port();
        if hu_tcp_ip.trim().is_empty() || hu_tcp_port <= 0 {
            return Err(format!(
                "HU WifiStartRequest had invalid endpoint ip={} port={}",
                hu_tcp_ip, hu_tcp_port
            )
            .into());
        }

        send_proxy_frame(
            &mut hu_stream,
            "POC -> HU",
            ProxyMessageId::WifiInfoRequest,
            &[],
        )
        .await?;

        let (hu_info_id, hu_info_payload) = read_proxy_frame(&mut hu_stream, "HU -> POC").await?;
        if hu_info_id != ProxyMessageId::WifiInfoResponse as u16 {
            return Err(format!(
                "expected HU WifiInfoResponse as second frame, got {} ({})",
                hu_info_id,
                ProxyMessageId::name(hu_info_id)
            )
            .into());
        }
        let hu_wifi_info = WifiInfoResponse::WifiInfoResponse::parse_from_bytes(&hu_info_payload)?;

        let join_iface = run_car_wifi_join(
            &options.join_cmd,
            options.auto_join,
            &options.join_control,
            &options.iface,
            options.keep_ap,
            &options.sta_iface,
            &options.ap_iface,
            &hu_wifi_info,
            options.wpactrl_socket_timeout,
            options.wifi_association_timeout,
            options.dhcp_timeout,
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let rewrite_ip = discover_rewrite_ip(&hu_tcp_ip, &join_iface, &options.rewrite_ip, options.dhcp_timeout).await?;
        let listen_addr = format!("0.0.0.0:{}", listen_port);
        let listener = TcpListener::bind(listen_addr.as_str()).await?;
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: MD TCP listener bound at {}; phone will receive {}:{} instead of HU {}:{}",
            NAME, listen_addr, rewrite_ip, listen_port, hu_tcp_ip, hu_tcp_port
        );

        let mut phone_start_req = WifiStartRequest::WifiStartRequest::parse_from_bytes(&hu_start_payload)?;
        phone_start_req.set_ip_address(rewrite_ip.clone());
        phone_start_req.set_port(listen_port as i32);
        let phone_start_payload = phone_start_req.write_to_bytes()?;
        send_proxy_frame(
            &mut phone_stream,
            "POC -> PHONE",
            ProxyMessageId::WifiStartRequest,
            &phone_start_payload,
        )
        .await?;

        let (phone_info_req_id, _phone_info_req_payload) = read_phone_bootstrap_frame(
            &mut phone_stream,
            ProxyMessageId::WifiInfoRequest,
            None,
            Duration::from_secs(30),
        )
        .await?;
        if phone_info_req_id != ProxyMessageId::WifiInfoRequest as u16 {
            warn!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: continuing after unexpected PHONE frame while waiting for WifiInfoRequest: {} ({})",
                NAME,
                phone_info_req_id,
                ProxyMessageId::name(phone_info_req_id)
            );
        }
        debug!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: consumed PHONE WifiInfoRequest locally; forwarding cached HU WifiInfoResponse to phone",
            NAME
        );

        send_proxy_frame(
            &mut phone_stream,
            "POC -> PHONE",
            ProxyMessageId::WifiInfoResponse,
            &hu_info_payload,
        )
        .await?;

        let (phone_start_resp_id, phone_start_resp_payload) = read_phone_bootstrap_frame(
            &mut phone_stream,
            ProxyMessageId::WifiStartResponse,
            Some(&hu_info_payload),
            Duration::from_secs(45),
        )
        .await?;
        if phone_start_resp_id != ProxyMessageId::WifiStartResponse as u16 {
            warn!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: expected PHONE WifiStartResponse, got {} ({})",
                NAME,
                phone_start_resp_id,
                ProxyMessageId::name(phone_start_resp_id)
            );
        }
        send_proxy_frame_raw(
            &mut hu_stream,
            "POC -> HU",
            phone_start_resp_id,
            &phone_start_resp_payload,
        )
        .await?;

        let hu_tcp_addr = format!("{}:{}", hu_tcp_ip, hu_tcp_port);
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: waiting for phone TCP and connecting HU TCP {}",
            NAME, hu_tcp_addr
        );

        let phone_tcp_fut = listener.accept();
        let hu_tcp_fut = TcpStream::connect(hu_tcp_addr.as_str());
        let ((mut phone_tcp, phone_tcp_addr), mut hu_tcp) = tokio::try_join!(
            async {
                let (stream, addr) = timeout(Duration::from_secs(45), phone_tcp_fut).await??;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((stream, addr))
            },
            async {
                let stream = timeout(Duration::from_secs(15), hu_tcp_fut).await??;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(stream)
            }
        )?;
        phone_tcp.set_nodelay(true)?;
        hu_tcp.set_nodelay(true)?;
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: phone TCP {} connected; HU TCP {} connected",
            NAME, phone_tcp_addr, hu_tcp_addr
        );

        let mut phone_rfcomm = phone_stream;
        let mut hu_rfcomm = hu_stream;
        let rfcomm_status_task = tokio::spawn(async move {
            match timeout(
                Duration::from_secs(20),
                read_proxy_frame(&mut phone_rfcomm, "PHONE -> POC"),
            )
            .await
            {
                Ok(Ok((phone_status_id, phone_status_payload))) => {
                    if phone_status_id != ProxyMessageId::WifiConnectStatus as u16 {
                        warn!(
                            "{} 🧪 bt-wireless-proxy car-wifi-mitm: expected PHONE WifiConnectStatus, got {} ({})",
                            NAME,
                            phone_status_id,
                            ProxyMessageId::name(phone_status_id)
                        );
                    }
                    send_proxy_frame_raw(
                        &mut hu_rfcomm,
                        "POC -> HU",
                        phone_status_id,
                        &phone_status_payload,
                    )
                    .await?;
                }
                Ok(Err(e)) => {
                    warn!(
                        "{} 🧪 bt-wireless-proxy car-wifi-mitm: failed reading PHONE WifiConnectStatus: {}; sending success to HU",
                        NAME, e
                    );
                    send_proxy_frame(
                        &mut hu_rfcomm,
                        "POC -> HU",
                        ProxyMessageId::WifiConnectStatus,
                        success_status_payload(),
                    )
                    .await?;
                }
                Err(_) => {
                    warn!(
                        "{} 🧪 bt-wireless-proxy car-wifi-mitm: timed out waiting for PHONE WifiConnectStatus; sending success to HU",
                        NAME
                    );
                    send_proxy_frame(
                        &mut hu_rfcomm,
                        "POC -> HU",
                        ProxyMessageId::WifiConnectStatus,
                        success_status_payload(),
                    )
                    .await?;
                }
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: starting raw AA TCP relay phone<->HU",
            NAME
        );
        let (phone_to_hu, hu_to_phone) = copy_bidirectional(&mut phone_tcp, &mut hu_tcp).await?;
        if !rfcomm_status_task.is_finished() {
            rfcomm_status_task.abort();
        } else if let Ok(Err(e)) = rfcomm_status_task.await {
            warn!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: RFCOMM status forward task failed: {}",
                NAME, e
            );
        }
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: TCP relay ended phone->HU={} bytes HU->phone={} bytes",
            NAME, phone_to_hu, hu_to_phone
        );

        Ok(())
    }


    pub async fn aa_wireless_probe_proxy(
        &mut self,
        hu_mac: String,
        hu_channel: Option<u8>,
        tcp_probe: bool,
    ) -> Result<()> {
        if hu_mac.trim().is_empty() {
            return Err("bt_wireless_proxy_hu_mac must be set for probe mode".into());
        }

        let hu_conn = self.connect_hu_aa_wireless_proxy(hu_mac.trim(), hu_channel).await?;
        let hu_endpoint = hu_conn.endpoint.clone();
        let ProxyHuConnection {
            mut stream,
            endpoint: _,
            _client_profile_session: hu_client_profile_session,
            _client_profile_handle: hu_client_profile_handle,
        } = hu_conn;
        let _hu_client_profile_guard = (hu_client_profile_session, hu_client_profile_handle);

        info!(
            "{} 🧪 bt-wireless-proxy probe: connected to HU {}; waiting for WifiStartRequest",
            NAME, hu_endpoint
        );

        let (message_id, payload) = read_proxy_frame(&mut stream, "HU -> POC").await?;
        if message_id != ProxyMessageId::WifiStartRequest as u16 {
            warn!(
                "{} 🧪 bt-wireless-proxy probe: first HU frame was {}, expected WifiStartRequest; continuing anyway",
                NAME, message_id
            );
        }

        let mut target_ip = String::new();
        let mut target_port = 0i32;
        if message_id == ProxyMessageId::WifiStartRequest as u16 {
            if let Ok(req) = WifiStartRequest::WifiStartRequest::parse_from_bytes(&payload) {
                target_ip = req.ip_address().to_string();
                target_port = req.port();
            }
        }

        send_proxy_frame(
            &mut stream,
            "POC -> HU",
            ProxyMessageId::WifiInfoRequest,
            &[],
        )
        .await?;

        let (message_id, _payload) = read_proxy_frame(&mut stream, "HU -> POC").await?;
        if message_id != ProxyMessageId::WifiInfoResponse as u16 {
            warn!(
                "{} 🧪 bt-wireless-proxy probe: second HU frame was {}, expected WifiInfoResponse",
                NAME, message_id
            );
        }

        send_proxy_frame(
            &mut stream,
            "POC -> HU",
            ProxyMessageId::WifiStartResponse,
            success_status_payload(),
        )
        .await?;

        if tcp_probe && !target_ip.is_empty() && target_port > 0 {
            let addr = format!("{}:{}", target_ip, target_port);
            info!(
                "{} 🧪 bt-wireless-proxy probe: trying TCP probe to HU AA endpoint {}",
                NAME, addr
            );
            match timeout(Duration::from_secs(5), TcpStream::connect(addr.as_str())).await {
                Ok(Ok(_tcp)) => info!(
                    "{} 🧪 bt-wireless-proxy probe: TCP probe connected to {}",
                    NAME, addr
                ),
                Ok(Err(e)) => warn!(
                    "{} 🧪 bt-wireless-proxy probe: TCP probe failed to {}: {}",
                    NAME, addr, e
                ),
                Err(e) => warn!(
                    "{} 🧪 bt-wireless-proxy probe: TCP probe timed out to {}: {}",
                    NAME, addr, e
                ),
            }
        }

        send_proxy_frame(
            &mut stream,
            "POC -> HU",
            ProxyMessageId::WifiConnectStatus,
            success_status_payload(),
        )
        .await?;

        info!(
            "{} 🧪 bt-wireless-proxy probe: bootstrap frames sent; keeping RFCOMM open until HU closes or 30s idle timeout",
            NAME
        );

        loop {
            match timeout(Duration::from_secs(30), read_proxy_frame(&mut stream, "HU -> POC")).await {
                Ok(Ok((_id, _payload))) => continue,
                Ok(Err(e)) => {
                    info!("{} 🧪 bt-wireless-proxy probe: RFCOMM ended: {}", NAME, e);
                    break;
                }
                Err(_) => {
                    info!("{} 🧪 bt-wireless-proxy probe: idle timeout; closing", NAME);
                    break;
                }
            }
        }

        Ok(())
    }

    pub async fn aa_handshake(
        &mut self,
        connect: BluetoothAddressList,
        wifi_config: WifiConfig,
        tcp_start: Arc<Notify>,
        bt_timeout: Duration,
        stopped: bool,
        quick_reconnect: bool,
        bt_poweroff: bool,
        bt_sco: bool,
        bt_sco_keep_bluetooth_alive: bool,
        mut need_restart: BroadcastReceiver<Option<Action>>,
        restart_tx: BroadcastSender<Option<Action>>,
        profile_connected: Arc<AtomicBool>,
    ) -> Result<()> {
        if bt_poweroff {
            let _ = self.adapter.set_powered(true).await;
        }
        //
        // --- HSP PROFILE REGISTRATION ---
        //
        let mut hsp_handle = None;

        if !self.dongle_mode {
            let session = bluer::Session::new().await?;
            let profile = Profile {
                uuid: HSP_HS_UUID,
                name: Some("HSP HS".to_string()),
                require_authentication: Some(false),
                require_authorization: Some(false),
                ..Default::default()
            };

            match session.register_profile(profile).await {
                Ok(handle) => {
                    info!("{} 🎧 Headset Profile (HSP): registered", NAME);

                    // Move ownership of handle into task. Keep the old safe behavior:
                    // accept and immediately drop the HSP control stream so Android Auto
                    // Bluetooth handshakes are not affected. The SCO/eSCO audio socket is
                    // handled separately by the bt_sco listener.
                    tokio::spawn(async move {
                        let mut h = handle;
                        loop {
                            let req = match h.next().await {
                                Some(req) => req,
                                None => {
                                    warn!(
                                        "{} 🎧 Headset Profile (HSP): no more connect requests",
                                        NAME
                                    );
                                    break;
                                }
                            };

                            let device = req.device().clone();
                            info!(
                                "{} 🎧 Headset Profile (HSP): connect from <b>{}</>",
                                NAME, device
                            );

                            match req.accept() {
                                Ok(stream) => {
                                    // IMPORTANT: Do not keep the HSP RFCOMM control stream open yet.
                                    // Keeping it open without a proper HSP/HFP AT-command state machine can
                                    // make Android route the call to this Bluetooth device and then wait forever
                                    // for headset-side responses. The independent SCO/eSCO listener remains
                                    // active; the HSP control stream is accepted and immediately dropped,
                                    // preserving the old Android Auto Bluetooth behavior.
                                    if bt_sco {
                                        info!(
                                            "{} 🎧 Headset Profile (HSP): accepted from <b>{}</>, dropping control stream in SCO mode",
                                            NAME,
                                            device
                                        );
                                    }
                                    drop(stream);
                                }
                                Err(e) => {
                                    warn!(
                                        "{} 🎧 Headset Profile (HSP): accept error from <b>{}</>: {}",
                                        NAME,
                                        device,
                                        e
                                    );
                                }
                            }
                        }
                    });

                    // Keep handle for unregister
                    hsp_handle = Some(session);
                }
                Err(e) => {
                    warn!(
                        "{} 🎧 Headset Profile (HSP) registering error: {}, ignoring",
                        NAME, e
                    );
                }
            }
        }

        // Check if we're using wildcard connect before moving ownership
        let is_wildcard_connect = connect.is_wildcard();

        // Use the provided session and adapter instead of creating new ones
        let (address, mut stream) = self
            .get_aa_profile_connection(connect, bt_timeout, stopped)
            .await?;

        let phone_name = match self.adapter.device(address) {
            Ok(device) => device.name().await.ok().flatten(),
            Err(_) => None,
        };
        sdr_ui::set_current_phone_from_bt(&address.to_string(), phone_name);

        Self::send_params(wifi_config.clone(), &mut stream).await?;

        // Record this device as a known-good AA device (only when using wildcard connect)
        if is_wildcard_connect {
            save_known_device(address);
        }
        tcp_start.notify_one();

        if quick_reconnect {
            // keep the bluetooth profile connection alive
            // and use it in a loop to restart handshake when necessary
            //
            // hsp_handle is moved into the task so that the HSP session stays
            // registered for the entire duration of the quick_reconnect loop.
            // It will be dropped (= unregistered from BlueZ) when the task exits.
            let hsp_session = hsp_handle.take();
            let adapter_cloned = self.adapter.clone();
            let _ = Some(tokio::spawn(async move {
                profile_connected.store(true, Ordering::Relaxed);
                loop {
                    // wait for restart notification from main loop (eg when HU disconnected)
                    let action = need_restart.recv().await;
                    if let Ok(Some(action)) = action {
                        // check if we need to stop now
                        if action == Action::Stop {
                            // attempt graceful RFCOMM shutdown then drain pending data, then disconnect
                            match stream.shutdown().await {
                                Ok(_) => debug!("{} RFCOMM stream shutdown succeeded", NAME),
                                Err(e) => warn!("{} RFCOMM stream shutdown error: {}", NAME, e),
                            }

                            // Try to drain any pending incoming data with short timeouts
                            let mut drain_buf = [0u8; 256];
                            loop {
                                match timeout(
                                    Duration::from_millis(50),
                                    stream.read(&mut drain_buf),
                                )
                                .await
                                {
                                    Ok(Ok(0)) => {
                                        debug!("{} RFCOMM drain: EOF", NAME);
                                        break;
                                    }
                                    Ok(Ok(n)) => {
                                        debug!("{} RFCOMM drained {} bytes", NAME, n);
                                        continue;
                                    }
                                    Ok(Err(e)) => {
                                        debug!("{} RFCOMM drain read error: {}", NAME, e);
                                        break;
                                    }
                                    Err(_) => {
                                        debug!("{} RFCOMM drain timeout, no more data", NAME);
                                        break;
                                    }
                                }
                            }

                            // allow controller time to finish frames
                            tokio::time::sleep(Duration::from_millis(500)).await;

                            if let Ok(device) = adapter_cloned.device(bluer::Address(*address)) {
                                if let Err(e) = device.disconnect().await {
                                    warn!("{} device.disconnect error: {}", NAME, e);
                                }
                            }

                            break;
                        }
                    }

                    // now restart handshake with the same params
                    match Self::send_params(wifi_config.clone(), &mut stream).await {
                        Ok(_) => {
                            tcp_start.notify_one();
                            continue;
                        }
                        Err(e) => {
                            error!(
                                "{} handshake restart error: {}, doing full restart!",
                                NAME, e
                            );
                            // this break should end this task
                            break;
                        }
                    }
                }
                // we are now disconnected, redo bluetooth connection
                profile_connected.store(false, Ordering::Relaxed);
                Self::unregister_hsp(hsp_session).await;
                // main loop could now wait so send an event to restart
                let _ = restart_tx.send(None);
            }));
        } else if bt_sco && bt_sco_keep_bluetooth_alive {
            // The SCO call-audio bridge needs the phone to keep routing calls to
            // aa-proxy-rs over Bluetooth after the AA Wi-Fi bootstrap completes.
            // Normal aa-proxy-rs behavior disconnects BT here so the phone can use
            // the real HU for calls; for the bridge we instead keep the accepted
            // AA RFCOMM stream and the HSP registration alive until the AA session
            // restarts/stops.
            info!(
                "{} 🎧 bt_sco_keep_bluetooth_alive enabled; keeping Bluetooth RFCOMM/HSP alive after Wi-Fi bootstrap",
                NAME
            );

            let hsp_session = hsp_handle.take();
            let adapter_cloned = self.adapter.clone();
            let device_address = bluer::Address(*address);
            let mut keepalive_restart_rx = need_restart;

            let _ = Some(tokio::spawn(async move {
                profile_connected.store(true, Ordering::Relaxed);

                // Hold `stream` and `hsp_session` by moving them into this task.
                // We intentionally do not send any more AA Wireless frames here;
                // this is not quick_reconnect. The task only keeps BT alive while
                // the current AA session is alive, then cleans up on restart/stop.
                let mut held_stream = stream;
                let _held_hsp_session = hsp_session;

                match keepalive_restart_rx.recv().await {
                    Ok(action) => {
                        info!(
                            "{} 🎧 bt_sco keepalive ending after restart notification: {:?}",
                            NAME, action
                        );
                    }
                    Err(e) => {
                        debug!(
                            "{} 🎧 bt_sco keepalive ending because restart channel closed: {}",
                            NAME, e
                        );
                    }
                }

                match held_stream.shutdown().await {
                    Ok(_) => debug!("{} bt_sco keepalive RFCOMM shutdown succeeded", NAME),
                    Err(e) => warn!("{} bt_sco keepalive RFCOMM shutdown error: {}", NAME, e),
                }

                tokio::time::sleep(Duration::from_millis(150)).await;

                if let Ok(device) = adapter_cloned.device(device_address) {
                    if let Err(e) = device.disconnect().await {
                        warn!("{} bt_sco keepalive device.disconnect error: {}", NAME, e);
                    }
                }

                if let Some(sess) = _held_hsp_session {
                    info!("{} 🎧 Headset Profile (HSP): unregistering ...", NAME);
                    drop(sess);
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    info!("{} 🎧 Headset Profile (HSP): unregistered", NAME);
                }

                if bt_poweroff {
                    let _ = adapter_cloned.set_powered(false).await;
                }

                profile_connected.store(false, Ordering::Relaxed);
            }));
        } else {
            // attempt graceful shutdown of the RFCOMM stream before disconnect
            let _ = stream.shutdown().await;
            // let some phones that have problems with handshake time to
            // finish all bluetooth frames before disconnect
            let _ = tokio::time::sleep(Duration::from_millis(150));
            // handshake complete, now disconnect the device so it should
            // connect to real HU for calls
            let device = self.adapter.device(bluer::Address(*address))?;
            let _ = device.disconnect().await;
            //
            // --- UNREGISTER HSP ---
            //
            if !self.dongle_mode {
                Self::unregister_hsp(hsp_handle.take()).await;
            }
            if bt_poweroff {
                let _ = self.adapter.set_powered(false).await;
            }
        }

        info!("{} 🚀 Bluetooth launch sequence completed", NAME);

        Ok(())
    }
}
