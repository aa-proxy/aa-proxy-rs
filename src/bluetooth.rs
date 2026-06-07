use crate::config::Action;
use crate::config::SharedConfig;
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
    Adapter, AdapterEvent, Address, AddressType, Session, Uuid,
};
use futures::{FutureExt, Stream as FuturesStream, StreamExt};
use simplelog::*;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::broadcast::Receiver as BroadcastReceiver;
use tokio::sync::broadcast::Sender as BroadcastSender;
use tokio::sync::Notify;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use crate::config::{TCP_DHU_PORT, TCP_SERVER_PORT};
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
const SDP_PDU_ERROR_RESPONSE: u8 = 0x01;
const SDP_PDU_SERVICE_SEARCH_ATTRIBUTE_REQUEST: u8 = 0x06;
const SDP_PDU_SERVICE_SEARCH_ATTRIBUTE_RESPONSE: u8 = 0x07;
// Match the successful Android-phone SDP query observed in the MBUX HCI trace:
// ServiceSearchAttributeRequest(AA Wireless UUID, max_attr_bytes=0x03f0, attrs=0x0000..0xffff).
// Asking only ProtocolDescriptorList with 0xffff max bytes made this HU answer with SDP ErrorResponse.
const SDP_PHONE_LIKE_MAX_ATTRIBUTE_BYTES: u16 = 0x03f0;
const SDP_ATTR_RANGE_ALL: u32 = 0x0000ffff;

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

    let attribute_id_list = sdp_de_sequence_u8(sdp_de_uint32(SDP_ATTR_RANGE_ALL).to_vec())?;

    let mut params = Vec::new();
    params.extend_from_slice(&service_search_pattern);
    params.extend_from_slice(&SDP_PHONE_LIKE_MAX_ATTRIBUTE_BYTES.to_be_bytes());
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

fn describe_sdp_error_response(params: &[u8]) -> String {
    if params.len() < 2 {
        return format!("short SDP ErrorResponse params={}", hex::encode(params));
    }

    let code = u16::from_be_bytes([params[0], params[1]]);
    let label = match code {
        0x0001 => "Invalid/unsupported SDP version",
        0x0002 => "Invalid service record handle",
        0x0003 => "Invalid request syntax",
        0x0004 => "Invalid PDU size",
        0x0005 => "Invalid continuation state",
        0x0006 => "Insufficient resources",
        _ => "Unknown SDP error",
    };
    format!("{} code=0x{:04x} params={}", label, code, hex::encode(params))
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

    for request_index in 0u16..8 {
        // Android's bt stack used transaction id 0 for the successful MBUX SDP query
        // in the captured HCI trace. Keep that exact shape; only request_index limits
        // continuation retries locally.
        let transaction_id = 0u16;
        let request = build_sdp_service_search_attribute_request(
            transaction_id,
            AAWG_PROFILE_UUID,
            &continuation_state,
        )?;
        debug!(
            "{} 🧪 bt-wireless-proxy: internal SDP discovery: TX req_index={} tid={} bytes={}",
            NAME,
            request_index,
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
        if pdu_id == SDP_PDU_ERROR_RESPONSE {
            return Err(format!(
                "HU returned SDP ErrorResponse for AA Wireless UUID {}: {}",
                AAWG_PROFILE_UUID,
                describe_sdp_error_response(&params)
            ).into());
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

// Phone-like SDP UUIDs used only as optional, dummy local service records while
// testing HUs that classify paired devices by the phone profile UUID set.
// Do not remove AAWG_PROFILE_UUID above: the phone side still needs the AA Wireless
// SDP record to connect to aa-proxy-rs as the projected head unit.
const SDP_OBEX_OBJECT_PUSH_UUID: Uuid = Uuid::from_u128(0x0000110500001000800000805f9b34fb);
const SDP_AUDIO_SOURCE_UUID: Uuid = Uuid::from_u128(0x0000110a00001000800000805f9b34fb);
const SDP_AVRCP_TARGET_UUID: Uuid = Uuid::from_u128(0x0000110c00001000800000805f9b34fb);
const SDP_AVRCP_REMOTE_UUID: Uuid = Uuid::from_u128(0x0000110e00001000800000805f9b34fb);
const SDP_AVRCP_CONTROLLER_UUID: Uuid = Uuid::from_u128(0x0000110f00001000800000805f9b34fb);
const SDP_PANU_UUID: Uuid = Uuid::from_u128(0x0000111500001000800000805f9b34fb);
const SDP_NAP_UUID: Uuid = Uuid::from_u128(0x0000111600001000800000805f9b34fb);
const SDP_HANDSFREE_AG_UUID: Uuid = Uuid::from_u128(0x0000111f00001000800000805f9b34fb);
const SDP_PHONEBOOK_ACCESS_SERVER_UUID: Uuid = Uuid::from_u128(0x0000112f00001000800000805f9b34fb);
const SDP_MESSAGE_ACCESS_SERVER_UUID: Uuid = Uuid::from_u128(0x0000113200001000800000805f9b34fb);
const SDP_PNP_INFORMATION_UUID: Uuid = Uuid::from_u128(0x0000120000001000800000805f9b34fb);
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

type CarWifiRendezvousResult = (
    Address,
    Stream,
    Stream,
    String,
    Option<bluer::Session>,
    Option<ProfileHandle>,
    Vec<(u16, Vec<u8>)>,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CarWifiRendezvousMode {
    Auto,
    HuFirst,
    PhoneFirst,
}

impl CarWifiRendezvousMode {
    fn parse(configured: &str) -> Self {
        let normalized = configured.trim().to_ascii_lowercase().replace('-', "_");
        let mode = match normalized.as_str() {
            "phone_first" | "phonefirst" | "phone" => Self::PhoneFirst,
            "hu_first" | "hufirst" | "headunit_first" | "head_unit_first" | "hu" => Self::HuFirst,
            "auto" | "hybrid" | "" => Self::Auto,
            other => {
                warn!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: unknown rendezvous mode {:?}; using auto",
                    NAME, other
                );
                Self::Auto
            }
        };
        mode
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::HuFirst => "hu_first",
            Self::PhoneFirst => "phone_first",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CarWifiMitmProxyOptions {
    pub hu_mac: String,
    pub hu_channel: Option<u8>,
    /// car-wifi-mitm Bluetooth rendezvous strategy: auto/hybrid, hu_first, phone_first.
    /// auto starts with the HU-first/hybrid path and falls back to phone-first if the
    /// phone AA Wireless RFCOMM connection never arrives.
    pub rendezvous_mode: String,
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
    /// for takeover mode, sta0 for keep_ap/proxy_ap mode.
    pub sta_iface: String,
    /// Optional PHY used when creating sta_iface. Empty auto-detects from ap_iface.
    /// Example: phy1.
    pub sta_phy: String,
    /// Existing AP interface to keep when keep_ap=true. Used to discover the
    /// phy for creating sta_iface. Example: wlan0.
    pub ap_iface: String,
    /// Phone-facing Wi-Fi mode: car_ap forwards HU Wi-Fi credentials to phone;
    /// proxy_ap sends normal aa-proxy AP credentials using a single radio (car STA + virtual phone AP);
    /// external_ap sends normal aa-proxy AP credentials using a second/external STA interface for HU Wi-Fi.
    pub phone_wifi_mode: String,
    pub phone_ap_ssid: String,
    pub phone_ap_key: String,
    pub phone_ap_ip: String,
    pub phone_ap_channel: u8,
    pub rewrite_ip: String,
    pub listen_port: u16,
    /// Notify the normal aa-proxy TCP/USB MITM loop to accept the phone-side TCP session.
    /// car-wifi-mitm uses the same AA packet/TLS MITM path as USB by bridging the real HU TCP
    /// socket into the local DHU-side TCP listener instead of raw-copying phone<->HU here.
    pub tcp_start: Arc<Notify>,
    /// Raised by the normal TCP MITM loop after the phone-side TCP connection has actually
    /// been accepted.  This is the commit barrier for strict HUs: do not tell the real HU
    /// Wi-Fi bootstrap succeeded, and do not open the real HU TCP leg, until the phone is
    /// already connected to aa-proxy.
    pub tcp_phone_connected: Arc<Notify>,
    pub tcp_phone_connection_seq: Arc<AtomicU64>,
    /// If HU WifiVersionRequest contains WifiProjectionProtocolInfo(ip/port) and no explicit
    /// WifiStartRequest arrives, synthesize WifiStartRequest from that endpoint.
    pub use_version_projection_fallback: bool,
    /// Send synthetic WifiPingRequest frames to the HU RFCOMM/WPP socket while
    /// aa-proxy is busy joining Wi-Fi / starting proxy_ap and waiting for the
    /// phone's Wi-Fi bootstrap response. This keeps impatient HUs from timing
    /// out before the TCP leg is ready.
    pub wpp_keepalive: bool,
    pub wpp_keepalive_interval: Duration,
    /// Timeout for the wpa_supplicant control socket to appear in wpactrl mode.
    pub wpactrl_socket_timeout: Duration,
    /// Timeout for STA association + IPv4 readiness after a Wi-Fi join attempt.
    pub wifi_association_timeout: Duration,
    /// Timeout for DHCP/udhcpc attempts.
    pub dhcp_timeout: Duration,
    /// How long to keep the HU RFCOMM socket open while waiting for the phone in
    /// HU-first rendezvous mode. HU frames received during this window are buffered
    /// and replayed to the phone when it arrives.
    pub hu_first_wait_phone_timeout: Duration,
    pub bt_timeout: Duration,
    pub stopped: bool,
}

#[derive(Clone, Copy)]
struct PhoneLikeSdpProfileSpec {
    uuid: Uuid,
    name: &'static str,
    tag: &'static str,
}

fn phone_like_sdp_profile_specs(profile_set: &str) -> Vec<PhoneLikeSdpProfileSpec> {
    let normalized = profile_set.trim().to_ascii_lowercase();

    let mut specs = vec![
        // The minimal set mirrors the common phone-facing capabilities seen on Android phones:
        // HFP Audio Gateway, PBAP server, MAP server, OPP, A2DP source, AVRCP target.
        PhoneLikeSdpProfileSpec { uuid: SDP_HANDSFREE_AG_UUID, name: "Handsfree Audio Gateway", tag: "hfp_ag" },
        PhoneLikeSdpProfileSpec { uuid: SDP_PHONEBOOK_ACCESS_SERVER_UUID, name: "Phonebook Access Server", tag: "pbap_server" },
        PhoneLikeSdpProfileSpec { uuid: SDP_MESSAGE_ACCESS_SERVER_UUID, name: "Message Access Server", tag: "map_server" },
        PhoneLikeSdpProfileSpec { uuid: SDP_OBEX_OBJECT_PUSH_UUID, name: "OBEX Object Push", tag: "opp" },
        PhoneLikeSdpProfileSpec { uuid: SDP_AUDIO_SOURCE_UUID, name: "Audio Source", tag: "a2dp_source" },
        PhoneLikeSdpProfileSpec { uuid: SDP_AVRCP_TARGET_UUID, name: "A/V Remote Control Target", tag: "avrcp_target" },
    ];

    match normalized.as_str() {
        "full" | "android" | "phone" => {
            specs.extend([
                PhoneLikeSdpProfileSpec { uuid: HSP_AG_UUID, name: "Headset Audio Gateway", tag: "hsp_ag" },
                PhoneLikeSdpProfileSpec { uuid: SDP_AVRCP_REMOTE_UUID, name: "A/V Remote Control", tag: "avrcp_remote" },
                PhoneLikeSdpProfileSpec { uuid: SDP_AVRCP_CONTROLLER_UUID, name: "A/V Remote Control Controller", tag: "avrcp_controller" },
                PhoneLikeSdpProfileSpec { uuid: SDP_PANU_UUID, name: "PANU", tag: "panu" },
                PhoneLikeSdpProfileSpec { uuid: SDP_NAP_UUID, name: "NAP", tag: "nap" },
                PhoneLikeSdpProfileSpec { uuid: SDP_PNP_INFORMATION_UUID, name: "PnP Information", tag: "pnp" },
            ]);
        }
        "minimal" | "" => {}
        other => {
            warn!(
                "{} 🧲 bt-wireless-proxy phone-like SDP: unknown profile set {:?}; using minimal set",
                NAME, other
            );
        }
    }

    specs
}

async fn drain_dummy_phone_like_profile_stream(
    mut stream: Stream,
    device: Address,
    service_name: String,
    uuid: Uuid,
) {
    let mut buf = [0u8; 256];
    match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            info!(
                "{} 🧲 bt-wireless-proxy phone-like SDP: {} ({}) from {} sent {} byte(s): {}",
                NAME,
                service_name,
                uuid,
                device,
                n,
                hex::encode(&buf[..n.min(64)])
            );
        }
        Ok(Ok(_)) => {
            info!(
                "{} 🧲 bt-wireless-proxy phone-like SDP: {} ({}) from {} closed without data",
                NAME, service_name, uuid, device
            );
        }
        Ok(Err(e)) => {
            warn!(
                "{} 🧲 bt-wireless-proxy phone-like SDP: {} ({}) read error from {}: {}",
                NAME, service_name, uuid, device, e
            );
        }
        Err(_) => {
            info!(
                "{} 🧲 bt-wireless-proxy phone-like SDP: {} ({}) from {} kept open for 2s without data; keeping it briefly then closing",
                NAME, service_name, uuid, device
            );
        }
    }

    // Do not immediately reset the profile connection. Some HUs connect just to verify
    // service availability after pairing; a short graceful hold gives us better logs and
    // avoids an instant failure signal. These dummy profiles intentionally do not implement
    // HFP/PBAP/MAP protocol semantics.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let _ = stream.shutdown().await;
    info!(
        "{} 🧲 bt-wireless-proxy phone-like SDP: closed dummy {} ({}) connection from {}",
        NAME, service_name, uuid, device
    );
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

async fn send_proxy_frame_raw<W: AsyncWrite + Unpin + ?Sized>(
    stream: &mut W,
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

async fn send_proxy_frame<W: AsyncWrite + Unpin + ?Sized>(
    stream: &mut W,
    direction: &'static str,
    message_id: ProxyMessageId,
    payload: &[u8],
) -> Result<()> {
    send_proxy_frame_raw(stream, direction, message_id as u16, payload).await
}

fn encode_proto_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push(((value as u8) & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn proto_int32_status_payload(field_number: u32, status: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    encode_proto_varint(((field_number as u64) << 3) | 0, &mut out);
    // proto2 int32 encodes negative values as sign-extended 64-bit varints.
    encode_proto_varint(status as i64 as u64, &mut out);
    out
}

fn wifi_connect_status_payload(status: i32) -> Vec<u8> {
    // WifiConnectStatus.status is field #1.
    proto_int32_status_payload(1, status)
}

fn wifi_start_response_status_payload(status: i32) -> Vec<u8> {
    // WifiStartResponse.status is field #3. Field #1 is ip_address, so using
    // a generic [08, 00] status payload here produces an invalid string field.
    proto_int32_status_payload(3, status)
}

fn now_millis_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn wifi_ping_request_payload(timestamp_ms: i64) -> Vec<u8> {
    // WifiPingRequest/PingRequest.timestamp is field #1, varint int64.
    let mut out = Vec::with_capacity(12);
    encode_proto_varint(0x08, &mut out);
    encode_proto_varint(timestamp_ms as u64, &mut out);
    out
}

struct TaskAbortGuard {
    name: &'static str,
    handle: Option<JoinHandle<()>>,
}

impl TaskAbortGuard {
    fn none(name: &'static str) -> Self {
        Self { name, handle: None }
    }

    fn new(name: &'static str, handle: JoinHandle<()>) -> Self {
        Self { name, handle: Some(handle) }
    }

    fn abort_now(&mut self) {
        if let Some(handle) = self.handle.take() {
            info!("{} 🧪 bt-wireless-proxy car-wifi-mitm: stopping {}", NAME, self.name);
            handle.abort();
        }
    }
}

impl Drop for TaskAbortGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

fn spawn_hu_wpp_keepalive<W>(
    hu_writer: Arc<Mutex<W>>,
    interval: Duration,
) -> TaskAbortGuard
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let interval = interval.max(Duration::from_millis(250));
    let handle = tokio::spawn(async move {
        let mut seq: u64 = 0;
        loop {
            tokio::time::sleep(interval).await;
            seq = seq.saturating_add(1);
            let ts = now_millis_i64();
            let payload = wifi_ping_request_payload(ts);
            let mut writer = hu_writer.lock().await;
            match send_proxy_frame(
                &mut *writer,
                "POC -> HU synthetic keepalive",
                ProxyMessageId::WifiPingRequest,
                &payload,
            )
            .await
            {
                Ok(()) => {
                    if seq == 1 || seq % 5 == 0 {
                        info!(
                            "{} 🧪 bt-wireless-proxy car-wifi-mitm: sent synthetic HU WifiPingRequest keepalive #{} timestamp={} interval={:?}",
                            NAME, seq, ts, interval
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "{} 🧪 bt-wireless-proxy car-wifi-mitm: synthetic HU WifiPingRequest keepalive failed after #{}: {}; stopping keepalive task",
                        NAME, seq, e
                    );
                    break;
                }
            }
        }
    });
    TaskAbortGuard::new("synthetic HU WPP keepalive", handle)
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

        if phone_id == ProxyMessageId::WifiPingResponse as u16 {
            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: PHONE sent WifiPingResponse while waiting for {}; treating it as keepalive and keeping state",
                NAME,
                ProxyMessageId::name(expected as u16)
            );
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

fn is_retriable_phone_bootstrap_disconnect(err: &str) -> bool {
    err.contains("Connection reset by peer")
        || err.contains("Software caused connection abort")
        || err.contains("Broken pipe")
        || err.contains("Transport endpoint is not connected")
        || err.contains("peer closed")
        || err.contains("unexpected end of file")
        || err.contains("early eof")
}

async fn reconnect_phone_aa_rfcomm_for_car_wifi_mitm(
    bluetooth: &mut Bluetooth,
    connect: BluetoothAddressList,
    options: &CarWifiMitmProxyOptions,
    attempt: u8,
    max_attempts: u8,
    previous_error: &str,
) -> Result<(Address, Stream)> {
    warn!(
        "{} 🧪 bt-wireless-proxy car-wifi-mitm: PHONE AA RFCOMM dropped during Wi-Fi bootstrap attempt {}/{} ({}); keeping HU RFCOMM/WPP alive and re-triggering phone AA RFCOMM",
        NAME,
        attempt,
        max_attempts,
        previous_error
    );

    // Give Android Auto/Gearhead a small breath before re-triggering. This is
    // intentionally shorter than the outer recovery path because the HU RFCOMM
    // socket is still alive and synthetic WPP keepalive is keeping MBUX from
    // timing out.
    tokio::time::sleep(Duration::from_millis(900)).await;

    let retry_timeout = options.bt_timeout.min(Duration::from_secs(45));
    let (addr, stream) = bluetooth
        .get_aa_profile_connection(connect, retry_timeout, options.stopped)
        .await?;
    info!(
        "{} 🧪 bt-wireless-proxy car-wifi-mitm: PHONE AA RFCOMM reconnected from {} for Wi-Fi bootstrap retry {}/{}",
        NAME,
        addr,
        attempt + 1,
        max_attempts
    );
    Ok((addr, stream))
}

async fn wait_for_phone_tcp_accept_barrier(
    notify: Arc<Notify>,
    seq: Arc<AtomicU64>,
    seq_before: u64,
    timeout_duration: Duration,
) -> Result<u64> {
    let start = Instant::now();
    loop {
        let current = seq.load(Ordering::Relaxed);
        if current > seq_before {
            return Ok(current);
        }

        let elapsed = start.elapsed();
        if elapsed >= timeout_duration {
            return Err(format!(
                "timed out after {:?} waiting for PHONE TCP accept barrier (seq_before={}, current={})",
                timeout_duration,
                seq_before,
                current
            )
            .into());
        }

        let remaining = timeout_duration - elapsed;
        match timeout(remaining, notify.notified()).await {
            Ok(()) => continue,
            Err(_) => {
                let current = seq.load(Ordering::Relaxed);
                return Err(format!(
                    "timed out after {:?} waiting for PHONE TCP accept barrier (seq_before={}, current={})",
                    timeout_duration,
                    seq_before,
                    current
                )
                .into());
            }
        }
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

fn merge_wifi_version_head_unit_info(dst: &mut WifiVersionRequestDebugInfo, src: WifiVersionRequestDebugInfo) {
    if dst.car_make.is_none() { dst.car_make = src.car_make; }
    if dst.car_model.is_none() { dst.car_model = src.car_model; }
    if dst.car_year.is_none() { dst.car_year = src.car_year; }
    if dst.vehicle_id.is_none() { dst.vehicle_id = src.vehicle_id; }
    if dst.head_unit_make.is_none() { dst.head_unit_make = src.head_unit_make; }
    if dst.head_unit_model.is_none() { dst.head_unit_model = src.head_unit_model; }
    if dst.head_unit_software_build.is_none() { dst.head_unit_software_build = src.head_unit_software_build; }
    if dst.head_unit_software_version.is_none() { dst.head_unit_software_version = src.head_unit_software_version; }
}

fn wifi_version_head_unit_info_looks_populated(info: &WifiVersionRequestDebugInfo) -> bool {
    info.car_make.is_some()
        || info.car_model.is_some()
        || info.car_year.is_some()
        || info.vehicle_id.is_some()
        || info.head_unit_make.is_some()
        || info.head_unit_model.is_some()
        || info.head_unit_software_build.is_some()
        || info.head_unit_software_version.is_some()
}

fn wifi_projection_info_looks_valid(info: &WifiProjectionProtocolDebugInfo) -> bool {
    let Some(ip) = info.ip_address.as_ref() else { return false; };
    if ip.parse::<IpAddr>().is_err() {
        return false;
    }
    info.port.unwrap_or(0) > 0
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
                    // MBUX traces carry a second channel/frequency-like varint at field #4
                    // (for example 5240/5765) before the HeadUnitInfo blob. Treat it as
                    // channel metadata for debug purposes instead of trying to parse it as
                    // the length-delimited HeadUnitInfo variant from other proto revisions.
                    4 => info.supported_wifi_channels.push(signed_from_proto_varint(value)),
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
                    5 => {
                        // There are at least two WifiVersionRequest revisions in the wild.
                        // The decompiled Gearhead proto uses field #5 for WifiProjectionProtocolInfo,
                        // but the MBUX HCI captures put HeadUnitInfo at field #5 and a varint
                        // channel/frequency at field #4. Parse field #5 defensively and only
                        // accept it as a projection endpoint when it actually contains a valid IP:port.
                        let projection = inspect_wifi_projection_protocol_info(data);
                        if wifi_projection_info_looks_valid(&projection) {
                            info.projection = projection;
                        } else {
                            let mut hu_info = WifiVersionRequestDebugInfo::default();
                            inspect_wifi_version_head_unit_info(data, &mut hu_info);
                            if wifi_version_head_unit_info_looks_populated(&hu_info) {
                                merge_wifi_version_head_unit_info(&mut info, hu_info);
                            } else {
                                info.projection = projection;
                            }
                        }
                    }
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
    mut initial_hu_frames: Vec<(u16, Vec<u8>)>,
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
    initial_hu_frames.reverse();
    if !initial_hu_frames.is_empty() {
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: pre-bootstrap has {} buffered HU frame(s) captured before phone arrived",
            NAME,
            initial_hu_frames.len()
        );
    }

    loop {
        let (hu_id, hu_payload) = if let Some(frame) = pending_hu_frame.take() {
            frame
        } else if let Some(frame) = initial_hu_frames.pop() {
            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: replaying buffered HU pre-bootstrap frame id={} ({}) len={} now that phone is connected",
                NAME,
                frame.0,
                ProxyMessageId::name(frame.0),
                frame.1.len()
            );
            frame
        } else {
            read_proxy_frame(hu_stream, "HU -> POC pre-bootstrap").await?
        };

        if hu_id == ProxyMessageId::WifiPingRequest as u16 {
            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: HU sent WifiPingRequest during pre-bootstrap; replying with WifiPingResponse and keeping state",
                NAME
            );
            send_proxy_frame(
                hu_stream,
                "POC -> HU pre-bootstrap",
                ProxyMessageId::WifiPingResponse,
                &hu_payload,
            )
            .await?;
            continue;
        }

        if hu_id == ProxyMessageId::WifiPingResponse as u16 {
            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: HU sent WifiPingResponse during pre-bootstrap; treating it as keepalive and keeping state",
                NAME
            );
            continue;
        }

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
            let (phone_id, phone_payload) = read_phone_bootstrap_frame(
                phone_stream,
                ProxyMessageId::WifiVersionResponse,
                None,
                Duration::from_secs(10),
            )
            .await?;

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

async fn current_iw_link_text(iface: &str) -> Option<String> {
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
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

async fn current_iw_ssid(iface: &str) -> Option<String> {
    let stdout = current_iw_link_text(iface).await?;
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(ssid) = line.strip_prefix("SSID:") {
            return Some(ssid.trim().to_string());
        }
    }
    None
}

async fn current_iw_connected(iface: &str) -> bool {
    current_iw_link_text(iface)
        .await
        .map(|stdout| stdout.lines().any(|line| line.trim_start().starts_with("Connected to ")))
        .unwrap_or(false)
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
    let iface = iface.trim();
    let ctrl_paths = [
        format!("/var/run/wpa_supplicant/{}", iface),
        format!("/run/wpa_supplicant/{}", iface),
    ];
    let start = Instant::now();
    while start.elapsed() < timeout_duration {
        for ctrl_path in &ctrl_paths {
            if tokio::fs::metadata(ctrl_path).await.is_ok() {
                return Ok(ctrl_path.clone());
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err(format!(
        "wpa_supplicant control socket did not appear at any of {:?} within {:?}",
        ctrl_paths, timeout_duration
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
        let _ = tokio::fs::remove_file(format!("/run/wpa_supplicant/{}", iface)).await;
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
    tokio::fs::write(&conf_path, wpa_supplicant_config(info_msg, false)).await?;

    info!(
        "{} 🧪 bt-wireless-proxy car-wifi-mitm: auto Wi-Fi join using wpactrl+wpa_supplicant iface={} ssid={} bssid={} key_len={}",
        NAME,
        iface,
        ssid,
        bssid,
        key.len()
    );

    let _ = tokio::fs::create_dir_all("/var/run/wpa_supplicant").await;
    let _ = tokio::fs::create_dir_all("/run/wpa_supplicant").await;
    let _ = run_shell_for_wifi(
        "stop old iface wpa_supplicant",
        &format!(
            "pidof wpa_supplicant >/dev/null 2>&1 && killall wpa_supplicant 2>/dev/null || true"
        ),
        5,
    )
    .await;
    let _ = tokio::fs::remove_file(format!("/var/run/wpa_supplicant/{}", iface)).await;
    let _ = tokio::fs::remove_file(format!("/run/wpa_supplicant/{}", iface)).await;

    start_wpa_supplicant_process(iface, &conf_path, Some("/var/run/wpa_supplicant"))
        .await
        .map_err(|e| format!("wpa_supplicant for wpactrl: {}", e))?;

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


async fn wait_for_iface_exists(iface: &str, wait: Duration) -> bool {
    let iface = iface.trim();
    if iface.is_empty() {
        return false;
    }
    let deadline = Instant::now() + wait;
    loop {
        if iface_exists(iface).await {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn push_unique_usb_wlan_candidate(out: &mut Vec<String>, iface: &str, exclude_iface: &str) {
    let iface = iface.trim();
    if iface.is_empty() || iface == exclude_iface || !iface.starts_with("wl") {
        return;
    }
    if !std::path::Path::new("/sys/class/net").join(iface).exists() {
        return;
    }
    if !out.iter().any(|existing| existing == iface) {
        out.push(iface.to_string());
    }
}

fn iface_device_path_looks_usb(iface: &str) -> bool {
    let path = std::path::Path::new("/sys/class/net").join(iface).join("device");
    match std::fs::canonicalize(path) {
        Ok(real) => real.to_string_lossy().contains("/usb"),
        Err(_) => false,
    }
}

async fn usb_wlan_ifaces(exclude_iface: &str) -> Vec<String> {
    let exclude_iface = exclude_iface.trim().to_string();
    let candidates = match tokio::task::spawn_blocking(move || {
        let mut out = Vec::<String>::new();

        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let iface = entry.file_name().to_string_lossy().trim().to_string();
                if iface_device_path_looks_usb(&iface) {
                    push_unique_usb_wlan_candidate(&mut out, &iface, &exclude_iface);
                }
            }
        }

        if let Ok(devices) = std::fs::read_dir("/sys/bus/usb/devices") {
            for dev in devices.flatten() {
                let net_dir = dev.path().join("net");
                let Ok(entries) = std::fs::read_dir(net_dir) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let iface = entry.file_name().to_string_lossy().trim().to_string();
                    push_unique_usb_wlan_candidate(&mut out, &iface, &exclude_iface);
                }
            }
        }

        out.sort();
        out
    })
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!(
                "{} 🧪 bt-wireless-proxy external_ap: failed to scan USB WLAN interfaces: {}",
                NAME, e
            );
            Vec::new()
        }
    };

    let mut stable = Vec::new();
    for iface in candidates {
        if wait_for_iface_exists(&iface, Duration::from_millis(600)).await {
            stable.push(iface);
        } else {
            warn!(
                "{} 🧪 bt-wireless-proxy external_ap: ignoring stale USB WLAN candidate {}; ip link cannot see it",
                NAME, iface
            );
        }
    }
    stable
}

async fn resolve_external_car_sta_iface(configured_sta_iface: &str, phone_ap_iface: &str) -> Result<String> {
    let configured_sta_iface = configured_sta_iface.trim();
    let phone_ap_iface = phone_ap_iface.trim();

    if !configured_sta_iface.is_empty() {
        if wait_for_iface_exists(configured_sta_iface, Duration::from_secs(8)).await {
            info!(
                "{} 🧪 bt-wireless-proxy external_ap: using configured car STA iface {}",
                NAME, configured_sta_iface
            );
            return Ok(configured_sta_iface.to_string());
        }
        return Err(format!(
            "external_ap configured car STA iface {} did not appear after module preload",
            configured_sta_iface
        )
        .into());
    }

    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let usb_ifaces = usb_wlan_ifaces(phone_ap_iface).await;
        if let Some(iface) = usb_ifaces.first() {
            info!(
                "{} 🧪 bt-wireless-proxy external_ap: auto-detected USB car STA iface {} (phone AP iface is {})",
                NAME, iface, phone_ap_iface
            );
            return Ok(iface.clone());
        }

        if phone_ap_iface != "wlan1" && wait_for_iface_exists("wlan1", Duration::from_millis(600)).await {
            info!(
                "{} 🧪 bt-wireless-proxy external_ap: using wlan1 fallback as car STA iface",
                NAME
            );
            return Ok("wlan1".to_string());
        }

        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    Err(format!(
        "external_ap could not find a stable USB/external Wi-Fi STA interface visible to ip link; set bt_wireless_proxy_car_wifi_sta_iface to the actual iface name, or check dongle/firmware/modprobe"
    )
    .into())
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

fn wpa_supplicant_config(
    info_msg: &WifiInfoResponse::WifiInfoResponse,
    include_bssid: bool,
) -> String {
    let ssid = info_msg.ssid();
    let key = info_msg.key();
    let bssid = info_msg.bssid().trim();
    let bssid_line = if include_bssid && !bssid.is_empty() {
        format!("    bssid={}\n", bssid)
    } else {
        String::new()
    };

    // Keep this file deliberately minimal. Some embedded/Android-derived
    // wpa_supplicant builds used by AA boxes reject otherwise-standard global
    // config keys such as `ctrl_interface=`, `update_config=` and `ap_scan=`
    // when they are provided from a generated file. The control socket, when
    // needed for wpactrl, is requested with the `-C` command-line option
    // instead of a config-file global.
    if key.is_empty() || info_msg.security_mode() == SecurityMode::OPEN {
        format!(
            "network={{\n    ssid={}\n{}    scan_ssid=1\n    key_mgmt=NONE\n}}\n",
            wpa_quote(ssid),
            bssid_line
        )
    } else {
        format!(
            "network={{\n    ssid={}\n{}    scan_ssid=1\n    key_mgmt=WPA-PSK\n    psk={}\n}}\n",
            wpa_quote(ssid),
            bssid_line,
            wpa_quote(key)
        )
    }
}

fn wpa_supplicant_parse_failure_text(stdout: &str, stderr: &str) -> bool {
    let combined = format!("{}\n{}", stdout, stderr).to_ascii_lowercase();
    combined.contains("failed to read or parse configuration")
        || combined.contains("invalid configuration line")
        || combined.contains("unknown global field")
}

async fn start_wpa_supplicant_process(
    iface: &str,
    conf_path: &str,
    ctrl_dir: Option<&str>,
) -> Result<()> {
    let mut cmd = Command::new("wpa_supplicant");
    cmd.args(["-B", "-i", iface, "-c", conf_path, "-D", "nl80211,wext"]);
    if let Some(ctrl_dir) = ctrl_dir {
        cmd.args(["-C", ctrl_dir]);
    }

    let output = timeout(Duration::from_secs(15), cmd.output()).await??;
    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let parse_hint = if wpa_supplicant_parse_failure_text(&stdout, &stderr) {
        " parse_failure=true"
    } else {
        ""
    };
    Err(format!(
        "wpa_supplicant failed status={}{} stdout={} stderr={}",
        output.status,
        parse_hint,
        stdout.trim(),
        stderr.trim()
    )
    .into())
}


async fn prepare_sta_iface_takeover(iface: &str) -> Result<String> {
    let iface = iface.trim();
    if iface.is_empty() {
        return Err("car Wi-Fi takeover needs a non-empty STA interface".into());
    }

    if !wait_for_iface_exists(iface, Duration::from_secs(3)).await {
        return Err(format!(
            "car Wi-Fi takeover STA iface {} is not visible to ip link; check actual USB Wi-Fi iface name with `ip link`/`iw dev` or set bt_wireless_proxy_car_wifi_sta_iface",
            iface
        )
        .into());
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

fn normalize_phy_name(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else if value.starts_with("phy") {
        Some(value.to_string())
    } else {
        Some(format!("phy{}", value))
    }
}

async fn phys_from_iw_dev() -> Vec<String> {
    let output = match timeout(Duration::from_secs(3), Command::new("iw").arg("dev").output()).await {
        Ok(Ok(output)) if output.status.success() => output,
        _ => return Vec::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut phys = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("phy#") {
            if let Some(id) = rest.split_whitespace().next() {
                if !id.is_empty() {
                    let phy = format!("phy{}", id);
                    if !phys.contains(&phy) {
                        phys.push(phy);
                    }
                }
            }
        }
    }
    phys
}

async fn sta_phy_candidates(ap_iface: &str, configured_phy: &str) -> Vec<String> {
    let mut candidates = Vec::new();

    // Prefer the currently visible phy for the phone-facing AP iface.  On some
    // Pi/BlueZ/driver combinations the wiphy number changes after a failed
    // virtual STA attempt, so a configured phy can become stale within the same
    // process lifetime.
    if let Some(auto_phy) = phy_for_iface(ap_iface).await {
        candidates.push(auto_phy);
    }

    if let Some(configured) = normalize_phy_name(configured_phy) {
        if !candidates.contains(&configured) {
            candidates.push(configured);
        }
    }

    for phy in phys_from_iw_dev().await {
        if !candidates.contains(&phy) {
            candidates.push(phy);
        }
    }

    candidates
}

async fn stop_wpa_supplicant_for_wifi(reason: &str) {
    let _ = run_shell_for_wifi(
        reason,
        "pidof wpa_supplicant >/dev/null 2>&1 && killall wpa_supplicant 2>/dev/null || true",
        5,
    )
    .await;
}

async fn prepare_sta_iface_keep_ap(
    sta_iface: &str,
    ap_iface: &str,
    sta_phy: &str,
    force_recreate: bool,
) -> Result<String> {
    let sta_iface = sta_iface.trim();
    if sta_iface.is_empty() {
        return Err("car Wi-Fi keep_ap mode needs bt_wireless_proxy_car_wifi_sta_iface".into());
    }
    if iface_exists(sta_iface).await && !force_recreate {
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

    let candidates = sta_phy_candidates(ap_iface, sta_phy).await;
    if candidates.is_empty() {
        return Err(format!(
            "car Wi-Fi keep_ap mode could not resolve a PHY from AP iface {}; set bt_wireless_proxy_car_wifi_sta_phy, e.g. phy1",
            ap_iface
        )
        .into());
    }

    let mut last_error = String::new();
    for (index, phy) in candidates.iter().enumerate() {
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: keep_ap mode; {} managed STA iface {} on {} while AP iface {} stays up (phy candidate {}/{})",
            NAME,
            if force_recreate { "recreating" } else { "creating" },
            sta_iface,
            phy,
            ap_iface,
            index + 1,
            candidates.len()
        );

        let _ = run_shell_for_wifi(
            "delete stale STA iface",
            &format!("iw dev {} del 2>/dev/null || true", shell_quote(sta_iface)),
            5,
        )
        .await;
        tokio::time::sleep(Duration::from_millis(400)).await;

        match run_shell_for_wifi(
            "create STA iface",
            &format!(
                "iw phy {} interface add {} type managed && ip link set {} up",
                shell_quote(phy),
                shell_quote(sta_iface),
                shell_quote(sta_iface)
            ),
            10,
        )
        .await
        {
            Ok(()) => {
                for attempt in 1..=5 {
                    if iface_exists(sta_iface).await {
                        info!(
                            "{} 🧪 bt-wireless-proxy car-wifi-mitm: verified managed STA iface {} exists on {} after create attempt",
                            NAME, sta_iface, phy
                        );
                        return Ok(sta_iface.to_string());
                    }
                    tokio::time::sleep(Duration::from_millis(200 * attempt)).await;
                }
                last_error = format!(
                    "created STA iface {} on {}, but the interface did not appear",
                    sta_iface, phy
                );
            }
            Err(e) => {
                last_error = format!("create STA iface on {} failed: {}", phy, e);
                warn!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: {}; trying next PHY candidate if available",
                    NAME, last_error
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(700)).await;
    }

    Err(format!(
        "car Wi-Fi keep_ap mode could not create STA iface {}; tried PHY candidates {:?}; last error: {}",
        sta_iface, candidates, last_error
    )
    .into())
}

async fn iface_mac_address(iface: &str) -> Option<String> {
    let path = format!("/sys/class/net/{}/address", iface.trim());
    tokio::fs::read_to_string(path).await.ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn wifi_channel_from_freq(freq_mhz: u32) -> Option<u32> {
    match freq_mhz {
        2412..=2472 => Some((freq_mhz - 2407) / 5),
        2484 => Some(14),
        5000..=5895 => Some((freq_mhz - 5000) / 5),
        5955..=7115 => Some(((freq_mhz - 5950) / 5) + 1),
        _ => None,
    }
}

fn parse_iw_channel_from_text(text: &str) -> Option<u32> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("freq:") {
            if let Ok(freq) = rest.trim().parse::<u32>() {
                if let Some(channel) = wifi_channel_from_freq(freq) {
                    return Some(channel);
                }
            }
        }
        if let Some(rest) = line.strip_prefix("channel ") {
            if let Some(first) = rest.split_whitespace().next() {
                if let Ok(channel) = first.parse::<u32>() {
                    return Some(channel);
                }
            }
        }
    }
    None
}

async fn current_iw_channel(iface: &str) -> Option<u32> {
    for args in [["dev", iface, "link"], ["dev", iface, "info"]] {
        let output = timeout(
            Duration::from_secs(3),
            Command::new("iw").args(args).output(),
        )
        .await
        .ok()?;
        let output = output.ok()?;
        if !output.status.success() {
            continue;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(channel) = parse_iw_channel_from_text(&stdout) {
            return Some(channel);
        }
    }
    None
}

async fn stop_phone_ap_for_proxy_ap(ap_iface: &str) {
    info!(
        "{} 🧪 bt-wireless-proxy proxy_ap: stopping phone-facing AP on {} only for active wireless bootstrap/channel switch",
        NAME, ap_iface
    );
    let _ = run_shell_for_wifi(
        "stop phone-facing AP helpers",
        "killall hostapd 2>/dev/null || true; killall dnsmasq 2>/dev/null || true",
        5,
    )
    .await;
    let _ = run_shell_for_wifi(
        "bring phone-facing AP iface down before STA join",
        &format!("ip link set {} down 2>/dev/null || true", shell_quote(ap_iface)),
        5,
    )
    .await;
    // brcmfmac can keep the previous AP role busy for a short moment after
    // hostapd exits.  Without this settle, creating ap0 next to wlan0 STA can
    // fail with `Device or resource busy (-16)` even though the manual command
    // sequence works.
    tokio::time::sleep(Duration::from_millis(500)).await;
}


async fn ensure_proxy_phone_ap_iface(ap_iface: &str, car_sta_iface: &str) -> Result<()> {
    let ap_iface = ap_iface.trim();
    let car_sta_iface = car_sta_iface.trim();
    if ap_iface.is_empty() {
        return Err("proxy_ap virtual AP creation needs a non-empty AP interface".into());
    }
    if iface_exists(ap_iface).await {
        info!(
            "{} 🧪 bt-wireless-proxy proxy_ap: phone AP iface {} already exists; reusing it",
            NAME, ap_iface
        );
        return Ok(());
    }
    if car_sta_iface.is_empty() {
        return Err(format!(
            "proxy_ap cannot create phone AP iface {} because car STA iface is empty",
            ap_iface
        )
        .into());
    }

    let candidates = sta_phy_candidates(car_sta_iface, "").await;
    if candidates.is_empty() {
        return Err(format!(
            "proxy_ap could not resolve PHY from car STA iface {} to create phone AP iface {}",
            car_sta_iface, ap_iface
        )
        .into());
    }

    let mut last_error = String::new();
    for (index, phy) in candidates.iter().enumerate() {
        info!(
            "{} 🧪 bt-wireless-proxy proxy_ap: creating phone AP iface {} on {} next to car STA iface {} (phy candidate {}/{})",
            NAME,
            ap_iface,
            phy,
            car_sta_iface,
            index + 1,
            candidates.len()
        );
        for create_attempt in 1..=3 {
            let _ = run_shell_for_wifi(
                "delete stale phone AP iface",
                &format!("iw dev {} del 2>/dev/null || true", shell_quote(ap_iface)),
                5,
            )
            .await;
            tokio::time::sleep(Duration::from_millis(300 * create_attempt)).await;

            match run_shell_for_wifi(
                "create phone AP iface",
                &format!(
                    "iw phy {phy} interface add {ap} type __ap && ip link set {ap} up",
                    phy = shell_quote(phy),
                    ap = shell_quote(ap_iface)
                ),
                10,
            )
            .await
            {
                Ok(()) => {
                    for attempt in 1..=5 {
                        if iface_exists(ap_iface).await {
                            info!(
                                "{} 🧪 bt-wireless-proxy proxy_ap: verified phone AP iface {} exists on {} after create attempt",
                                NAME, ap_iface, phy
                            );
                            return Ok(());
                        }
                        tokio::time::sleep(Duration::from_millis(200 * attempt)).await;
                    }
                    last_error = format!(
                        "created phone AP iface {} on {}, but the interface did not appear",
                        ap_iface, phy
                    );
                }
                Err(e) => {
                    last_error = format!(
                        "create phone AP iface {} on {} failed attempt {}/3: {}",
                        ap_iface, phy, create_attempt, e
                    );
                    warn!(
                        "{} 🧪 bt-wireless-proxy proxy_ap: {}; settling and retrying if possible",
                        NAME, last_error
                    );
                    tokio::time::sleep(Duration::from_millis(700 * create_attempt)).await;
                }
            }
        }
    }

    Err(format!(
        "proxy_ap could not create phone AP iface {}; tried PHY candidates {:?}; last error: {}",
        ap_iface, candidates, last_error
    )
    .into())
}

fn hostapd_hw_mode_for_channel(channel: u32) -> &'static str {
    if channel <= 14 { "g" } else { "a" }
}

async fn start_proxy_phone_ap(
    ap_iface: &str,
    ssid: &str,
    key: &str,
    ip: &str,
    channel: u32,
) -> Result<()> {
    let ap_iface = ap_iface.trim();
    if ap_iface.is_empty() {
        return Err("proxy_ap needs a non-empty AP interface".into());
    }
    let ssid = ssid.trim();
    if ssid.is_empty() {
        return Err("proxy_ap needs a non-empty phone AP SSID".into());
    }
    let key = key.trim();
    if !key.is_empty() && key.len() < 8 {
        return Err("proxy_ap phone AP WPA2 key must be empty/open or at least 8 characters".into());
    }
    let ip = if ip.trim().is_empty() { "10.0.0.1" } else { ip.trim() };

    let hostapd_conf = format!("/tmp/aa-proxy-phone-ap-{}.conf", ap_iface.replace('/', "_"));
    let mut conf = format!(
        "interface={iface}\ndriver=nl80211\nssid={ssid}\nhw_mode={hw_mode}\nchannel={channel}\nieee80211n=1\nwmm_enabled=1\nauth_algs=1\nignore_broadcast_ssid=0\n",
        iface = ap_iface,
        ssid = ssid,
        hw_mode = hostapd_hw_mode_for_channel(channel),
        channel = channel,
    );
    if key.is_empty() {
        conf.push_str("wpa=0\n");
    } else {
        conf.push_str(&format!(
            "wpa=2\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=CCMP\nrsn_pairwise=CCMP\nwpa_passphrase={}\n",
            key
        ));
    }
    tokio::fs::write(&hostapd_conf, conf).await?;

    let dnsmasq_conf = format!("/tmp/aa-proxy-phone-ap-{}-dnsmasq.conf", ap_iface.replace('/', "_"));
    let dhcp_range = if ip.starts_with("10.0.0.") {
        "10.0.0.50,10.0.0.150,255.255.255.0,12h".to_string()
    } else if let Some((prefix, _)) = ip.rsplit_once('.') {
        format!("{}.50,{}.150,255.255.255.0,12h", prefix, prefix)
    } else {
        "10.0.0.50,10.0.0.150,255.255.255.0,12h".to_string()
    };
    tokio::fs::write(
        &dnsmasq_conf,
        format!(
            "interface={}\nbind-interfaces\ndhcp-range={}\ndhcp-option=3,{}\ndhcp-option=6,{}\nlog-dhcp\n",
            ap_iface, dhcp_range, ip, ip
        ),
    )
    .await?;

    let cmd = format!(
        "killall hostapd 2>/dev/null || true; killall dnsmasq 2>/dev/null || true; ip link set {iface} down 2>/dev/null || true; ip addr flush dev {iface} 2>/dev/null || true; ip addr add {ip}/24 dev {iface}; ip link set {iface} up; hostapd -B {hostapd_conf}; dnsmasq -C {dnsmasq_conf}",
        iface = shell_quote(ap_iface),
        ip = shell_quote(ip),
        hostapd_conf = shell_quote(&hostapd_conf),
        dnsmasq_conf = shell_quote(&dnsmasq_conf),
    );
    info!(
        "{} 🧪 bt-wireless-proxy proxy_ap: starting phone AP iface={} ssid={} ip={} channel={}",
        NAME, ap_iface, ssid, ip, channel
    );
    run_shell_for_wifi("start proxy phone AP", &cmd, 20).await?;
    Ok(())
}

async fn iw_iface_type(iface: &str) -> Option<String> {
    let output = timeout(
        Duration::from_secs(3),
        Command::new("iw").args(["dev", iface.trim(), "info"]).output(),
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
        if let Some(kind) = line.strip_prefix("type ") {
            return Some(kind.trim().to_string());
        }
    }
    None
}

async fn wait_for_iface_type(iface: &str, expected: &str, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        if iw_iface_type(iface).await.as_deref() == Some(expected) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn start_external_phone_ap(
    ap_iface: &str,
    ssid: &str,
    key: &str,
    ip: &str,
    configured_channel: u8,
    fallback_channel: u32,
) -> Result<u32> {
    let ap_iface = ap_iface.trim();
    if ap_iface.is_empty() {
        return Err("external_ap needs a non-empty phone AP interface".into());
    }
    if !iface_exists(ap_iface).await {
        return Err(format!(
            "external_ap phone AP iface {} does not exist; set bt_wireless_proxy_car_wifi_base_iface or bt_wireless_proxy_car_wifi_ap_iface",
            ap_iface
        )
        .into());
    }

    let channel = if configured_channel > 0 {
        configured_channel as u32
    } else if let Some(channel) = current_iw_channel(ap_iface).await {
        channel
    } else if fallback_channel > 0 {
        fallback_channel
    } else {
        36
    };

    info!(
        "{} 🧪 bt-wireless-proxy external_ap: starting/refreshing phone AP iface={} ssid={} ip={} channel={} before handing Wi-Fi info to phone",
        NAME, ap_iface, ssid, ip, channel
    );
    start_proxy_phone_ap(ap_iface, ssid, key, ip, channel).await?;

    if !wait_for_iface_type(ap_iface, "AP", Duration::from_secs(5)).await {
        let actual = iw_iface_type(ap_iface).await.unwrap_or_else(|| "<unknown>".to_string());
        return Err(format!(
            "external_ap phone AP iface {} did not enter AP mode after hostapd start; current iw type is {}",
            ap_iface, actual
        )
        .into());
    }

    if iface_ipv4(ap_iface).await.as_deref() != Some(ip.trim()) {
        warn!(
            "{} 🧪 bt-wireless-proxy external_ap: phone AP iface {} did not report IPv4 {} after hostapd start; forcing address again",
            NAME, ap_iface, ip
        );
        run_shell_for_wifi(
            "repair external_ap phone AP IPv4",
            &format!(
                "ip addr add {ip}/24 dev {iface} 2>/dev/null || true; ip link set {iface} up",
                ip = shell_quote(ip.trim()),
                iface = shell_quote(ap_iface)
            ),
            5,
        )
        .await?;
    }

    Ok(channel)
}

fn build_proxy_phone_wifi_info(
    ssid: &str,
    key: &str,
    bssid: &str,
) -> Result<WifiInfoResponse::WifiInfoResponse> {
    let mut info = WifiInfoResponse::WifiInfoResponse::new();
    info.set_ssid(ssid.to_string());
    info.set_key(key.to_string());
    // protobuf for this generated message treats bssid as required even when
    // we do not want to pin the phone to a specific AP MAC.  Set it explicitly
    // to an empty string for now; we can fill it from the AP iface MAC later if
    // phones require stronger disambiguation.
    info.set_bssid(bssid.trim().to_string());
    if key.trim().is_empty() {
        info.set_security_mode(SecurityMode::OPEN);
    } else {
        info.set_security_mode(SecurityMode::WPA2_PERSONAL);
    }
    info.set_access_point_type(AccessPointType::STATIC);
    Ok(info)
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
    if !command_available("wpa_supplicant").await {
        return Err("wpa_supplicant auto join needs wpa_supplicant binary".into());
    }

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

    let conf_path = format!("/tmp/aa-proxy-car-wifi-{}.conf", iface.replace('/', "_"));
    tokio::fs::write(&conf_path, wpa_supplicant_config(info_msg, true)).await?;

    let first_start = start_wpa_supplicant_process(iface, &conf_path, None).await;
    if let Err(first_error) = first_start {
        let bssid = info_msg.bssid().trim();
        if bssid.is_empty() {
            return Err(format!("wpa_supplicant: {}", first_error).into());
        }

        warn!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: wpa_supplicant failed with bssid pinned ({}); retrying without bssid",
            NAME,
            first_error
        );
        let _ = run_shell_for_wifi(
            "stop failed bssid-pinned wpa_supplicant",
            "pidof wpa_supplicant >/dev/null 2>&1 && killall wpa_supplicant 2>/dev/null || true",
            5,
        )
        .await;

        let no_bssid_conf_path = format!(
            "/tmp/aa-proxy-car-wifi-{}-nobssid.conf",
            iface.replace('/', "_")
        );
        tokio::fs::write(&no_bssid_conf_path, wpa_supplicant_config(info_msg, false)).await?;
        start_wpa_supplicant_process(iface, &no_bssid_conf_path, None)
            .await
            .map_err(|second_error| {
                format!(
                    "wpa_supplicant failed with bssid pinned and without bssid; first={} second={}",
                    first_error, second_error
                )
            })?;
    }

    let ssid = info_msg.ssid().trim().to_string();
    let mut associated = false;
    for attempt in 1..=20 {
        if !iface_exists(iface).await {
            stop_wpa_supplicant_for_wifi("stop wpa_supplicant after iface disappeared during association wait").await;
            return Err(format!(
                "wpa_supplicant started but iface {} disappeared before association wait attempt {}",
                iface, attempt
            )
            .into());
        }
        let current_ssid = current_iw_ssid(iface).await;
        if ssid.is_empty() || current_ssid.as_deref() == Some(ssid.as_str()) {
            associated = true;
            break;
        }
        if current_iw_connected(iface).await {
            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: iface {} reports Connected in iw link but SSID parse was {:?}; proceeding to DHCP without waiting the full association timeout",
                NAME,
                iface,
                current_ssid
            );
            associated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    if !associated {
        warn!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: iface {} did not report association to ssid={} before DHCP; trying DHCP anyway",
            NAME, iface, ssid
        );
    }

    if !iface_exists(iface).await {
        stop_wpa_supplicant_for_wifi("stop wpa_supplicant after iface disappeared before DHCP").await;
        return Err(format!(
            "wpa_supplicant started but iface {} disappeared before DHCP",
            iface
        )
        .into());
    }
    let dhcp_ok = run_udhcpc_for_iface(iface, "after wpa_supplicant start", dhcp_timeout).await;
    if !dhcp_ok {
        if !iface_exists(iface).await {
            stop_wpa_supplicant_for_wifi("stop wpa_supplicant after iface disappeared during DHCP").await;
            return Err(format!(
                "iface {} disappeared while/after running DHCP",
                iface
            )
            .into());
        }
        return Err(format!("udhcpc did not return success on iface {}", iface).into());
    }

    Ok(())
}

async fn run_car_wifi_join(
    custom_template: &str,
    auto_join: bool,
    join_control: &str,
    base_iface: &str,
    keep_ap: bool,
    sta_iface: &str,
    sta_phy: &str,
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

    let mut join_iface = if keep_ap {
        // If an existing association was healthy, we returned above. At this point
        // stale virtual STA state from a previous failed bootstrap is more harmful
        // than useful, so recreate the STA interface before starting supplicant.
        prepare_sta_iface_keep_ap(requested_sta_iface, ap_iface, sta_phy, true).await?
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
                warn!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: wpactrl returned success but association/IPv4 was not observed; trying direct wpa_supplicant fallback",
                    NAME
                );
            }
            Err(e) => {
                warn!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: wpactrl failed: {}; trying direct wpa_supplicant fallback before aborting",
                    NAME, e
                );
                if keep_ap {
                    warn!(
                        "{} 🧪 bt-wireless-proxy car-wifi-mitm: recreating STA iface {} before direct wpa_supplicant fallback because wpactrl cleanup/driver may have dropped the virtual iface",
                        NAME, join_iface
                    );
                    stop_wpa_supplicant_for_wifi("stop stale wpa_supplicant before recreating STA iface for fallback").await;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    join_iface = prepare_sta_iface_keep_ap(&join_iface, ap_iface, sta_phy, true).await?;
                }
            }
        }

        if !iface_exists(&join_iface).await {
            return Err(format!(
                "car Wi-Fi join iface {} disappeared before direct wpa_supplicant fallback",
                join_iface
            ).into());
        }

        match run_wpa_supplicant_wifi_join(&join_iface, info_msg, dhcp_timeout).await {
            Ok(()) => {
                if wait_for_wifi_ready(&join_iface, ssid, wifi_association_timeout).await {
                    return Ok(join_iface);
                }
                return Err("wpactrl and direct wpa_supplicant fallback returned success but association/IPv4 was not observed".into());
            }
            Err(e) => return Err(format!("wpactrl fallback wpa_supplicant: {}", e).into()),
        }
    }

    if join_control == "wpa_supplicant" {
        let max_attempts = if keep_ap { 3 } else { 1 };
        let mut last_error = String::new();
        for attempt in 1..=max_attempts {
            if keep_ap && attempt > 1 {
                warn!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: recreating STA iface {} before wpa_supplicant retry {}/{}",
                    NAME, join_iface, attempt, max_attempts
                );
                stop_wpa_supplicant_for_wifi("stop stale wpa_supplicant before recreating STA iface for retry").await;
                tokio::time::sleep(Duration::from_secs(1)).await;
                match prepare_sta_iface_keep_ap(&join_iface, ap_iface, sta_phy, true).await {
                    Ok(iface) => join_iface = iface,
                    Err(e) => {
                        last_error = format!("prepare STA iface before retry failed: {}", e);
                        warn!(
                            "{} 🧪 bt-wireless-proxy car-wifi-mitm: wpa_supplicant join attempt {}/{} could not recreate STA iface: {}",
                            NAME, attempt, max_attempts, last_error
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                }
            }
            if !iface_exists(&join_iface).await {
                last_error = format!(
                    "car Wi-Fi join iface {} disappeared before wpa_supplicant start",
                    join_iface
                );
                continue;
            }
            match run_wpa_supplicant_wifi_join(&join_iface, info_msg, dhcp_timeout).await {
                Ok(()) => {
                    if wait_for_wifi_ready(&join_iface, ssid, wifi_association_timeout).await {
                        return Ok(join_iface);
                    }
                    last_error = "wpa_supplicant returned success but association/IPv4 was not observed".to_string();
                }
                Err(e) => {
                    last_error = format!("wpa_supplicant: {}", e);
                }
            }
            warn!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: wpa_supplicant join attempt {}/{} failed on iface {}: {}",
                NAME, attempt, max_attempts, join_iface, last_error
            );
        }
        return Err(last_error.into());
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


async fn install_ipv4_host_route(target_ip: &str, iface: &str, src_ip: &str) -> Result<()> {
    let target_ip = target_ip.trim();
    let iface = iface.trim();
    let src_ip = src_ip.trim();

    if target_ip.is_empty() || iface.is_empty() || src_ip.is_empty() {
        return Err(format!(
            "cannot install car-side host route with target_ip={:?} iface={:?} src_ip={:?}",
            target_ip, iface, src_ip
        )
        .into());
    }

    if !matches!(target_ip.parse::<IpAddr>(), Ok(IpAddr::V4(_))) {
        warn!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: HU endpoint {} is not IPv4; skipping explicit car-side route install",
            NAME, target_ip
        );
        return Ok(());
    }
    if !matches!(src_ip.parse::<IpAddr>(), Ok(IpAddr::V4(_))) {
        return Err(format!(
            "cannot install IPv4 car-side route to {} via {} because source {} is not IPv4",
            target_ip, iface, src_ip
        )
        .into());
    }

    info!(
        "{} 🧪 bt-wireless-proxy car-wifi-mitm: installing explicit car-side host route {} via {} src {}",
        NAME, target_ip, iface, src_ip
    );
    run_shell_for_wifi(
        "install car-side HU host route",
        &format!(
            "ip -4 route replace {target}/32 dev {iface} src {src}",
            target = shell_quote(target_ip),
            iface = shell_quote(iface),
            src = shell_quote(src_ip),
        ),
        5,
    )
    .await?;

    if let Ok(Ok(output)) = timeout(
        Duration::from_secs(3),
        Command::new("ip")
            .args(["-4", "route", "get", target_ip])
            .output(),
    )
    .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() {
            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: route to HU after install: {}",
                NAME,
                stdout.trim()
            );
        } else {
            warn!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: route check after install failed status={} stdout={} stderr={}",
                NAME,
                output.status,
                stdout.trim(),
                stderr.trim()
            );
        }
    }

    Ok(())
}

async fn repair_car_side_route_after_phone_ap(
    target_ip: &str,
    iface: &str,
    expected_ssid: &str,
    expected_src_ip: &str,
    dhcp_timeout: Duration,
) -> Result<String> {
    let iface = iface.trim();
    if iface.is_empty() {
        return Err("cannot repair car-side route: join iface is empty".into());
    }

    let current_ssid = current_iw_ssid(iface).await;
    let mut current_ip = iface_ipv4(iface).await;
    let associated = if expected_ssid.trim().is_empty() {
        current_ssid.is_some()
    } else {
        current_ssid.as_deref() == Some(expected_ssid.trim())
    };

    if !associated || current_ip.is_none() {
        warn!(
            "{} 🧪 bt-wireless-proxy proxy_ap: after starting phone AP, car STA {} is not fully ready (ssid={:?}, ip={:?}); waiting/re-DHCP before HU TCP connect",
            NAME,
            iface,
            current_ssid,
            current_ip
        );
        if current_ssid.is_some() && current_ip.is_none() {
            let _ = run_udhcpc_for_iface(iface, "proxy_ap phone AP start left car STA without IPv4", dhcp_timeout).await;
        }
        let _ = wait_for_wifi_ready(iface, expected_ssid, Duration::from_secs(5)).await;
        current_ip = iface_ipv4(iface).await;
    }

    let src_ip = current_ip.unwrap_or_else(|| expected_src_ip.trim().to_string());
    if src_ip.trim().is_empty() {
        return Err(format!(
            "proxy_ap car STA {} has no IPv4 after phone AP start; cannot route to HU {}",
            iface,
            target_ip.trim()
        )
        .into());
    }

    if !ipv4_likely_same_lan(&src_ip, target_ip.trim()) {
        return Err(format!(
            "proxy_ap car STA {} IPv4 {} does not look reachable for HU {}; refusing to continue",
            iface,
            src_ip,
            target_ip.trim()
        )
        .into());
    }

    install_ipv4_host_route(target_ip, iface, &src_ip).await?;
    Ok(src_ip)
}


async fn warm_car_side_route_for_hu(target_ip: &str, iface: &str) {
    let target_ip = target_ip.trim();
    let iface = iface.trim();
    if target_ip.is_empty() || iface.is_empty() {
        return;
    }

    // ICMP success is not required here.  The useful side effect is ARP/neighbor
    // resolution and giving the single-radio AP+STA state a moment to settle
    // before the real HU TCP connect.
    let cmd = format!(
        "ping -c 1 -W 1 -I {iface} {target} >/dev/null 2>&1 || true",
        iface = shell_quote(iface),
        target = shell_quote(target_ip),
    );
    let _ = run_shell_for_wifi("warm car-side HU route", &cmd, 2).await;
}

async fn log_car_side_route_state(target_ip: &str, iface: &str, context: &str) {
    let target_ip = target_ip.trim();
    let iface = iface.trim();
    if target_ip.is_empty() {
        return;
    }

    if let Ok(Ok(output)) = timeout(
        Duration::from_secs(2),
        Command::new("ip")
            .args(["-4", "route", "get", target_ip])
            .output(),
    )
    .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() {
            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: route to HU {}: {}",
                NAME,
                context,
                stdout.trim()
            );
        } else {
            warn!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: route to HU {} failed status={} stdout={} stderr={}",
                NAME,
                context,
                output.status,
                stdout.trim(),
                stderr.trim()
            );
        }
    }

    if !iface.is_empty() {
        let ssid = current_iw_ssid(iface).await;
        let ip = iface_ipv4(iface).await;
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: car-side iface state {} iface={} ssid={:?} ip={:?}",
            NAME,
            context,
            iface,
            ssid,
            ip
        );
    }
}

async fn connect_real_hu_tcp_with_route_retry(
    hu_tcp_addr: &str,
    hu_tcp_ip: &str,
    iface: &str,
    expected_ssid: &str,
    src_ip_hint: &str,
    dhcp_timeout: Duration,
) -> Result<TcpStream> {
    let mut last_error = String::new();
    let max_attempts = 5usize;

    for attempt in 1..=max_attempts {
        if attempt > 1 {
            let delay = Duration::from_millis(750 * attempt as u64);
            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: delaying {:?} before HU TCP retry {}/{}",
                NAME,
                delay,
                attempt,
                max_attempts
            );
            tokio::time::sleep(delay).await;
        }

        match repair_car_side_route_after_phone_ap(
            hu_tcp_ip,
            iface,
            expected_ssid,
            src_ip_hint,
            dhcp_timeout,
        )
        .await
        {
            Ok(src) => {
                debug!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: HU TCP attempt {}/{} route repaired via {} src {}",
                    NAME,
                    attempt,
                    max_attempts,
                    iface,
                    src
                );
            }
            Err(e) => {
                warn!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: HU TCP attempt {}/{} could not fully repair route before connect: {}",
                    NAME,
                    attempt,
                    max_attempts,
                    e
                );
            }
        }

        log_car_side_route_state(hu_tcp_ip, iface, "before HU TCP connect attempt").await;
        warm_car_side_route_for_hu(hu_tcp_ip, iface).await;

        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: connecting real HU TCP {} attempt {}/{}",
            NAME,
            hu_tcp_addr,
            attempt,
            max_attempts
        );
        match timeout(Duration::from_secs(5), TcpStream::connect(hu_tcp_addr)).await {
            Ok(Ok(stream)) => {
                info!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: real HU TCP {} connected on attempt {}/{}",
                    NAME,
                    hu_tcp_addr,
                    attempt,
                    max_attempts
                );
                return Ok(stream);
            }
            Ok(Err(e)) => {
                last_error = e.to_string();
                warn!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: real HU TCP {} connect attempt {}/{} failed: {}",
                    NAME,
                    hu_tcp_addr,
                    attempt,
                    max_attempts,
                    last_error
                );
            }
            Err(_) => {
                last_error = "timed out after 5s".to_string();
                warn!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: real HU TCP {} connect attempt {}/{} timed out after 5s",
                    NAME,
                    hu_tcp_addr,
                    attempt,
                    max_attempts
                );
            }
        }
    }

    log_car_side_route_state(hu_tcp_ip, iface, "after HU TCP connect retries failed").await;
    Err(format!(
        "real HU TCP {} failed after {} attempts; last error: {}",
        hu_tcp_addr,
        max_attempts,
        last_error
    )
    .into())
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
    hu_pairing_original_alias: Option<String>,
    hu_pairing_original_class: Option<String>,
    hu_pairing_class_iface: Option<String>,
    phone_like_sdp_profiles_registered: bool,
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
        hu_pairing_original_alias: None,
        hu_pairing_original_class: None,
        hu_pairing_class_iface: None,
        phone_like_sdp_profiles_registered: false,
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


async fn log_hu_device_snapshot(adapter: &Adapter, hu_addr: Address, context: &str) {
    match adapter.device(hu_addr) {
        Ok(device) => {
            let alias = device.alias().await.ok();
            let name = device.name().await.ok().flatten();
            let address_type = device.address_type().await.ok();
            let paired = device.is_paired().await.ok();
            let trusted = device.is_trusted().await.ok();
            let connected = device.is_connected().await.ok();
            let rssi = device.rssi().await.ok().flatten();
            let legacy_pairing = device.is_legacy_pairing().await.ok();
            let services_resolved = device.is_services_resolved().await.ok();
            info!(
                "{} 🧲 bt-wireless-proxy pairing: device snapshot [{}] addr={} alias={:?} name={:?} address_type={:?} paired={:?} trusted={:?} connected={:?} rssi={:?} legacy_pairing={:?} services_resolved={:?}",
                NAME,
                context,
                hu_addr,
                alias,
                name,
                address_type,
                paired,
                trusted,
                connected,
                rssi,
                legacy_pairing,
                services_resolved
            );
        }
        Err(e) => warn!(
            "{} 🧲 bt-wireless-proxy pairing: failed to open device snapshot [{}] for {}: {}",
            NAME, context, hu_addr, e
        ),
    }
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

    fn normalize_bt_class_value(value: &str) -> Option<String> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        let hex = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        if hex.is_empty() || hex.len() > 6 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let parsed = u32::from_str_radix(hex, 16).ok()? & 0x00ff_ffff;
        Some(format!("0x{:06x}", parsed))
    }

    async fn read_adapter_class_via_hciconfig(iface: &str) -> Option<String> {
        let output = Command::new("hciconfig")
            .arg(iface)
            .arg("class")
            .output()
            .await
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}\n{}", stdout, stderr);
        for token in combined.split(|c: char| c.is_whitespace() || c == ',') {
            let token = token.trim();
            if token.starts_with("0x") || token.starts_with("0X") {
                if let Some(normalized) = Self::normalize_bt_class_value(token) {
                    return Some(normalized);
                }
            }
        }
        None
    }

    async fn set_adapter_class_via_hciconfig(iface: &str, class_value: &str) -> Result<()> {
        let output = Command::new("hciconfig")
            .arg(iface)
            .arg("class")
            .arg(class_value)
            .output()
            .await?;
        if output.status.success() {
            Ok(())
        } else {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!(
                "hciconfig {} class {} failed status={:?} stdout={} stderr={}",
                iface,
                class_value,
                output.status.code(),
                stdout.trim(),
                stderr.trim()
            )
            .into())
        }
    }

    pub async fn register_phone_like_sdp_profiles(
        &mut self,
        enabled: bool,
        profile_set: &str,
    ) -> Result<()> {
        if !enabled {
            info!(
                "{} 🧲 bt-wireless-proxy phone-like SDP: disabled; AA Wireless UUID {} remains registered={} for phone-side AA connection",
                NAME,
                AAWG_PROFILE_UUID,
                self.handle_aa.is_some()
            );
            return Ok(());
        }

        if self.phone_like_sdp_profiles_registered {
            info!(
                "{} 🧲 bt-wireless-proxy phone-like SDP: already registered; not registering duplicates. AA Wireless UUID {} remains registered={}",
                NAME,
                AAWG_PROFILE_UUID,
                self.handle_aa.is_some()
            );
            return Ok(());
        }

        let specs = phone_like_sdp_profile_specs(profile_set);
        info!(
            "{} 🧲 bt-wireless-proxy phone-like SDP: registering {} dummy phone-like SDP profile(s), set={:?}; AA Wireless UUID {} remains registered={} and will NOT be removed",
            NAME,
            specs.len(),
            profile_set,
            AAWG_PROFILE_UUID,
            self.handle_aa.is_some()
        );
        info!(
            "{} 🧲 bt-wireless-proxy phone-like SDP: dummy profiles only advertise phone capabilities for HU classification; they do not implement HFP/PBAP/MAP semantics",
            NAME
        );

        let mut registered = 0usize;
        for spec in specs {
            let profile = Profile {
                uuid: spec.uuid,
                name: Some(spec.name.to_string()),
                role: Some(Role::Server),
                require_authentication: Some(false),
                require_authorization: Some(false),
                ..Default::default()
            };

            match self.session.register_profile(profile).await {
                Ok(mut handle) => {
                    registered += 1;
                    info!(
                        "{} 🧲 bt-wireless-proxy phone-like SDP: registered dummy profile tag={} name={:?} uuid={} channel=auto",
                        NAME, spec.tag, spec.name, spec.uuid
                    );

                    let service_name = spec.name.to_string();
                    let service_tag = spec.tag.to_string();
                    let uuid = spec.uuid;
                    tokio::spawn(async move {
                        while let Some(req) = handle.next().await {
                            let device = req.device().clone();
                            info!(
                                "{} 🧲 bt-wireless-proxy phone-like SDP: incoming dummy profile connection tag={} name={:?} uuid={} from {}",
                                NAME, service_tag, service_name, uuid, device
                            );
                            match req.accept() {
                                Ok(stream) => {
                                    info!(
                                        "{} 🧲 bt-wireless-proxy phone-like SDP: accepted dummy profile tag={} uuid={} from {}; will log first bytes and close gracefully",
                                        NAME, service_tag, uuid, device
                                    );
                                    tokio::spawn(drain_dummy_phone_like_profile_stream(
                                        stream,
                                        device,
                                        service_name.clone(),
                                        uuid,
                                    ));
                                }
                                Err(e) => {
                                    warn!(
                                        "{} 🧲 bt-wireless-proxy phone-like SDP: accept failed for dummy profile tag={} uuid={} from {}: {}",
                                        NAME, service_tag, uuid, device, e
                                    );
                                }
                            }
                        }
                        warn!(
                            "{} 🧲 bt-wireless-proxy phone-like SDP: dummy profile accept loop ended tag={} uuid={}",
                            NAME, service_tag, uuid
                        );
                    });
                }
                Err(e) => {
                    warn!(
                        "{} 🧲 bt-wireless-proxy phone-like SDP: failed to register dummy profile tag={} name={:?} uuid={}: {}",
                        NAME, spec.tag, spec.name, spec.uuid, e
                    );
                }
            }
        }

        self.phone_like_sdp_profiles_registered = registered > 0;
        if registered == 0 {
            warn!(
                "{} 🧲 bt-wireless-proxy phone-like SDP: no dummy phone-like profiles were registered; MBUX may continue to classify aa-proxy as non-AA/non-phone",
                NAME
            );
        } else {
            info!(
                "{} 🧲 bt-wireless-proxy phone-like SDP: registered {} dummy profile(s); compare bluetoothctl info UUID list against OPPO/Xiaomi/AAWireless dongle",
                NAME, registered
            );
        }

        Ok(())
    }

    async fn apply_phone_like_hu_pairing_identity(
        &mut self,
        enabled: bool,
        requested_alias: &str,
        requested_class: &str,
    ) {
        if !enabled {
            info!(
                "{} 🧲 bt-wireless-proxy pairing: temporary phone-like pairing identity is disabled",
                NAME
            );
            return;
        }

        let alias = requested_alias.trim();
        let alias = if alias.is_empty() { "AndroidAuto" } else { alias };
        let class_value = match Self::normalize_bt_class_value(requested_class) {
            Some(value) => value,
            None => {
                warn!(
                    "{} 🧲 bt-wireless-proxy pairing: invalid bt_wireless_proxy_phone_like_pairing_class={:?}; using default phone/smartphone class 0x00020c",
                    NAME, requested_class
                );
                "0x00020c".to_string()
            }
        };
        let iface = self.adapter.name().to_string();

        self.hu_pairing_original_alias = Some(self.adapter_alias.clone());
        self.hu_pairing_class_iface = Some(iface.clone());
        self.hu_pairing_original_class = Self::read_adapter_class_via_hciconfig(&iface).await;

        info!(
            "{} 🧲 bt-wireless-proxy pairing: enabling temporary phone-like identity for HU pairing: alias={:?} class={} iface={} original_alias={:?} original_class={:?}",
            NAME,
            alias,
            class_value,
            iface,
            self.hu_pairing_original_alias,
            self.hu_pairing_original_class
        );

        match self.adapter.set_alias(alias.to_string()).await {
            Ok(()) => info!(
                "{} 🧲 bt-wireless-proxy pairing: temporary adapter alias set to {:?}",
                NAME, alias
            ),
            Err(e) => warn!(
                "{} 🧲 bt-wireless-proxy pairing: failed to set temporary adapter alias {:?}: {}",
                NAME, alias, e
            ),
        }

        match Self::set_adapter_class_via_hciconfig(&iface, &class_value).await {
            Ok(()) => info!(
                "{} 🧲 bt-wireless-proxy pairing: temporary Bluetooth Class of Device set to {} on {}",
                NAME, class_value, iface
            ),
            Err(e) => warn!(
                "{} 🧲 bt-wireless-proxy pairing: failed to set temporary Bluetooth Class of Device {} on {}: {}; continuing with alias/pairable/discoverable only",
                NAME, class_value, iface, e
            ),
        }
    }

    async fn restore_phone_like_hu_pairing_identity(&mut self) {
        if let Some(alias) = self.hu_pairing_original_alias.take() {
            match self.adapter.set_alias(alias.clone()).await {
                Ok(()) => info!(
                    "{} 🧲 bt-wireless-proxy pairing: restored adapter alias to {:?}",
                    NAME, alias
                ),
                Err(e) => warn!(
                    "{} 🧲 bt-wireless-proxy pairing: failed to restore adapter alias {:?}: {}",
                    NAME, alias, e
                ),
            }
        }

        let iface = self.hu_pairing_class_iface.take();
        let class_value = self.hu_pairing_original_class.take();
        if let (Some(iface), Some(class_value)) = (iface, class_value) {
            match Self::set_adapter_class_via_hciconfig(&iface, &class_value).await {
                Ok(()) => info!(
                    "{} 🧲 bt-wireless-proxy pairing: restored Bluetooth Class of Device to {} on {}",
                    NAME, class_value, iface
                ),
                Err(e) => warn!(
                    "{} 🧲 bt-wireless-proxy pairing: failed to restore Bluetooth Class of Device {} on {}: {}",
                    NAME, class_value, iface, e
                ),
            }
        }
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
        self.restore_phone_like_hu_pairing_identity().await;

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
        phone_like_pairing: bool,
        phone_like_pairing_alias: &str,
        phone_like_pairing_class: &str,
    ) -> Result<()> {
        let hu_mac = hu_mac.trim();
        if hu_mac.is_empty() {
            info!(
                "{} 🧲 bt-wireless-proxy pairing: configured HU MAC is empty; skipping HU pairing preflight",
                NAME
            );
            return Ok(());
        }

        let hu_addr: Address = hu_mac.parse()?;
        log_hu_device_snapshot(&self.adapter, hu_addr, "preflight-before-check").await;

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
            Err(e) => {
                info!(
                    "{} 🧲 bt-wireless-proxy pairing: HU {} is not known to BlueZ yet or cannot be opened: {}",
                    NAME, hu_addr, e
                );
                false
            }
        };

        if already_ready {
            info!(
                "{} 🧲 bt-wireless-proxy pairing: HU {} is already paired and trusted; skipping pairing window",
                NAME, hu_addr
            );
            return Ok(());
        }

        let window_secs = pairing_window_secs.max(10) as u32;
        self.apply_phone_like_hu_pairing_identity(
            phone_like_pairing,
            phone_like_pairing_alias,
            phone_like_pairing_class,
        )
        .await;
        if let Err(e) = self.register_hu_pairing_agent(hu_addr).await {
            self.cleanup_hu_pairing_window().await;
            return Err(e);
        }
        if let Err(e) = self
            .set_adapter_pairable_discoverable(true, true, window_secs)
            .await
        {
            self.cleanup_hu_pairing_window().await;
            return Err(e);
        }
        info!(
            "{} 🧲 bt-wireless-proxy pairing: HU {} is not paired/trusted; starting active+passive pairing window for {}s before USB/phone flow",
            NAME, hu_addr, window_secs
        );
        info!(
            "{} 🧲 bt-wireless-proxy pairing: passive mode is open: aa-proxy is pairable/discoverable and will accept pairing callbacks for the configured HU",
            NAME
        );
        info!(
            "{} 🧲 bt-wireless-proxy pairing: active mode will scan for configured HU {} and call Pair() when it is discovered",
            NAME, hu_addr
        );

        let mut discovery: Option<Pin<Box<dyn FuturesStream<Item = AdapterEvent> + Send>>> = match self.adapter.discover_devices_with_changes().await {
            Ok(stream) => {
                info!(
                    "{} 🧲 bt-wireless-proxy pairing: BlueZ discovery started for configured HU {}; known devices will be reported first",
                    NAME, hu_addr
                );
                Some(Box::pin(stream))
            }
            Err(e) => {
                warn!(
                    "{} 🧲 bt-wireless-proxy pairing: failed to start BlueZ discovery for HU {}; passive inbound pairing only for this window: {}",
                    NAME, hu_addr, e
                );
                None
            }
        };

        let mut discovery_done = discovery.is_none();
        let mut active_pair_attempts: u32 = 0;
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
                    log_hu_device_snapshot(&self.adapter, hu_addr, "paired-ready").await;
                    self.cleanup_hu_pairing_window().await;
                    return Ok(());
                }
            }

            if started.elapsed() >= Duration::from_secs(window_secs as u64) {
                log_hu_device_snapshot(&self.adapter, hu_addr, "timeout-final-state").await;
                self.cleanup_hu_pairing_window().await;
                return Err(format!(
                    "timed out waiting {}s for HU {} pairing; on HUs like MBUX open the car's add-phone screen and keep bt_wireless_proxy_hu_mac set to the HU Bluetooth MAC, not Wi-Fi BSSID",
                    window_secs, hu_addr
                )
                .into());
            }

            if discovery_done {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }

            let remaining_secs = window_secs
                .saturating_sub(started.elapsed().as_secs() as u32)
                .max(1);

            let next_event = {
                let Some(discovery_stream) = discovery.as_mut() else {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                };
                timeout(Duration::from_secs(1), discovery_stream.next()).await
            };

            match next_event {
                Ok(Some(AdapterEvent::DeviceAdded(addr))) => {
                    if addr == hu_addr {
                        active_pair_attempts += 1;
                        info!(
                            "{} 🧲 bt-wireless-proxy pairing: discovered configured HU {} during active scan; active_pair_attempt={} remaining={}s",
                            NAME, hu_addr, active_pair_attempts, remaining_secs
                        );
                        log_hu_device_snapshot(&self.adapter, hu_addr, "discovered-target-before-pair").await;

                        match self.adapter.device(hu_addr) {
                            Ok(device) => {
                                let paired = device.is_paired().await.unwrap_or(false);
                                if paired {
                                    info!(
                                        "{} 🧲 bt-wireless-proxy pairing: discovered HU {} is already paired; trusting and finishing",
                                        NAME, hu_addr
                                    );
                                    let _ = device.set_trusted(true).await;
                                    log_hu_device_snapshot(&self.adapter, hu_addr, "discovered-already-paired").await;
                                    self.cleanup_hu_pairing_window().await;
                                    return Ok(());
                                }

                                let pair_timeout_secs = remaining_secs.min(45).max(5);
                                info!(
                                    "{} 🧲 bt-wireless-proxy pairing: initiating BlueZ Pair() to configured HU {} with {}s timeout",
                                    NAME, hu_addr, pair_timeout_secs
                                );
                                let pair_started = Instant::now();
                                match timeout(Duration::from_secs(pair_timeout_secs as u64), device.pair()).await {
                                    Ok(Ok(())) => {
                                        info!(
                                            "{} 🧲 bt-wireless-proxy pairing: Pair() to HU {} succeeded in {} ms",
                                            NAME,
                                            hu_addr,
                                            pair_started.elapsed().as_millis()
                                        );
                                    }
                                    Ok(Err(e)) => {
                                        warn!(
                                            "{} 🧲 bt-wireless-proxy pairing: Pair() to HU {} failed after {} ms: {}; continuing active/passive window",
                                            NAME,
                                            hu_addr,
                                            pair_started.elapsed().as_millis(),
                                            e
                                        );
                                    }
                                    Err(_) => {
                                        warn!(
                                            "{} 🧲 bt-wireless-proxy pairing: Pair() to HU {} timed out after {}s; continuing active/passive window",
                                            NAME, hu_addr, pair_timeout_secs
                                        );
                                    }
                                }

                                log_hu_device_snapshot(&self.adapter, hu_addr, "after-pair-attempt").await;
                                if device.is_paired().await.unwrap_or(false) {
                                    match device.set_trusted(true).await {
                                        Ok(()) => info!(
                                            "{} 🧲 bt-wireless-proxy pairing: HU {} paired and trusted after active Pair()",
                                            NAME, hu_addr
                                        ),
                                        Err(e) => warn!(
                                            "{} 🧲 bt-wireless-proxy pairing: HU {} paired after active Pair() but trust failed: {}",
                                            NAME, hu_addr, e
                                        ),
                                    }
                                    self.cleanup_hu_pairing_window().await;
                                    return Ok(());
                                }
                            }
                            Err(e) => warn!(
                                "{} 🧲 bt-wireless-proxy pairing: discovered target HU {} but failed to open BlueZ device object: {}",
                                NAME, hu_addr, e
                            ),
                        }
                    } else if active_pair_attempts == 0 {
                        // Keep non-target logs sparse but useful. Once we have started trying the target,
                        // avoid flooding the console with every background device in the car/garage.
                        if let Ok(device) = self.adapter.device(addr) {
                            let alias = device.alias().await.ok();
                            let name = device.name().await.ok().flatten();
                            let paired = device.is_paired().await.ok();
                            let rssi = device.rssi().await.ok().flatten();
                            info!(
                                "{} 🧲 bt-wireless-proxy pairing: discovered non-target device addr={} alias={:?} name={:?} paired={:?} rssi={:?}; waiting for configured HU {}",
                                NAME, addr, alias, name, paired, rssi, hu_addr
                            );
                        }
                    }
                }
                Ok(Some(AdapterEvent::DeviceRemoved(addr))) => {
                    if addr == hu_addr {
                        warn!(
                            "{} 🧲 bt-wireless-proxy pairing: configured HU {} was removed during discovery window",
                            NAME, hu_addr
                        );
                    }
                }
                Ok(Some(AdapterEvent::PropertyChanged(prop))) => {
                    info!(
                        "{} 🧲 bt-wireless-proxy pairing: adapter discovery property changed while waiting for HU {}: {:?}",
                        NAME, hu_addr, prop
                    );
                }
                Ok(None) => {
                    warn!(
                        "{} 🧲 bt-wireless-proxy pairing: BlueZ discovery stream ended while waiting for HU {}; passive inbound pairing remains active until timeout",
                        NAME, hu_addr
                    );
                    discovery_done = true;
                    discovery = None;
                }
                Err(_) => {
                    // 1s tick: no discovery event. Passive pairing may still complete through the agent.
                }
            }
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

    async fn trigger_phone_aa_connection(
        &mut self,
        connect: BluetoothAddressList,
        stopped: bool,
    ) -> Result<()> {
        // Try to nudge the phone into opening the AA Wireless RFCOMM profile. This is
        // intentionally the same pre-accept behavior used by the normal phone-first path;
        // HU-first rendezvous calls it after the HU socket is ready.
        if let Some(addresses_to_connect) = connect.0 {
            if !stopped {
                let adapter_cloned = self.adapter.clone();

                let addresses: Vec<Address> = if addresses_to_connect
                    .iter()
                    .any(|addr| *addr == Address::any())
                {
                    let known = load_known_devices();
                    if !known.is_empty() {
                        info!("{} 🥏 Using {} known-good device(s)...", NAME, known.len());
                    } else {
                        info!("{} 🥏 No known-good devices, passively waiting for incoming phone connection...", NAME);
                    }
                    known
                } else {
                    addresses_to_connect
                };

                if !addresses.is_empty() {
                    info!("{} 🧲 Attempting to start an AndroidAuto phone session via bluetooth with the following devices, in this order: {:?}", NAME, addresses);
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
                            .retry(retry_policy)
                            .sleep(tokio::time::sleep)
                            .notify(
                                |err: &Box<dyn std::error::Error + Send + Sync + 'static>,
                                 dur: Duration| {
                                    debug!(
                                        "{} Retrying phone connect trigger due to error: {:?} after {:?}",
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

        Ok(())
    }

    async fn wait_for_phone_aa_profile_request(
        &mut self,
        bt_timeout: Duration,
        reason: &str,
        reject_addr: Option<Address>,
    ) -> Result<(Address, Stream)> {
        let handle_aa = self
            .handle_aa
            .as_mut()
            .ok_or("AA Wireless local server profile is not registered in this mode")?;

        let start = Instant::now();
        info!(
            "{} 🧪 bt-wireless-proxy: waiting up to {:?} for PHONE AA Wireless RFCOMM ({})",
            NAME,
            bt_timeout,
            reason
        );

        loop {
            let elapsed = start.elapsed();
            if elapsed >= bt_timeout {
                return Err(format!(
                    "timed out after {:?} waiting for PHONE AA Wireless RFCOMM ({})",
                    bt_timeout, reason
                )
                .into());
            }
            let remaining = bt_timeout - elapsed;

            let req = timeout(remaining, handle_aa.next())
                .await
                .map_err(|_| format!(
                    "timed out after {:?} waiting for PHONE AA Wireless RFCOMM ({})",
                    bt_timeout, reason
                ))?
                .ok_or("AA Wireless local server profile ended while waiting for PHONE AA RFCOMM")?;
            let addr = req.device().clone();
            info!(
                "{} 📱 AA Wireless Profile: inbound RFCOMM from <b>{}</> while {}",
                NAME,
                addr,
                reason
            );

            if reject_addr == Some(addr) {
                warn!(
                    "{} 🧪 bt-wireless-proxy: inbound AA Wireless RFCOMM came from HU {}; accepting and dropping it while waiting for phone ({})",
                    NAME,
                    addr,
                    reason
                );
                match req.accept() {
                    Ok(mut duplicate) => {
                        let _ = duplicate.shutdown().await;
                    }
                    Err(e) => warn!(
                        "{} 🧪 bt-wireless-proxy: failed to accept/drop duplicate HU AA RFCOMM from {} while {}: {}",
                        NAME,
                        addr,
                        reason,
                        e
                    ),
                }
                continue;
            }

            let stream = req.accept()?;
            info!(
                "{} 🧪 bt-wireless-proxy: accepted PHONE AA Wireless RFCOMM from {} ({})",
                NAME,
                addr,
                reason
            );
            return Ok((addr, stream));
        }
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

        self.wait_for_phone_aa_profile_request(
            bt_timeout,
            "after phone BT trigger",
            None,
        )
        .await
    }

    async fn wait_for_phone_aa_profile_while_buffering_hu(
        &mut self,
        hu_addr: Address,
        hu_stream: &mut Stream,
        wait_timeout: Duration,
    ) -> Result<(Address, Stream, Vec<(u16, Vec<u8>)>)> {
        let handle_aa = self
            .handle_aa
            .as_mut()
            .ok_or("AA Wireless local server profile is not registered in this mode")?;

        let start = Instant::now();
        let mut buffered_hu_frames: Vec<(u16, Vec<u8>)> = Vec::new();
        info!(
            "{} 🧪 bt-wireless-proxy rendezvous: HU socket is ready; waiting up to {:?} for phone AA RFCOMM while buffering HU pre-bootstrap frames",
            NAME, wait_timeout
        );

        loop {
            let elapsed = start.elapsed();
            if elapsed >= wait_timeout {
                return Err(format!(
                    "timed out after {:?} waiting for phone AA RFCOMM after HU-first connect; buffered {} HU frame(s)",
                    wait_timeout,
                    buffered_hu_frames.len()
                )
                .into());
            }
            let remaining = wait_timeout - elapsed;

            tokio::select! {
                req = handle_aa.next() => {
                    let req = req.ok_or("AA Wireless local server profile ended while waiting for phone")?;
                    let addr = req.device().clone();
                    info!(
                        "{} 🧪 bt-wireless-proxy rendezvous: incoming local AA Wireless RFCOMM from {} while HU-first wait is active",
                        NAME, addr
                    );

                    if addr == hu_addr {
                        warn!(
                            "{} 🧪 bt-wireless-proxy rendezvous: incoming AA Wireless RFCOMM is from configured HU {}; outbound HU socket is already open, accepting and dropping duplicate HU-side connection",
                            NAME, addr
                        );
                        match req.accept() {
                            Ok(mut duplicate) => {
                                let _ = duplicate.shutdown().await;
                            }
                            Err(e) => warn!(
                                "{} 🧪 bt-wireless-proxy rendezvous: failed to accept duplicate HU AA RFCOMM from {}: {}",
                                NAME, addr, e
                            ),
                        }
                        continue;
                    }

                    let stream = req.accept()?;
                    info!(
                        "{} 🧪 bt-wireless-proxy rendezvous: accepted PHONE AA RFCOMM from {}; buffered {} HU frame(s) will be replayed",
                        NAME,
                        addr,
                        buffered_hu_frames.len()
                    );
                    return Ok((addr, stream, buffered_hu_frames));
                }
                hu_frame = read_proxy_frame(hu_stream, "HU -> POC buffered-before-phone") => {
                    match hu_frame {
                        Ok((hu_id, hu_payload)) => {
                            if hu_id == ProxyMessageId::WifiPingRequest as u16 {
                                info!(
                                    "{} 🧪 bt-wireless-proxy rendezvous: HU sent WifiPingRequest before phone arrived; replying with WifiPingResponse and continuing to wait",
                                    NAME
                                );
                                send_proxy_frame(
                                    hu_stream,
                                    "POC -> HU buffered-before-phone",
                                    ProxyMessageId::WifiPingResponse,
                                    &hu_payload,
                                )
                                .await?;
                                continue;
                            }
                            if hu_id == ProxyMessageId::WifiPingResponse as u16 {
                                info!(
                                    "{} 🧪 bt-wireless-proxy rendezvous: HU sent WifiPingResponse before phone arrived; treating it as keepalive and continuing to wait",
                                    NAME
                                );
                                continue;
                            }

                            info!(
                                "{} 🧪 bt-wireless-proxy rendezvous: buffering HU frame id={} ({}) len={} until phone arrives",
                                NAME,
                                hu_id,
                                ProxyMessageId::name(hu_id),
                                hu_payload.len()
                            );
                            buffered_hu_frames.push((hu_id, hu_payload));
                            if buffered_hu_frames.len() > 32 {
                                return Err("too many HU frames buffered before phone arrived in HU-first rendezvous".into());
                            }
                        }
                        Err(e) => {
                            return Err(format!(
                                "HU RFCOMM ended while waiting for phone in HU-first rendezvous after buffering {} frame(s): {}",
                                buffered_hu_frames.len(),
                                e
                            ).into());
                        }
                    }
                }
                _ = tokio::time::sleep(remaining) => {
                    return Err(format!(
                        "timed out after {:?} waiting for phone AA RFCOMM after HU-first connect; buffered {} HU frame(s)",
                        wait_timeout,
                        buffered_hu_frames.len()
                    )
                    .into());
                }
            }
        }
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
                                // Keep the classic BT trigger behavior identical to the normal
                                // aa_handshake path: accept and immediately drop the HSP control
                                // RFCOMM stream. Holding this stream without a real HSP/HFP AT state
                                // machine can leave Android stuck at "Android Auto is starting" and
                                // it did not make the PHONE AA Wireless RFCOMM arrive in car-wifi-mitm
                                // tests. The AA Wireless profile itself is polled separately.
                                if bt_sco {
                                    info!(
                                        "{} 🎧 Headset Profile (HSP): accepted from <b>{}</>, dropping control stream in SCO mode",
                                        NAME, device
                                    );
                                } else {
                                    info!(
                                        "{} 🎧 Headset Profile (HSP): accepted from <b>{}</>, dropping trigger control stream immediately to mirror normal AA handshake behavior",
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
            tokio::time::sleep(Duration::from_millis(300)).await;
            info!("{} 🎧 Headset Profile (HSP): unregistered", NAME);
        }
    }

    async fn connect_hu_aa_wireless_proxy(
        &self,
        hu_mac: &str,
        hu_channel: Option<u8>,
    ) -> Result<ProxyHuConnection> {
        Self::connect_hu_aa_wireless_proxy_inner(hu_mac, hu_channel).await
    }

    async fn connect_hu_aa_wireless_proxy_inner(
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

    async fn car_wifi_mitm_hu_first_rendezvous(
        &mut self,
        connect: BluetoothAddressList,
        options: &CarWifiMitmProxyOptions,
    ) -> Result<CarWifiRendezvousResult> {
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: HU-first legacy rendezvous: connect to HU first, then trigger phone AA RFCOMM",
            NAME
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

        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: HU-first connected to HU {}; now triggering/waiting for phone for up to {:?}",
            NAME,
            hu_endpoint,
            options.hu_first_wait_phone_timeout
        );

        // This intentionally mirrors the last known-good sequencing: do not nudge the
        // phone before the HU AA RFCOMM socket is established. Some phones appear to
        // enter a stale cached WPP/TCP path when HSP is triggered too early, before the
        // bridge is ready to replay the HU Bluetooth bootstrap frames.
        self.trigger_phone_aa_connection(connect, options.stopped).await?;

        let hu_addr: Address = options.hu_mac.trim().parse()?;
        let (phone_addr, phone_stream, buffered_hu_frames) = self
            .wait_for_phone_aa_profile_while_buffering_hu(
                hu_addr,
                &mut hu_stream,
                options.hu_first_wait_phone_timeout,
            )
            .await?;

        Ok((
            phone_addr,
            phone_stream,
            hu_stream,
            hu_endpoint,
            hu_client_profile_session,
            hu_client_profile_handle,
            buffered_hu_frames,
        ))
    }

    async fn disconnect_triggered_phone_devices(
        &self,
        connect: &BluetoothAddressList,
        reason: &str,
    ) {
        let Some(addresses_to_connect) = connect.0.as_ref() else {
            return;
        };
        let addresses: Vec<Address> = if addresses_to_connect
            .iter()
            .any(|addr| *addr == Address::any())
        {
            load_known_devices()
        } else {
            addresses_to_connect.clone()
        };
        if addresses.is_empty() {
            return;
        }
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: disconnecting {} triggered phone device(s) to clear stale AA/HSP state after {}",
            NAME,
            addresses.len(),
            reason
        );
        for addr in addresses {
            match self.adapter.device(addr) {
                Ok(device) => {
                    match device.disconnect().await {
                        Ok(_) => info!(
                            "{} 🧪 bt-wireless-proxy car-wifi-mitm: disconnected phone {} after {}",
                            NAME,
                            addr,
                            reason
                        ),
                        Err(e) => debug!(
                            "{} 🧪 bt-wireless-proxy car-wifi-mitm: phone {} disconnect after {} returned: {}",
                            NAME,
                            addr,
                            reason,
                            e
                        ),
                    }
                }
                Err(e) => debug!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: cannot get phone device {} for stale-state disconnect after {}: {}",
                    NAME,
                    addr,
                    reason,
                    e
                ),
            }
        }
        tokio::time::sleep(Duration::from_millis(750)).await;
    }

    async fn disconnect_hu_device_for_recovery(&self, hu_mac: &str, reason: &str) {
        let trimmed = hu_mac.trim();
        if trimmed.is_empty() {
            return;
        }
        let Ok(addr) = trimmed.parse::<Address>() else {
            debug!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: cannot parse HU MAC '{}' for stale-state disconnect after {}",
                NAME,
                trimmed,
                reason
            );
            return;
        };
        match self.adapter.device(addr) {
            Ok(device) => match device.disconnect().await {
                Ok(_) => info!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: disconnected HU {} after {}",
                    NAME,
                    addr,
                    reason
                ),
                Err(e) => debug!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: HU {} disconnect after {} returned: {}",
                    NAME,
                    addr,
                    reason,
                    e
                ),
            },
            Err(e) => debug!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: cannot get HU device {} for stale-state disconnect after {}: {}",
                NAME,
                addr,
                reason,
                e
            ),
        }
    }

    pub async fn recover_after_car_wifi_mitm_error(
        &self,
        connect: &BluetoothAddressList,
        hu_mac: &str,
        reason: &str,
    ) {
        let reason = reason.trim();
        let reason = if reason.is_empty() { "car-wifi-mitm error" } else { reason };
        warn!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: recovery cleanup after {}; closing stale HU/phone Bluetooth state before retry",
            NAME,
            reason
        );
        self.disconnect_triggered_phone_devices(connect, reason).await;
        self.disconnect_hu_device_for_recovery(hu_mac, reason).await;
        let cooldown = if reason.contains("could not find RFCOMM channel")
            || reason.contains("attrs=3500")
            || reason.contains("internal SDP discovery failed")
        {
            Duration::from_secs(25)
        } else if reason.contains("Connection reset by peer")
            || reason.contains("Software caused connection abort")
            || reason.contains("Transport endpoint is not connected")
        {
            Duration::from_secs(12)
        } else {
            Duration::from_secs(7)
        };
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: cooldown {:?} after {}; giving phone/HU AA stacks time to return to initial START state",
            NAME,
            cooldown,
            reason
        );
        tokio::time::sleep(cooldown).await;
    }

    async fn car_wifi_mitm_phone_first_rendezvous(
        &mut self,
        connect: BluetoothAddressList,
        options: &CarWifiMitmProxyOptions,
        hu_endpoint_hint: &str,
    ) -> Result<CarWifiRendezvousResult> {
        let (phone_addr, phone_stream) = self
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
            stream: hu_stream,
            endpoint: _,
            _client_profile_session: hu_client_profile_session,
            _client_profile_handle: hu_client_profile_handle,
        } = hu_conn;

        Ok((
            phone_addr,
            phone_stream,
            hu_stream,
            hu_endpoint,
            hu_client_profile_session,
            hu_client_profile_handle,
            Vec::new(),
        ))
    }

    pub async fn aa_wireless_car_wifi_mitm_proxy(
        &mut self,
        connect: BluetoothAddressList,
        options: CarWifiMitmProxyOptions,
    ) -> Result<()> {
        if options.hu_mac.trim().is_empty() {
            return Err("bt_wireless_proxy_hu_mac must be set for car-wifi-mitm mode".into());
        }

        let main_mitm_listen_port = TCP_SERVER_PORT as u16;
        let mut listen_port: u16 = if options.listen_port == 0 {
            main_mitm_listen_port
        } else {
            options.listen_port
        };
        if listen_port != main_mitm_listen_port {
            warn!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: overriding bt_wireless_proxy_listen_port={} with main MITM MD TCP port {} so the wireless session uses the normal aa-proxy packet/TLS MITM path",
                NAME,
                listen_port,
                main_mitm_listen_port
            );
            listen_port = main_mitm_listen_port;
        }
        let hu_endpoint_hint = match options.hu_channel.filter(|channel| *channel > 0) {
            Some(channel) => format!("{} RFCOMM channel {}", options.hu_mac.trim(), channel),
            None => format!("{} AA Wireless SDP auto-discovery", options.hu_mac.trim()),
        };

        let rendezvous_mode = CarWifiRendezvousMode::parse(&options.rendezvous_mode);
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: rendezvous_mode={} HU endpoint {}",
            NAME,
            rendezvous_mode.as_str(),
            hu_endpoint_hint
        );

        // Keep the same phone-trigger behavior as the normal AA handshake path.
        // Without a local HSP HS profile, BlueZ device.connect_profile(HSP_AG) often
        // fails with br-connection-profile-unavailable and the phone never opens the
        // AA Wireless RFCOMM profile. The HSP control stream is accepted and dropped,
        // exactly like the normal path, only to nudge Android into starting wireless AA.
        let _hsp_session = self.register_hsp_trigger_profile(false).await;

        let (
            mut phone_addr,
            mut phone_stream,
            mut hu_stream,
            hu_endpoint,
            hu_client_profile_session,
            hu_client_profile_handle,
            buffered_hu_frames,
        ) = match rendezvous_mode {
            CarWifiRendezvousMode::HuFirst => {
                info!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: strict HU-first rendezvous selected",
                    NAME
                );
                self.car_wifi_mitm_hu_first_rendezvous(connect.clone(), &options).await?
            }
            CarWifiRendezvousMode::PhoneFirst => {
                info!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: strict phone-first rendezvous selected",
                    NAME
                );
                self.car_wifi_mitm_phone_first_rendezvous(connect.clone(), &options, &hu_endpoint_hint).await?
            }
            CarWifiRendezvousMode::Auto => {
                info!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: auto rendezvous: HU-first/hybrid only; passive phone-first and same-run phone-first fallback are disabled to avoid stale Gearhead Wi-Fi/TCP loops",
                    NAME
                );

                match self
                    .car_wifi_mitm_hu_first_rendezvous(connect.clone(), &options)
                    .await
                {
                    Ok(result) => result,
                    Err(hu_first_err) => {
                        let hu_first_err_msg = hu_first_err.to_string();
                        warn!(
                            "{} 🧪 bt-wireless-proxy car-wifi-mitm: auto rendezvous HU-first/hybrid attempt failed: {}",
                            NAME,
                            hu_first_err_msg
                        );

                        // Do not try a phone-first fallback in the same run. The latest phone
                        // logcat shows Gearhead can jump to a cached Wi-Fi/WPP TCP path
                        // (DK / 192.168.43.43:22977) without ever opening PHONE AA RFCOMM.
                        // Re-triggering the phone in that state only produces repeated
                        // connect/refused/disconnect loops. Reset to START so the fake/real HU
                        // and the phone are both forced through a fresh HU-first Bluetooth
                        // bootstrap attempt.
                        self.disconnect_triggered_phone_devices(&connect, "auto HU-first/hybrid failure").await;
                        return Err(format!(
                            "auto rendezvous HU-first/hybrid failed; resetting Bluetooth/Wi-Fi bootstrap to initial START state instead of passive/phone-first fallback: {}",
                            hu_first_err_msg
                        )
                        .into());
                    }
                }
            }
        };
        let _hu_client_profile_guard = (hu_client_profile_session, hu_client_profile_handle);

        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: rendezvous ready phone={} HU={}; starting delayed bootstrap MITM; waiting up to 10s for HU bootstrap frame; buffered_hu_frames={} version_projection_fallback={}",
            NAME,
            phone_addr,
            hu_endpoint,
            buffered_hu_frames.len(),
            options.use_version_projection_fallback
        );

        let hu_start_payload = match timeout(
            Duration::from_secs(10),
            read_hu_wifi_start_with_prebootstrap_passthrough(
                &mut hu_stream,
                &mut phone_stream,
                options.use_version_projection_fallback,
                buffered_hu_frames,
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

        let (_hu_rfcomm_read, hu_rfcomm_write) = hu_stream.into_split();
        let hu_rfcomm_writer = Arc::new(Mutex::new(hu_rfcomm_write));
        let mut hu_wpp_keepalive = if options.wpp_keepalive {
            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: starting synthetic HU WifiPingRequest keepalive every {:?} after HU WifiInfoResponse while Wi-Fi/TCP bootstrap completes",
                NAME,
                options.wpp_keepalive_interval
            );
            spawn_hu_wpp_keepalive(hu_rfcomm_writer.clone(), options.wpp_keepalive_interval)
        } else {
            TaskAbortGuard::none("synthetic HU WPP keepalive")
        };

        let phone_wifi_mode = options.phone_wifi_mode.trim().to_ascii_lowercase();
        let external_phone_ap = matches!(phone_wifi_mode.as_str(), "external_ap" | "external-ap" | "externalap" | "external_proxy_ap" | "external-proxy-ap");
        let proxy_phone_ap = external_phone_ap
            || matches!(phone_wifi_mode.as_str(), "proxy_ap" | "proxy-ap" | "proxyap" | "ap_proxy");
        let base_iface = options.iface.trim();
        let mut effective_keep_ap = options.keep_ap;
        let mut proxy_ap_uses_virtual_ap_iface = false;
        let mut effective_ap_iface = if options.ap_iface.trim().is_empty() {
            if proxy_phone_ap && (base_iface.is_empty() || base_iface.starts_with("sta")) {
                "wlan0".to_string()
            } else {
                base_iface.to_string()
            }
        } else {
            options.ap_iface.trim().to_string()
        };
        let mut effective_sta_iface = if options.sta_iface.trim().is_empty() {
            if proxy_phone_ap || options.keep_ap {
                "sta0".to_string()
            } else {
                base_iface.to_string()
            }
        } else {
            options.sta_iface.trim().to_string()
        };
        if external_phone_ap {
            let phone_ap_iface = if !options.ap_iface.trim().is_empty() {
                options.ap_iface.trim().to_string()
            } else if base_iface.is_empty() {
                "wlan0".to_string()
            } else {
                base_iface.to_string()
            };
            let car_sta_iface = resolve_external_car_sta_iface(&options.sta_iface, &phone_ap_iface).await?;
            effective_ap_iface = phone_ap_iface;
            effective_sta_iface = car_sta_iface;
            effective_keep_ap = false;
            proxy_ap_uses_virtual_ap_iface = false;
            info!(
                "{} 🧪 bt-wireless-proxy external_ap: using two-radio layout phone_ap_iface={} car_sta_iface={} (external/USB STA joins HU Wi-Fi; phone stays on aa-proxy AP)",
                NAME, effective_ap_iface, effective_sta_iface
            );
        } else if proxy_phone_ap {
            // On Raspberry Pi's single-radio brcmfmac setup the natural-looking layout
            // (wlan0 as phone AP, sta0 as virtual car STA) is unstable: wpa_supplicant
            // can make the virtual sta0 disappear while associating. Manual testing
            // showed the inverted layout is stable:
            //   wlan0 = car-side STA connected to HU Wi-Fi
            //   ap0   = phone-facing AP on the same channel
            // Keep the already-running AP alive until active bootstrap starts, then
            // stop it on wlan0 and reopen the phone-facing AP as ap0 after wlan0 has
            // joined the car Wi-Fi.
            if effective_ap_iface.starts_with("sta") && effective_sta_iface.starts_with("wlan") {
                warn!(
                    "{} 🧪 bt-wireless-proxy proxy_ap: AP/STA ifaces look reversed (ap_iface={} sta_iface={}); treating {} as current phone AP before inverted layout",
                    NAME, effective_ap_iface, effective_sta_iface, effective_sta_iface
                );
                std::mem::swap(&mut effective_ap_iface, &mut effective_sta_iface);
            }

            let current_phone_ap_iface = if effective_ap_iface.trim().is_empty() {
                "wlan0".to_string()
            } else {
                effective_ap_iface.clone()
            };
            stop_phone_ap_for_proxy_ap(&current_phone_ap_iface).await;

            effective_sta_iface = current_phone_ap_iface;
            effective_ap_iface = if effective_sta_iface == "ap0" {
                "wlan0".to_string()
            } else {
                "ap0".to_string()
            };
            effective_keep_ap = false;
            proxy_ap_uses_virtual_ap_iface = true;

            info!(
                "{} 🧪 bt-wireless-proxy proxy_ap: using inverted single-radio layout phone_ap_iface={} car_sta_iface={} (car joins first, phone AP starts after channel is known)",
                NAME, effective_ap_iface, effective_sta_iface
            );
        } else {
            // car_ap means the phone will join the HU/car AP. aa-proxy must also
            // join that same car AP on the base interface and expose its car-side
            // IP to the phone. Keeping aa-proxy's own AP alive via sta0 is both
            // unnecessary and unstable on single-radio Pi setups, and it broke the
            // car_ap path when bt_wireless_proxy_car_wifi_keep_ap was left true in
            // old configs. Treat keep_ap/sta_iface as proxy_ap-only internals.
            if effective_keep_ap || effective_sta_iface.starts_with("sta") {
                info!(
                    "{} 🧪 bt-wireless-proxy car_ap: forcing takeover layout car_sta_iface={} and ignoring keep_ap/sta_iface config for this mode",
                    NAME,
                    if base_iface.is_empty() { "wlan0" } else { base_iface }
                );
            }
            effective_keep_ap = false;
            effective_ap_iface = String::new();
            effective_sta_iface = if base_iface.is_empty() {
                "wlan0".to_string()
            } else {
                base_iface.to_string()
            };
        }

        let effective_join_control = if proxy_phone_ap
            && matches!(options.join_control.trim().to_ascii_lowercase().as_str(), "" | "auto" | "wpactrl")
        {
            info!(
                "{} 🧪 bt-wireless-proxy {}: forcing Wi-Fi join control=wpa_supplicant for car STA iface",
                NAME,
                if external_phone_ap { "external_ap" } else { "proxy_ap" }
            );
            "wpa_supplicant".to_string()
        } else {
            options.join_control.clone()
        };

        let join_base_iface = if proxy_phone_ap {
            effective_sta_iface.as_str()
        } else {
            options.iface.as_str()
        };
        let join_attempt = run_car_wifi_join(
            &options.join_cmd,
            options.auto_join,
            &effective_join_control,
            join_base_iface,
            effective_keep_ap,
            &effective_sta_iface,
            &options.sta_phy,
            &effective_ap_iface,
            &hu_wifi_info,
            options.wpactrl_socket_timeout,
            options.wifi_association_timeout,
            options.dhcp_timeout,
        )
        .await;

        let join_iface = match join_attempt {
            Ok(iface) => iface,
            Err(e) if !external_phone_ap && proxy_phone_ap && e.to_string().contains("disappeared before association") => {
                warn!(
                    "{} 🧪 bt-wireless-proxy proxy_ap: car STA iface {} disappeared during virtual-STA join: {}; falling back to inverted single-radio mode: wlan0 as car STA, ap0 as phone AP",
                    NAME,
                    effective_sta_iface,
                    e
                );
                stop_wpa_supplicant_for_wifi("stop stale wpa_supplicant before inverted proxy_ap fallback").await;
                let fallback_car_sta_iface = if effective_ap_iface.trim().is_empty() {
                    "wlan0".to_string()
                } else {
                    effective_ap_iface.clone()
                };
                let fallback_phone_ap_iface = if fallback_car_sta_iface == "ap0" {
                    "wlan0".to_string()
                } else {
                    "ap0".to_string()
                };
                warn!(
                    "{} 🧪 bt-wireless-proxy proxy_ap: inverted fallback roles phone_ap_iface={} car_sta_iface={}",
                    NAME,
                    fallback_phone_ap_iface,
                    fallback_car_sta_iface
                );
                effective_ap_iface = fallback_phone_ap_iface;
                effective_sta_iface = fallback_car_sta_iface;
                proxy_ap_uses_virtual_ap_iface = true;
                run_car_wifi_join(
                    &options.join_cmd,
                    options.auto_join,
                    "wpa_supplicant",
                    &effective_sta_iface,
                    false,
                    &effective_sta_iface,
                    "",
                    "",
                    &hu_wifi_info,
                    options.wpactrl_socket_timeout,
                    options.wifi_association_timeout,
                    options.dhcp_timeout,
                )
                .await?
            }
            Err(e) => return Err(e),
        };
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut car_side_rewrite_ip = discover_rewrite_ip(&hu_tcp_ip, &join_iface, &options.rewrite_ip, options.dhcp_timeout).await?;
        let mut rewrite_ip = car_side_rewrite_ip.clone();
        let mut phone_wifi_info_payload = hu_info_payload.clone();

        if proxy_phone_ap {
            let phone_ap_ip = if options.phone_ap_ip.trim().is_empty() {
                "10.0.0.1".to_string()
            } else {
                options.phone_ap_ip.trim().to_string()
            };
            let channel = if external_phone_ap {
                let fallback_channel = if let Some(channel) = current_iw_channel(&effective_ap_iface).await {
                    channel
                } else {
                    current_iw_channel(&join_iface).await.unwrap_or(0)
                };
                let channel = start_external_phone_ap(
                    &effective_ap_iface,
                    &options.phone_ap_ssid,
                    &options.phone_ap_key,
                    &phone_ap_ip,
                    options.phone_ap_channel,
                    fallback_channel,
                )
                .await?;
                tokio::time::sleep(Duration::from_millis(500)).await;
                channel
            } else {
                let channel = current_iw_channel(&join_iface)
                    .await
                    .ok_or_else(|| format!("proxy_ap could not determine car STA channel from iface {}", join_iface))?;
                if proxy_ap_uses_virtual_ap_iface {
                    ensure_proxy_phone_ap_iface(&effective_ap_iface, &join_iface).await?;
                }
                start_proxy_phone_ap(
                    &effective_ap_iface,
                    &options.phone_ap_ssid,
                    &options.phone_ap_key,
                    &phone_ap_ip,
                    channel,
                )
                .await?;
                tokio::time::sleep(Duration::from_millis(500)).await;
                channel
            };
            let car_side_route_src_ip = repair_car_side_route_after_phone_ap(
                &hu_tcp_ip,
                &join_iface,
                hu_wifi_info.ssid(),
                &car_side_rewrite_ip,
                options.dhcp_timeout,
            )
            .await?;
            car_side_rewrite_ip = car_side_route_src_ip.clone();
            info!(
                "{} 🧪 bt-wireless-proxy {}: car-side HU route is ready via {} src {} after phone AP preparation",
                NAME,
                if external_phone_ap { "external_ap" } else { "proxy_ap" },
                join_iface,
                car_side_route_src_ip
            );
            // Gearhead appears to require a concrete BSSID for the Wi-Fi
            // NetworkSpecifier it builds from WifiInfoResponse.  Sending the
            // field as an empty string lets the protobuf serialize, but some
            // phones then only show the SSID in the normal Wi-Fi list and never
            // let Gearhead initiate the local-only connection.  Use the actual
            // MAC of the phone-facing AP iface (ap0 in inverted proxy_ap mode).
            let phone_ap_bssid = iface_mac_address(&effective_ap_iface)
                .await
                .map(|v| v.to_ascii_lowercase())
                .unwrap_or_default();
            if phone_ap_bssid.is_empty() {
                warn!(
                    "{} 🧪 bt-wireless-proxy {}: could not read BSSID/MAC for phone AP iface {}; WifiInfoResponse will contain an empty bssid and the phone may not attempt Wi-Fi connect",
                    NAME,
                    if external_phone_ap { "external_ap" } else { "proxy_ap" },
                    effective_ap_iface
                );
            } else {
                info!(
                    "{} 🧪 bt-wireless-proxy {}: using phone AP BSSID {} from iface {} for WifiInfoResponse",
                    NAME,
                    if external_phone_ap { "external_ap" } else { "proxy_ap" },
                    phone_ap_bssid,
                    effective_ap_iface
                );
            }
            let phone_wifi_info = build_proxy_phone_wifi_info(
                &options.phone_ap_ssid,
                &options.phone_ap_key,
                &phone_ap_bssid,
            )?;
            phone_wifi_info_payload = phone_wifi_info.write_to_bytes()?;
            rewrite_ip = phone_ap_ip;
            info!(
                "{} 🧪 bt-wireless-proxy {}: car side is {} via {}; phone side will receive AP ssid={} bssid={} ip={}:{} on iface={} channel={} instead of HU Wi-Fi ssid={} {}:{}",
                NAME,
                if external_phone_ap { "external_ap" } else { "proxy_ap" },
                car_side_rewrite_ip,
                join_iface,
                options.phone_ap_ssid,
                phone_ap_bssid,
                rewrite_ip,
                listen_port,
                effective_ap_iface,
                channel,
                hu_wifi_info.ssid(),
                hu_tcp_ip,
                hu_tcp_port
            );
        }

        let listen_addr = format!("0.0.0.0:{}", listen_port);
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: handing phone TCP {}:{} to the main aa-proxy MITM listener at {}; HU TCP {}:{} will be bridged into local DHU port {}",
            NAME, rewrite_ip, listen_port, listen_addr, hu_tcp_ip, hu_tcp_port, TCP_DHU_PORT
        );
        let phone_tcp_seq_before = options.tcp_phone_connection_seq.load(Ordering::Relaxed);
        options.tcp_start.notify_one();

        let mut phone_start_req = WifiStartRequest::WifiStartRequest::parse_from_bytes(&hu_start_payload)?;
        phone_start_req.set_ip_address(rewrite_ip.clone());
        phone_start_req.set_port(listen_port as i32);
        let phone_start_payload = phone_start_req.write_to_bytes()?;
        let max_phone_bootstrap_attempts: u8 = 3;
        let mut phone_start_resp_id: u16 = 0;
        let mut phone_start_resp_payload: Vec<u8> = Vec::new();
        let mut phone_bootstrap_ok = false;
        let mut last_phone_bootstrap_error = String::new();

        for phone_bootstrap_attempt in 1..=max_phone_bootstrap_attempts {
            if phone_bootstrap_attempt > 1 {
                let (new_phone_addr, new_phone_stream) = reconnect_phone_aa_rfcomm_for_car_wifi_mitm(
                    self,
                    connect.clone(),
                    &options,
                    phone_bootstrap_attempt - 1,
                    max_phone_bootstrap_attempts,
                    &last_phone_bootstrap_error,
                )
                .await?;
                phone_addr = new_phone_addr;
                phone_stream = new_phone_stream;
            }

            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: PHONE Wi-Fi bootstrap attempt {}/{} over AA RFCOMM from {}",
                NAME,
                phone_bootstrap_attempt,
                max_phone_bootstrap_attempts,
                phone_addr
            );
            // Ensure the main MD TCP listener is awake for every retry. The
            // previous attempt may have timed out its accept deadline while the
            // phone AA RFCOMM was being re-triggered.
            options.tcp_start.notify_one();

            if let Err(e) = send_proxy_frame(
                &mut phone_stream,
                "POC -> PHONE",
                ProxyMessageId::WifiStartRequest,
                &phone_start_payload,
            )
            .await
            {
                let err = e.to_string();
                if is_retriable_phone_bootstrap_disconnect(&err)
                    && phone_bootstrap_attempt < max_phone_bootstrap_attempts
                {
                    last_phone_bootstrap_error = format!(
                        "send WifiStartRequest failed: {}",
                        err
                    );
                    continue;
                }
                return Err(e);
            }

            let (phone_info_req_id, _phone_info_req_payload) = match read_phone_bootstrap_frame(
                &mut phone_stream,
                ProxyMessageId::WifiInfoRequest,
                None,
                Duration::from_secs(30),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    let err = e.to_string();
                    if is_retriable_phone_bootstrap_disconnect(&err)
                        && phone_bootstrap_attempt < max_phone_bootstrap_attempts
                    {
                        last_phone_bootstrap_error = format!(
                            "waiting for WifiInfoRequest failed: {}",
                            err
                        );
                        continue;
                    }
                    return Err(e);
                }
            };
            if phone_info_req_id != ProxyMessageId::WifiInfoRequest as u16 {
                warn!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: continuing after unexpected PHONE frame while waiting for WifiInfoRequest: {} ({})",
                    NAME,
                    phone_info_req_id,
                    ProxyMessageId::name(phone_info_req_id)
                );
            }
            info!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: consumed PHONE WifiInfoRequest locally; sending {} WifiInfoResponse to phone",
                NAME,
                if proxy_phone_ap { "proxy_ap phone-facing" } else { "cached HU" }
            );

            if let Err(e) = send_proxy_frame(
                &mut phone_stream,
                "POC -> PHONE",
                ProxyMessageId::WifiInfoResponse,
                &phone_wifi_info_payload,
            )
            .await
            {
                let err = e.to_string();
                if is_retriable_phone_bootstrap_disconnect(&err)
                    && phone_bootstrap_attempt < max_phone_bootstrap_attempts
                {
                    last_phone_bootstrap_error = format!(
                        "send WifiInfoResponse failed: {}",
                        err
                    );
                    continue;
                }
                return Err(e);
            }

            let start_resp = match read_phone_bootstrap_frame(
                &mut phone_stream,
                ProxyMessageId::WifiStartResponse,
                Some(&phone_wifi_info_payload),
                Duration::from_secs(45),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    let err = e.to_string();
                    if is_retriable_phone_bootstrap_disconnect(&err)
                        && phone_bootstrap_attempt < max_phone_bootstrap_attempts
                    {
                        last_phone_bootstrap_error = format!(
                            "waiting for WifiStartResponse failed: {}",
                            err
                        );
                        continue;
                    }
                    return Err(e);
                }
            };
            phone_start_resp_id = start_resp.0;
            phone_start_resp_payload = start_resp.1;
            if phone_start_resp_id != ProxyMessageId::WifiStartResponse as u16 {
                warn!(
                    "{} 🧪 bt-wireless-proxy car-wifi-mitm: expected PHONE WifiStartResponse, got {} ({})",
                    NAME,
                    phone_start_resp_id,
                    ProxyMessageId::name(phone_start_resp_id)
                );
            }
            phone_bootstrap_ok = true;
            break;
        }

        if !phone_bootstrap_ok {
            return Err(format!(
                "PHONE Wi-Fi bootstrap failed after {} AA RFCOMM attempt(s) while keeping HU RFCOMM alive; last error: {}",
                max_phone_bootstrap_attempts,
                last_phone_bootstrap_error
            )
            .into());
        }
        let mut phone_rfcomm = phone_stream;
        let phone_status_task = tokio::spawn(async move {
            match timeout(
                Duration::from_secs(30),
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
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>((phone_status_id, phone_status_payload))
                }
                Ok(Err(e)) => {
                    warn!(
                        "{} 🧪 bt-wireless-proxy car-wifi-mitm: failed reading PHONE WifiConnectStatus before HU commit: {}; will synthesize success for HU",
                        NAME, e
                    );
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                        ProxyMessageId::WifiConnectStatus as u16,
                        wifi_connect_status_payload(0),
                    ))
                }
                Err(_) => {
                    warn!(
                        "{} 🧪 bt-wireless-proxy car-wifi-mitm: timed out waiting for PHONE WifiConnectStatus before HU commit; will synthesize success for HU",
                        NAME
                    );
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                        ProxyMessageId::WifiConnectStatus as u16,
                        wifi_connect_status_payload(0),
                    ))
                }
            }
        });

        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: PHONE WifiStartResponse received; delaying HU WifiStartResponse and real HU TCP connect until PHONE TCP is accepted by the normal MITM listener",
            NAME
        );
        let phone_tcp_seq = wait_for_phone_tcp_accept_barrier(
            options.tcp_phone_connected.clone(),
            options.tcp_phone_connection_seq.clone(),
            phone_tcp_seq_before,
            Duration::from_secs(75),
        )
        .await?;
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: PHONE TCP accept barrier passed seq={} (before={}); committing HU Wi-Fi bootstrap now",
            NAME,
            phone_tcp_seq,
            phone_tcp_seq_before
        );

        {
            let mut hu_writer = hu_rfcomm_writer.lock().await;
            send_proxy_frame_raw(
                &mut *hu_writer,
                "POC -> HU",
                phone_start_resp_id,
                &phone_start_resp_payload,
            )
            .await?;
        }


        let hu_tcp_addr = format!("{}:{}", hu_tcp_ip, hu_tcp_port);
        let local_hu_tcp_addr = format!("127.0.0.1:{}", TCP_DHU_PORT);
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: connecting real HU TCP {} and local aa-proxy HU-side TCP {}; PHONE TCP is already accepted, keeping synthetic WPP keepalive alive until TCP bridge is ready",
            NAME, hu_tcp_addr, local_hu_tcp_addr
        );

        let mut hu_tcp = connect_real_hu_tcp_with_route_retry(
            &hu_tcp_addr,
            &hu_tcp_ip,
            &join_iface,
            hu_wifi_info.ssid(),
            &car_side_rewrite_ip,
            options.dhcp_timeout,
        )
        .await?;
        let mut local_hu_tcp = timeout(Duration::from_secs(45), TcpStream::connect(local_hu_tcp_addr.as_str())).await??;
        hu_wpp_keepalive.abort_now();
        hu_tcp.set_nodelay(true)?;
        local_hu_tcp.set_nodelay(true)?;
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: real HU TCP {} connected; local HU-side TCP {} connected; main MITM owns phone TCP on port {}",
            NAME, hu_tcp_addr, local_hu_tcp_addr, listen_port
        );

        let hu_rfcomm_writer_for_status = hu_rfcomm_writer.clone();
        let rfcomm_status_task = tokio::spawn(async move {
            let (phone_status_id, phone_status_payload) = match phone_status_task.await {
                Ok(Ok(status)) => status,
                Ok(Err(e)) => {
                    warn!(
                        "{} 🧪 bt-wireless-proxy car-wifi-mitm: PHONE WifiConnectStatus collector failed: {}; sending success to HU",
                        NAME, e
                    );
                    (
                        ProxyMessageId::WifiConnectStatus as u16,
                        wifi_connect_status_payload(0),
                    )
                }
                Err(e) => {
                    warn!(
                        "{} 🧪 bt-wireless-proxy car-wifi-mitm: PHONE WifiConnectStatus collector task join failed: {}; sending success to HU",
                        NAME, e
                    );
                    (
                        ProxyMessageId::WifiConnectStatus as u16,
                        wifi_connect_status_payload(0),
                    )
                }
            };
            let mut hu_rfcomm = hu_rfcomm_writer_for_status.lock().await;
            send_proxy_frame_raw(
                &mut *hu_rfcomm,
                "POC -> HU",
                phone_status_id,
                &phone_status_payload,
            )
            .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: starting HU TCP bridge into normal aa-proxy MITM path; remove_bluetooth/remove_wifi now apply exactly like USB/DHU sessions",
            NAME
        );
        let (hu_to_proxy, proxy_to_hu) = copy_bidirectional(&mut hu_tcp, &mut local_hu_tcp).await?;
        if !rfcomm_status_task.is_finished() {
            rfcomm_status_task.abort();
        } else if let Ok(Err(e)) = rfcomm_status_task.await {
            warn!(
                "{} 🧪 bt-wireless-proxy car-wifi-mitm: RFCOMM status forward task failed: {}",
                NAME, e
            );
        }
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: HU TCP bridge ended HU->proxy={} proxy->HU={} bytes",
            NAME, hu_to_proxy, proxy_to_hu
        );
        info!(
            "{} 🧪 bt-wireless-proxy car-wifi-mitm: wireless session ended; dropping transient RFCOMM/TCP state so the next run starts from rendezvous START state",
            NAME
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

        let start_response_payload = wifi_start_response_status_payload(0);
        send_proxy_frame(
            &mut stream,
            "POC -> HU",
            ProxyMessageId::WifiStartResponse,
            &start_response_payload,
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

        let connect_status_payload = wifi_connect_status_payload(0);
        send_proxy_frame(
            &mut stream,
            "POC -> HU",
            ProxyMessageId::WifiConnectStatus,
            &connect_status_payload,
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
        shared_config: SharedConfig,
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
        // Clear Stop flag here — after BT handshake succeeds but before the proxy loop
        // is notified. The proxy checks action_requested on every iteration; leaving Stop
        // set would cause it to kill the session immediately (~20ms).
        if stopped {
            info!("{} 🔄 User-stop cleared, phone reconnected manually", NAME);
            shared_config.write().await.action_requested = None;
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
                    tokio::time::sleep(Duration::from_millis(300)).await;
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
