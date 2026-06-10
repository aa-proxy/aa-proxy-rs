use crate::companion_protocol::{
    COMPANION_OP_ECHO, COMPANION_OP_ECHO_REPLY, COMPANION_OP_ERROR, COMPANION_OP_GET_STATUS,
    COMPANION_OP_ON_SCRIPT_EVENT, COMPANION_OP_ON_TOPIC_EVENT, COMPANION_OP_PING,
    COMPANION_OP_PONG, COMPANION_OP_REST_CALL, COMPANION_OP_REST_CALL_REPLY,
    COMPANION_OP_REST_CALL_RESULT, COMPANION_OP_REST_CALL_SYNC, COMPANION_OP_STATUS,
    COMPANION_OP_SUBSCRIBE_TOPIC_EVENT, COMPANION_OP_UNSUBSCRIBE_TOPIC_EVENT,
};
use crate::config::AppConfig;
use crate::config_types::HexdumpLevel;
use crate::mitm::protos::ControlMessageType;
use crate::mitm::protos::ControlMessageType::*;
use crate::mitm::protos::*;
use crate::mitm::{get_name, ModifyContext, Packet, ProxyType, Result};
use log::{debug, info, log_enabled, Level};
use protobuf::text_format::print_to_string_pretty;
use protobuf::{Enum, Message};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PacketDebugServiceKind {
    Unknown,
    Control,
    SensorSource,
    MediaSink,
    InputSource,
    MediaSource,
    Bluetooth,
    Radio,
    NavigationStatus,
    MediaPlaybackStatus,
    PhoneStatus,
    MediaBrowser,
    VendorExtension,
    GenericNotification,
    WifiProjection,
    CarProperty,
}

impl PacketDebugServiceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Control => "control",
            Self::SensorSource => "sensor_source",
            Self::MediaSink => "media_sink",
            Self::InputSource => "input_source",
            Self::MediaSource => "media_source",
            Self::Bluetooth => "bluetooth",
            Self::Radio => "radio",
            Self::NavigationStatus => "navigation_status",
            Self::MediaPlaybackStatus => "media_playback_status",
            Self::PhoneStatus => "phone_status",
            Self::MediaBrowser => "media_browser",
            Self::VendorExtension => "vendor_extension",
            Self::GenericNotification => "generic_notification",
            Self::WifiProjection => "wifi_projection",
            Self::CarProperty => "car_property",
        }
    }
}

fn split_filter_tokens(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split(|c| c == ',' || c == ';' || c == ' ' || c == '\n' || c == '\t')
        .map(|part| part.trim().to_ascii_lowercase())
        .filter(|part| !part.is_empty())
}

fn parse_filter_u8(value: &str) -> Option<u8> {
    let token = value.trim();
    if token.is_empty() {
        return None;
    }

    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        u8::from_str_radix(hex, 16).ok()
    } else {
        token.parse::<u8>().ok()
    }
}

fn parse_filter_u16(value: &str) -> Option<u16> {
    let token = value.trim();
    if token.is_empty() {
        return None;
    }

    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        u16::from_str_radix(hex, 16).ok()
    } else {
        token.parse::<u16>().ok()
    }
}

fn list_contains_u8(list: &str, value: u8) -> bool {
    split_filter_tokens(list).any(|token| parse_filter_u8(&token) == Some(value))
}

fn list_contains_u16(list: &str, value: u16) -> bool {
    split_filter_tokens(list).any(|token| parse_filter_u16(&token) == Some(value))
}

fn hexdump_stage_token(stage: HexdumpLevel) -> &'static str {
    match stage {
        HexdumpLevel::Disabled => "disabled",
        HexdumpLevel::DecryptedInput => "decrypted_input",
        HexdumpLevel::RawInput => "raw_input",
        HexdumpLevel::DecryptedOutput => "decrypted_output",
        HexdumpLevel::RawOutput => "raw_output",
        HexdumpLevel::All => "all",
    }
}

fn stage_matches_filter(filter: &str, stage: HexdumpLevel) -> bool {
    let wanted = hexdump_stage_token(stage);
    split_filter_tokens(filter).any(|token| {
        token == wanted
            || token == "all"
            || token.replace('-', "_") == wanted
            || token.replace('-', "_") == wanted.replace('_', "")
            || token.eq_ignore_ascii_case(&format!("{:?}", stage))
    })
}

fn proxy_matches_filter(filter: &str, proxy_type: ProxyType) -> bool {
    match filter.trim().to_ascii_lowercase().as_str() {
        "" | "both" | "all" | "any" => true,
        "hu" | "headunit" | "head_unit" | "head-unit" => proxy_type == ProxyType::HeadUnit,
        "md" | "mobile" | "mobiledevice" | "mobile_device" | "mobile-device" => {
            proxy_type == ProxyType::MobileDevice
        }
        _ => true,
    }
}

fn service_kind_matches_filter(filter: &str, kind: PacketDebugServiceKind) -> bool {
    let wanted = kind.as_str();
    split_filter_tokens(filter).any(|token| {
        token == wanted
            || token == "all"
            || token == "any"
            || token == wanted.replace('_', "")
            || match kind {
                PacketDebugServiceKind::Control => {
                    matches!(token.as_str(), "control_channel" | "control")
                }
                PacketDebugServiceKind::SensorSource => {
                    matches!(token.as_str(), "sensor" | "sensor_source_channel")
                }
                PacketDebugServiceKind::MediaSink => matches!(
                    token.as_str(),
                    "sink" | "media_sink_service" | "media_sink_service_channel"
                ),
                PacketDebugServiceKind::InputSource => matches!(
                    token.as_str(),
                    "input" | "input_source_service" | "input_source_service_channel"
                ),
                PacketDebugServiceKind::MediaSource => matches!(
                    token.as_str(),
                    "source" | "media_source_service" | "media_source_service_channel"
                ),
                PacketDebugServiceKind::Bluetooth => matches!(
                    token.as_str(),
                    "bt" | "bluetooth_service" | "bluetooth_service_channel"
                ),
                PacketDebugServiceKind::Radio => {
                    matches!(token.as_str(), "radio_service" | "radio_service_channel")
                }
                PacketDebugServiceKind::NavigationStatus => matches!(
                    token.as_str(),
                    "nav"
                        | "navigation"
                        | "navigation_status_service"
                        | "navigation_status_service_channel"
                ),
                PacketDebugServiceKind::MediaPlaybackStatus => matches!(
                    token.as_str(),
                    "media_playback"
                        | "media_playback_service"
                        | "media_playback_status_service_channel"
                ),
                PacketDebugServiceKind::PhoneStatus => matches!(
                    token.as_str(),
                    "phone" | "phone_status_service" | "phone_status_service_channel"
                ),
                PacketDebugServiceKind::MediaBrowser => matches!(
                    token.as_str(),
                    "browser" | "media_browser_service" | "media_browser_service_channel"
                ),
                PacketDebugServiceKind::VendorExtension => matches!(
                    token.as_str(),
                    "vendor"
                        | "vec"
                        | "vendor_extension_service"
                        | "vendor_extension_service_channel"
                ),
                PacketDebugServiceKind::GenericNotification => matches!(
                    token.as_str(),
                    "notification"
                        | "generic_notification_service"
                        | "generic_notification_service_channel"
                ),
                PacketDebugServiceKind::WifiProjection => matches!(
                    token.as_str(),
                    "wifi" | "wifi_projection_service" | "wifi_projection_service_channel"
                ),
                PacketDebugServiceKind::CarProperty => matches!(
                    token.as_str(),
                    "car_property_service" | "car_property_service_channel"
                ),
                PacketDebugServiceKind::Unknown => token == "unknown",
            }
    })
}

fn pkt_debug_service_kind_for_service(svc: &Service) -> PacketDebugServiceKind {
    if svc.sensor_source_service.is_some() {
        PacketDebugServiceKind::SensorSource
    } else if svc.media_sink_service.is_some() {
        PacketDebugServiceKind::MediaSink
    } else if svc.input_source_service.is_some() {
        PacketDebugServiceKind::InputSource
    } else if svc.media_source_service.is_some() {
        PacketDebugServiceKind::MediaSource
    } else if svc.bluetooth_service.is_some() {
        PacketDebugServiceKind::Bluetooth
    } else if svc.radio_service.is_some() {
        PacketDebugServiceKind::Radio
    } else if svc.navigation_status_service.is_some() {
        PacketDebugServiceKind::NavigationStatus
    } else if svc.media_playback_service.is_some() {
        PacketDebugServiceKind::MediaPlaybackStatus
    } else if svc.phone_status_service.is_some() {
        PacketDebugServiceKind::PhoneStatus
    } else if svc.media_browser_service.is_some() {
        PacketDebugServiceKind::MediaBrowser
    } else if svc.vendor_extension_service.is_some() {
        PacketDebugServiceKind::VendorExtension
    } else if svc.generic_notification_service.is_some() {
        PacketDebugServiceKind::GenericNotification
    } else if svc.wifi_projection_service.is_some() {
        PacketDebugServiceKind::WifiProjection
    } else {
        PacketDebugServiceKind::Unknown
    }
}

pub fn update_debug_channel_kinds(ctx: &mut ModifyContext, msg: &ServiceDiscoveryResponse) {
    ctx.debug_channel_kinds.clear();
    ctx.debug_channel_kinds
        .insert(0, PacketDebugServiceKind::Control);

    for svc in msg.services.iter() {
        let Ok(channel) = u8::try_from(svc.id()) else {
            continue;
        };
        ctx.debug_channel_kinds
            .insert(channel, pkt_debug_service_kind_for_service(svc));
    }
}

fn pkt_debug_service_kind(
    pkt: &Packet,
    debug_channel_kinds: Option<&HashMap<u8, PacketDebugServiceKind>>,
) -> PacketDebugServiceKind {
    if pkt.channel == 0 {
        return PacketDebugServiceKind::Control;
    }

    debug_channel_kinds
        .and_then(|kinds| kinds.get(&pkt.channel).copied())
        .unwrap_or(PacketDebugServiceKind::Unknown)
}

fn pkt_debug_filter_matches(
    proxy_type: ProxyType,
    hexdump: HexdumpLevel,
    pkt: &Packet,
    message_id: u16,
    service_kind: PacketDebugServiceKind,
    cfg: &AppConfig,
) -> bool {
    if !cfg.pkt_debug_filter_enabled {
        return true;
    }

    if !proxy_matches_filter(&cfg.pkt_debug_filter_proxy, proxy_type) {
        return false;
    }

    if !cfg.pkt_debug_filter_stages.trim().is_empty()
        && !stage_matches_filter(&cfg.pkt_debug_filter_stages, hexdump)
    {
        return false;
    }

    if !cfg.pkt_debug_filter_service_kinds.trim().is_empty()
        && !service_kind_matches_filter(&cfg.pkt_debug_filter_service_kinds, service_kind)
    {
        return false;
    }

    if !cfg.pkt_debug_filter_channels.trim().is_empty()
        && !list_contains_u8(&cfg.pkt_debug_filter_channels, pkt.channel)
    {
        return false;
    }

    if !cfg.pkt_debug_filter_exclude_channels.trim().is_empty()
        && list_contains_u8(&cfg.pkt_debug_filter_exclude_channels, pkt.channel)
    {
        return false;
    }

    if !cfg.pkt_debug_filter_message_ids.trim().is_empty()
        && !list_contains_u16(&cfg.pkt_debug_filter_message_ids, message_id)
    {
        return false;
    }

    if !cfg.pkt_debug_filter_exclude_message_ids.trim().is_empty()
        && list_contains_u16(&cfg.pkt_debug_filter_exclude_message_ids, message_id)
    {
        return false;
    }

    true
}

fn format_packet_for_debug(pkt: &Packet, max_payload_bytes: Option<usize>) -> String {
    let payload_len = pkt.payload.len();
    let shown_len = max_payload_bytes
        .filter(|max| *max > 0)
        .map(|max| payload_len.min(max))
        .unwrap_or(payload_len);
    let truncated = shown_len < payload_len;

    let mut out = String::new();
    out.push_str("packet dump:\n");
    out.push_str(&format!(" channel: {:02X}\n", pkt.channel));
    out.push_str(&format!(" flags: {:02X}\n", pkt.flags));
    out.push_str(&format!(" final length: {:04X?}\n", pkt.final_length));
    out.push_str(&format!(" payload length: {}\n", payload_len));
    out.push_str(&format!(" payload: {:02X?}", &pkt.payload[..shown_len]));
    if truncated {
        out.push_str(&format!(
            "\n ... truncated {} byte(s)",
            payload_len - shown_len
        ));
    }
    out
}

fn trim_preview(value: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for ch in value.chars().take(max_chars) {
        out.push(ch);
    }
    if value.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}

fn bytes_preview(data: &[u8], max_bytes: usize) -> String {
    let shown_len = data.len().min(max_bytes);
    let mut out = format!("len={}", data.len());
    if shown_len > 0 {
        out.push_str(&format!(" preview={:02X?}", &data[..shown_len]));
    }
    if shown_len < data.len() {
        out.push_str(&format!(
            " ... truncated {} byte(s)",
            data.len() - shown_len
        ));
    }
    out
}

fn json_field_string(value: &serde_json::Value, name: &str) -> Option<String> {
    value.get(name)?.as_str().map(ToOwned::to_owned)
}

fn json_field_i64(value: &serde_json::Value, name: &str) -> Option<i64> {
    value.get(name)?.as_i64()
}

fn json_payload_len_and_preview(value: &serde_json::Value, name: &str) -> Option<String> {
    let raw = value.get(name)?;
    if let Some(s) = raw.as_str() {
        return Some(format!(
            "{} chars, preview={}",
            s.len(),
            trim_preview(s, 240)
        ));
    }

    let rendered = raw.to_string();
    Some(format!(
        "{} chars json, preview={}",
        rendered.len(),
        trim_preview(&rendered, 240)
    ))
}

fn vec_opcode_name(opcode: u8) -> &'static str {
    match opcode {
        COMPANION_OP_PING => "COMPANION_OP_PING",
        COMPANION_OP_GET_STATUS => "COMPANION_OP_GET_STATUS",
        COMPANION_OP_ECHO => "COMPANION_OP_ECHO",
        COMPANION_OP_REST_CALL => "COMPANION_OP_REST_CALL",
        COMPANION_OP_REST_CALL_SYNC => "COMPANION_OP_REST_CALL_SYNC",
        COMPANION_OP_SUBSCRIBE_TOPIC_EVENT => "COMPANION_OP_SUBSCRIBE_TOPIC_EVENT",
        COMPANION_OP_UNSUBSCRIBE_TOPIC_EVENT => "COMPANION_OP_UNSUBSCRIBE_TOPIC_EVENT",
        COMPANION_OP_ON_SCRIPT_EVENT => "COMPANION_OP_ON_SCRIPT_EVENT",
        COMPANION_OP_PONG => "COMPANION_OP_PONG",
        COMPANION_OP_STATUS => "COMPANION_OP_STATUS",
        COMPANION_OP_ECHO_REPLY => "COMPANION_OP_ECHO_REPLY",
        COMPANION_OP_REST_CALL_REPLY => "COMPANION_OP_REST_CALL_REPLY",
        COMPANION_OP_REST_CALL_RESULT => "COMPANION_OP_REST_CALL_RESULT",
        COMPANION_OP_ON_TOPIC_EVENT => "COMPANION_OP_ON_TOPIC_EVENT",
        COMPANION_OP_ERROR => "COMPANION_OP_ERROR",
        _ => "COMPANION_OP_UNKNOWN",
    }
}

fn pretty_vec_app_packet(pkt: &Packet) -> Option<String> {
    if pkt.payload.len() < 2 {
        return Some("Companion app packet too short".to_string());
    }

    let version = pkt.payload[0];
    let opcode = pkt.payload[1];
    let body = &pkt.payload[2..];
    let opcode_name = vec_opcode_name(opcode);

    let mut out = format!(
        "{}\n  version: {}\n  opcode: {:#04x}\n  body_len: {}",
        opcode_name,
        version,
        opcode,
        body.len()
    );

    if version != 0x01 {
        out.push_str("\n  warning: unsupported VEC app version");
    }

    match opcode {
        0x02 | 0x81 | 0x04 | 0x83 => {
            if !body.is_empty() {
                if let Ok(text) = std::str::from_utf8(body) {
                    out.push_str(&format!("\n  body_text: {}", trim_preview(text, 240)));
                } else {
                    out.push_str(&format!("\n  body_bytes: {}", bytes_preview(body, 64)));
                }
            }
        }
        0x03 => {}
        0x82 => {
            if let Ok(text) = std::str::from_utf8(body) {
                out.push_str(&format!("\n  status: {}", trim_preview(text, 240)));
            }
        }
        0x05 | 0x06 => match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(json) => {
                if let Some(method) = json_field_string(&json, "method") {
                    out.push_str(&format!("\n  method: {}", method));
                }
                if let Some(path) = json_field_string(&json, "path") {
                    out.push_str(&format!("\n  path: {}", path));
                }
                if let Some(body_info) = json_payload_len_and_preview(&json, "body") {
                    out.push_str(&format!("\n  request_body: {}", body_info));
                }
            }
            Err(e) => out.push_str(&format!("\n  json_error: {}", e)),
        },
        0x85 => match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(json) => {
                if let Some(request_id) = json_field_string(&json, "request_id") {
                    out.push_str(&format!("\n  request_id: {}", request_id));
                }
                if let Some(status) = json_field_i64(&json, "status") {
                    out.push_str(&format!("\n  status: {}", status));
                }
            }
            Err(e) => out.push_str(&format!("\n  json_error: {}", e)),
        },
        0x86 => match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(json) => {
                if let Some(request_id) = json_field_string(&json, "request_id") {
                    out.push_str(&format!("\n  request_id: {}", request_id));
                }
                if let Some(payload_info) = json_payload_len_and_preview(&json, "payload") {
                    out.push_str(&format!("\n  payload: {}", payload_info));
                }
            }
            Err(e) => out.push_str(&format!("\n  json_error: {}", e)),
        },
        0x07 | 0x08 => match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(json) => {
                if let Some(topic) = json_field_string(&json, "topic") {
                    out.push_str(&format!("\n  topic: {}", topic));
                }
            }
            Err(e) => out.push_str(&format!("\n  json_error: {}", e)),
        },
        0x09 | 0x87 => match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(json) => {
                if let Some(topic) = json_field_string(&json, "topic") {
                    out.push_str(&format!("\n  topic: {}", topic));
                }
                if let Some(payload_info) = json_payload_len_and_preview(&json, "payload") {
                    out.push_str(&format!("\n  payload: {}", payload_info));
                }
            }
            Err(e) => out.push_str(&format!("\n  json_error: {}", e)),
        },
        0xFF => {
            if let Ok(text) = std::str::from_utf8(body) {
                out.push_str(&format!("\n  error: {}", trim_preview(text, 240)));
            }
        }
        _ => {
            out.push_str(&format!("\n  body_bytes: {}", bytes_preview(body, 64)));
        }
    }

    Some(out)
}

fn message_name_for_kind(
    service_kind: PacketDebugServiceKind,
    message_id: u16,
    pkt: &Packet,
) -> String {
    match service_kind {
        PacketDebugServiceKind::Control => {
            format!("{:?}", ControlMessageType::from_i32(message_id.into()))
        }
        PacketDebugServiceKind::SensorSource => {
            format!("{:?}", SensorMessageId::from_i32(message_id.into()))
        }
        PacketDebugServiceKind::MediaSink | PacketDebugServiceKind::MediaSource => {
            format!("{:?}", MediaMessageId::from_i32(message_id.into()))
        }
        PacketDebugServiceKind::InputSource => {
            format!("{:?}", InputMessageId::from_i32(message_id.into()))
        }
        PacketDebugServiceKind::Bluetooth => {
            format!("{:?}", BluetoothMessageId::from_i32(message_id.into()))
        }
        PacketDebugServiceKind::WifiProjection => {
            format!("{:?}", WifiProjectionMessageId::from_i32(message_id.into()))
        }
        PacketDebugServiceKind::Radio => {
            format!("{:?}", RadioMessageId::from_i32(message_id.into()))
        }
        PacketDebugServiceKind::NavigationStatus => {
            format!(
                "{:?}",
                NavigationStatusMessageId::from_i32(message_id.into())
            )
        }
        PacketDebugServiceKind::MediaPlaybackStatus => {
            format!(
                "{:?}",
                MediaPlaybackStatusMessageId::from_i32(message_id.into())
            )
        }
        PacketDebugServiceKind::PhoneStatus => {
            format!("{:?}", PhoneStatusMessageId::from_i32(message_id.into()))
        }
        PacketDebugServiceKind::MediaBrowser => {
            format!("{:?}", MediaBrowserMessageId::from_i32(message_id.into()))
        }
        PacketDebugServiceKind::GenericNotification => {
            format!(
                "{:?}",
                GenericNotificationMessageId::from_i32(message_id.into())
            )
        }
        PacketDebugServiceKind::VendorExtension => {
            if pkt.payload.len() >= 2 && pkt.payload[0] == 0x01 {
                format!("Some({})", vec_opcode_name(pkt.payload[1]))
            } else {
                format!(
                    "{:?}",
                    GalVerificationVendorExtensionMessageId::from_i32(message_id.into())
                )
            }
        }
        PacketDebugServiceKind::Unknown | PacketDebugServiceKind::CarProperty => "None".to_string(),
    }
}

fn pretty_parse_error(type_name: &str, err: protobuf::Error) -> String {
    format!("pretty parse failed as {}: {}", type_name, err)
}

macro_rules! parse_pretty_message {
    ($ty:ty, $data:expr) => {{
        match <$ty>::parse_from_bytes($data) {
            Ok(msg) => Some(print_to_string_pretty(&msg)),
            Err(e) => Some(pretty_parse_error(stringify!($ty), e)),
        }
    }};
}

fn pretty_control_message(control: Option<ControlMessageType>, data: &[u8]) -> Option<String> {
    match control.unwrap_or(MESSAGE_UNEXPECTED_MESSAGE) {
        MESSAGE_VERSION_REQUEST => parse_pretty_message!(VersionRequestOptions, data),
        MESSAGE_VERSION_RESPONSE => parse_pretty_message!(VersionResponseOptions, data),
        MESSAGE_BYEBYE_REQUEST => parse_pretty_message!(ByeByeRequest, data),
        MESSAGE_BYEBYE_RESPONSE => parse_pretty_message!(ByeByeResponse, data),
        MESSAGE_AUTH_COMPLETE => parse_pretty_message!(AuthResponse, data),
        MESSAGE_SERVICE_DISCOVERY_REQUEST => parse_pretty_message!(ServiceDiscoveryRequest, data),
        MESSAGE_SERVICE_DISCOVERY_RESPONSE => parse_pretty_message!(ServiceDiscoveryResponse, data),
        MESSAGE_SERVICE_DISCOVERY_UPDATE => parse_pretty_message!(ServiceDiscoveryUpdate, data),
        MESSAGE_PING_REQUEST => parse_pretty_message!(PingRequest, data),
        MESSAGE_PING_RESPONSE => parse_pretty_message!(PingResponse, data),
        MESSAGE_NAV_FOCUS_REQUEST => parse_pretty_message!(NavFocusRequestNotification, data),
        MESSAGE_NAV_FOCUS_NOTIFICATION => parse_pretty_message!(NavFocusNotification, data),
        MESSAGE_CHANNEL_OPEN_RESPONSE => parse_pretty_message!(ChannelOpenResponse, data),
        MESSAGE_CHANNEL_OPEN_REQUEST => parse_pretty_message!(ChannelOpenRequest, data),
        MESSAGE_CHANNEL_CLOSE_NOTIFICATION => parse_pretty_message!(ChannelCloseNotification, data),
        MESSAGE_VOICE_SESSION_NOTIFICATION => parse_pretty_message!(VoiceSessionNotification, data),
        MESSAGE_AUDIO_FOCUS_REQUEST => parse_pretty_message!(AudioFocusRequestNotification, data),
        MESSAGE_AUDIO_FOCUS_NOTIFICATION => parse_pretty_message!(AudioFocusNotification, data),
        MESSAGE_CAR_CONNECTED_DEVICES_REQUEST => {
            parse_pretty_message!(CarConnectedDevicesRequest, data)
        }
        MESSAGE_CAR_CONNECTED_DEVICES_RESPONSE => parse_pretty_message!(CarConnectedDevices, data),
        MESSAGE_USER_SWITCH_REQUEST => parse_pretty_message!(UserSwitchRequest, data),
        MESSAGE_USER_SWITCH_RESPONSE => parse_pretty_message!(UserSwitchResponse, data),
        MESSAGE_BATTERY_STATUS_NOTIFICATION => {
            parse_pretty_message!(BatteryStatusNotification, data)
        }
        MESSAGE_CALL_AVAILABILITY_STATUS => parse_pretty_message!(CallAvailabilityStatus, data),
        _ => None,
    }
}

fn pretty_sensor_message(message_id: u16, data: &[u8]) -> Option<String> {
    match SensorMessageId::from_i32(message_id.into())
        .unwrap_or(SensorMessageId::SENSOR_MESSAGE_ERROR)
    {
        SensorMessageId::SENSOR_MESSAGE_REQUEST => parse_pretty_message!(SensorRequest, data),
        SensorMessageId::SENSOR_MESSAGE_RESPONSE => parse_pretty_message!(SensorResponse, data),
        SensorMessageId::SENSOR_MESSAGE_BATCH => parse_pretty_message!(SensorBatch, data),
        SensorMessageId::SENSOR_MESSAGE_ERROR => {
            Some(format!("SENSOR_MESSAGE_ERROR raw_len={}", data.len()))
        }
    }
}

fn pretty_media_message(message_id: u16, data: &[u8]) -> Option<String> {
    match MediaMessageId::from_i32(message_id.into()).unwrap_or(MediaMessageId::MEDIA_MESSAGE_DATA)
    {
        MediaMessageId::MEDIA_MESSAGE_DATA => {
            Some(format!("MEDIA_MESSAGE_DATA {}", bytes_preview(data, 64)))
        }
        MediaMessageId::MEDIA_MESSAGE_CODEC_CONFIG => Some(format!(
            "MEDIA_MESSAGE_CODEC_CONFIG {}",
            bytes_preview(data, 64)
        )),
        MediaMessageId::MEDIA_MESSAGE_SETUP => parse_pretty_message!(Setup, data),
        MediaMessageId::MEDIA_MESSAGE_START => parse_pretty_message!(Start, data),
        MediaMessageId::MEDIA_MESSAGE_STOP => parse_pretty_message!(Stop, data),
        MediaMessageId::MEDIA_MESSAGE_CONFIG => parse_pretty_message!(Config, data),
        MediaMessageId::MEDIA_MESSAGE_ACK => parse_pretty_message!(Ack, data),
        MediaMessageId::MEDIA_MESSAGE_MICROPHONE_REQUEST => {
            parse_pretty_message!(MicrophoneRequest, data)
        }
        MediaMessageId::MEDIA_MESSAGE_MICROPHONE_RESPONSE => {
            parse_pretty_message!(MicrophoneResponse, data)
        }
        MediaMessageId::MEDIA_MESSAGE_VIDEO_FOCUS_REQUEST => {
            parse_pretty_message!(VideoFocusRequestNotification, data)
        }
        MediaMessageId::MEDIA_MESSAGE_VIDEO_FOCUS_NOTIFICATION => {
            parse_pretty_message!(VideoFocusNotification, data)
        }
        MediaMessageId::MEDIA_MESSAGE_UPDATE_UI_CONFIG_REQUEST => {
            parse_pretty_message!(UpdateUiConfigRequest, data)
        }
        MediaMessageId::MEDIA_MESSAGE_UPDATE_UI_CONFIG_REPLY => {
            parse_pretty_message!(UpdateUiConfigReply, data)
        }
        MediaMessageId::MEDIA_MESSAGE_AUDIO_UNDERFLOW_NOTIFICATION => {
            parse_pretty_message!(AudioUnderflowNotification, data)
        }
    }
}

fn pretty_input_message(message_id: u16, data: &[u8]) -> Option<String> {
    match InputMessageId::from_i32(message_id.into())? {
        InputMessageId::INPUT_MESSAGE_INPUT_REPORT => parse_pretty_message!(InputReport, data),
        InputMessageId::INPUT_MESSAGE_KEY_BINDING_REQUEST => {
            parse_pretty_message!(KeyBindingRequest, data)
        }
        InputMessageId::INPUT_MESSAGE_KEY_BINDING_RESPONSE => {
            parse_pretty_message!(KeyBindingResponse, data)
        }
        InputMessageId::INPUT_MESSAGE_INPUT_FEEDBACK => parse_pretty_message!(InputFeedback, data),
    }
}

fn pretty_bluetooth_message(message_id: u16, data: &[u8]) -> Option<String> {
    match BluetoothMessageId::from_i32(message_id.into())? {
        BluetoothMessageId::BLUETOOTH_MESSAGE_PAIRING_REQUEST => {
            parse_pretty_message!(BluetoothPairingRequest, data)
        }
        BluetoothMessageId::BLUETOOTH_MESSAGE_PAIRING_RESPONSE => {
            parse_pretty_message!(BluetoothPairingResponse, data)
        }
        BluetoothMessageId::BLUETOOTH_MESSAGE_AUTHENTICATION_DATA => {
            parse_pretty_message!(BluetoothAuthenticationData, data)
        }
        BluetoothMessageId::BLUETOOTH_MESSAGE_AUTHENTICATION_RESULT => {
            parse_pretty_message!(BluetoothAuthenticationResult, data)
        }
    }
}

fn pretty_wifi_message(message_id: u16, data: &[u8]) -> Option<String> {
    match WifiProjectionMessageId::from_i32(message_id.into())? {
        WifiProjectionMessageId::WIFI_MESSAGE_CREDENTIALS_REQUEST => {
            parse_pretty_message!(WifiCredentialsRequest, data)
        }
        WifiProjectionMessageId::WIFI_MESSAGE_CREDENTIALS_RESPONSE => {
            parse_pretty_message!(WifiCredentialsResponse, data)
        }
    }
}

fn pretty_radio_message(message_id: u16, data: &[u8]) -> Option<String> {
    match RadioMessageId::from_i32(message_id.into())? {
        RadioMessageId::RADIO_MESSAGE_ACTIVE_RADIO_NOTIFICATION => {
            parse_pretty_message!(ActiveRadioNotification, data)
        }
        RadioMessageId::RADIO_MESSAGE_SELECT_ACTIVE_RADIO_REQUEST => {
            parse_pretty_message!(SelectActiveRadioRequest, data)
        }
        RadioMessageId::RADIO_MESSAGE_STEP_CHANNEL_REQUEST => {
            parse_pretty_message!(StepChannelRequest, data)
        }
        RadioMessageId::RADIO_MESSAGE_STEP_CHANNEL_RESPONSE => {
            parse_pretty_message!(StepChannelResponse, data)
        }
        RadioMessageId::RADIO_MESSAGE_SEEK_STATION_REQUEST => {
            parse_pretty_message!(SeekStationRequest, data)
        }
        RadioMessageId::RADIO_MESSAGE_SEEK_STATION_RESPONSE => {
            parse_pretty_message!(SeekStationResponse, data)
        }
        RadioMessageId::RADIO_MESSAGE_SCAN_STATIONS_REQUEST => {
            parse_pretty_message!(ScanStationsRequest, data)
        }
        RadioMessageId::RADIO_MESSAGE_SCAN_STATIONS_RESPONSE => {
            parse_pretty_message!(ScanStationsResponse, data)
        }
        RadioMessageId::RADIO_MESSAGE_TUNE_TO_STATION_REQUEST => {
            parse_pretty_message!(TuneToStationRequest, data)
        }
        RadioMessageId::RADIO_MESSAGE_TUNE_TO_STATION_RESPONSE => {
            parse_pretty_message!(TuneToStationResponse, data)
        }
        RadioMessageId::RADIO_MESSAGE_GET_PROGRAM_LIST_REQUEST => {
            parse_pretty_message!(GetProgramListRequest, data)
        }
        RadioMessageId::RADIO_MESSAGE_GET_PROGRAM_LIST_RESPONSE => {
            parse_pretty_message!(GetProgramListResponse, data)
        }
        RadioMessageId::RADIO_MESSAGE_STATION_PRESETS_NOTIFICATION => {
            parse_pretty_message!(StationPresetsNotification, data)
        }
        RadioMessageId::RADIO_MESSAGE_CANCEL_OPERATIONS_REQUEST => {
            parse_pretty_message!(CancelRadioOperationsRequest, data)
        }
        RadioMessageId::RADIO_MESSAGE_CANCEL_OPERATIONS_RESPONSE => {
            parse_pretty_message!(CancelRadioOperationsResponse, data)
        }
        RadioMessageId::RADIO_MESSAGE_CONFIGURE_CHANNEL_SPACING_REQUEST => {
            parse_pretty_message!(ConfigureChannelSpacingRequest, data)
        }
        RadioMessageId::RADIO_MESSAGE_CONFIGURE_CHANNEL_SPACING_RESPONSE => {
            parse_pretty_message!(ConfigureChannelSpacingResponse, data)
        }
        RadioMessageId::RADIO_MESSAGE_RADIO_STATION_INFO_NOTIFICATION => {
            parse_pretty_message!(RadioStationInfoNotification, data)
        }
        RadioMessageId::RADIO_MESSAGE_MUTE_RADIO_REQUEST => {
            parse_pretty_message!(MuteRadioRequest, data)
        }
        RadioMessageId::RADIO_MESSAGE_MUTE_RADIO_RESPONSE => {
            parse_pretty_message!(MuteRadioResponse, data)
        }
        RadioMessageId::RADIO_MESSAGE_GET_TRAFFIC_UPDATE_REQUEST => {
            parse_pretty_message!(GetTrafficUpdateRequest, data)
        }
        RadioMessageId::RADIO_MESSAGE_GET_TRAFFIC_UPDATE_RESPONSE => {
            parse_pretty_message!(GetTrafficUpdateResponse, data)
        }
        RadioMessageId::RADIO_MESSAGE_RADIO_SOURCE_REQUEST => {
            parse_pretty_message!(RadioSourceRequest, data)
        }
        RadioMessageId::RADIO_MESSAGE_RADIO_SOURCE_RESPONSE => {
            parse_pretty_message!(RadioSourceResponse, data)
        }
        RadioMessageId::RADIO_MESSAGE_STATE_NOTIFICATION => {
            parse_pretty_message!(RadioStateNotification, data)
        }
    }
}

fn pretty_navigation_status_message(message_id: u16, data: &[u8]) -> Option<String> {
    match NavigationStatusMessageId::from_i32(message_id.into())? {
        NavigationStatusMessageId::INSTRUMENT_CLUSTER_START => {
            parse_pretty_message!(NavigationStatusStart, data)
        }
        NavigationStatusMessageId::INSTRUMENT_CLUSTER_STOP => {
            parse_pretty_message!(NavigationStatusStop, data)
        }
        NavigationStatusMessageId::INSTRUMENT_CLUSTER_NAVIGATION_STATUS => {
            parse_pretty_message!(NavigationStatus, data)
        }
        NavigationStatusMessageId::INSTRUMENT_CLUSTER_NAVIGATION_TURN_EVENT => {
            parse_pretty_message!(NavigationNextTurnEvent, data)
        }
        NavigationStatusMessageId::INSTRUMENT_CLUSTER_NAVIGATION_DISTANCE_EVENT => {
            parse_pretty_message!(NavigationNextTurnDistanceEvent, data)
        }
        NavigationStatusMessageId::INSTRUMENT_CLUSTER_NAVIGATION_STATE => {
            parse_pretty_message!(NavigationState, data)
        }
        NavigationStatusMessageId::INSTRUMENT_CLUSTER_NAVIGATION_CURRENT_POSITION => {
            parse_pretty_message!(NavigationCurrentPosition, data)
        }
    }
}

fn pretty_media_playback_status_message(message_id: u16, data: &[u8]) -> Option<String> {
    match MediaPlaybackStatusMessageId::from_i32(message_id.into())? {
        MediaPlaybackStatusMessageId::MEDIA_PLAYBACK_STATUS => {
            parse_pretty_message!(MediaPlaybackStatus, data)
        }
        MediaPlaybackStatusMessageId::MEDIA_PLAYBACK_INPUT => {
            parse_pretty_message!(InstrumentClusterInput, data)
        }
        MediaPlaybackStatusMessageId::MEDIA_PLAYBACK_METADATA => {
            parse_pretty_message!(MediaPlaybackMetadata, data)
        }
    }
}

fn pretty_phone_status_message(message_id: u16, data: &[u8]) -> Option<String> {
    match PhoneStatusMessageId::from_i32(message_id.into())? {
        PhoneStatusMessageId::PHONE_STATUS => parse_pretty_message!(PhoneStatus, data),
        PhoneStatusMessageId::PHONE_STATUS_INPUT => parse_pretty_message!(PhoneStatusInput, data),
    }
}

fn pretty_media_browser_message(message_id: u16, data: &[u8]) -> Option<String> {
    match MediaBrowserMessageId::from_i32(message_id.into())? {
        MediaBrowserMessageId::MEDIA_ROOT_NODE => parse_pretty_message!(MediaRootNode, data),
        MediaBrowserMessageId::MEDIA_SOURCE_NODE => parse_pretty_message!(MediaSourceNode, data),
        MediaBrowserMessageId::MEDIA_LIST_NODE => parse_pretty_message!(MediaListNode, data),
        MediaBrowserMessageId::MEDIA_SONG_NODE => parse_pretty_message!(MediaSongNode, data),
        MediaBrowserMessageId::MEDIA_GET_NODE => parse_pretty_message!(MediaGetNode, data),
        MediaBrowserMessageId::MEDIA_BROWSE_INPUT => parse_pretty_message!(MediaBrowserInput, data),
    }
}

fn pretty_gal_verification_message(message_id: u16, data: &[u8]) -> Option<String> {
    match GalVerificationVendorExtensionMessageId::from_i32(message_id.into())? {
        GalVerificationVendorExtensionMessageId::GAL_VERIFICATION_SET_SENSOR => {
            parse_pretty_message!(GalVerificationSetSensor, data)
        }
        GalVerificationVendorExtensionMessageId::GAL_VERIFICATION_MEDIA_SINK_STATUS => {
            parse_pretty_message!(GalVerificationMediaSinkStatus, data)
        }
        GalVerificationVendorExtensionMessageId::GAL_VERIFICATION_VIDEO_FOCUS => {
            parse_pretty_message!(GalVerificationVideoFocus, data)
        }
        GalVerificationVendorExtensionMessageId::GAL_VERIFICATION_AUDIO_FOCUS => {
            parse_pretty_message!(GalVerificationAudioFocus, data)
        }
        GalVerificationVendorExtensionMessageId::GAL_VERIFICATION_INJECT_INPUT => {
            parse_pretty_message!(GalVerificationInjectInput, data)
        }
        GalVerificationVendorExtensionMessageId::GAL_VERIFICATION_BUG_REPORT_REQUEST => {
            parse_pretty_message!(GalVerificationBugReportRequest, data)
        }
        GalVerificationVendorExtensionMessageId::GAL_VERIFICATION_BUG_REPORT_RESPONSE => {
            parse_pretty_message!(GalVerificationBugReportResponse, data)
        }
        GalVerificationVendorExtensionMessageId::GAL_VERIFICATION_SCREEN_CAPTURE_REQUEST => {
            parse_pretty_message!(GalVerificationScreenCaptureRequest, data)
        }
        GalVerificationVendorExtensionMessageId::GAL_VERIFICATION_SCREEN_CAPTURE_RESPONSE => {
            parse_pretty_message!(GalVerificationScreenCaptureResponse, data)
        }
        GalVerificationVendorExtensionMessageId::GAL_VERIFICATION_DISPLAY_INFORMATION_REQUEST => {
            parse_pretty_message!(GalVerificationDisplayInformationRequest, data)
        }
        GalVerificationVendorExtensionMessageId::GAL_VERIFICATION_DISPLAY_INFORMATION_RESPONSE => {
            parse_pretty_message!(GalVerificationDisplayInformationResponse, data)
        }
    }
}

fn pretty_generic_notification_message(message_id: u16, data: &[u8]) -> Option<String> {
    match GenericNotificationMessageId::from_i32(message_id.into())? {
        GenericNotificationMessageId::GENERIC_NOTIFICATION_SUBSCRIBE => {
            parse_pretty_message!(GenericNotificationSubscribe, data)
        }
        GenericNotificationMessageId::GENERIC_NOTIFICATION_UNSUBSCRIBE => {
            parse_pretty_message!(GenericNotificationUnsubscribe, data)
        }
        GenericNotificationMessageId::GENERIC_NOTIFICATION_MESSAGE => {
            parse_pretty_message!(GenericNotificationMessage, data)
        }
        GenericNotificationMessageId::GENERIC_NOTIFICATION_ACK => {
            parse_pretty_message!(GenericNotificationAck, data)
        }
    }
}

fn pretty_packet_message(
    service_kind: PacketDebugServiceKind,
    control: Option<ControlMessageType>,
    message_id: u16,
    data: &[u8],
    pkt: &Packet,
) -> Option<String> {
    match service_kind {
        PacketDebugServiceKind::Control => pretty_control_message(control, data),
        PacketDebugServiceKind::SensorSource => pretty_sensor_message(message_id, data),
        PacketDebugServiceKind::MediaSink | PacketDebugServiceKind::MediaSource => {
            pretty_media_message(message_id, data)
        }
        PacketDebugServiceKind::InputSource => pretty_input_message(message_id, data),
        PacketDebugServiceKind::Bluetooth => pretty_bluetooth_message(message_id, data),
        PacketDebugServiceKind::Radio => pretty_radio_message(message_id, data),
        PacketDebugServiceKind::NavigationStatus => {
            pretty_navigation_status_message(message_id, data)
        }
        PacketDebugServiceKind::MediaPlaybackStatus => {
            pretty_media_playback_status_message(message_id, data)
        }
        PacketDebugServiceKind::PhoneStatus => pretty_phone_status_message(message_id, data),
        PacketDebugServiceKind::MediaBrowser => pretty_media_browser_message(message_id, data),
        PacketDebugServiceKind::VendorExtension => {
            if pkt.payload.len() >= 2 && pkt.payload[0] == 0x01 {
                pretty_vec_app_packet(pkt)
            } else {
                pretty_gal_verification_message(message_id, data)
            }
        }
        PacketDebugServiceKind::GenericNotification => {
            pretty_generic_notification_message(message_id, data)
        }
        PacketDebugServiceKind::WifiProjection => pretty_wifi_message(message_id, data),
        PacketDebugServiceKind::Unknown | PacketDebugServiceKind::CarProperty => None,
    }
}

fn wrap_pretty_block(title: &str, text: &str) -> String {
    let trimmed = text.trim();

    if trimmed.is_empty() {
        return format!("\n{} {{}}", title);
    }

    let body = trimmed
        .lines()
        .map(|line| format!("  {}", line))
        .collect::<Vec<_>>()
        .join("\n");

    format!("\n{} {{\n{}\n}}", title, body)
}

/// shows packet/message contents as pretty string for debug
pub async fn pkt_debug(
    proxy_type: ProxyType,
    hexdump: HexdumpLevel,
    hex_requested: HexdumpLevel,
    pkt: &Packet,
    cfg: &AppConfig,
    debug_channel_kinds: Option<&HashMap<u8, PacketDebugServiceKind>>,
) -> Result<()> {
    // Keep packet debug independent from global debug logging.
    // - debug=true: old behavior, pkt_debug lines use DEBUG level.
    // - pkt_debug=true: packet debug is emitted at INFO level even when debug=false,
    //   so enabling packet logs does not enable every other debug!() message.
    let standalone_pkt_debug = cfg.pkt_debug;
    if !standalone_pkt_debug && !log_enabled!(Level::Debug) {
        return Ok(());
    }

    let emit_pkt_debug = |line: String| {
        if standalone_pkt_debug {
            info!("{}", line);
        } else {
            debug!("{}", line);
        }
    };

    // if for some reason we have too small packet, bail out
    if pkt.payload.len() < 2 {
        return Ok(());
    }
    // message_id is the first 2 bytes of payload
    let message_id: u16 = u16::from_be_bytes(pkt.payload[0..=1].try_into()?);

    let service_kind = pkt_debug_service_kind(pkt, debug_channel_kinds);
    if !pkt_debug_filter_matches(proxy_type, hexdump, pkt, message_id, service_kind, cfg) {
        return Ok(());
    }

    let control = ControlMessageType::from_i32(message_id.into());
    let message_name = message_name_for_kind(service_kind, message_id, pkt);
    emit_pkt_debug(format!(
        "message_id = {:04X}, {}, channel={:#04x}, service_kind={}",
        message_id,
        message_name,
        pkt.channel,
        service_kind.as_str()
    ));

    if hex_requested >= hexdump {
        let max_payload_bytes = if cfg.pkt_debug_filter_enabled {
            Some(cfg.pkt_debug_filter_max_payload_bytes)
        } else {
            None
        };
        emit_pkt_debug(format!(
            "{} {:?} {}",
            get_name(proxy_type),
            hexdump,
            format_packet_for_debug(pkt, max_payload_bytes)
        ));
    }

    if cfg.pkt_debug_filter_enabled && !cfg.pkt_debug_filter_pretty_proto {
        return Ok(());
    }

    // parsing data
    let data = &pkt.payload[2..]; // start of message data
    if let Some(pretty) = pretty_packet_message(service_kind, control, message_id, data, pkt) {
        emit_pkt_debug(wrap_pretty_block("proto", &pretty));
    }

    Ok(())
}
