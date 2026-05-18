use crate::bt_sco;
use crate::bt_sco_media_bridge;
use crate::ev::send_ev_data;
use crate::ev::BatteryData;
#[cfg(feature = "wasm-scripting")]
use crate::script_wasm::bindings::aa::packet::types::Decision;
#[cfg(feature = "wasm-scripting")]
use crate::script_wasm::{
    apply_wasm_packet, from_wasm_packet, to_wasm_cfg, to_wasm_modify_context, to_wasm_packet,
    LoadedScript, ScriptProxyType, ScriptRegistry,
};
#[cfg(not(feature = "wasm-scripting"))]
type ScriptRegistry = ();
use crate::display::add_display_services;
use crate::display::emulate_injected_media_packet;
use crate::display::maybe_emit_pending_injected_focus;
use crate::display::InjectedMediaState;
use crate::mitm_prettyprint::{pkt_debug, update_debug_channel_kinds, PacketDebugServiceKind};
use crate::sdr_ui;
use crate::vendor_ext::{
    add_vendor_extension_service, ensure_vendor_channel_open, ensure_vendor_topic_event_bridge,
    handle_vendor_channel_packet, has_vendor_extension_service, is_vendor_channel,
    is_vendor_service_id, mark_vendor_channel_open, VecChannelState, VecTopicEventBridge,
    VecTopicEventRuntime, OUR_VEC_PACKAGE, OUR_VEC_SERVICE_NAME,
};
use crate::web::ServerEvent;
use anyhow::Context;
use openssl::ssl::{ErrorCode, Ssl, SslContextBuilder, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};
use simplelog::*;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fmt;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast::Sender as BroadcastSender;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::RwLock;
use tokio::time::timeout;
use tokio_uring::buf::BoundedBuf;

// protobuf stuff:
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
use crate::mitm::protos::navigation_maneuver::NavigationType::*;
use crate::mitm::protos::Config as AudioConfig;
use crate::mitm::protos::InputMessageId::INPUT_MESSAGE_INPUT_REPORT;
use crate::mitm::protos::*;
use crate::mitm::protos::{relative_event, RelativeEvent};
use crate::mitm::protos::{InputReport, KeyEvent};
use crate::mitm::sensor_source_service::Sensor;
use crate::mitm::AudioStreamType::*;
use crate::mitm::ByeByeReason::USER_SELECTION;
use crate::mitm::Gear::GEAR_PARK;
use crate::mitm::MediaMessageId::*;
use crate::mitm::SensorMessageId::*;
use crate::mitm::SensorType::*;
use protobuf::{Enum, EnumOrUnknown, Message};
use protos::ControlMessageType::{self, *};

use crate::config::{Action::Stop, AppConfig, BtScoMediaBridgeAudioType, SharedConfig};
use crate::config_types::HexdumpLevel;
use crate::ev::EvTaskCommand;
use crate::hu_input::{handle_hu_input, HuInputState};
use crate::io_uring::Endpoint;
use crate::io_uring::IoDevice;
use crate::io_uring::BUFFER_LEN;
pub use crate::media_tap::{
    media_tcp_server, AudioStreamConfig, MediaSink, MediaStreamInfo, MediaStreamKind,
};
use crate::media_tap::{reassemble_media_packet, tap_media_message, MediaFrameBuffer};

// module name for logging engine
pub fn get_name(proxy_type: ProxyType) -> String {
    let proxy = match proxy_type {
        ProxyType::HeadUnit => "HU",
        ProxyType::MobileDevice => "MD",
    };
    format!("<i><bright-black> mitm/{}: </>", proxy)
}

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Last ServiceDiscoveryResponse observed by the MITM path, stored as protobuf JSON.
pub type SharedServiceDiscoveryResponse = Arc<RwLock<Option<serde_json::Value>>>;
pub type SharedMediaSinks = Arc<tokio::sync::Mutex<HashMap<u8, MediaSink>>>;
pub type SharedMediaChannels = Arc<tokio::sync::Mutex<HashMap<u8, MediaSink>>>;

// message related constants:
pub const HEADER_LENGTH: usize = 4;
pub const FRAME_TYPE_FIRST: u8 = 1 << 0;
pub const FRAME_TYPE_LAST: u8 = 1 << 1;
pub const FRAME_TYPE_MASK: u8 = FRAME_TYPE_FIRST | FRAME_TYPE_LAST;
const _CONTROL: u8 = 1 << 2;
pub const ENCRYPTED: u8 = 1 << 3;

// location for hu_/md_ private keys and certificates:
const KEYS_PATH: &str = crate::base_config_dir!();

// DHU string consts for developer mode
pub const DHU_MAKE: &str = "Google";
pub const DHU_MODEL: &str = "Desktop Head Unit";

pub struct ModifyContext {
    pub(crate) sensor_channel: Option<u8>,
    pub(crate) sensors: Option<Vec<Sensor>>,
    pub(crate) nav_channel: Option<u8>,
    pub(crate) audio_channels: Vec<u8>,
    pub(crate) ev_tx: Sender<EvTaskCommand>,
    pub(crate) input_channel: Option<u8>,
    pub(crate) hu_tx: Option<Sender<Packet>>,
    pub(crate) hu_input_state: HuInputState,
    /// Shared offset→sink map. TCP listeners are created lazily from the rewritten SDR,
    /// so audio/video port count follows the actual media sink services instead of a fixed pool.
    pub(crate) media_sinks: SharedMediaSinks,
    /// Shared channel_id→sink map populated from the final rewritten SDR.
    /// Both proxy directions use this because the SDR is rewritten on the HU side,
    /// while media DATA/codec frames are tapped on the MD side.
    pub(crate) shared_media_channels: SharedMediaChannels,
    /// Base TCP port for media tap listeners.
    pub(crate) media_dump_base_port: Option<u16>,
    /// Whether video tap clients wait for a live IDR before streaming.
    pub(crate) media_wait_for_live_idr: bool,
    /// channel_id→sink map. Populated from SDR. Used for tapping data packets.
    pub(crate) media_channels: HashMap<u8, MediaSink>,
    /// Per-channel reassembly state for tapped media messages that span multiple
    /// AA transport frames.
    pub(crate) media_fragments: HashMap<u8, MediaFrameBuffer>,
    /// Original HU-advertised services from ServiceDiscoveryResponse.
    pub(crate) hu_service_ids: HashSet<i32>,
    /// Services synthesized by aa-proxy-rs and exposed only to the phone side.
    pub(crate) injected_service_ids: HashSet<i32>,
    /// Channels corresponding to injected services that must never be forwarded to HU.
    pub(crate) injected_channels: HashSet<u8>,
    /// Injected media service_id/channel -> display type.
    pub(crate) injected_media_display: HashMap<u8, DisplayType>,
    /// Per-channel media state for injected virtual sinks (hidden from HU).
    pub(crate) injected_media_state: HashMap<u8, InjectedMediaState>,
    /// Last observed tap client connection generation by media channel.
    pub(crate) injected_media_connect_gen: HashMap<u8, u64>,
    /// Last observed tap-consumer presence by media channel.
    pub(crate) injected_media_had_tap_client: HashMap<u8, bool>,
    /// VEC service ids injected by aa-proxy-rs into the service discovery response.
    pub(crate) vendor_service_ids: HashSet<u8>,
    /// Active VEC channel ids opened by the mobile device against our injected VEC(s).
    pub(crate) vendor_channel_states: HashMap<u8, VecChannelState>,
    /// Per-VEC-channel topic event bridge state. Each VEC channel has its own
    /// local subscription set, just like each websocket connection does.
    pub(crate) vendor_topic_event_bridges: HashMap<u8, VecTopicEventBridge>,
    /// Channel id -> semantic service kind map used only by pkt_debug filtering.
    pub(crate) debug_channel_kinds: HashMap<u8, PacketDebugServiceKind>,
}

fn service_audio_config(svc: &Service) -> Option<AudioStreamConfig> {
    svc.media_sink_service
        .audio_configs
        .first()
        .map(|acfg| AudioStreamConfig {
            sample_rate: acfg.sampling_rate(),
            channels: acfg.number_of_channels(),
            bits: acfg.number_of_bits(),
        })
}

fn display_type_label(display_type: DisplayType) -> &'static str {
    match display_type {
        DisplayType::DISPLAY_TYPE_MAIN => "main",
        DisplayType::DISPLAY_TYPE_CLUSTER => "cluster",
        DisplayType::DISPLAY_TYPE_AUXILIARY => "aux",
    }
}

fn audio_type_label(audio_type: AudioStreamType) -> &'static str {
    match audio_type {
        AUDIO_STREAM_GUIDANCE => "guidance",
        AUDIO_STREAM_SYSTEM_AUDIO => "system",
        AUDIO_STREAM_MEDIA => "media",
        AUDIO_STREAM_TELEPHONY => "telephony",
    }
}

fn is_video_media_sink(svc: &Service) -> bool {
    !svc.media_sink_service.video_configs.is_empty()
}

fn is_audio_media_sink(svc: &Service) -> bool {
    !svc.media_sink_service.audio_configs.is_empty() || svc.media_sink_service.audio_type.is_some()
}

fn media_sink_label(svc: &Service, offset: u8, is_video: bool) -> String {
    let label = if is_video {
        format!(
            "video-{}",
            display_type_label(svc.media_sink_service.display_type())
        )
    } else {
        format!(
            "audio-{}",
            audio_type_label(svc.media_sink_service.audio_type())
        )
    };

    if label.is_empty() {
        format!("media-{offset:02}")
    } else {
        label.chars().take(48).collect()
    }
}

async fn get_or_create_media_sink_for_offset(
    ctx: &mut ModifyContext,
    offset: u8,
    label: String,
) -> Option<MediaSink> {
    let Some(base_port) = ctx.media_dump_base_port else {
        return None;
    };

    let mut media_sinks = ctx.media_sinks.lock().await;
    if let Some(sink) = media_sinks.get(&offset).cloned() {
        return Some(sink);
    }

    let Some(port) = base_port.checked_add(offset as u16) else {
        warn!(
            "<yellow>media tap:</> cannot expose media offset <b>{}</>; base port <b>{}</> would overflow",
            offset,
            base_port
        );
        return None;
    };

    let sink = MediaSink::new(128);
    tokio::spawn(media_tcp_server(
        port,
        label,
        sink.clone(),
        ctx.media_wait_for_live_idr,
    ));
    media_sinks.insert(offset, sink.clone());
    Some(sink)
}

async fn register_media_channel_sink(ctx: &mut ModifyContext, channel: u8, sink: MediaSink) {
    ctx.media_channels.insert(channel, sink.clone());
    let mut shared_media_channels = ctx.shared_media_channels.lock().await;
    shared_media_channels.insert(channel, sink);
}

async fn media_sink_for_channel(ctx: &mut ModifyContext, channel: u8) -> Option<MediaSink> {
    if let Some(sink) = ctx.media_channels.get(&channel).cloned() {
        return Some(sink);
    }

    let sink = {
        let shared_media_channels = ctx.shared_media_channels.lock().await;
        shared_media_channels.get(&channel).cloned()
    };

    if let Some(sink) = sink.clone() {
        ctx.media_channels.insert(channel, sink.clone());
    }

    sink
}

async fn populate_media_tap_channels_by_order(
    proxy_type: ProxyType,
    ctx: &mut ModifyContext,
    msg: &ServiceDiscoveryResponse,
) {
    if ctx.media_dump_base_port.is_none() {
        return;
    }

    // Rebuild the channel map from the latest rewritten SDR. Port offsets are assigned
    // in a stable two-pass order: all video sinks first, then audio sinks as actually
    // advertised by the SDR. This allows multiple displays without colliding with audio.
    ctx.media_channels.clear();
    {
        let mut shared_media_channels = ctx.shared_media_channels.lock().await;
        shared_media_channels.clear();
    }

    let mut ordered_services: Vec<(&Service, bool)> = Vec::new();
    for svc in msg.services.iter().filter(|svc| is_video_media_sink(svc)) {
        ordered_services.push((svc, true));
    }
    for svc in msg
        .services
        .iter()
        .filter(|svc| !is_video_media_sink(svc) && is_audio_media_sink(svc))
    {
        ordered_services.push((svc, false));
    }

    for (index, (svc, has_video)) in ordered_services.into_iter().enumerate() {
        if index > u8::MAX as usize {
            warn!(
                "{} <yellow>media tap:</> too many media sinks in SDR; channel <b>{:#04x}</> is not exposed",
                get_name(proxy_type),
                svc.id() as u8
            );
            continue;
        }

        let offset = index as u8;
        let ch = svc.id() as u8;
        let label = media_sink_label(svc, offset, has_video);
        let Some(sink) = get_or_create_media_sink_for_offset(ctx, offset, label).await else {
            continue;
        };

        if has_video {
            sink.set_video_stream_info(
                svc.media_sink_service.available_type(),
                svc.media_sink_service.display_type(),
            )
            .await;
            register_media_channel_sink(ctx, ch, sink).await;
            debug!(
                "{} media_channels.insert: ch={:#04x} offset={} media_order=video_first",
                get_name(proxy_type),
                ch,
                offset
            );
            info!(
                "{} <blue>media tap:</> video channel <b>{:#04x}</> → port offset <b>{}</> ({:?}, {:?}, display_id={})",
                get_name(proxy_type),
                ch,
                offset,
                svc.media_sink_service.available_type(),
                svc.media_sink_service.display_type(),
                svc.media_sink_service.display_id()
            );
        } else {
            let audio_config = service_audio_config(svc);
            sink.set_audio_stream_info(
                svc.media_sink_service.available_type(),
                svc.media_sink_service.audio_type(),
                audio_config,
            )
            .await;
            register_media_channel_sink(ctx, ch, sink).await;
            debug!(
                "{} media_channels.insert: ch={:#04x} offset={} media_order=audio_after_video",
                get_name(proxy_type),
                ch,
                offset
            );
            if let Some(acfg) = audio_config {
                info!(
                    "{} <blue>media tap:</> audio channel <b>{:#04x}</> → port offset <b>{}</> ({:?}, {:?}, {}Hz, {}ch, {}bit)",
                    get_name(proxy_type),
                    ch,
                    offset,
                    svc.media_sink_service.available_type(),
                    svc.media_sink_service.audio_type(),
                    acfg.sample_rate,
                    acfg.channels,
                    acfg.bits
                );
            } else {
                info!(
                    "{} <blue>media tap:</> audio channel <b>{:#04x}</> → port offset <b>{}</> ({:?}, {:?})",
                    get_name(proxy_type),
                    ch,
                    offset,
                    svc.media_sink_service.available_type(),
                    svc.media_sink_service.audio_type()
                );
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OdometerData {
    /// Odometer reading in kilometers
    pub odometer_km: f32,
    /// Trip odometer in kilometers (optional)
    pub trip_km: Option<f32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TirePressureData {
    /// Tire pressure in kPa, in order: front-left, front-right, rear-left, rear-right
    pub pressures_kpa: Vec<f32>,
}

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum ProxyType {
    HeadUnit,
    MobileDevice,
}

/// Action returned by [`pkt_modify_hook`] and [`handle_hu_input`].
///
/// The main loop uses this to decide what to do with the packet after
/// the hook has run.
#[derive(Debug, PartialEq)]
pub enum PacketAction {
    /// Forward the packet to the other side in the normal way.
    Forward,
    /// Drop the packet entirely — do not transmit it anywhere.
    Drop,
    /// Send the packet back toward the originating side (crafted reply).
    SendBack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketFlow {
    /// Packet observed on endpoint reader path (device -> proxy).
    FromEndpoint,
    /// Packet observed on forwarding path (proxy -> endpoint).
    ToEndpoint,
}

/// rust-openssl doesn't support BIO_s_mem
/// This SslMemBuf is about to provide `Read` and `Write` implementations
/// to be used with `openssl::ssl::SslStream`
/// more info:
/// https://github.com/sfackler/rust-openssl/issues/1697
type LocalDataBuffer = Arc<Mutex<VecDeque<u8>>>;
#[derive(Clone)]
pub struct SslMemBuf {
    /// a data buffer that the server writes to and the client reads from
    pub server_stream: LocalDataBuffer,
    /// a data buffer that the client writes to and the server reads from
    pub client_stream: LocalDataBuffer,
}

// Read implementation used internally by OpenSSL
impl Read for SslMemBuf {
    fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        self.client_stream.lock().unwrap().read(buf)
    }
}

// Write implementation used internally by OpenSSL
impl Write for SslMemBuf {
    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        self.server_stream.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
        self.server_stream.lock().unwrap().flush()
    }
}

// Own functions for accessing shared data
impl SslMemBuf {
    fn read_to(&mut self, buf: &mut Vec<u8>) -> std::result::Result<usize, std::io::Error> {
        self.server_stream.lock().unwrap().read_to_end(buf)
    }
    fn write_from(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        self.client_stream.lock().unwrap().write(buf)
    }
}

pub struct Packet {
    pub channel: u8,
    pub flags: u8,
    pub final_length: Option<u32>,
    pub payload: Vec<u8>,
}

impl Packet {
    /// payload encryption if needed
    async fn encrypt_payload(
        &mut self,
        mem_buf: &mut SslMemBuf,
        server: &mut openssl::ssl::SslStream<SslMemBuf>,
    ) -> Result<()> {
        if (self.flags & ENCRYPTED) == ENCRYPTED {
            // save plain data for encryption
            server.ssl_write(&self.payload)?;
            // read encrypted data
            let mut res: Vec<u8> = Vec::new();
            mem_buf.read_to(&mut res)?;
            self.payload = res;
        }

        Ok(())
    }

    /// payload decryption if needed
    async fn decrypt_payload(
        &mut self,
        mem_buf: &mut SslMemBuf,
        server: &mut openssl::ssl::SslStream<SslMemBuf>,
    ) -> Result<()> {
        if (self.flags & ENCRYPTED) == ENCRYPTED {
            // save encrypted data
            mem_buf.write_from(&self.payload)?;
            // read plain data
            let mut res: Vec<u8> = Vec::new();
            server.read_to_end(&mut res)?;
            self.payload = res;
        }

        Ok(())
    }

    /// composes a final frame and transmits it to endpoint device (HU/MD)
    async fn transmit<A: Endpoint<A>>(
        &self,
        device: &mut IoDevice<A>,
    ) -> std::result::Result<usize, std::io::Error> {
        let len = self.payload.len() as u16;
        let mut frame: Vec<u8> = vec![];
        frame.push(self.channel);
        frame.push(self.flags);
        frame.push((len >> 8) as u8);
        frame.push((len & 0xff) as u8);
        if let Some(final_len) = self.final_length {
            // adding addional 4-bytes of final_len header
            frame.push((final_len >> 24) as u8);
            frame.push((final_len >> 16) as u8);
            frame.push((final_len >> 8) as u8);
            frame.push((final_len & 0xff) as u8);
        }
        match device {
            IoDevice::UsbWriter(device, _) => {
                frame.append(&mut self.payload.clone());
                let mut dev = device.borrow_mut();
                dev.write(&frame).await
            }
            IoDevice::EndpointIo(device) => {
                frame.append(&mut self.payload.clone());
                device.write(frame).submit().await.0
            }
            IoDevice::TcpStreamIo(device) => {
                frame.append(&mut self.payload.clone());
                device.write(frame).submit().await.0
            }
            _ => todo!(),
        }
    }

    /// decapsulates SSL payload and writes to SslStream
    async fn ssl_decapsulate_write(&self, mem_buf: &mut SslMemBuf) -> Result<()> {
        let message_type = u16::from_be_bytes(self.payload[0..=1].try_into()?);
        if message_type == ControlMessageType::MESSAGE_ENCAPSULATED_SSL as u16 {
            mem_buf.write_from(&self.payload[2..])?;
        }
        Ok(())
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "packet dump:\n")?;
        write!(f, " channel: {:02X}\n", self.channel)?;
        write!(f, " flags: {:02X}\n", self.flags)?;
        write!(f, " final length: {:04X?}\n", self.final_length)?;
        write!(f, " payload: {:02X?}\n", self.payload.clone().into_iter())?;

        Ok(())
    }
}

fn choose_bt_sco_microphone_source(
    msg: &ServiceDiscoveryResponse,
) -> Option<(u8, AudioStreamConfig, i32)> {
    let mut best: Option<(i32, u8, AudioStreamConfig)> = None;

    for svc in msg.services.iter() {
        let source = &svc.media_source_service;
        if source.audio_config.is_none() {
            continue;
        }
        if source.available_type() != MediaCodecType::MEDIA_CODEC_AUDIO_PCM {
            continue;
        }

        let acfg = source.audio_config.as_ref().unwrap();
        let cfg = AudioStreamConfig {
            sample_rate: acfg.sampling_rate(),
            channels: acfg.number_of_channels(),
            bits: acfg.number_of_bits(),
        };

        let format_score = if cfg.sample_rate == 16_000 && cfg.channels == 1 && cfg.bits == 16 {
            0
        } else if cfg.sample_rate == 8_000 && cfg.channels == 1 && cfg.bits == 16 {
            10
        } else {
            (cfg.sample_rate as i32 - 16_000).abs() / 1000
                + (cfg.channels as i32 - 1).abs() * 20
                + (cfg.bits as i32 - 16).abs() * 10
                + 50
        };

        let call_score = if source.available_while_in_call() {
            0
        } else {
            5
        };
        let score = format_score + call_score;

        if best
            .as_ref()
            .map(|(best_score, _, _)| score < *best_score)
            .unwrap_or(true)
        {
            best = Some((score, svc.id() as u8, cfg));
        }
    }

    best.map(|(score, channel, cfg)| (channel, cfg, score))
}

#[cfg(not(feature = "wasm-scripting"))]
async fn run_wasm_hooks(
    _proxy_type: ProxyType,
    _pkt: &mut Packet,
    _ctx: &mut ModifyContext,
    _cfg: &AppConfig,
    _script_registry: Option<&ScriptRegistry>,
) -> Result<Option<bool>> {
    Ok(None)
}

#[cfg(feature = "wasm-scripting")]
async fn run_wasm_hooks(
    proxy_type: ProxyType,
    pkt: &mut Packet,
    ctx: &mut ModifyContext,
    cfg: &AppConfig,
    script_registry: Option<&ScriptRegistry>,
) -> Result<Option<bool>> {
    let Some(registry) = script_registry else {
        return Ok(None);
    };

    let loaded: Vec<LoadedScript> = registry.list_scripts();
    if loaded.is_empty() {
        return Ok(None);
    }

    for script in loaded {
        let wasm_ctx = to_wasm_modify_context(ctx);
        let wasm_pkt = to_wasm_packet(
            match proxy_type {
                ProxyType::HeadUnit => ScriptProxyType::HeadUnit,
                ProxyType::MobileDevice => ScriptProxyType::MobileDevice,
            },
            pkt,
        )?;
        let wasm_cfg = to_wasm_cfg(cfg);

        match script
            .engine
            .modify_packet(wasm_ctx, wasm_pkt, wasm_cfg)
            .await
        {
            Ok((decision, effects)) => {
                if let Some(replacement) = effects.replacement {
                    apply_wasm_packet(pkt, replacement);
                }

                for out in effects.packets {
                    if let Some(tx) = ctx.hu_tx.clone() {
                        tx.send(from_wasm_packet(out)).await?;
                    }
                }

                match decision {
                    Decision::Forward => {}
                    Decision::Drop => {
                        log::info!("wasm script {} dropped packet", script.path.display());
                        return Ok(Some(true));
                    }
                }
            }
            Err(err) => {
                log::warn!(
                    "wasm script runtime error [{}], forwarding original packet: {err:#}",
                    script.path.display()
                );
            }
        }
    }

    Ok(Some(false))
}

fn choose_bt_sco_media_bridge_sink(
    msg: &ServiceDiscoveryResponse,
    preferred_audio_type: BtScoMediaBridgeAudioType,
) -> Option<(u8, AudioStreamConfig, AudioStreamType, i32)> {
    let mut best: Option<(i32, u8, AudioStreamConfig, AudioStreamType)> = None;

    for svc in msg.services.iter() {
        let sink = &svc.media_sink_service;
        if sink.audio_configs.is_empty() {
            continue;
        }
        if sink.available_type() != MediaCodecType::MEDIA_CODEC_AUDIO_PCM {
            continue;
        }

        let audio_type = sink.audio_type();
        let audio_type_score = match preferred_audio_type {
            // Call-audio mode: try GUIDANCE first because several HUs mute MEDIA
            // while a phone call/microphone session is active.
            // Call-audio mode: try GUIDANCE first because several HUs mute MEDIA
            // while a phone call/microphone session is active.
            BtScoMediaBridgeAudioType::Guidance => match audio_type {
                AUDIO_STREAM_GUIDANCE => 0,
                AUDIO_STREAM_MEDIA => 40,
                AUDIO_STREAM_SYSTEM_AUDIO => 80,
                _ => 120,
            },
            BtScoMediaBridgeAudioType::Media => match audio_type {
                AUDIO_STREAM_MEDIA => 0,
                AUDIO_STREAM_GUIDANCE => 40,
                AUDIO_STREAM_SYSTEM_AUDIO => 80,
                _ => 120,
            },
            // Legacy behaviour: prefer normal media first.
            BtScoMediaBridgeAudioType::Auto => match audio_type {
                AUDIO_STREAM_MEDIA => 0,
                AUDIO_STREAM_GUIDANCE => 40,
                AUDIO_STREAM_SYSTEM_AUDIO => 80,
                _ => 120,
            },
        };

        for acfg in sink.audio_configs.iter() {
            let cfg = AudioStreamConfig {
                sample_rate: acfg.sampling_rate(),
                channels: acfg.number_of_channels(),
                bits: acfg.number_of_bits(),
            };

            let ideal_channels = match audio_type {
                AUDIO_STREAM_GUIDANCE => 1,
                _ => 2,
            };

            let format_score =
                if cfg.sample_rate == 48_000 && cfg.channels == ideal_channels && cfg.bits == 16 {
                    0
                } else {
                    (cfg.sample_rate as i32 - 48_000).abs() / 1000
                        + (cfg.channels as i32 - ideal_channels as i32).abs() * 20
                        + (cfg.bits as i32 - 16).abs() * 5
                };

            let score = audio_type_score + format_score;
            match best {
                Some((best_score, _, _, _)) if best_score <= score => {}
                _ => best = Some((score, svc.id() as u8, cfg, audio_type)),
            }
        }
    }

    best.map(|(score, channel, cfg, audio_type)| (channel, cfg, audio_type, score))
}

async fn update_last_service_discovery_response(
    proxy_type: ProxyType,
    last_service_discovery_response: &SharedServiceDiscoveryResponse,
    msg: &ServiceDiscoveryResponse,
) {
    match protobuf_json_mapping::print_to_string(msg) {
        Ok(json_string) => match serde_json::from_str::<serde_json::Value>(&json_string) {
            Ok(json_value) => {
                *last_service_discovery_response.write().await = Some(json_value);
            }
            Err(e) => {
                warn!(
                    "{} failed to parse protobuf JSON ServiceDiscoveryResponse: {}",
                    get_name(proxy_type),
                    e
                );
            }
        },
        Err(e) => {
            warn!(
                "{} failed to convert ServiceDiscoveryResponse to JSON: {}",
                get_name(proxy_type),
                e
            );
        }
    }
}

/// packet modification hook
pub async fn pkt_modify_hook(
    proxy_type: ProxyType,
    flow: PacketFlow,
    pkt: &mut Packet,
    ctx: &mut ModifyContext,
    tap_media: bool,
    sensor_channel: Arc<tokio::sync::Mutex<Option<u8>>>,
    input_channel: Arc<tokio::sync::Mutex<Option<u8>>>,
    last_battery: Arc<RwLock<Option<BatteryData>>>,
    last_speed: Arc<RwLock<Option<i32>>>,
    last_service_discovery_response: SharedServiceDiscoveryResponse,
    cfg: &AppConfig,
    config: &mut SharedConfig,
    script_registry: Option<Arc<ScriptRegistry>>,
    ws_event_tx: BroadcastSender<ServerEvent>,
) -> Result<PacketAction> {
    // if for some reason we have too small packet, bail out
    if pkt.payload.len() < 2 {
        return Ok(PacketAction::Forward);
    }

    if let Some(handled) =
        run_wasm_hooks(proxy_type, pkt, ctx, cfg, script_registry.as_deref()).await?
    {
        match handled {
            true => return Ok(PacketAction::SendBack),
            false => {}
        }
    }

    // HU button interception (only active when a handler command is configured)
    if proxy_type == ProxyType::HeadUnit && cfg.hu_button_handler.is_some() {
        if let Some(input_ch) = ctx.input_channel {
            let action = handle_hu_input(
                pkt,
                &mut ctx.hu_input_state,
                ctx.hu_tx.as_ref(),
                input_ch,
                cfg.hu_button_handler.as_deref(),
            )
            .await;

            match action {
                PacketAction::Drop => {
                    debug!("{} hu_input: packet dropped", get_name(proxy_type));
                    return Ok(PacketAction::Drop);
                }
                PacketAction::SendBack => {
                    debug!("{} hu_input: sending packet back", get_name(proxy_type));
                    return Ok(PacketAction::SendBack);
                }
                PacketAction::Forward => {}
            }
        }
    }

    // message_id is the first 2 bytes of payload
    let message_id: i32 = u16::from_be_bytes(pkt.payload[0..=1].try_into()?).into();
    let data = &pkt.payload[2..]; // start of message data

    // handling data on sensor channel
    if let Some(ch) = ctx.sensor_channel {
        if ch == pkt.channel {
            match protos::SensorMessageId::from_i32(message_id).unwrap_or(SENSOR_MESSAGE_ERROR) {
                SENSOR_MESSAGE_REQUEST => {
                    if let Ok(mut msg) = SensorRequest::parse_from_bytes(data) {
                        if msg.type_() == SensorType::SENSOR_VEHICLE_ENERGY_MODEL_DATA {
                            let has_sensor_fuel = ctx
                                .sensors
                                .as_ref()
                                .map(|sensors| {
                                    sensors
                                        .iter()
                                        .any(|sensor| sensor.sensor_type() == SENSOR_FUEL)
                                })
                                .unwrap_or(false);

                            info!(
                                "{} EV: AA requested SENSOR_VEHICLE_ENERGY_MODEL_DATA; ev_battery_logger={} has_sensor_fuel={}",
                                get_name(proxy_type),
                                cfg.ev_battery_logger.is_some(),
                                has_sensor_fuel
                            );

                            // check if we have some battery logger configured and the car doesn't
                            // provide SENSOR_FUEL
                            if cfg.ev_battery_logger.is_some() || !has_sensor_fuel {
                                debug!(
                                    "additional SENSOR_MESSAGE_REQUEST for {:?}, making a response with success...",
                                    msg.type_()
                                );
                                let mut response = SensorResponse::new();
                                response.set_status(MessageStatus::STATUS_SUCCESS);

                                let mut payload: Vec<u8> = response.write_to_bytes()?;
                                payload.insert(0, ((SENSOR_MESSAGE_RESPONSE as u16) >> 8) as u8);
                                payload.insert(1, ((SENSOR_MESSAGE_RESPONSE as u16) & 0xff) as u8);

                                let reply = Packet {
                                    channel: ch,
                                    flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
                                    final_length: None,
                                    payload,
                                };
                                *pkt = reply;

                                return Ok(PacketAction::SendBack);
                            } else {
                                // MD requests the energy model sensor from the HU. Since we do not
                                // have any data logger configured for EV data, we assume the following
                                // scenario: the vehicle provides battery level data via SENSOR_FUEL.
                                //
                                // Therefore, we redirect the request to SENSOR_FUEL so that the HU
                                // starts streaming real fuel_data (no need to start eg ABRP on phone).
                                //
                                // We will inject the ENERGY_MODEL_DATA on every SENSOR_MESSAGE_BATCH
                                // that contains fuel_data (see below).
                                info!(
                                    "{} EV: AA requested SENSOR_VEHICLE_ENERGY_MODEL_DATA \
                                     → redirecting to SENSOR_FUEL",
                                    get_name(proxy_type)
                                );
                                msg.set_type(SensorType::SENSOR_FUEL);

                                let mut payload = msg.write_to_bytes()?;
                                payload.insert(0, ((SENSOR_MESSAGE_REQUEST as u16) >> 8) as u8);
                                payload.insert(1, ((SENSOR_MESSAGE_REQUEST as u16) & 0xff) as u8);
                                pkt.payload = payload;

                                // return false = forward the modified request to the HU,
                                // do not send an early reply
                                return Ok(PacketAction::Forward);
                            }
                        }
                    }
                }
                SENSOR_MESSAGE_BATCH => {
                    if let Ok(mut msg) = SensorBatch::parse_from_bytes(data) {
                        if cfg.video_in_motion || cfg.disable_driving_status {
                            // === DRIVING STATUS: must be UNRESTRICTED (0) ===
                            // This is the primary flag AA checks. Value is a bitmask:
                            // 0 = unrestricted, 1 = no video, 2 = no keyboard, etc.
                            if !msg.driving_status_data.is_empty() {
                                msg.driving_status_data[0].set_status(0);
                            }
                        }

                        if cfg.video_in_motion {
                            // === GEAR: force PARK ===
                            if !msg.gear_data.is_empty() {
                                msg.gear_data[0].set_gear(GEAR_PARK);
                            }

                            // === PARKING BRAKE: engaged ===
                            // Modern AA cross-checks parking brake with gear/speed.
                            if !msg.parking_brake_data.is_empty() {
                                msg.parking_brake_data[0].set_parking_brake(true);
                            }

                            // === VEHICLE SPEED: zero ===
                            // SpeedData.speed_e3 is speed in m/s * 1000. Zero = stopped.
                            if !msg.speed_data.is_empty() {
                                msg.speed_data[0].set_speed_e3(0);
                                // Also ensure cruise control is disengaged
                                msg.speed_data[0].set_cruise_engaged(false);
                            }

                            // === GPS/LOCATION: zero speed, keep position ===
                            // LocationData.speed_e3 is GPS-derived speed.
                            // Modern AA compares this against SpeedData for consistency.
                            if !msg.location_data.is_empty() {
                                msg.location_data[0].set_speed_e3(0);
                                // Zero bearing = not turning
                                msg.location_data[0].set_bearing_e6(0);
                            }

                            // === ACCELEROMETER: gravity only (stationary) ===
                            // A parked car only feels gravity on Z axis (~9810 mm/s²).
                            // Any X/Y acceleration implies movement/turning.
                            if !msg.accelerometer_data.is_empty() {
                                msg.accelerometer_data[0].set_acceleration_x_e3(0);
                                msg.accelerometer_data[0].set_acceleration_y_e3(0);
                                msg.accelerometer_data[0].set_acceleration_z_e3(9810);
                            }

                            // === GYROSCOPE: zero rotation ===
                            // Any rotation speed implies the vehicle is turning.
                            if !msg.gyroscope_data.is_empty() {
                                msg.gyroscope_data[0].set_rotation_speed_x_e3(0);
                                msg.gyroscope_data[0].set_rotation_speed_y_e3(0);
                                msg.gyroscope_data[0].set_rotation_speed_z_e3(0);
                            }

                            // === DEAD RECKONING: zero wheel speed + steering ===
                            // Wheel speed ticks and steering angle are used by Toyota
                            // and other modern HUs as independent motion verification.
                            if !msg.dead_reckoning_data.is_empty() {
                                msg.dead_reckoning_data[0].set_steering_angle_e1(0);
                                msg.dead_reckoning_data[0].wheel_speed_e3.clear();
                                // Push four zero values for the four wheels
                                msg.dead_reckoning_data[0].wheel_speed_e3.push(0);
                                msg.dead_reckoning_data[0].wheel_speed_e3.push(0);
                                msg.dead_reckoning_data[0].wheel_speed_e3.push(0);
                                msg.dead_reckoning_data[0].wheel_speed_e3.push(0);
                            }

                            // === COMPASS: freeze bearing ===
                            // Changing compass bearing implies turning/moving.
                            if !msg.compass_data.is_empty() {
                                msg.compass_data[0].set_pitch_e6(0);
                                msg.compass_data[0].set_roll_e6(0);
                            }

                            // === RPM: idle engine ===
                            // High RPM with zero speed is suspicious on some HUs.
                            // ~700 RPM idle is realistic for a parked car.
                            if !msg.rpm_data.is_empty() {
                                msg.rpm_data[0].set_rpm_e3(700_000);
                            }

                            // Regenerate payload with ALL spoofed fields
                            pkt.payload = msg.write_to_bytes()?;
                            pkt.payload.insert(0, (message_id >> 8) as u8);
                            pkt.payload.insert(1, (message_id & 0xff) as u8);
                        }

                        if cfg.collect_speed {
                            if !msg.speed_data.is_empty() {
                                let speed_e3 = msg.speed_data[0].speed_e3();

                                match speed_e3.try_into() {
                                    Ok(speed) => {
                                        *last_speed.write().await = Some(speed);

                                        let _ = ws_event_tx.send(ServerEvent {
                                            topic: "speed".to_string(),
                                            payload: speed_e3.to_string(),
                                        });
                                    }
                                    Err(e) => {
                                        warn!(
                                            "invalid speed_e3 value {}, ignoring speed sample: {:?}",
                                            speed_e3, e
                                        );
                                    }
                                }
                            }
                        }

                        if cfg.odometer {
                            if !msg.odometer_data.is_empty() {
                                let od_json = serde_json::json!({
                                    "kms": msg.odometer_data[0].kms_e1(),
                                    "trip_kms": msg.odometer_data[0].trip_kms_e1(),
                                });

                                let payload = od_json.to_string();

                                //Send to ws
                                let _ = ws_event_tx.send(ServerEvent {
                                    topic: "odometer".to_string(),
                                    payload: payload,
                                });
                            }
                        }

                        // Parse fuel_data from HU SensorBatch (HU proxy only).
                        // The HU sends SENSOR_FUEL data in response to our earlier
                        // SENSOR_MESSAGE_REQUEST
                        // We use the SoC to populate the EV model for MD/Android
                        if cfg.ev && proxy_type == ProxyType::HeadUnit && !msg.fuel_data.is_empty()
                        {
                            let soc = msg.fuel_data[0].fuel_level();
                            info!(
                                "{} EV: received fuel_data from HU, SoC={}, sending as model...",
                                get_name(proxy_type),
                                soc
                            );
                            if let (Some(htx), Some(ch)) = (ctx.hu_tx.clone(), ctx.sensor_channel) {
                                let _ = send_ev_data(
                                    htx,
                                    ch,
                                    BatteryData {
                                        battery_level_percentage: Some(soc as f32),
                                        battery_level_wh: None,
                                        battery_capacity_wh: None,
                                        reference_air_density: None,
                                        external_temp_celsius: None,
                                    },
                                    last_battery,
                                )
                                .await;
                            }
                        }
                    }
                }
                _ => (),
            }
            // end sensors processing
            return Ok(PacketAction::Forward);
        }
    }

    // apply waze workaround on navigation data
    if let Some(ch) = ctx.nav_channel {
        // check for channel and a specific packet header only
        if ch == pkt.channel
            && proxy_type == ProxyType::HeadUnit
            && pkt.payload[0] == 0x80
            && pkt.payload[1] == 0x06
            && pkt.payload[2] == 0x0A
        {
            if let Ok(mut msg) = NavigationState::parse_from_bytes(&data) {
                if msg.steps[0].maneuver.type_() == U_TURN_LEFT {
                    msg.steps[0]
                        .maneuver
                        .as_mut()
                        .unwrap()
                        .set_type(U_TURN_RIGHT);
                    info!(
                        "{} swapped U_TURN_LEFT to U_TURN_RIGHT",
                        get_name(proxy_type)
                    );

                    // rewrite payload to new message contents
                    pkt.payload = msg.write_to_bytes()?;
                    // inserting 2 bytes of message_id at the beginning
                    pkt.payload.insert(0, (message_id >> 8) as u8);
                    pkt.payload.insert(1, (message_id & 0xff) as u8);
                    return Ok(PacketAction::Forward);
                }
            }
            // end navigation service processing
            return Ok(PacketAction::Forward);
        }
    }

    // if configured, override max_unacked for matching audio channels
    if cfg.audio_max_unacked > 0
        && ctx.audio_channels.contains(&pkt.channel)
        && proxy_type == ProxyType::HeadUnit
    {
        match protos::MediaMessageId::from_i32(message_id).unwrap_or(MEDIA_MESSAGE_DATA) {
            m @ MEDIA_MESSAGE_CONFIG => {
                if let Ok(mut msg) = AudioConfig::parse_from_bytes(&data) {
                    // get previous/original value
                    let prev_val = msg.max_unacked();
                    // set new value
                    msg.set_max_unacked(cfg.audio_max_unacked.into());

                    info!(
                        "{} <yellow>{:?}</>: overriding max audio unacked from <b>{}</> to <b>{}</> for channel: <b>{:#04x}</>",
                        get_name(proxy_type),
                        m,
                        prev_val,
                        cfg.audio_max_unacked,
                        pkt.channel,
                    );

                    // FIXME: this code fragment is used multiple times
                    // rewrite payload to new message contents
                    pkt.payload = msg.write_to_bytes()?;
                    // inserting 2 bytes of message_id at the beginning
                    pkt.payload.insert(0, (message_id >> 8) as u8);
                    pkt.payload.insert(1, (message_id & 0xff) as u8);
                    return Ok(PacketAction::Forward);
                }
                // end processing
                return Ok(PacketAction::Forward);
            }
            _ => (),
        }
    }

    if cfg.bt_sco
        && cfg.bt_sco_media_bridge
        && proxy_type == ProxyType::MobileDevice
        && pkt.channel != 0
        && message_id == MEDIA_MESSAGE_CONFIG as i32
    {
        if let Ok(msg) = AudioConfig::parse_from_bytes(data) {
            bt_sco_media_bridge::notify_media_config(pkt.channel, &msg);
        }
    }

    if cfg.bt_sco
        && cfg.bt_sco_mic_bridge
        && proxy_type == ProxyType::MobileDevice
        && pkt.channel != 0
    {
        match protos::MediaMessageId::from_i32(message_id).unwrap_or(MEDIA_MESSAGE_DATA) {
            MEDIA_MESSAGE_DATA => {
                if let Some((sample_rate, channels, bits)) =
                    bt_sco_media_bridge::microphone_source_config(pkt.channel)
                {
                    // AA media DATA payload is: uint64 timestamp/PTS followed by PCM bytes.
                    if data.len() >= 8 {
                        let mic_pcm = &data[8..];
                        bt_sco::push_sco_uplink_pcm_from_aa_mic(
                            mic_pcm,
                            sample_rate,
                            channels,
                            bits,
                            cfg.bt_sco_mic_uplink_ring_capacity,
                        );
                    } else {
                        warn!(
                            "{} <blue>bt-sco mic bridge:</> DATA on mic channel <b>{:#04x}</> too short: {} bytes",
                            get_name(proxy_type),
                            pkt.channel,
                            data.len()
                        );
                    }
                }
            }
            MEDIA_MESSAGE_MICROPHONE_RESPONSE => {
                bt_sco_media_bridge::notify_microphone_response(pkt.channel, data);
            }
            _ => {}
        }
    }

    // tap media frames for debug streaming (only on MobileDevice path = phone → HU direction)
    if tap_media && proxy_type == ProxyType::MobileDevice {
        if let Some(frame_data) = reassemble_media_packet(&mut ctx.media_fragments, pkt) {
            if frame_data.len() >= 2 {
                if let Some(sink) = media_sink_for_channel(ctx, pkt.channel).await {
                    tap_media_message(proxy_type, pkt, &sink, &frame_data).await;
                } else {
                    debug!(
                        "{} media tap: no sink registered for channel {:#04x}",
                        get_name(proxy_type),
                        pkt.channel
                    );
                }
            }
        }
    }

    let control = protos::ControlMessageType::from_i32(message_id);

    if pkt.channel != 0 {
        // Non-zero channel AAP lifecycle/control frame.
        // Keep this separate from our custom vendor app-data parser.
        // The custom parser below does not inspect CONTROL flags or AAP control message ids.
        if pkt.payload.len() >= 2 && (pkt.flags & _CONTROL) == _CONTROL {
            let control_msg_id = u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]);

            if control_msg_id == MESSAGE_CHANNEL_OPEN_REQUEST as u16 {
                let req = match ChannelOpenRequest::parse_from_bytes(&pkt.payload[2..]) {
                    Ok(req) => req,
                    Err(e) => {
                        error!(
                            "{} failed to parse non-zero CHANNEL_OPEN_REQUEST on channel {:#04x}: {}",
                            get_name(proxy_type),
                            pkt.channel,
                            e
                        );
                        return Ok(PacketAction::Forward);
                    }
                };

                let service_id = req.service_id() as u8;
                let is_our_vendor_service = is_vendor_service_id(ctx, service_id);

                debug!(
                    "{} non-zero CHANNEL_OPEN_REQUEST channel={:#04x} priority={} service_id={} vendor_match={}",
                    get_name(proxy_type),
                    pkt.channel,
                    req.priority(),
                    service_id,
                    is_our_vendor_service,
                );

                if is_our_vendor_service {
                    let mut resp = ChannelOpenResponse::new();
                    resp.set_status(MessageStatus::STATUS_SUCCESS);

                    let payload = resp.write_to_bytes()?;
                    *pkt = build_control_reply_on_channel(
                        pkt.channel,
                        MESSAGE_CHANNEL_OPEN_RESPONSE,
                        payload,
                    );

                    mark_vendor_channel_open(ctx, pkt.channel);
                    let vec_event_runtime = VecTopicEventRuntime {
                        ws_event_tx: ws_event_tx.clone(),
                        script_registry: script_registry.clone(),
                    };
                    ensure_vendor_topic_event_bridge(ctx, pkt.channel, vec_event_runtime);

                    info!(
                        "{} accepted injected VEC open channel={:#04x} service_id={}; custom app messages will be handled locally",
                        get_name(proxy_type),
                        pkt.channel,
                        service_id,
                    );

                    return Ok(PacketAction::SendBack);
                }
            }
        }

        // Vendor-extension app-data is not an AAP control message, so it must be
        // intercepted before the generic non-zero-channel forward guard below.
        if is_vendor_channel(ctx, pkt.channel) {
            debug!(
                "{} intercepted VEC app-data packet channel=<b>{:#04x}</> len={} proxy_type={:?} state={:?}",
                get_name(proxy_type),
                pkt.channel,
                pkt.payload.len(),
                proxy_type,
                ctx.vendor_channel_states.get(&pkt.channel),
            );

            let vec_event_runtime = VecTopicEventRuntime {
                ws_event_tx: ws_event_tx.clone(),
                script_registry: script_registry.clone(),
            };
            return handle_vendor_channel_packet(pkt, ctx, vec_event_runtime).await;
        }

        let control_allowed_on_service_channel = matches!(
            control,
            Some(MESSAGE_CHANNEL_OPEN_REQUEST | MESSAGE_CHANNEL_OPEN_RESPONSE)
        );

        if !control_allowed_on_service_channel {
            return Ok(PacketAction::Forward);
        }
    }

    // trying to obtain an Enum from message_id
    debug!(
        "message_id = {:04X}, {:?}, proxy_type: {:?}, flow: {:?}",
        message_id, control, proxy_type, flow
    );

    // parsing data
    match control.unwrap_or(MESSAGE_UNEXPECTED_MESSAGE) {
        MESSAGE_BYEBYE_REQUEST => {
            if cfg.stop_on_disconnect && proxy_type == ProxyType::MobileDevice {
                if let Ok(msg) = ByeByeRequest::parse_from_bytes(data) {
                    if msg.reason.unwrap_or_default() == USER_SELECTION.into() {
                        info!(
                        "{} <bold><blue>Disconnect</> option selected in Android Auto; auto-connect temporarily disabled",
                        get_name(proxy_type),
                    );
                        config.write().await.action_requested = Some(Stop);
                    }
                }
            }
        }
        MESSAGE_CHANNEL_OPEN_REQUEST => {
            let msg = match ChannelOpenRequest::parse_from_bytes(data) {
                Err(e) => {
                    error!(
                        "{} error parsing ChannelOpenRequest: {}, ignored!",
                        get_name(proxy_type),
                        e
                    );
                    return Ok(PacketAction::Forward);
                }
                Ok(msg) => msg,
            };

            let service_id = msg.service_id() as u8;

            // display code
            let injected = ctx.injected_service_ids.contains(&msg.service_id());
            let hu_known = ctx.hu_service_ids.contains(&msg.service_id());

            info!(
                "{} <blue>ChannelOpenRequest:</> flow={:?}, service_id=<b>{}</>, priority={}, injected={}, hu_known={}",
                get_name(proxy_type),
                flow,
                service_id,
                msg.priority(),
                injected,
                hu_known
            );

            if injected {
                if proxy_type == ProxyType::HeadUnit && flow == PacketFlow::ToEndpoint {
                    // Keep injected services hidden from HU: answer locally with success.
                    ctx.injected_channels.insert(service_id);

                    let mut response = ChannelOpenResponse::new();
                    response.set_status(MessageStatus::STATUS_SUCCESS);
                    let mut payload = response.write_to_bytes()?;
                    payload.insert(0, ((MESSAGE_CHANNEL_OPEN_RESPONSE as u16) >> 8) as u8);
                    payload.insert(1, ((MESSAGE_CHANNEL_OPEN_RESPONSE as u16) & 0xff) as u8);
                    pkt.payload = payload;

                    info!(
                        "{} <yellow>transparency:</> synthesized CHANNEL_OPEN_RESPONSE for injected service_id <b>{}</>; HU path suppressed",
                        get_name(proxy_type),
                        service_id
                    );

                    // handled=true => send this reply packet back to MD side only.
                    return Ok(PacketAction::SendBack);
                }
            }

            // VEC code
            info!(
                "{} <yellow>{:?}</>: received CHANNEL_OPEN_REQUEST for service_id=<b>{:#04x}</> vendor_match={}",
                get_name(proxy_type),
                control.unwrap(),
                service_id,
                is_vendor_service_id(ctx, service_id),
            );

            // If the phone sends the synthetic vendor open as a normal channel-0
            // CHANNEL_OPEN_REQUEST, catch it in the proxy context that owns
            // vendor_service_ids. In current DHU traces the phone uses channel 0x08,
            // but real phones/HUs may use channel 0 for this control message.
            if is_vendor_service_id(ctx, service_id) {
                let mut response = ChannelOpenResponse::new();
                response.set_status(MessageStatus::STATUS_SUCCESS);

                let payload: Vec<u8> = response.write_to_bytes()?;
                *pkt = build_control_reply(MESSAGE_CHANNEL_OPEN_RESPONSE, payload);

                ensure_vendor_channel_open(ctx, service_id);
                let vec_event_runtime = VecTopicEventRuntime {
                    ws_event_tx: ws_event_tx.clone(),
                    script_registry: script_registry.clone(),
                };
                ensure_vendor_topic_event_bridge(ctx, service_id, vec_event_runtime);

                info!(
                    "{} <yellow>{:?}</>: accepted channel-0 open for injected VEC service_id=<b>{:#04x}</>; replying locally",
                    get_name(proxy_type),
                    control.unwrap(),
                    service_id,
                );

                return Ok(PacketAction::SendBack);
            }
        }
        MESSAGE_SERVICE_DISCOVERY_RESPONSE => {
            let mut msg = match ServiceDiscoveryResponse::parse_from_bytes(data) {
                Err(e) => {
                    error!(
                        "{} error parsing SDR: {}, ignored!",
                        get_name(proxy_type),
                        e
                    );
                    return Ok(PacketAction::Forward);
                }
                Ok(msg) => msg,
            };

            // Keep a semantic channel map for pkt_debug filters. This is updated
            // again after SDR rewriting/injected services below.
            update_debug_channel_kinds(ctx, &msg);

            if let Some(svc) = msg
                .services
                .iter()
                .find(|svc| !svc.sensor_source_service.sensors.is_empty())
            {
                ctx.sensors = Some(svc.sensor_source_service.sensors.clone());
            }

            if proxy_type == ProxyType::HeadUnit {
                ctx.hu_service_ids = msg.services.iter().map(|s| s.id()).collect();
            }

            if cfg.bt_sco && cfg.bt_sco_media_bridge && proxy_type == ProxyType::MobileDevice {
                if let Some((bridge_channel, acfg, audio_type, score)) =
                    choose_bt_sco_media_bridge_sink(&msg, cfg.bt_sco_media_bridge_audio_type)
                {
                    if let Some(tx) = ctx.hu_tx.clone() {
                        bt_sco_media_bridge::init_or_update(tx);
                        bt_sco_media_bridge::set_target_channel(
                            bridge_channel,
                            acfg.sample_rate,
                            acfg.channels,
                            acfg.bits,
                            cfg.bt_sco_media_bridge_gain_percent,
                            cfg.bt_sco_media_bridge_limiter,
                            cfg.bt_sco_media_bridge_start_existing,
                            cfg.bt_sco_media_bridge_start_on_first_audio,
                            cfg.bt_sco_media_bridge_audio_peak_threshold,
                            cfg.bt_sco_media_bridge_start_timeout_ms,
                            cfg.bt_sco_media_bridge_stop_existing_on_disconnect,
                            cfg.bt_sco_media_bridge_fixed_cadence,
                            cfg.bt_sco_media_bridge_cadence_ms,
                            cfg.bt_sco_media_bridge_jitter_buffer_ms,
                        );
                        info!(
                            "{} <blue>bt-sco media bridge:</> selected PCM sink channel=<b>{:#04x}</> ({:?}, {}Hz, {}ch, {}bit, preference={}, gain={}%, limiter={}, resampler={}, start_existing={}, start_on_first_audio={}, peak_threshold={}, start_timeout={}ms, stop_on_disconnect={}, fixed_cadence={}ms/{}, jitter_buffer={}ms, score={})",
                            get_name(proxy_type),
                            bridge_channel,
                            audio_type,
                            acfg.sample_rate,
                            acfg.channels,
                            acfg.bits,
                            cfg.bt_sco_media_bridge_audio_type,
                            cfg.bt_sco_media_bridge_gain_percent,
                            cfg.bt_sco_media_bridge_limiter,
                            cfg.bt_sco_media_bridge_resampler,
                            cfg.bt_sco_media_bridge_start_existing,
                            cfg.bt_sco_media_bridge_start_on_first_audio,
                            cfg.bt_sco_media_bridge_audio_peak_threshold,
                            cfg.bt_sco_media_bridge_start_timeout_ms,
                            cfg.bt_sco_media_bridge_stop_existing_on_disconnect,
                            cfg.bt_sco_media_bridge_cadence_ms,
                            cfg.bt_sco_media_bridge_fixed_cadence,
                            cfg.bt_sco_media_bridge_jitter_buffer_ms,
                            score
                        );
                    } else {
                        warn!(
                            "{} <blue>bt-sco media bridge:</> cannot start, HU tx is missing",
                            get_name(proxy_type)
                        );
                    }
                } else {
                    warn!(
                        "{} <blue>bt-sco media bridge:</> no usable PCM media sink found in SDR",
                        get_name(proxy_type)
                    );
                }
            }

            if cfg.bt_sco && cfg.bt_sco_mic_bridge && proxy_type == ProxyType::MobileDevice {
                if let Some((mic_channel, acfg, score)) = choose_bt_sco_microphone_source(&msg) {
                    if let Some(tx) = ctx.hu_tx.clone() {
                        bt_sco_media_bridge::init_or_update(tx);
                        bt_sco_media_bridge::set_microphone_source(
                            mic_channel,
                            acfg.sample_rate,
                            acfg.channels,
                            acfg.bits,
                            cfg.bt_sco_mic_request,
                        );
                        info!(
                            "{} <blue>bt-sco mic bridge:</> selected PCM microphone source channel=<b>{:#04x}</> ({}Hz, {}ch, {}bit, score={}, request={})",
                            get_name(proxy_type),
                            mic_channel,
                            acfg.sample_rate,
                            acfg.channels,
                            acfg.bits,
                            score,
                            cfg.bt_sco_mic_request
                        );
                    } else {
                        warn!(
                            "{} <blue>bt-sco mic bridge:</> cannot start, tx is missing",
                            get_name(proxy_type)
                        );
                    }
                } else {
                    warn!(
                        "{} <blue>bt-sco mic bridge:</> no usable PCM media_source/microphone source found in SDR",
                        get_name(proxy_type)
                    );
                }
            }

            // SDR rewriting is HeadUnit-only; MobileDevice sees SDR read-only (for channel map above)
            if proxy_type == ProxyType::MobileDevice {
                return Ok(PacketAction::Forward);
            }

            // DPI
            if cfg.dpi > 0 {
                if let Some(svc) = msg
                    .services
                    .iter_mut()
                    .find(|svc| !svc.media_sink_service.video_configs.is_empty())
                {
                    // get previous/original value
                    let prev_val = svc.media_sink_service.video_configs[0].density();
                    // set new value
                    svc.media_sink_service.as_mut().unwrap().video_configs[0]
                        .set_density(cfg.dpi.into());
                    info!(
                        "{} <yellow>{:?}</>: replacing DPI value: from <b>{}</> to <b>{}</>",
                        get_name(proxy_type),
                        control.unwrap(),
                        prev_val,
                        cfg.dpi
                    );
                }
            }

            // disable tts sink
            if cfg.disable_tts_sink {
                while let Some(svc) = msg.services.iter_mut().find(|svc| {
                    !svc.media_sink_service.audio_configs.is_empty()
                        && svc.media_sink_service.audio_type() == AUDIO_STREAM_GUIDANCE
                }) {
                    svc.media_sink_service
                        .as_mut()
                        .unwrap()
                        .set_audio_type(AUDIO_STREAM_SYSTEM_AUDIO);
                }
                info!(
                    "{} <yellow>{:?}</>: TTS sink disabled",
                    get_name(proxy_type),
                    control.unwrap(),
                );
            }

            // disable media sink
            if cfg.disable_media_sink {
                msg.services
                    .retain(|svc| svc.media_sink_service.audio_type() != AUDIO_STREAM_MEDIA);
                info!(
                    "{} <yellow>{:?}</>: media sink disabled",
                    get_name(proxy_type),
                    control.unwrap(),
                );
            }

            // save all audio sink channels in context
            if cfg.audio_max_unacked > 0 {
                for svc in msg
                    .services
                    .iter()
                    .filter(|svc| !svc.media_sink_service.audio_configs.is_empty())
                {
                    ctx.audio_channels.push(svc.id() as u8);
                }
                info!(
                    "{} <blue>media_sink_service:</> channels: <b>{:02x?}</>",
                    get_name(proxy_type),
                    ctx.audio_channels
                );
            }

            // save sensor channel in context
            if cfg.ev
                || cfg.video_in_motion
                || cfg.odometer
                || cfg.collect_speed
                || cfg.tire_pressure
            {
                if let Some(svc) = msg
                    .services
                    .iter()
                    .find(|svc| !svc.sensor_source_service.sensors.is_empty())
                {
                    // set in local context
                    ctx.sensor_channel = Some(svc.id() as u8);
                    // set in REST server context for remote EV requests
                    let mut sc_lock = sensor_channel.lock().await;
                    *sc_lock = Some(svc.id() as u8);

                    info!(
                        "{} <blue>sensor_source_service</> channel is: <b>{:#04x}</>",
                        get_name(proxy_type),
                        svc.id() as u8
                    );
                }
            }

            // save input source channel
            if let Some(svc) = msg
                .services
                .iter()
                .find(|svc| svc.input_source_service.is_some())
            {
                ctx.input_channel = Some(svc.id() as u8);
                let mut ic_lock = input_channel.lock().await;
                *ic_lock = Some(svc.id() as u8);
                info!(
                    "{} <blue>input_source_service</> channel is: <b>{:#04x}</>",
                    get_name(proxy_type),
                    svc.id() as u8
                );
            }

            // save navigation channel in context
            if cfg.waze_lht_workaround {
                if let Some(svc) = msg
                    .services
                    .iter()
                    .find(|svc| svc.navigation_status_service.is_some())
                {
                    // set in local context
                    ctx.nav_channel = Some(svc.id() as u8);

                    info!(
                        "{} <blue>navigation_status_service</> channel is: <b>{:#04x}</>",
                        get_name(proxy_type),
                        svc.id() as u8
                    );
                }
            }

            // remove tap restriction by removing SENSOR_SPEED
            if cfg.remove_tap_restriction && !cfg.collect_speed {
                if let Some(svc) = msg
                    .services
                    .iter_mut()
                    .find(|svc| !svc.sensor_source_service.sensors.is_empty())
                {
                    svc.sensor_source_service
                        .as_mut()
                        .unwrap()
                        .sensors
                        .retain(|s| s.sensor_type() != SENSOR_SPEED);
                }
            }

            // video_in_motion: strip motion-related sensors from SDR capabilities
            // and downgrade location_characterization so AA cannot cross-validate
            if cfg.video_in_motion {
                if let Some(svc) = msg
                    .services
                    .iter_mut()
                    .find(|svc| !svc.sensor_source_service.sensors.is_empty())
                {
                    // Remove sensor types that reveal vehicle motion.
                    // Keep DRIVING_STATUS, GEAR, PARKING_BRAKE, LOCATION (we spoof those)
                    // but remove the ones that are harder to spoof consistently per-HU.
                    let sensors_to_strip = [
                        SENSOR_ACCELEROMETER_DATA,
                        SENSOR_GYROSCOPE_DATA,
                        SENSOR_DEAD_RECKONING_DATA,
                        SENSOR_SPEED,
                    ];
                    svc.sensor_source_service
                        .as_mut()
                        .unwrap()
                        .sensors
                        .retain(|s| !sensors_to_strip.contains(&s.sensor_type()));

                    // Reset location_characterization to RAW_GPS_ONLY (256).
                    // This tells AA the HU does NOT fuse wheel speed, gyroscope,
                    // accelerometer, or dead reckoning into position fixes, so AA
                    // will not expect those signals for cross-validation.
                    svc.sensor_source_service
                        .as_mut()
                        .unwrap()
                        .set_location_characterization(256); // RAW_GPS_ONLY

                    info!(
                        "{} <yellow>{:?}</> video_in_motion: stripped motion sensors from SDR, location_characterization=RAW_GPS_ONLY",
                        get_name(proxy_type),
                        control.unwrap(),
                    );
                }
            }

            // enabling developer mode
            if cfg.developer_mode {
                msg.set_make(DHU_MAKE.into());
                msg.set_model(DHU_MODEL.into());
                msg.set_head_unit_make(DHU_MAKE.into());
                msg.set_head_unit_model(DHU_MODEL.into());
                if let Some(info) = msg.headunit_info.as_mut() {
                    info.set_make(DHU_MAKE.into());
                    info.set_model(DHU_MODEL.into());
                    info.set_head_unit_make(DHU_MAKE.into());
                    info.set_head_unit_model(DHU_MODEL.into());
                }
                info!(
                    "{} <yellow>{:?}</>: enabling developer mode",
                    get_name(proxy_type),
                    control.unwrap(),
                );
            }

            if cfg.remove_bluetooth {
                msg.services.retain(|svc| svc.bluetooth_service.is_none());
            }

            if cfg.remove_wifi {
                msg.services
                    .retain(|svc| svc.wifi_projection_service.is_none());
            }

            // EV routing features
            if cfg.ev {
                if let Some(svc) = msg
                    .services
                    .iter_mut()
                    .find(|svc| !svc.sensor_source_service.sensors.is_empty())
                {
                    info!(
                        "{} <yellow>{:?}</>: adding <b><green>EV</> features...",
                        get_name(proxy_type),
                        control.unwrap(),
                    );

                    // add VEHICLE_ENERGY_MODEL_DATA sensor
                    let mut sensor = Sensor::new();
                    sensor.set_sensor_type(SENSOR_VEHICLE_ENERGY_MODEL_DATA);
                    svc.sensor_source_service
                        .as_mut()
                        .unwrap()
                        .sensors
                        .push(sensor);

                    // set FUEL_TYPE
                    svc.sensor_source_service
                        .as_mut()
                        .unwrap()
                        .supported_fuel_types = vec![FuelType::FUEL_TYPE_ELECTRIC.into()];

                    // supported connector types
                    let connectors: Vec<EnumOrUnknown<EvConnectorType>> =
                        match &cfg.ev_connector_types.0 {
                            Some(types) => types.iter().map(|&t| t.into()).collect(),
                            None => {
                                vec![EvConnectorType::EV_CONNECTOR_TYPE_MENNEKES.into()]
                            }
                        };
                    info!(
                        "{} <yellow>{:?}</>: EV connectors: {:?}",
                        get_name(proxy_type),
                        control.unwrap(),
                        connectors,
                    );
                    svc.sensor_source_service
                        .as_mut()
                        .unwrap()
                        .supported_ev_connector_types = connectors;
                }

                // check if we have some battery logger configured
                if let Some(path) = &cfg.ev_battery_logger {
                    // start EV battery logger if needed
                    ctx.ev_tx
                        .send(EvTaskCommand::Start(path.to_string()))
                        .await?;
                }
            }

            // Odometer sensor
            if cfg.odometer {
                if let Some(svc) = msg
                    .services
                    .iter_mut()
                    .find(|svc| !svc.sensor_source_service.sensors.is_empty())
                {
                    info!(
                        "{} <yellow>{:?}</>: adding <b><green>ODOMETER</> sensor...",
                        get_name(proxy_type),
                        control.unwrap(),
                    );
                    let mut sensor = Sensor::new();
                    sensor.set_sensor_type(SENSOR_ODOMETER);
                    svc.sensor_source_service
                        .as_mut()
                        .unwrap()
                        .sensors
                        .push(sensor);
                }
            }

            // Tire pressure sensor
            if cfg.tire_pressure {
                if let Some(svc) = msg
                    .services
                    .iter_mut()
                    .find(|svc| !svc.sensor_source_service.sensors.is_empty())
                {
                    info!(
                        "{} <yellow>{:?}</>: adding <b><green>TIRE_PRESSURE</> sensor...",
                        get_name(proxy_type),
                        control.unwrap(),
                    );
                    let mut sensor = Sensor::new();
                    sensor.set_sensor_type(SENSOR_TIRE_PRESSURE_DATA);
                    svc.sensor_source_service
                        .as_mut()
                        .unwrap()
                        .sensors
                        .push(sensor);
                }
            }

            let added_services = add_display_services(&mut msg, cfg);
            if added_services > 0 {
                let before_ids: HashSet<i32> = ctx.hu_service_ids.clone();
                let after_ids: HashSet<i32> = msg.services.iter().map(|s| s.id()).collect();
                for sid in after_ids.difference(&before_ids) {
                    ctx.injected_service_ids.insert(*sid);
                    if let Some(svc) = msg.services.iter().find(|s| s.id() == *sid) {
                        if !svc.media_sink_service.video_configs.is_empty() {
                            ctx.injected_media_display
                                .insert(*sid as u8, svc.media_sink_service.display_type());
                        }
                    }
                }
                info!(
                    "{} <yellow>{:?}</>: injected <b>{}</> display service(s)",
                    get_name(proxy_type),
                    control.unwrap(),
                    added_services,
                );
                info!(
                    "{} <blue>injected service ids:</> <b>{:?}</>",
                    get_name(proxy_type),
                    ctx.injected_service_ids
                );
            }

            match sdr_ui::process_service_discovery_response(&mut msg, cfg).await {
                Ok(summary) => {
                    info!(
                        "{} <blue>SDR UI:</> vehicle=<b>{}</> ({}) profile_enabled={} phone_profile_enabled={} patch_applied={} patch_count={}",
                        get_name(proxy_type),
                        summary.vehicle_id,
                        summary.vehicle_name,
                        summary.vehicle_profile_enabled,
                        summary.phone_profile_enabled,
                        summary.patch_applied,
                        summary.patch_count,
                    );
                }
                Err(e) => {
                    warn!(
                        "{} <blue>SDR UI:</> failed to process overrides; forwarding original UI config: {:#}",
                        get_name(proxy_type),
                        e
                    );
                }
            }

            // add vendor channel as extra, do not touch existing HU channels
            // this must be last entry do not replace
            if cfg.add_vendor_channel {
                let already_present = has_vendor_extension_service(&msg);

                info!(
                    "{} SDR_TRACE add_vendor_channel requested; already_present={} current_ids={:?}",
                    get_name(proxy_type),
                    already_present,
                    msg.services.iter().map(|svc| svc.id()).collect::<Vec<_>>()
                );

                if let Some(service_id) = add_vendor_extension_service(&mut msg, ctx) {
                    info!(
                        "{} <yellow>{:?}</>: added extra <blue>vendor_extension_service</> id=<b>{:#04x}</> name=<b>{}</> package=<b>{}</>",
                        get_name(proxy_type),
                        control.unwrap(),
                        service_id,
                        OUR_VEC_SERVICE_NAME,
                        OUR_VEC_PACKAGE,
                    );
                }
            }

            // Refresh channel kinds after all SDR mutations, especially after adding
            // injected vendor/display services.
            update_debug_channel_kinds(ctx, &msg);

            // Populate media tap channels from the final rewritten SDR. Ports are opened
            // lazily and only for the media sinks actually present in this SDR.
            let media_sink_count = ctx.media_sinks.lock().await.len();
            debug!(
                "{} SDR handling: media_sinks.len()={} media_channels.len()={}",
                get_name(proxy_type),
                media_sink_count,
                ctx.media_channels.len()
            );
            populate_media_tap_channels_by_order(proxy_type, ctx, &msg).await;

            info!(
                "{} vendor_service_ids now = {:?}",
                get_name(proxy_type),
                ctx.vendor_service_ids
            );

            info!(
                "{} final SDR service ids: {:?}",
                get_name(proxy_type),
                msg.services.iter().map(|s| s.id()).collect::<Vec<_>>()
            );

            debug!(
                "{} SDR after changes: {}",
                get_name(proxy_type),
                protobuf::text_format::print_to_string_pretty(&msg)
            );

            update_last_service_discovery_response(
                proxy_type,
                &last_service_discovery_response,
                &msg,
            )
            .await;

            // rewrite payload to new message contents
            pkt.payload = msg.write_to_bytes()?;
            // inserting 2 bytes of message_id at the beginning
            pkt.payload.insert(0, (message_id >> 8) as u8);
            pkt.payload.insert(1, (message_id & 0xff) as u8);
        }
        MESSAGE_SERVICE_DISCOVERY_UPDATE => {
            if let Ok(msg) = ServiceDiscoveryUpdate::parse_from_bytes(data) {
                if let Some(service) = msg.service.as_ref() {
                    let sid = service.id();
                    let injected = ctx.injected_service_ids.contains(&sid);
                    let hu_advertised = ctx.hu_service_ids.contains(&sid);

                    info!(
                        "{} <blue>SDU:</> flow={:?}, service_id=<b>{}</>, injected={}, hu_advertised={}",
                        get_name(proxy_type),
                        flow,
                        sid,
                        injected,
                        hu_advertised
                    );

                    if proxy_type == ProxyType::HeadUnit && flow == PacketFlow::FromEndpoint {
                        ctx.hu_service_ids.insert(sid);
                    }
                } else {
                    info!(
                        "{} <blue>SDU:</> flow={:?}, no service payload",
                        get_name(proxy_type),
                        flow
                    );
                }
            }
        }
        _ => return Ok(PacketAction::Forward),
    };

    Ok(PacketAction::Forward)
}

pub async fn send_key_event(tx: Sender<Packet>, input_ch: u8, keycode: u32) -> Result<()> {
    let now_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;

    // Helper to build one InputReport (down=true or down=false)
    let build_pkt = |ch: u8, down: bool, flags: u8| -> Packet {
        let mut key = crate::mitm::protos::key_event::Key::new();
        key.set_keycode(keycode);
        key.set_down(down);
        key.set_metastate(0);
        key.set_longpress(false);

        let mut key_event = KeyEvent::new();
        key_event.keys.push(key);

        let mut report = InputReport::new();
        report.set_timestamp(now_us);
        report.key_event = protobuf::MessageField::some(key_event);

        let mut payload = report.write_to_bytes().expect("serialize InputReport");
        let msg_id = INPUT_MESSAGE_INPUT_REPORT as u16;
        payload.insert(0, (msg_id >> 8) as u8);
        payload.insert(1, (msg_id & 0xff) as u8);

        Packet {
            channel: ch,
            flags,
            final_length: None,
            payload,
        }
    };

    // Send key DOWN
    tx.send(build_pkt(
        input_ch,
        true,
        ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
    ))
    .await?;
    info!("mitm/web: injecting key DOWN (keycode={})", keycode);

    // Send key UP
    tx.send(build_pkt(
        input_ch,
        false,
        ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
    ))
    .await?;
    info!("mitm/web: injecting key UP (keycode={})", keycode);

    Ok(())
}

/// Injects a rotary dial turn event into the input channel.
/// delta: positive = clockwise, negative = counterclockwise
/// Per AAP spec: absolute value of 1 = single UI step, scales linearly
pub async fn send_rotary_event(tx: Sender<Packet>, input_ch: u8, delta: i32) -> Result<()> {
    let now_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;

    let mut rel = relative_event::Rel::new();
    rel.set_keycode(KeyCode::KEYCODE_ROTARY_CONTROLLER as u32);
    rel.set_delta(delta);

    let mut rel_event = RelativeEvent::new();
    rel_event.data.push(rel);

    let mut report = InputReport::new();
    report.set_timestamp(now_us);
    report.relative_event = protobuf::MessageField::some(rel_event);

    let mut payload = report.write_to_bytes()?;
    let msg_id = InputMessageId::INPUT_MESSAGE_INPUT_REPORT as u16;
    payload.insert(0, (msg_id >> 8) as u8);
    payload.insert(1, (msg_id & 0xff) as u8);

    let pkt = Packet {
        channel: input_ch,
        flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload,
    };

    tx.send(pkt).await?;
    info!("mitm/web: injecting ROTARY delta={}", delta);

    Ok(())
}

/// Inject a key input event on AA input channel.
/// FIXME: make single function from this and send_key_event above
pub async fn send_input_key(
    tx: Sender<Packet>,
    input_ch: u8,
    keycode: u32,
    down: bool,
    longpress: bool,
) -> Result<()> {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;

    let mut key = key_event::Key::new();
    key.set_keycode(keycode);
    key.set_down(down);
    key.set_metastate(0);
    key.set_longpress(longpress);

    let mut key_event = KeyEvent::new();
    key_event.keys.push(key);

    let mut input = InputReport::new();
    input.set_timestamp(ts);
    input.key_event = Some(key_event).into();

    let mut payload: Vec<u8> = input.write_to_bytes()?;
    payload.insert(0, ((INPUT_MESSAGE_INPUT_REPORT as u16) >> 8) as u8);
    payload.insert(1, ((INPUT_MESSAGE_INPUT_REPORT as u16) & 0xff) as u8);

    let pkt = Packet {
        channel: input_ch,
        flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload,
    };
    tx.send(pkt).await?;
    info!(
        "mitm/web: injecting INPUT_REPORT key packet (keycode={}, down={}, longpress={})...",
        keycode, down, longpress
    );

    Ok(())
}

/// Inject toll card presence data via sensor batch.
pub async fn send_toll_card(
    tx: Sender<Packet>,
    sensor_ch: u8,
    is_card_present: bool,
) -> Result<()> {
    let mut msg = SensorBatch::new();
    let mut toll = TollCardData::new();
    toll.set_is_card_present(is_card_present);
    msg.toll_card_data.push(toll);

    // creating back binary data for sending
    let mut payload: Vec<u8> = msg.write_to_bytes()?;
    // add SENSOR header
    payload.insert(0, ((SENSOR_MESSAGE_BATCH as u16) >> 8) as u8);
    payload.insert(1, ((SENSOR_MESSAGE_BATCH as u16) & 0xff) as u8);

    let pkt = Packet {
        channel: sensor_ch,
        flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload,
    };
    tx.send(pkt).await?;
    info!(
        "mitm/web: injecting TOLL_CARD_DATA packet (is_card_present={})...",
        is_card_present
    );

    Ok(())
}

/// Send a ByeByeRequest on the control channel (channel 0) to the phone,
/// requesting a clean AA session teardown with reason USER_SELECTION.
pub async fn send_byebye(tx: Sender<Packet>) -> Result<()> {
    let mut msg = ByeByeRequest::new();
    msg.set_reason(ByeByeReason::USER_SELECTION);

    let mut payload: Vec<u8> = msg.write_to_bytes()?;
    // prepend 2-byte message_id for MESSAGE_BYEBYE_REQUEST (= 15 = 0x000F)
    let msg_id = ControlMessageType::MESSAGE_BYEBYE_REQUEST as u16;
    payload.insert(0, (msg_id >> 8) as u8);
    payload.insert(1, (msg_id & 0xff) as u8);

    let pkt = Packet {
        channel: 0,
        flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload,
    };
    tx.send(pkt).await?;
    info!("mitm: Sending ByeByeRequest (USER_SELECTION) to phone...");
    Ok(())
}

pub async fn send_odometer_data(
    tx: Sender<Packet>,
    sensor_ch: u8,
    data: OdometerData,
    last_odometer: Arc<RwLock<Option<OdometerData>>>,
    ws_event_tx: BroadcastSender<ServerEvent>,
) -> Result<()> {
    let mut msg = SensorBatch::new();

    let mut od = protos::OdometerData::new();
    // kms_e1 stores kilometers in tenths (0.1 km resolution), so multiply by 10
    od.kms_e1 = Some((data.odometer_km * 10.0).round() as i32);
    if let Some(trip) = data.trip_km {
        od.trip_kms_e1 = Some((trip * 10.0).round() as i32);
    }

    let od_json = serde_json::json!({
        "kms": od.kms_e1,
        "trip_kms": od.trip_kms_e1,
    });

    msg.odometer_data.push(od);

    let payload = od_json.to_string();

    //Send to ws
    let _ = ws_event_tx.send(ServerEvent {
        topic: "odometer".to_string(),
        payload: payload,
    });

    let mut payload: Vec<u8> = msg.write_to_bytes()?;
    payload.insert(0, ((SENSOR_MESSAGE_BATCH as u16) >> 8) as u8);
    payload.insert(1, ((SENSOR_MESSAGE_BATCH as u16) & 0xff) as u8);

    let pkt = Packet {
        channel: sensor_ch,
        flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload,
    };
    tx.send(pkt).await?;
    info!(
        "mitm/web: injecting ODOMETER packet ({} km, trip: {:?} km)...",
        data.odometer_km, data.trip_km
    );

    *last_odometer.write().await = Some(data);
    Ok(())
}

pub async fn send_tire_pressure_data(
    tx: Sender<Packet>,
    sensor_ch: u8,
    data: TirePressureData,
    last_tire_pressure: Arc<RwLock<Option<TirePressureData>>>,
    ws_event_tx: BroadcastSender<ServerEvent>,
) -> Result<()> {
    let mut msg = SensorBatch::new();

    let mut tp = protos::TirePressureData::new();
    // tire_pressures_e2 stores kPa in hundredths (0.01 kPa resolution), so multiply by 100
    for p in &data.pressures_kpa {
        tp.tire_pressures_e2.push((p * 100.0).round() as i32);
    }

    let tp_json = serde_json::json!({
        "tire_pressures": tp.tire_pressures_e2,
    });

    msg.tire_pressure_data.push(tp);

    let payload = tp_json.to_string();

    //Send to ws
    let _ = ws_event_tx.send(ServerEvent {
        topic: "tpms".to_string(),
        payload: payload,
    });

    let mut payload: Vec<u8> = msg.write_to_bytes()?;
    payload.insert(0, ((SENSOR_MESSAGE_BATCH as u16) >> 8) as u8);
    payload.insert(1, ((SENSOR_MESSAGE_BATCH as u16) & 0xff) as u8);

    let pkt = Packet {
        channel: sensor_ch,
        flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload,
    };
    tx.send(pkt).await?;
    info!(
        "mitm/web: injecting TIRE_PRESSURE packet ({:?} kPa)...",
        data.pressures_kpa
    );

    *last_tire_pressure.write().await = Some(data);
    Ok(())
}

/// encapsulates SSL data into Packet
async fn ssl_encapsulate(mut mem_buf: SslMemBuf) -> Result<Packet> {
    // read SSL-generated data
    let mut res: Vec<u8> = Vec::new();
    mem_buf.read_to(&mut res)?;

    // create MESSAGE_ENCAPSULATED_SSL Packet
    let message_type = ControlMessageType::MESSAGE_ENCAPSULATED_SSL as u16;
    res.insert(0, (message_type >> 8) as u8);
    res.insert(1, (message_type & 0xff) as u8);
    Ok(Packet {
        channel: 0x00,
        flags: FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload: res,
    })
}

/// creates Ssl for HeadUnit (SSL server) and MobileDevice (SSL client)
async fn ssl_builder(proxy_type: ProxyType) -> Result<Ssl> {
    let mut ctx_builder = SslContextBuilder::new(SslMethod::tls())?;

    // for HU/headunit we need to act as a MD/mobiledevice, so load "md" key and cert
    // and vice versa
    let prefix = match proxy_type {
        ProxyType::HeadUnit => "md",
        ProxyType::MobileDevice => "hu",
    };
    ctx_builder.set_certificate_file(format!("{KEYS_PATH}/{prefix}_cert.pem"), SslFiletype::PEM)?;
    ctx_builder.set_private_key_file(format!("{KEYS_PATH}/{prefix}_key.pem"), SslFiletype::PEM)?;
    ctx_builder.check_private_key()?;
    // trusted root certificates:
    ctx_builder.set_ca_file(format!("{KEYS_PATH}/galroot_cert.pem"))?;

    ctx_builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
    ctx_builder.set_options(openssl::ssl::SslOptions::NO_TLSV1_3);

    let openssl_ctx = ctx_builder.build();
    let mut ssl = Ssl::new(&openssl_ctx)?;
    if proxy_type == ProxyType::HeadUnit {
        ssl.set_accept_state(); // SSL server
    } else if proxy_type == ProxyType::MobileDevice {
        ssl.set_connect_state(); // SSL client
    }

    Ok(ssl)
}

/// reads all available data to VecDeque
async fn read_input_data<A: Endpoint<A>>(
    rbuf: &mut VecDeque<u8>,
    obj: &mut IoDevice<A>,
    incremental_read: bool,
) -> Result<usize> {
    let mut newdata = vec![0u8; BUFFER_LEN];
    let mut n;
    let mut len;

    match obj {
        IoDevice::UsbReader(device, _) => {
            let mut dev = device.borrow_mut();
            let retval = dev.read(&mut newdata);
            len = retval
                .await
                .context("read_input_data: UsbReader read error")?;
        }
        IoDevice::EndpointIo(device) => {
            if incremental_read {
                // read header
                newdata = vec![0u8; HEADER_LENGTH];
                let retval = device.read(newdata);
                (n, newdata) = timeout(Duration::from_millis(15000), retval)
                    .await
                    .context("read_input_data/header: EndpointIo timeout")?;
                len = n.context("read_input_data/header: EndpointIo read error")?;

                // fill the output/read buffer with the obtained header data
                rbuf.write(&newdata.clone().slice(..len))?;

                // compute payload size
                let mut payload_size = (newdata[3] as u16 + ((newdata[2] as u16) << 8)) as usize;
                if (newdata[1] & FRAME_TYPE_MASK) == FRAME_TYPE_FIRST {
                    // header is 8 bytes; need to read 4 more bytes
                    payload_size += 4;
                }
                // prepare buffer for the payload and continue normally
                newdata = vec![0u8; payload_size];
            }
            let retval = device.read(newdata);
            (n, newdata) = timeout(Duration::from_millis(15000), retval)
                .await
                .context("read_input_data: EndpointIo timeout")?;
            len = n.context("read_input_data: EndpointIo read error")?;
        }
        IoDevice::TcpStreamIo(device) => {
            let retval = device.read(newdata);
            (n, newdata) = timeout(Duration::from_millis(15000), retval)
                .await
                .context("read_input_data: TcpStreamIo timeout")?;
            len = n.context("read_input_data: TcpStreamIo read error")?;
            if len == 0 {
                // TCP EOF means the peer closed the connection; propagate as disconnect.
                return Err("read_input_data: TcpStreamIo EOF".into());
            }
        }
        _ => todo!(),
    }
    if len > 0 {
        rbuf.write(&newdata.slice(..len))?;
    }
    Ok(len)
}

/// runtime musl detection
fn is_musl() -> bool {
    std::path::Path::new("/lib/ld-musl-riscv64.so.1").exists()
}

/// main reader thread for a device
pub async fn endpoint_reader<A: Endpoint<A>>(
    mut device: IoDevice<A>,
    tx: Sender<Packet>,
    hu: bool,
) -> Result<()> {
    let mut rbuf: VecDeque<u8> = VecDeque::new();
    let incremental_read = if !hu && is_musl() { true } else { false };
    loop {
        read_input_data(&mut rbuf, &mut device, incremental_read).await?;
        // check if we have complete packet available
        loop {
            // Accept packets as soon as we have the complete fixed header.
            // Using >= is required for valid zero-payload frames (frame_size == HEADER_LENGTH).
            if rbuf.len() >= HEADER_LENGTH {
                let channel = rbuf[0];
                let flags = rbuf[1];

                // FIRST frames carry an extended 8-byte header. If only 4 bytes
                // are buffered, wait for the remaining header bytes before parsing.
                if (flags & FRAME_TYPE_MASK) == FRAME_TYPE_FIRST && rbuf.len() < 8 {
                    break;
                }

                let mut header_size = HEADER_LENGTH;
                let mut final_length = None;
                let payload_size = (rbuf[3] as u16 + ((rbuf[2] as u16) << 8)) as usize;
                if rbuf.len() >= 8 && (flags & FRAME_TYPE_MASK) == FRAME_TYPE_FIRST {
                    header_size += 4;
                    final_length = Some(
                        ((rbuf[4] as u32) << 24)
                            + ((rbuf[5] as u32) << 16)
                            + ((rbuf[6] as u32) << 8)
                            + (rbuf[7] as u32),
                    );
                }
                let frame_size = header_size + payload_size;
                if rbuf.len() >= frame_size {
                    let mut frame = vec![0u8; frame_size];
                    rbuf.read_exact(&mut frame)?;
                    // we now have all header data analyzed/read, so remove
                    // the header from frame to have payload only left
                    frame.drain(..header_size);
                    let pkt = Packet {
                        channel,
                        flags,
                        final_length,
                        payload: frame,
                    };
                    // send packet to main thread for further process
                    tx.send(pkt).await?;
                    // check if we have another packet
                    continue;
                }
            }
            // no more complete packets available
            break;
        }
    }
}

/// checking if there was a true fatal SSL error
/// Note that the error may not be fatal. For example if the underlying
/// stream is an asynchronous one then `HandshakeError::WouldBlock` may
/// just mean to wait for more I/O to happen later.
fn ssl_check_failure<T>(res: std::result::Result<T, openssl::ssl::Error>) -> Result<()> {
    if let Err(err) = res {
        match err.code() {
            ErrorCode::WANT_READ | ErrorCode::WANT_WRITE | ErrorCode::SYSCALL => Ok(()),
            _ => return Err(Box::new(err)),
        }
    } else {
        Ok(())
    }
}

fn build_control_reply(message_id: ControlMessageType, payload: Vec<u8>) -> Packet {
    let mut payload = payload;
    payload.insert(0, ((message_id as u16) >> 8) as u8);
    payload.insert(1, ((message_id as u16) & 0xff) as u8);

    Packet {
        channel: 0,
        flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload,
    }
}

fn build_control_reply_on_channel(
    channel: u8,
    message_id: ControlMessageType,
    payload: Vec<u8>,
) -> Packet {
    let mut payload = payload;
    payload.insert(0, ((message_id as u16) >> 8) as u8);
    payload.insert(1, ((message_id as u16) & 0xff) as u8);

    Packet {
        channel,
        // Non-zero service-channel control frames observed from real HU/DHU use 0x0f:
        // ENCRYPTED | CONTROL | FIRST | LAST. Without CONTROL (0x04), Android may
        // not treat our synthetic CHANNEL_OPEN_RESPONSE as a channel-control frame.
        flags: ENCRYPTED | _CONTROL | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload,
    }
}

/// main thread doing all packet processing of an endpoint/device
pub async fn proxy<A: Endpoint<A> + 'static>(
    proxy_type: ProxyType,
    mut device: IoDevice<A>,
    bytes_written: Arc<AtomicUsize>,
    tx: Sender<Packet>,
    mut rx: Receiver<Packet>,
    mut rxr: Receiver<Packet>,
    mut config: SharedConfig,
    sensor_channel: Arc<tokio::sync::Mutex<Option<u8>>>,
    input_channel: Arc<tokio::sync::Mutex<Option<u8>>>,
    last_battery: Arc<RwLock<Option<BatteryData>>>,
    last_speed: Arc<RwLock<Option<i32>>>,
    last_service_discovery_response: SharedServiceDiscoveryResponse,
    ev_tx: Sender<EvTaskCommand>,
    hu_tx: Option<Sender<Packet>>,
    script_registry: Option<Arc<ScriptRegistry>>,
    media_sinks: SharedMediaSinks,
    shared_media_channels: SharedMediaChannels,
    ws_event_tx: BroadcastSender<ServerEvent>,
) -> Result<()> {
    let cfg = config.read().await.clone();
    let passthrough = !cfg.mitm || cfg.runtime_mitm_failed;
    let hex_requested = cfg.hexdump_level;

    // in full_frames/passthrough mode we only directly pass packets from one endpoint to the other
    if passthrough {
        loop {
            tokio::select! {
            // handling data from opposite device's thread, which needs to be transmitted
            Some(pkt) = rx.recv() => {
                debug!("{} rx.recv", get_name(proxy_type));
                let _ = pkt_debug(proxy_type, HexdumpLevel::RawOutput, hex_requested, &pkt, &cfg, None).await;

                pkt.transmit(&mut device)
                    .await
                    .with_context(|| format!("proxy/{}: transmit failed", get_name(proxy_type)))?;

                // Increment byte counters for statistics
                // fixme: compute final_len for precise stats
                bytes_written.fetch_add(HEADER_LENGTH + pkt.payload.len(), Ordering::Relaxed);
            }

            // handling input data from the reader thread
            Some(pkt) = rxr.recv() => {
                debug!("{} rxr.recv", get_name(proxy_type));
                let _ = pkt_debug(proxy_type, HexdumpLevel::RawOutput, hex_requested, &pkt, &cfg, None).await;

                tx.send(pkt).await?;
            }
            }
        }
    }

    let ssl = match ssl_builder(proxy_type).await {
        Ok(s) => s,
        Err(e) => {
            config.write().await.runtime_mitm_failed = true;
            return Err(e);
        }
    };

    let mut mem_buf = SslMemBuf {
        client_stream: Arc::new(Mutex::new(VecDeque::new())),
        server_stream: Arc::new(Mutex::new(VecDeque::new())),
    };
    let mut server = openssl::ssl::SslStream::new(ssl, mem_buf.clone())?;

    // initial phase: passing version and doing SSL handshake
    // for both HU and MD
    if proxy_type == ProxyType::HeadUnit {
        // waiting for initial version frame (HU is starting transmission)
        let pkt = rxr.recv().await.ok_or("reader channel hung up")?;
        let _ = pkt_debug(
            proxy_type,
            HexdumpLevel::DecryptedInput, // the packet is not encrypted
            hex_requested,
            &pkt,
            &cfg,
            None,
        )
        .await;
        // sending to the MD
        tx.send(pkt).await?;
        // waiting for MD reply
        let pkt = rx.recv().await.ok_or("rx channel hung up")?;
        // sending reply back to the HU
        let _ = pkt_debug(
            proxy_type,
            HexdumpLevel::RawOutput,
            hex_requested,
            &pkt,
            &cfg,
            None,
        )
        .await;
        pkt.transmit(&mut device)
            .await
            .with_context(|| format!("proxy/{}: transmit failed", get_name(proxy_type)))?;

        // doing SSL handshake
        const STEPS: u8 = 2;
        for i in 1..=STEPS {
            let pkt = rxr.recv().await.ok_or("reader channel hung up")?;
            let _ = pkt_debug(
                proxy_type,
                HexdumpLevel::RawInput,
                hex_requested,
                &pkt,
                &cfg,
                None,
            )
            .await;
            pkt.ssl_decapsulate_write(&mut mem_buf).await?;
            if let Err(e) = ssl_check_failure(server.accept()) {
                config.write().await.runtime_mitm_failed = true;
                return Err(e);
            }
            info!(
                "{} 🔒 stage #{} of {}: SSL handshake: {}",
                get_name(proxy_type),
                i,
                STEPS,
                server.ssl().state_string_long(),
            );
            if server.ssl().is_init_finished() {
                info!(
                    "{} 🔒 SSL init complete, negotiated cipher: <b><blue>{}</>",
                    get_name(proxy_type),
                    server.ssl().current_cipher().unwrap().name(),
                );
            }
            let pkt = ssl_encapsulate(mem_buf.clone()).await?;
            let _ = pkt_debug(
                proxy_type,
                HexdumpLevel::RawOutput,
                hex_requested,
                &pkt,
                &cfg,
                None,
            )
            .await;
            pkt.transmit(&mut device)
                .await
                .with_context(|| format!("proxy/{}: transmit failed", get_name(proxy_type)))?;
        }
    } else if proxy_type == ProxyType::MobileDevice {
        // expecting version request from the HU here...
        let pkt = rx.recv().await.ok_or("rx channel hung up")?;
        // sending to the MD
        let _ = pkt_debug(
            proxy_type,
            HexdumpLevel::RawOutput,
            hex_requested,
            &pkt,
            &cfg,
            None,
        )
        .await;
        pkt.transmit(&mut device)
            .await
            .with_context(|| format!("proxy/{}: transmit failed", get_name(proxy_type)))?;
        // waiting for MD reply
        let pkt = rxr.recv().await.ok_or("reader channel hung up")?;
        let _ = pkt_debug(
            proxy_type,
            HexdumpLevel::DecryptedInput, // the packet is not encrypted
            hex_requested,
            &pkt,
            &cfg,
            None,
        )
        .await;
        // sending reply back to the HU
        tx.send(pkt).await?;

        // doing SSL handshake
        const STEPS: u8 = 3;
        for i in 1..=STEPS {
            if let Err(e) = ssl_check_failure(server.do_handshake()) {
                config.write().await.runtime_mitm_failed = true;
                return Err(e);
            }
            info!(
                "{} 🔒 stage #{} of {}: SSL handshake: {}",
                get_name(proxy_type),
                i,
                STEPS,
                server.ssl().state_string_long(),
            );
            if server.ssl().is_init_finished() {
                info!(
                    "{} 🔒 SSL init complete, negotiated cipher: <b><blue>{}</>",
                    get_name(proxy_type),
                    server.ssl().current_cipher().unwrap().name(),
                );
            }
            if i == 3 {
                // this was the last handshake step, need to break here
                break;
            };
            let pkt = ssl_encapsulate(mem_buf.clone()).await?;
            let _ = pkt_debug(
                proxy_type,
                HexdumpLevel::RawOutput,
                hex_requested,
                &pkt,
                &cfg,
                None,
            )
            .await;
            pkt.transmit(&mut device)
                .await
                .with_context(|| format!("proxy/{}: transmit failed", get_name(proxy_type)))?;

            let pkt = rxr.recv().await.ok_or("reader channel hung up")?;
            let _ = pkt_debug(
                proxy_type,
                HexdumpLevel::RawInput,
                hex_requested,
                &pkt,
                &cfg,
                None,
            )
            .await;
            pkt.ssl_decapsulate_write(&mut mem_buf).await?;
        }
    }

    // main data processing/transfer loop
    let mut ctx = ModifyContext {
        sensor_channel: None,
        sensors: None,
        input_channel: None,
        nav_channel: None,
        audio_channels: vec![],
        ev_tx,
        hu_tx,
        hu_input_state: HuInputState::default(),
        media_sinks,
        shared_media_channels,
        media_dump_base_port: cfg.media_dump_base_port,
        media_wait_for_live_idr: cfg.media_wait_for_live_idr,
        media_channels: HashMap::new(),
        media_fragments: HashMap::new(),
        hu_service_ids: HashSet::new(),
        injected_service_ids: HashSet::new(),
        injected_channels: HashSet::new(),
        injected_media_display: HashMap::new(),
        injected_media_state: HashMap::new(),
        injected_media_connect_gen: HashMap::new(),
        injected_media_had_tap_client: HashMap::new(),
        vendor_service_ids: HashSet::new(),
        vendor_channel_states: HashMap::new(),
        vendor_topic_event_bridges: HashMap::new(),
        debug_channel_kinds: HashMap::from([(0, PacketDebugServiceKind::Control)]),
    };
    let mut focus_poll = tokio::time::interval(Duration::from_millis(100));
    focus_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    focus_poll.tick().await;
    loop {
        tokio::select! {
        // handling data from opposite device's thread, which needs to be transmitted
        Some(mut pkt) = rx.recv() => {
            if proxy_type == ProxyType::HeadUnit {
                maybe_emit_pending_injected_focus(proxy_type, &mut ctx, &cfg, &tx)?;
            }

            // Keep injected-only channels invisible to HU.
            if proxy_type == ProxyType::HeadUnit
                && pkt.channel != 0
                && ctx.injected_channels.contains(&pkt.channel)
            {
                if ctx.injected_media_display.contains_key(&pkt.channel) {
                    let had_fragment_state = ctx.media_fragments.contains_key(&pkt.channel);
                    // Injected media packets were already tapped on the MobileDevice ingress path.
                    // Reassemble here only so ACK synthesis can track whole media messages.
                    let reassembled_frame = reassemble_media_packet(&mut ctx.media_fragments, &pkt);

                    if emulate_injected_media_packet(
                        proxy_type,
                        &mut pkt,
                        &mut ctx,
                        reassembled_frame.as_deref(),
                        had_fragment_state,
                    )? {
                        debug!(
                            "{} synthesized injected media reply on channel <b>{:#04x}</>",
                            get_name(proxy_type),
                            pkt.channel
                        );
                        tx.send(pkt).await?;

                        maybe_emit_pending_injected_focus(proxy_type, &mut ctx, &cfg, &tx)?;

                        continue;
                    }
                }

                let msg_id = pkt.payload
                    .get(0..2)
                    .map(|bytes| {
                        format!(
                            "0x{:04X}",
                            u16::from_be_bytes([bytes[0], bytes[1]])
                        )
                    })
                    .unwrap_or_else(|| "none".to_string());

                debug!(
                    "{} dropping injected channel packet towards HU on channel <b>{:#04x}</> message_id={}",
                    get_name(proxy_type),
                    pkt.channel,
                    msg_id
                );
                continue;
            }

            let action = pkt_modify_hook(
                proxy_type,
                PacketFlow::ToEndpoint,
                &mut pkt,
                &mut ctx,
                false,
                sensor_channel.clone(),
                input_channel.clone(),
                last_battery.clone(),
                last_speed.clone(),
                last_service_discovery_response.clone(),
                &cfg,
                &mut config,
                script_registry.clone(),
                ws_event_tx.clone()
            )
            .await?;
            let _ = pkt_debug(
                proxy_type,
                HexdumpLevel::DecryptedOutput,
                hex_requested,
                &pkt,
                &cfg,
                Some(&ctx.debug_channel_kinds),
            )
            .await;

            match action {
                PacketAction::Drop => {
                    debug!("{} pkt_modify_hook: packet dropped", get_name(proxy_type));
                }
                PacketAction::SendBack => {
                    debug!(
                        "{} pkt_modify_hook: message has been handled, sending reply packet only...",
                        get_name(proxy_type)
                    );
                    tx.send(pkt).await?;
                }
                PacketAction::Forward => {
                    pkt.encrypt_payload(&mut mem_buf, &mut server).await?;
                    let _ =
                        pkt_debug(proxy_type, HexdumpLevel::RawOutput, hex_requested, &pkt, &cfg, Some(&ctx.debug_channel_kinds)).await;
                    pkt.transmit(&mut device).await.with_context(|| {
                        format!("proxy/{}: transmit failed", get_name(proxy_type))
                    })?;

                    // Increment byte counters for statistics
                    // fixme: compute final_len for precise stats
                    bytes_written.fetch_add(HEADER_LENGTH + pkt.payload.len(), Ordering::Relaxed);
                }
            }
        }

        // handling input data from the reader thread
        Some(mut pkt) = rxr.recv() => {
            let _ = pkt_debug(proxy_type, HexdumpLevel::RawInput, hex_requested, &pkt, &cfg, Some(&ctx.debug_channel_kinds)).await;
            match pkt.decrypt_payload(&mut mem_buf, &mut server).await {
                Ok(_) => {
                    let action = pkt_modify_hook(
                        proxy_type,
                        PacketFlow::FromEndpoint,
                        &mut pkt,
                        &mut ctx,
                        proxy_type == ProxyType::MobileDevice,
                        sensor_channel.clone(),
                        input_channel.clone(),
                        last_battery.clone(),
                        last_speed.clone(),
                        last_service_discovery_response.clone(),
                        &cfg,
                        &mut config,
                        script_registry.clone(),
                        ws_event_tx.clone(),
                    )
                    .await?;
                    let _ = pkt_debug(
                        proxy_type,
                        HexdumpLevel::DecryptedInput,
                        hex_requested,
                        &pkt,
                        &cfg,
                        Some(&ctx.debug_channel_kinds),
                    )
                    .await;
                    match action {
                        PacketAction::Drop => {}
                        PacketAction::SendBack | PacketAction::Forward => {
                            tx.send(pkt).await?;
                        }
                    }
                }
                Err(e) => error!("decrypt_payload: {:?}", e),
            }
        }

        _ = focus_poll.tick(), if proxy_type == ProxyType::HeadUnit => {
            maybe_emit_pending_injected_focus(proxy_type, &mut ctx, &cfg, &tx)?;
        }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn test_ctx() -> ModifyContext {
        let (ev_tx, _) = mpsc::channel(1);
        ModifyContext {
            sensor_channel: None,
            sensors: None,
            nav_channel: None,
            audio_channels: vec![],
            ev_tx,
            input_channel: None,
            hu_tx: None,
            hu_input_state: HuInputState::default(),
            media_sinks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            shared_media_channels: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            media_dump_base_port: None,
            media_wait_for_live_idr: false,
            media_channels: HashMap::new(),
            media_fragments: HashMap::new(),
            hu_service_ids: HashSet::new(),
            injected_service_ids: HashSet::new(),
            injected_channels: HashSet::new(),
            injected_media_display: HashMap::new(),
            injected_media_state: HashMap::new(),
            injected_media_connect_gen: HashMap::new(),
            injected_media_had_tap_client: HashMap::new(),
            vendor_service_ids: HashSet::new(),
            vendor_channel_states: HashMap::new(),
            vendor_topic_event_bridges: HashMap::new(),
            debug_channel_kinds: HashMap::from([(0, PacketDebugServiceKind::Control)]),
        }
    }

    fn test_packet(channel: u8, flags: u8, final_length: Option<u32>, payload: &[u8]) -> Packet {
        Packet {
            channel,
            flags,
            final_length,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn media_tap_keeps_single_frame_packets_intact() {
        let mut ctx = test_ctx();
        let pkt = test_packet(
            0x21,
            FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
            None,
            &[0x00, 0x01, 0xAA, 0xBB],
        );

        let assembled = reassemble_media_packet(&mut ctx.media_fragments, &pkt);

        assert_eq!(assembled, Some(vec![0x00, 0x01, 0xAA, 0xBB]));
        assert!(!ctx.media_fragments.contains_key(&0x21));
    }

    #[test]
    fn media_tap_reassembles_fragmented_packets() {
        let mut ctx = test_ctx();
        let first = test_packet(0x21, FRAME_TYPE_FIRST, Some(6), &[0x00, 0x01, 0xAA]);
        let middle = test_packet(0x21, 0, None, &[0xBB]);
        let last = test_packet(0x21, FRAME_TYPE_LAST, None, &[0xCC, 0xDD]);

        assert_eq!(
            reassemble_media_packet(&mut ctx.media_fragments, &first),
            None
        );
        assert_eq!(
            reassemble_media_packet(&mut ctx.media_fragments, &middle),
            None
        );
        assert_eq!(
            reassemble_media_packet(&mut ctx.media_fragments, &last),
            Some(vec![0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD])
        );
        assert!(!ctx.media_fragments.contains_key(&0x21));
    }

    #[test]
    fn media_tap_drops_length_mismatches() {
        let mut ctx = test_ctx();
        let first = test_packet(0x21, FRAME_TYPE_FIRST, Some(7), &[0x00, 0x01, 0xAA]);
        let last = test_packet(0x21, FRAME_TYPE_LAST, None, &[0xBB, 0xCC]);

        assert_eq!(
            reassemble_media_packet(&mut ctx.media_fragments, &first),
            None
        );
        assert_eq!(
            reassemble_media_packet(&mut ctx.media_fragments, &last),
            None
        );
        assert!(!ctx.media_fragments.contains_key(&0x21));
    }
}
