use crate::config_types::{
    BluetoothAddressList, EvConnectorTypes, HexdumpLevel, InjectClusterCodecResolution,
    InjectDisplayTypes, UsbId,
};
use indexmap::IndexMap;
use serde::de::{Deserializer, Error as DeError};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use simplelog::*;
use std::io::Error;
use std::process::Command;
use std::{fmt::Display, fs, io, path::PathBuf, str::FromStr, sync::Arc};
use tokio::sync::RwLock;
use toml_edit::{value, DocumentMut};

// Device identity (Bluetooth alias + SSID)
pub const IDENTITY_NAME: &str = "aa-proxy";
#[macro_export]
macro_rules! base_config_dir {
    () => {
        "/etc/aa-proxy-rs"
    };
}
pub const BASE_CONFIG_DIR: &str = base_config_dir!();
pub const DEFAULT_WLAN_ADDR: &str = "10.0.0.1";
pub const TCP_SERVER_PORT: i32 = 5288;
pub const TCP_DHU_PORT: i32 = 5277;

pub const DEFAULT_WASM_HOOKS_DIR: &str = "/data/wasm-hooks";
pub const DEFAULT_CRASH_DIR: &str = "/data/aa-proxy-rs/crashes";
pub const DEFAULT_SDR_UI_OVERRIDE_FILE: &str = "/data/aa-proxy-rs/sdr-ui-overrides.toml";
pub const DEFAULT_INJECT_DISPLAYS_FILE: &str = "/data/aa-proxy-rs/inject-displays.toml";

pub type SharedConfig = Arc<RwLock<AppConfig>>;
pub type SharedConfigJson = Arc<RwLock<ConfigJson>>;

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Reconnect,
    Reboot,
    Stop,
}

#[derive(Clone)]
pub struct WifiConfig {
    pub ip_addr: String,
    pub port: i32,
    pub ssid: String,
    pub bssid: String,
    pub wpa_key: String,
}

pub fn empty_string_as_none<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: FromStr,
    T::Err: Display,
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    if s.trim().is_empty() {
        Ok(None)
    } else {
        T::from_str(&s).map(Some).map_err(DeError::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BtScoMediaBridgeAudioType {
    Guidance,
    Media,
    Auto,
}

impl Default for BtScoMediaBridgeAudioType {
    fn default() -> Self {
        Self::Guidance
    }
}

impl Display for BtScoMediaBridgeAudioType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Guidance => "guidance",
            Self::Media => "media",
            Self::Auto => "auto",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BtScoMediaBridgeLimiter {
    Off,
    Hard,
    Soft,
}

impl Default for BtScoMediaBridgeLimiter {
    fn default() -> Self {
        Self::Off
    }
}

impl Display for BtScoMediaBridgeLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Off => "off",
            Self::Hard => "hard",
            Self::Soft => "soft",
        })
    }
}

impl BtScoMediaBridgeLimiter {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Hard,
            2 => Self::Soft,
            _ => Self::Off,
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Hard => 1,
            Self::Soft => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BtScoMediaBridgeResampler {
    Repeat,
    Linear,
}

impl Default for BtScoMediaBridgeResampler {
    fn default() -> Self {
        Self::Repeat
    }
}

impl Display for BtScoMediaBridgeResampler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Repeat => "repeat",
            Self::Linear => "linear",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BtScoMicEchoControl {
    Off,
    Ducking,
}

impl Default for BtScoMicEchoControl {
    fn default() -> Self {
        Self::Off
    }
}

impl Display for BtScoMicEchoControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Off => "off",
            Self::Ducking => "ducking",
        })
    }
}

fn webserver_default_bind() -> Option<String> {
    Some("0.0.0.0:80".into())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ConfigValue {
    pub typ: String,
    pub description: String,
    pub values: Option<Vec<String>>,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ConfigValues {
    pub title: String,
    pub values: IndexMap<String, ConfigValue>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ConfigJson {
    pub titles: Vec<ConfigValues>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AppConfig {
    pub advertise: bool,
    pub enable_btle: bool,
    pub dongle_mode: bool,
    pub debug: bool,
    /// Enable packet debug output independently from global debug logging.
    /// When enabled, pkt_debug lines are emitted at INFO level so `debug = false` can be kept.
    pub pkt_debug: bool,
    pub hexdump_level: HexdumpLevel,
    pub disable_console_debug: bool,
    /// Enable additional packet debug filtering on top of `hexdump_level`.
    pub pkt_debug_filter_enabled: bool,
    /// Packet debug proxy filter: `both`, `hu`, or `md`.
    pub pkt_debug_filter_proxy: String,
    /// Comma-separated hexdump stages: `raw_input`, `raw_output`, `decrypted_input`, `decrypted_output`. Empty means all.
    pub pkt_debug_filter_stages: String,
    /// Comma-separated semantic service kinds, e.g. `control,sensor_source,vendor_extension`. Empty means all.
    pub pkt_debug_filter_service_kinds: String,
    /// Comma-separated numeric channel IDs, e.g. `0x00,0x08,8`. Empty means all.
    pub pkt_debug_filter_channels: String,
    /// Comma-separated numeric channel IDs to exclude.
    pub pkt_debug_filter_exclude_channels: String,
    /// Comma-separated numeric message IDs, e.g. `0x0006,6`. Empty means all.
    pub pkt_debug_filter_message_ids: String,
    /// Comma-separated numeric message IDs to exclude.
    pub pkt_debug_filter_exclude_message_ids: String,
    /// When packet debug filtering is enabled, try to print protobuf text for known control messages.
    pub pkt_debug_filter_pretty_proto: bool,
    /// When packet debug filtering is enabled, truncate packet payload dumps to this many bytes. 0 disables truncation.
    pub pkt_debug_filter_max_payload_bytes: usize,
    pub legacy: bool,
    pub quick_reconnect: bool,
    pub bt_poweroff: bool,
    pub connect: BluetoothAddressList,
    pub logfile: PathBuf,
    /// Enable writing Rust panic reports to disk.
    pub crash_handler_enabled: bool,
    /// Directory where panic reports are written.
    pub crash_dir: PathBuf,
    /// Enable SDR ui_config margin/content inset overrides.
    pub sdr_ui_override_enabled: bool,
    /// Auto-create per-vehicle SDR UI profiles from the first observed ServiceDiscoveryResponse.
    pub sdr_ui_override_autocreate_profiles: bool,
    /// TOML file that stores per-vehicle and optional per-phone SDR UI overrides.
    pub sdr_ui_override_file: PathBuf,
    /// TOML file used to store injected display service profiles. Display IDs are assigned automatically from the current SDR.
    pub inject_displays_file: PathBuf,
    pub stats_interval: u16,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub udc: Option<String>,
    pub iface: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub btalias: Option<String>,
    pub timeout_secs: u16,
    #[serde(
        default = "webserver_default_bind",
        deserialize_with = "empty_string_as_none"
    )]
    pub webserver: Option<String>,
    pub bt_timeout_secs: u16,
    pub mitm: bool,
    pub dpi: u16,
    pub audio_max_unacked: u8,
    pub add_vendor_channel: bool,
    pub remove_tap_restriction: bool,
    pub video_in_motion: bool,
    pub disable_media_sink: bool,
    pub disable_tts_sink: bool,
    pub developer_mode: bool,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub wired: Option<UsbId>,
    pub dhu: bool,
    /// Optional direct TCP address for Android Auto Head Unit Server on the MD/phone side.
    /// Empty keeps the normal USB/Bluetooth/Wi-Fi MD transport behavior.
    pub aa_server_tcp_addr: String,
    pub ev: bool,
    pub odometer: bool,
    pub tire_pressure: bool,
    pub remove_bluetooth: bool,
    pub remove_wifi: bool,
    pub inject_display_types: InjectDisplayTypes,
    pub inject_add_input_sources: bool,
    pub inject_cluster_display_id: u16,
    pub inject_cluster_width_margin: u16,
    pub inject_cluster_height_margin: u16,
    pub inject_cluster_density: u16,
    pub inject_cluster_viewing_distance: u16,
    pub inject_cluster_codec_resolution: InjectClusterCodecResolution,
    pub inject_cluster_touch_width: u16,
    pub inject_cluster_touch_height: u16,
    pub inject_aux_display_id: u16,
    pub inject_aux_width_margin: u16,
    pub inject_aux_height_margin: u16,
    pub inject_aux_density: u16,
    pub inject_aux_viewing_distance: u16,
    pub inject_aux_touch_width: u16,
    pub inject_aux_touch_height: u16,
    /// Test-mode override: send injected video focus even without active tap clients.
    /// Default false keeps injected streams idle until a tap client connects.
    #[serde(default)]
    pub inject_force_focus_without_tap: bool,
    pub change_usb_order: bool,
    pub stop_on_disconnect: bool,
    pub waze_lht_workaround: bool,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub ev_battery_logger: Option<String>,
    pub ev_connector_types: EvConnectorTypes,
    pub enable_ssh: bool,
    pub usb_serial_console: bool,
    pub wifi_version: u16,
    pub band: String,
    pub country_code: String,
    pub channel: u8,
    pub ssid: String,
    pub wpa_passphrase: String,
    pub eth_mode: String,
    pub startup_delay: u8,
    pub ble_password: String,
    pub external_antenna: bool,
    /// Base TCP port for media stream tapping. One port is allocated per media sink
    /// by order in the rewritten ServiceDiscoveryResponse: first media sink uses +0,
    /// second uses +1, and so on. This avoids collisions when multiple displays
    /// with the same display type are injected.
    /// Requires mitm = true. Connect with e.g. `vlc tcp://127.0.0.1:12345`.
    #[serde(default)]
    pub media_dump_base_port: Option<u16>,
    /// Startup behavior for media TCP tap clients.
    /// true  = wait for a fresh live IDR before forwarding inter-frames (clean decode)
    /// false = forward immediately after cached-IDR preview (lower latency, may artifact)
    pub media_wait_for_live_idr: bool,
    pub collect_speed: bool,
    pub disable_driving_status: bool,
    /// Optional shell command invoked on HU media-key long press.
    ///
    /// The command is split on whitespace (shell-word rules), so you can include
    /// arguments, e.g. `/data/bin/my-script --mode aa`.
    /// Two extra arguments are always appended by aa-proxy-rs:
    ///   1. keycode (u32) — the raw Android key code that was long-pressed
    ///   2. elapsed_ms (u128) — how long the key was held in milliseconds
    ///
    /// When this option is empty or absent, HU media-key interception is disabled
    /// and all key events are forwarded unmodified.
    /// Requires `mitm = true`.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub hu_button_handler: Option<String>,

    /// Master switch for the experimental Bluetooth SCO/eSCO call-audio bridge/listener.
    ///
    /// When enabled, the SCO listener can stay active and, if configured, bridge
    /// call downlink/uplink audio.
    pub bt_sco: bool,
    /// Keep the Android Auto Bluetooth profile/RFCOMM connection alive after Wi-Fi
    /// bootstrap while the SCO bridge is enabled. This is required when the phone
    /// should keep routing call audio to aa-proxy-rs instead of dropping BT after
    /// the AA Wi-Fi setup phase.
    pub bt_sco_keep_bluetooth_alive: bool,
    /// Experimental downlink bridge: SCO call audio -> AA PCM media sink.
    /// Disabled by default. Requires `mitm = true`.
    pub bt_sco_media_bridge: bool,
    /// Preferred AA PCM sink type for SCO downlink.
    /// Values: `guidance`, `media`, or `auto`. For phone calls, `guidance` is
    /// often more audible because AA/HU may mute the normal media stream while a
    /// call and microphone session are active.
    pub bt_sco_media_bridge_audio_type: BtScoMediaBridgeAudioType,
    /// Output gain for SCO downlink after conversion, as percent. 100 means no gain.
    /// Useful because the raw SCO downlink can be quiet on some phones/HUs.
    pub bt_sco_media_bridge_gain_percent: u32,
    /// Optional limiter applied after gain. `off` keeps the existing behavior
    /// except for unavoidable i16 saturation; `hard` clips earlier; `soft`
    /// compresses peaks more gently.
    pub bt_sco_media_bridge_limiter: BtScoMediaBridgeLimiter,
    /// SCO 8 kHz -> AA 48 kHz resampler. `repeat` preserves the proven path;
    /// `linear` smooths the 6x upsampling and can reduce roughness/crackle.
    pub bt_sco_media_bridge_resampler: BtScoMediaBridgeResampler,
    /// Converted AA PCM chunk ring capacity for the SCO media bridge.
    /// Higher values tolerate stalls; lower values reduce latency. 128 is safe.
    pub bt_sco_media_bridge_ring_capacity: usize,
    /// Send MEDIA_MESSAGE_START on the selected, already-configured AA PCM sink
    /// when SCO connects. This is useful for DHU/HUs that discard DATA until the
    /// existing stream is explicitly started. CHANNEL_OPEN/SETUP are still not sent.
    pub bt_sco_media_bridge_start_existing: bool,
    /// If enabled, delay MEDIA_MESSAGE_START/DATA until the SCO downlink carries
    /// non-silent audio. This helps diagnose/avoid call-routing cases where the
    /// phone opens SCO but sends silence until the route is toggled.
    pub bt_sco_media_bridge_start_on_first_audio: bool,
    /// Peak threshold used by start_on_first_audio. Values below this are treated
    /// as silence after conversion/gain. 64 is conservative for 16-bit PCM.
    pub bt_sco_media_bridge_audio_peak_threshold: u32,
    /// Fallback timeout for start_on_first_audio. If no non-silent downlink is
    /// seen within this many milliseconds, START/DATA begins anyway so calls are
    /// not muted forever.
    pub bt_sco_media_bridge_start_timeout_ms: u32,
    /// Send MEDIA_MESSAGE_STOP on the selected existing AA PCM sink when SCO disconnects.
    pub bt_sco_media_bridge_stop_existing_on_disconnect: bool,
    /// If enabled, pace outgoing AA DATA packets with a fixed cadence instead
    /// of sending as soon as converted SCO chunks arrive. This can reduce jitter
    /// on some HUs, but is disabled by default to preserve the proven behavior.
    pub bt_sco_media_bridge_fixed_cadence: bool,
    /// Fixed DATA cadence in milliseconds when fixed cadence is enabled.
    pub bt_sco_media_bridge_cadence_ms: u32,
    /// Minimum converted-audio buffer before the first fixed-cadence DATA packet.
    pub bt_sco_media_bridge_jitter_buffer_ms: u32,
    /// Experimental uplink bridge: AA HU microphone/source PCM -> Bluetooth SCO uplink.
    /// Disabled by default. Requires `mitm = true`.
    pub bt_sco_mic_bridge: bool,
    /// Send AA MEDIA_MESSAGE_MICROPHONE_REQUEST open/close while SCO is connected.
    /// Keep enabled for the first mic test; disable to observe/passively log mic frames only.
    pub bt_sco_mic_request: bool,
    /// Maximum 60-byte SCO uplink packets buffered for the mic bridge.
    pub bt_sco_mic_uplink_ring_capacity: usize,
    /// Echo handling for the microphone uplink. `off` preserves the current
    /// proven path; `ducking` lowers mic gain while downlink audio is active.
    pub bt_sco_mic_echo_control: BtScoMicEchoControl,
    /// Microphone uplink gain percent after echo processing. 100 means no gain.
    pub bt_sco_mic_gain_percent: u32,
    /// Downlink peak threshold that marks far-end audio as active for ducking.
    pub bt_sco_mic_duck_threshold: i16,
    /// Mic gain percent while far-end/downlink audio is active.
    pub bt_sco_mic_duck_percent: u32,
    /// How long to keep ducking after the last active downlink frame.
    pub bt_sco_mic_duck_hold_ms: u32,

    /// Directory where `.wasm` hook files are loaded from.
    /// Each script gets read-only WASI access only to a private subfolder named
    /// after the .wasm file stem.
    pub wasm_hooks_dir: PathBuf,
    /// Maximum linear memory size, in MiB, allowed for each live WASM script instance.
    pub wasm_script_memory_limit_mb: u32,
    /// Maximum number of component/core instances allowed inside each WASM script store.
    pub wasm_script_instance_limit: u32,
    /// Maximum number of memories allowed inside each WASM script store.
    pub wasm_script_memory_count_limit: u32,
    /// Maximum number of tables allowed inside each WASM script store.
    pub wasm_script_table_limit: u32,
    /// Maximum number of table elements allowed inside each WASM script store.
    pub wasm_script_table_elements_limit: u32,
    /// Epoch deadline used for modify-packet calls. Epochs are incremented every 10 ms.
    pub wasm_script_packet_epoch_deadline: u64,
    /// Epoch deadline used for lifecycle/config/websocket calls. Epochs are incremented every 10 ms.
    pub wasm_script_lifecycle_epoch_deadline: u64,

    #[serde(skip)]
    pub action_requested: Option<Action>,

    #[serde(skip)]
    pub runtime_mitm_failed: bool,
}

impl Default for ConfigValue {
    fn default() -> Self {
        Self {
            typ: String::new(),
            description: String::new(),
            values: None,
        }
    }
}

impl Default for ConfigValues {
    fn default() -> Self {
        Self {
            title: String::new(),
            values: IndexMap::new(),
        }
    }
}

impl Default for ConfigJson {
    fn default() -> Self {
        Self { titles: Vec::new() }
    }
}

fn filter_iw_list(pattern: &str) -> std::io::Result<bool> {
    // Run the command `iw list`
    let output = Command::new("iw").arg("list").output()?;

    // Convert the command output bytes to a string
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Iterate over each line in the output
    for line in stdout.lines() {
        // Check if the line contains search pattern
        if line.contains(pattern) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn supports_5ghz_wifi() -> std::io::Result<bool> {
    filter_iw_list("5180.0 MHz")
}

fn get_latest_wifi_version() -> std::io::Result<u16> {
    // note:
    // for checking 6GHz: filter_iw_list("5955.0 MHz")
    // We don't use this right now. This is for future expansion with Wi-Fi 6E devices

    if filter_iw_list("HE PHY Capabilities")? {
        // 802.11ax
        Ok(6)
    } else if filter_iw_list("VHT Capabilities")? {
        // 802.11ac
        Ok(5)
    } else if filter_iw_list(" HT Capabilities")? {
        // 802.11n
        Ok(4)
    } else if filter_iw_list("54.0 Mbps")? {
        // 802.11g
        Ok(3)
    } else if supports_5ghz_wifi()? {
        // I don't know a proper way to check for 802.11a, but it is the first version to support
        // 5 GHz Wi-Fi and this far down the if statement we can use this to check.
        Ok(2)
    } else if filter_iw_list("11.0 Mbps")? {
        // 802.11b
        Ok(1)
    } else {
        Err(Error::new(
            io::ErrorKind::InvalidData,
            "Device does not support anything newer than 802.11-1997?!?!",
        ))
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            advertise: true,
            enable_btle: true,
            dongle_mode: false,
            debug: false,
            pkt_debug: false,
            hexdump_level: HexdumpLevel::Disabled,
            disable_console_debug: false,
            pkt_debug_filter_enabled: false,
            pkt_debug_filter_proxy: "both".to_string(),
            pkt_debug_filter_stages: String::new(),
            pkt_debug_filter_service_kinds: String::new(),
            pkt_debug_filter_channels: String::new(),
            pkt_debug_filter_exclude_channels: String::new(),
            pkt_debug_filter_message_ids: String::new(),
            pkt_debug_filter_exclude_message_ids: String::new(),
            pkt_debug_filter_pretty_proto: true,
            pkt_debug_filter_max_payload_bytes: 2048,
            legacy: true,
            quick_reconnect: false,
            bt_poweroff: false,
            connect: BluetoothAddressList::default(),
            logfile: "/var/log/aa-proxy-rs.log".into(),
            crash_handler_enabled: true,
            crash_dir: DEFAULT_CRASH_DIR.into(),
            sdr_ui_override_enabled: true,
            sdr_ui_override_autocreate_profiles: true,
            sdr_ui_override_file: DEFAULT_SDR_UI_OVERRIDE_FILE.into(),
            inject_displays_file: DEFAULT_INJECT_DISPLAYS_FILE.into(),
            stats_interval: 0,
            udc: None,
            iface: "wlan0".to_string(),
            btalias: None,
            timeout_secs: 10,
            webserver: webserver_default_bind(),
            bt_timeout_secs: 120,
            mitm: false,
            dpi: 0,
            audio_max_unacked: 0,
            add_vendor_channel: true,
            remove_tap_restriction: false,
            video_in_motion: false,
            disable_media_sink: false,
            disable_tts_sink: false,
            developer_mode: false,
            wired: None,
            dhu: false,
            aa_server_tcp_addr: String::new(),
            ev: false,
            odometer: false,
            tire_pressure: false,
            remove_bluetooth: false,
            remove_wifi: false,
            inject_display_types: InjectDisplayTypes::default(),
            inject_add_input_sources: false,
            inject_cluster_display_id: 1,
            inject_cluster_width_margin: 270,
            inject_cluster_height_margin: 344,
            inject_cluster_density: 180,
            inject_cluster_viewing_distance: 100,
            inject_cluster_codec_resolution: InjectClusterCodecResolution::default(),
            inject_cluster_touch_width: 1280,
            inject_cluster_touch_height: 720,
            inject_aux_display_id: 2,
            inject_aux_width_margin: 0,
            inject_aux_height_margin: 0,
            inject_aux_density: 160,
            inject_aux_viewing_distance: 300,
            inject_aux_touch_width: 1280,
            inject_aux_touch_height: 720,
            inject_force_focus_without_tap: false,
            change_usb_order: false,
            stop_on_disconnect: false,
            waze_lht_workaround: false,
            ev_battery_logger: None,
            action_requested: None,
            ev_connector_types: EvConnectorTypes::default(),
            enable_ssh: true,
            usb_serial_console: false,
            wifi_version: get_latest_wifi_version().unwrap_or(1),
            band: {
                if supports_5ghz_wifi().unwrap_or(false) {
                    // Eventually: Add check for 6 GHz
                    "5"
                } else {
                    "2.4"
                }
                .to_string()
            },
            country_code: "US".to_string(),
            channel: {
                if supports_5ghz_wifi().unwrap_or(false) {
                    // Eventually: Add check for 6 GHz
                    36
                } else {
                    6
                }
            },
            ssid: String::from(IDENTITY_NAME),
            wpa_passphrase: String::from(IDENTITY_NAME),
            eth_mode: String::new(),
            startup_delay: 0,
            ble_password: String::new(),
            external_antenna: false,
            media_dump_base_port: None,
            media_wait_for_live_idr: true,
            collect_speed: false,
            disable_driving_status: false,
            hu_button_handler: None,
            bt_sco: false,
            bt_sco_keep_bluetooth_alive: true,
            bt_sco_media_bridge: false,
            bt_sco_media_bridge_audio_type: BtScoMediaBridgeAudioType::Media,
            bt_sco_media_bridge_gain_percent: 300,
            bt_sco_media_bridge_limiter: BtScoMediaBridgeLimiter::Off,
            bt_sco_media_bridge_resampler: BtScoMediaBridgeResampler::Repeat,
            bt_sco_media_bridge_ring_capacity: 128,
            bt_sco_media_bridge_start_existing: true,
            bt_sco_media_bridge_start_on_first_audio: true,
            bt_sco_media_bridge_audio_peak_threshold: 256,
            bt_sco_media_bridge_start_timeout_ms: 5000,
            bt_sco_media_bridge_stop_existing_on_disconnect: true,
            bt_sco_media_bridge_fixed_cadence: false,
            bt_sco_media_bridge_cadence_ms: 22,
            bt_sco_media_bridge_jitter_buffer_ms: 60,
            bt_sco_mic_bridge: false,
            bt_sco_mic_request: true,
            bt_sco_mic_uplink_ring_capacity: 256,
            bt_sco_mic_echo_control: BtScoMicEchoControl::Ducking,
            bt_sco_mic_gain_percent: 100,
            bt_sco_mic_duck_threshold: 700,
            bt_sco_mic_duck_percent: 35,
            bt_sco_mic_duck_hold_ms: 180,
            wasm_hooks_dir: DEFAULT_WASM_HOOKS_DIR.into(),
            wasm_script_memory_limit_mb: 5,
            wasm_script_instance_limit: 16,
            wasm_script_memory_count_limit: 4,
            wasm_script_table_limit: 8,
            wasm_script_table_elements_limit: 512,
            wasm_script_packet_epoch_deadline: 100,
            wasm_script_lifecycle_epoch_deadline: 1000,
            runtime_mitm_failed: false,
        }
    }
}

#[cfg(feature = "wasm-scripting")]
pub fn wasm_script_limits_config_section() -> ConfigValues {
    let mut values = IndexMap::new();

    values.insert(
        "wasm_hooks_dir".to_string(),
        ConfigValue {
            typ: "string".to_string(),
            description: "Directory where WASM hook files are loaded from. Each script gets read-only access only to a private subfolder named after the .wasm file stem. Default: /data/wasm-hooks.".to_string(),
            values: None,
        },
    );

    values.insert(
        "wasm_script_memory_limit_mb".to_string(),
        ConfigValue {
            typ: "integer".to_string(),
            description: "Maximum linear memory size, in MiB, allowed for each live WASM script instance. Default: 5.".to_string(),
            values: None,
        },
    );
    values.insert(
        "wasm_script_instance_limit".to_string(),
        ConfigValue {
            typ: "integer".to_string(),
            description: "Maximum number of component/core instances allowed inside each WASM script store. Default: 16.".to_string(),
            values: None,
        },
    );
    values.insert(
        "wasm_script_memory_count_limit".to_string(),
        ConfigValue {
            typ: "integer".to_string(),
            description:
                "Maximum number of memories allowed inside each WASM script store. Default: 4."
                    .to_string(),
            values: None,
        },
    );
    values.insert(
        "wasm_script_table_limit".to_string(),
        ConfigValue {
            typ: "integer".to_string(),
            description:
                "Maximum number of tables allowed inside each WASM script store. Default: 8."
                    .to_string(),
            values: None,
        },
    );
    values.insert(
        "wasm_script_table_elements_limit".to_string(),
        ConfigValue {
            typ: "integer".to_string(),
            description: "Maximum number of table elements allowed inside each WASM script store. Default: 512.".to_string(),
            values: None,
        },
    );
    values.insert(
        "wasm_script_packet_epoch_deadline".to_string(),
        ConfigValue {
            typ: "integer".to_string(),
            description: "Epoch deadline for modify-packet calls. The host increments epochs every 10 ms, so 100 is roughly 1 second. Default: 100.".to_string(),
            values: None,
        },
    );
    values.insert(
        "wasm_script_lifecycle_epoch_deadline".to_string(),
        ConfigValue {
            typ: "integer".to_string(),
            description: "Epoch deadline for on-create, on-destroy, custom-configs, on-config-changed, and websocket calls. The host increments epochs every 10 ms, so 1000 is roughly 10 seconds. Default: 1000.".to_string(),
            values: None,
        },
    );

    ConfigValues {
        title: "WASM script limits".to_string(),
        values,
    }
}

impl AppConfig {
    const CONFIG_JSON: &str = include_str!("../static/config.json");

    pub fn load(config_file: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        use ::config::File;
        let config_builder = ::config::Config::builder()
            .add_source(File::from(config_file.clone()).required(false))
            .build()?;

        let file_config = config_builder.try_deserialize();

        if let Err(e) = file_config {
            return Err(Box::new(e));
        }

        Ok(file_config.unwrap())
    }

    pub fn save(&self, config_file: PathBuf) {
        debug!("Saving config: {:?}", self);
        let raw = fs::read_to_string(&config_file).unwrap_or_default();
        let mut doc = raw.parse::<DocumentMut>().unwrap_or_else(|_| {
            // if the file doesn't exists or there is parse error, create a new one
            DocumentMut::new()
        });

        doc["advertise"] = value(self.advertise);
        doc["enable_btle"] = value(self.enable_btle);
        doc["dongle_mode"] = value(self.dongle_mode);
        doc["debug"] = value(self.debug);
        doc["pkt_debug"] = value(self.pkt_debug);
        doc["hexdump_level"] = value(format!("{:?}", self.hexdump_level));
        doc["disable_console_debug"] = value(self.disable_console_debug);
        doc["pkt_debug_filter_enabled"] = value(self.pkt_debug_filter_enabled);
        doc["pkt_debug_filter_proxy"] = value(self.pkt_debug_filter_proxy.to_string());
        doc["pkt_debug_filter_stages"] = value(self.pkt_debug_filter_stages.to_string());
        doc["pkt_debug_filter_service_kinds"] =
            value(self.pkt_debug_filter_service_kinds.to_string());
        doc["pkt_debug_filter_channels"] = value(self.pkt_debug_filter_channels.to_string());
        doc["pkt_debug_filter_exclude_channels"] =
            value(self.pkt_debug_filter_exclude_channels.to_string());
        doc["pkt_debug_filter_message_ids"] = value(self.pkt_debug_filter_message_ids.to_string());
        doc["pkt_debug_filter_exclude_message_ids"] =
            value(self.pkt_debug_filter_exclude_message_ids.to_string());
        doc["pkt_debug_filter_pretty_proto"] = value(self.pkt_debug_filter_pretty_proto);
        doc["pkt_debug_filter_max_payload_bytes"] =
            value(self.pkt_debug_filter_max_payload_bytes as i64);
        doc["legacy"] = value(self.legacy);
        doc["quick_reconnect"] = value(self.quick_reconnect);
        doc["bt_poweroff"] = value(self.bt_poweroff);
        doc["connect"] = value(self.connect.to_string());
        doc["logfile"] = value(self.logfile.display().to_string());
        doc["crash_handler_enabled"] = value(self.crash_handler_enabled);
        doc["crash_dir"] = value(self.crash_dir.display().to_string());
        doc["sdr_ui_override_enabled"] = value(self.sdr_ui_override_enabled);
        doc["sdr_ui_override_autocreate_profiles"] =
            value(self.sdr_ui_override_autocreate_profiles);
        doc["sdr_ui_override_file"] = value(self.sdr_ui_override_file.display().to_string());
        doc["inject_displays_file"] = value(self.inject_displays_file.display().to_string());
        doc["stats_interval"] = value(self.stats_interval as i64);
        if let Some(udc) = &self.udc {
            doc["udc"] = value(udc);
        }
        doc["iface"] = value(&self.iface);
        if let Some(alias) = &self.btalias {
            doc["btalias"] = value(alias);
        }
        doc["timeout_secs"] = value(self.timeout_secs as i64);
        if let Some(webserver) = &self.webserver {
            doc["webserver"] = value(webserver);
        }
        doc["bt_timeout_secs"] = value(self.bt_timeout_secs as i64);
        doc["mitm"] = value(self.mitm);
        doc["dpi"] = value(self.dpi as i64);
        doc["audio_max_unacked"] = value(self.audio_max_unacked as i64);
        doc["add_vendor_channel"] = value(self.add_vendor_channel);
        doc["remove_tap_restriction"] = value(self.remove_tap_restriction);
        doc["video_in_motion"] = value(self.video_in_motion);
        doc["disable_media_sink"] = value(self.disable_media_sink);
        doc["disable_tts_sink"] = value(self.disable_tts_sink);
        doc["developer_mode"] = value(self.developer_mode);
        doc["wired"] = value(self.wired.as_ref().map_or(String::new(), |w| w.to_string()));
        doc["dhu"] = value(self.dhu);
        doc["aa_server_tcp_addr"] = value(self.aa_server_tcp_addr.to_string());
        doc["ev"] = value(self.ev);
        doc["odometer"] = value(self.odometer);
        doc["tire_pressure"] = value(self.tire_pressure);
        doc["remove_bluetooth"] = value(self.remove_bluetooth);
        doc["remove_wifi"] = value(self.remove_wifi);
        doc["inject_display_types"] = value(self.inject_display_types.to_string());
        doc["inject_add_input_sources"] = value(self.inject_add_input_sources);
        doc["inject_cluster_display_id"] = value(self.inject_cluster_display_id as i64);
        doc["inject_cluster_width_margin"] = value(self.inject_cluster_width_margin as i64);
        doc["inject_cluster_height_margin"] = value(self.inject_cluster_height_margin as i64);
        doc["inject_cluster_density"] = value(self.inject_cluster_density as i64);
        doc["inject_cluster_viewing_distance"] = value(self.inject_cluster_viewing_distance as i64);
        doc["inject_cluster_codec_resolution"] =
            value(self.inject_cluster_codec_resolution.to_string());
        doc["inject_cluster_touch_width"] = value(self.inject_cluster_touch_width as i64);
        doc["inject_cluster_touch_height"] = value(self.inject_cluster_touch_height as i64);
        doc["inject_aux_display_id"] = value(self.inject_aux_display_id as i64);
        doc["inject_aux_width_margin"] = value(self.inject_aux_width_margin as i64);
        doc["inject_aux_height_margin"] = value(self.inject_aux_height_margin as i64);
        doc["inject_aux_density"] = value(self.inject_aux_density as i64);
        doc["inject_aux_viewing_distance"] = value(self.inject_aux_viewing_distance as i64);
        doc["inject_aux_touch_width"] = value(self.inject_aux_touch_width as i64);
        doc["inject_aux_touch_height"] = value(self.inject_aux_touch_height as i64);
        doc["inject_force_focus_without_tap"] = value(self.inject_force_focus_without_tap);
        doc["change_usb_order"] = value(self.change_usb_order);
        doc["stop_on_disconnect"] = value(self.stop_on_disconnect);
        doc["waze_lht_workaround"] = value(self.waze_lht_workaround);
        if let Some(path) = &self.ev_battery_logger {
            doc["ev_battery_logger"] = value(path);
        }
        doc["ev_connector_types"] = value(self.ev_connector_types.to_string());
        doc["enable_ssh"] = value(self.enable_ssh);
        doc["usb_serial_console"] = value(self.usb_serial_console);
        doc["wifi_version"] = value(self.wifi_version as i64);
        doc["band"] = value(self.band.to_string());
        doc["country_code"] = value(&self.country_code);
        doc["channel"] = value(self.channel as i64);
        doc["ssid"] = value(&self.ssid);
        doc["wpa_passphrase"] = value(&self.wpa_passphrase);
        doc["eth_mode"] = value(&self.eth_mode);
        doc["startup_delay"] = value(self.startup_delay as i64);
        doc["ble_password"] = value(&self.ble_password);
        doc["external_antenna"] = value(self.external_antenna);
        if let Some(port) = self.media_dump_base_port {
            doc["media_dump_base_port"] = value(port as i64);
        }
        doc["media_wait_for_live_idr"] = value(self.media_wait_for_live_idr);
        doc["collect_speed"] = value(self.collect_speed);
        doc["disable_driving_status"] = value(self.disable_driving_status);
        if let Some(cmd) = &self.hu_button_handler {
            doc["hu_button_handler"] = value(cmd);
        }
        doc["bt_sco"] = value(self.bt_sco);
        doc["bt_sco_keep_bluetooth_alive"] = value(self.bt_sco_keep_bluetooth_alive);
        doc["bt_sco_media_bridge"] = value(self.bt_sco_media_bridge);
        doc["bt_sco_media_bridge_audio_type"] =
            value(self.bt_sco_media_bridge_audio_type.to_string());
        doc["bt_sco_media_bridge_gain_percent"] =
            value(self.bt_sco_media_bridge_gain_percent as i64);
        doc["bt_sco_media_bridge_limiter"] = value(self.bt_sco_media_bridge_limiter.to_string());
        doc["bt_sco_media_bridge_resampler"] =
            value(self.bt_sco_media_bridge_resampler.to_string());
        doc["bt_sco_media_bridge_ring_capacity"] =
            value(self.bt_sco_media_bridge_ring_capacity as i64);
        doc["bt_sco_media_bridge_start_existing"] = value(self.bt_sco_media_bridge_start_existing);
        doc["bt_sco_media_bridge_start_on_first_audio"] =
            value(self.bt_sco_media_bridge_start_on_first_audio);
        doc["bt_sco_media_bridge_audio_peak_threshold"] =
            value(self.bt_sco_media_bridge_audio_peak_threshold as i64);
        doc["bt_sco_media_bridge_start_timeout_ms"] =
            value(self.bt_sco_media_bridge_start_timeout_ms as i64);
        doc["bt_sco_media_bridge_stop_existing_on_disconnect"] =
            value(self.bt_sco_media_bridge_stop_existing_on_disconnect);
        doc["bt_sco_media_bridge_fixed_cadence"] = value(self.bt_sco_media_bridge_fixed_cadence);
        doc["bt_sco_media_bridge_cadence_ms"] = value(self.bt_sco_media_bridge_cadence_ms as i64);
        doc["bt_sco_media_bridge_jitter_buffer_ms"] =
            value(self.bt_sco_media_bridge_jitter_buffer_ms as i64);
        doc["bt_sco_mic_bridge"] = value(self.bt_sco_mic_bridge);
        doc["bt_sco_mic_request"] = value(self.bt_sco_mic_request);
        doc["bt_sco_mic_uplink_ring_capacity"] = value(self.bt_sco_mic_uplink_ring_capacity as i64);
        doc["bt_sco_mic_echo_control"] = value(self.bt_sco_mic_echo_control.to_string());
        doc["bt_sco_mic_gain_percent"] = value(self.bt_sco_mic_gain_percent as i64);
        doc["bt_sco_mic_duck_threshold"] = value(self.bt_sco_mic_duck_threshold as i64);
        doc["bt_sco_mic_duck_percent"] = value(self.bt_sco_mic_duck_percent as i64);
        doc["bt_sco_mic_duck_hold_ms"] = value(self.bt_sco_mic_duck_hold_ms as i64);
        doc["wasm_hooks_dir"] = value(self.wasm_hooks_dir.display().to_string());
        doc["wasm_script_memory_limit_mb"] = value(self.wasm_script_memory_limit_mb as i64);
        doc["wasm_script_instance_limit"] = value(self.wasm_script_instance_limit as i64);
        doc["wasm_script_memory_count_limit"] = value(self.wasm_script_memory_count_limit as i64);
        doc["wasm_script_table_limit"] = value(self.wasm_script_table_limit as i64);
        doc["wasm_script_table_elements_limit"] =
            value(self.wasm_script_table_elements_limit as i64);
        doc["wasm_script_packet_epoch_deadline"] =
            value(self.wasm_script_packet_epoch_deadline as i64);
        doc["wasm_script_lifecycle_epoch_deadline"] =
            value(self.wasm_script_lifecycle_epoch_deadline as i64);

        let _ = fs::write(config_file, doc.to_string());
    }

    pub fn load_config_json() -> Result<ConfigJson, Box<dyn std::error::Error>> {
        let parsed: ConfigJson = serde_json::from_str(Self::CONFIG_JSON)?;
        Ok(parsed)
    }
}
