use crate::config_types::{BluetoothAddressList, EvConnectorTypes, HexdumpLevel, UsbId};
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
pub const DEFAULT_WLAN_ADDR: &str = "10.0.0.1";
pub const TCP_SERVER_PORT: i32 = 5288;
pub const TCP_DHU_PORT: i32 = 5277;

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
    pub dongle_mode: bool,
    pub debug: bool,
    pub hexdump_level: HexdumpLevel,
    pub disable_console_debug: bool,
    pub legacy: bool,
    pub connect: BluetoothAddressList,
    pub logfile: PathBuf,
    pub stats_interval: u16,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub udc: Option<String>,
    pub iface: String,
    pub hostapd_conf: PathBuf,
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
    pub remove_tap_restriction: bool,
    pub video_in_motion: bool,
    pub disable_media_sink: bool,
    pub disable_tts_sink: bool,
    pub developer_mode: bool,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub wired: Option<UsbId>,
    pub dhu: bool,
    pub ev: bool,
    pub remove_bluetooth: bool,
    pub remove_wifi: bool,
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

    #[serde(skip)]
    pub action_requested: Option<Action>,
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
            dongle_mode: false,
            debug: false,
            hexdump_level: HexdumpLevel::Disabled,
            disable_console_debug: false,
            legacy: true,
            connect: BluetoothAddressList::default(),
            logfile: "/var/log/aa-proxy-rs.log".into(),
            stats_interval: 0,
            udc: None,
            iface: "wlan0".to_string(),
            hostapd_conf: "/var/run/hostapd.conf".into(),
            btalias: None,
            timeout_secs: 10,
            webserver: webserver_default_bind(),
            bt_timeout_secs: 120,
            mitm: false,
            dpi: 0,
            remove_tap_restriction: false,
            video_in_motion: false,
            disable_media_sink: false,
            disable_tts_sink: false,
            developer_mode: false,
            wired: None,
            dhu: false,
            ev: false,
            remove_bluetooth: false,
            remove_wifi: false,
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
            eth_mode: String::default(),
            startup_delay: 0,
        }
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
        doc["dongle_mode"] = value(self.dongle_mode);
        doc["debug"] = value(self.debug);
        doc["hexdump_level"] = value(format!("{:?}", self.hexdump_level));
        doc["disable_console_debug"] = value(self.disable_console_debug);
        doc["legacy"] = value(self.legacy);
        doc["connect"] = value(self.connect.to_string());
        doc["logfile"] = value(self.logfile.display().to_string());
        doc["stats_interval"] = value(self.stats_interval as i64);
        if let Some(udc) = &self.udc {
            doc["udc"] = value(udc);
        }
        doc["iface"] = value(&self.iface);
        doc["hostapd_conf"] = value(self.hostapd_conf.display().to_string());
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
        doc["remove_tap_restriction"] = value(self.remove_tap_restriction);
        doc["video_in_motion"] = value(self.video_in_motion);
        doc["disable_media_sink"] = value(self.disable_media_sink);
        doc["disable_tts_sink"] = value(self.disable_tts_sink);
        doc["developer_mode"] = value(self.developer_mode);
        doc["wired"] = value(
            self.wired
                .as_ref()
                .map_or("".to_string(), |w| w.to_string()),
        );
        doc["dhu"] = value(self.dhu);
        doc["ev"] = value(self.ev);
        doc["remove_bluetooth"] = value(self.remove_bluetooth);
        doc["remove_wifi"] = value(self.remove_wifi);
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

        let _ = fs::write(config_file, doc.to_string());
    }

    pub fn load_config_json() -> Result<ConfigJson, Box<dyn std::error::Error>> {
        let parsed: ConfigJson = serde_json::from_str(Self::CONFIG_JSON)?;
        Ok(parsed)
    }
}
