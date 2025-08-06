use bluer::Address;
use serde::de::{self, Deserializer, Error as DeError, Visitor};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use simplelog::*;
use std::{
    fmt::{self, Display},
    fs,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};
use tokio::sync::RwLock;
use toml_edit::{value, DocumentMut};
use std::collections::HashMap;
use indexmap::IndexMap;

pub type SharedConfig = Arc<RwLock<AppConfig>>;
pub type SharedConfigJson = Arc<RwLock<ConfigJson>>;

#[derive(
    clap::ValueEnum, Default, Debug, PartialEq, PartialOrd, Clone, Copy, Deserialize, Serialize,
)]
pub enum HexdumpLevel {
    #[default]
    Disabled,
    DecryptedInput,
    RawInput,
    DecryptedOutput,
    RawOutput,
    All,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsbId {
    pub vid: u16,
    pub pid: u16,
}

impl std::str::FromStr for UsbId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err("Expected format VID:PID".to_string());
        }
        let vid = u16::from_str_radix(parts[0], 16).map_err(|e| e.to_string())?;
        let pid = u16::from_str_radix(parts[1], 16).map_err(|e| e.to_string())?;
        Ok(UsbId { vid, pid })
    }
}

impl fmt::Display for UsbId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}:{:x}", self.vid, self.pid)
    }
}

impl<'de> Deserialize<'de> for UsbId {
    fn deserialize<D>(deserializer: D) -> Result<UsbId, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UsbIdVisitor;

        impl<'de> Visitor<'de> for UsbIdVisitor {
            type Value = UsbId;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string in the format VID:PID")
            }

            fn visit_str<E>(self, value: &str) -> Result<UsbId, E>
            where
                E: de::Error,
            {
                UsbId::from_str(value).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(UsbIdVisitor)
    }
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
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub connect: Option<Address>,
    pub logfile: PathBuf,
    pub stats_interval: u16,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub udc: Option<String>,
    pub iface: String,
    pub hostapd_conf: PathBuf,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub btalias: Option<String>,
    pub keepalive: bool,
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
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub ev_battery_logger: Option<PathBuf>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub ev_connector_types: Option<String>,

    #[serde(skip)]
    pub restart_requested: bool,
}

impl Default for ConfigValue {
    fn default() -> Self {
        Self {
            typ: String::new(),
            description: String::new(),
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
        Self {
            titles: Vec::new(),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            advertise: false,
            dongle_mode: false,
            debug: false,
            hexdump_level: HexdumpLevel::Disabled,
            disable_console_debug: false,
            legacy: true,
            connect: None,
            logfile: "/var/log/aa-proxy-rs.log".into(),
            stats_interval: 0,
            udc: None,
            iface: "wlan0".to_string(),
            hostapd_conf: "/var/run/hostapd.conf".into(),
            btalias: None,
            keepalive: false,
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
            ev_battery_logger: None,
            restart_requested: false,
            ev_connector_types: None,
        }
    }
}

impl AppConfig {
    const CONFIG_JSON: &str = include_str!("../static/config.json");

    pub fn load(config_file: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        use ::config::File;
        let file_config: AppConfig = ::config::Config::builder()
            .add_source(File::from(config_file).required(false))
            .build()?
            .try_deserialize()
            .unwrap_or_default();

        Ok(file_config)
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
        doc["connect"] = match &self.connect {
            Some(c) => value(c.to_string()),
            None => value(""),
        };
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
        doc["keepalive"] = value(self.keepalive);
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
        if let Some(path) = &self.ev_battery_logger {
            doc["ev_battery_logger"] = value(path.display().to_string());
        }
        if let Some(ev_connector_types) = &self.ev_connector_types {
            doc["ev_connector_types"] = value(ev_connector_types);
        }

        let _ = fs::write(config_file, doc.to_string());
    }

    pub fn load_config_json() -> Result<ConfigJson, Box<dyn std::error::Error>> {
        let parsed: ConfigJson = serde_json::from_str(Self::CONFIG_JSON)?;
        Ok(parsed)
    }
}
