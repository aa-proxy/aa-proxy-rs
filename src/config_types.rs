use crate::mitm;
use crate::mitm::protos::DisplayType;
use crate::mitm::protos::EvConnectorType;
use crate::mitm::protos::VideoCodecResolutionType;
use crate::mitm::protos::VideoFrameRateType;
use bluer::Address;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone)]
pub struct BluetoothAddressList(pub Option<Vec<Address>>);

impl BluetoothAddressList {
    /// Returns true if the list is the default wildcard (00:00:00:00:00:00),
    /// meaning "connect to any paired device".
    pub fn is_wildcard(&self) -> bool {
        self.0.as_ref().map_or(false, |addrs| {
            addrs.iter().any(|addr| *addr == Address::any())
        })
    }

    fn to_string_internal(&self) -> String {
        match &self.0 {
            Some(addresses) => addresses
                .iter()
                .map(|addr| addr.to_string())
                .collect::<Vec<_>>()
                .join(","),
            None => "".to_string(),
        }
    }
}

impl<'de> Deserialize<'de> for BluetoothAddressList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Ok(BluetoothAddressList(None));
        }

        let addresses: Result<Vec<Address>, _> = s
            .split(',')
            .map(|addr_str| addr_str.trim().parse::<Address>())
            .collect();

        match addresses {
            Ok(addrs) => {
                let wildcard_present = addrs.iter().any(|addr| addr == &Address::any());

                if wildcard_present && addrs.len() > 1 {
                    return Err(de::Error::custom(
                        "'connect' - Wildcard address '00:00:00:00:00:00' cannot be combined with other addresses"
                    ));
                }
                Ok(BluetoothAddressList(Some(addrs)))
            }
            Err(e) => Err(de::Error::custom(format!(
                "'connect' - Failed to parse addresses: {}",
                e
            ))),
        }
    }
}

impl Serialize for BluetoothAddressList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let addresses_str = self.to_string_internal();
        serializer.serialize_str(&addresses_str)
    }
}

impl fmt::Display for BluetoothAddressList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_internal())
    }
}

impl Default for BluetoothAddressList {
    fn default() -> Self {
        BluetoothAddressList(Some(vec![Address::any()]))
    }
}

fn parse_display_type_token(token: &str) -> Option<DisplayType> {
    match token.trim().to_ascii_lowercase().as_str() {
        "main" | "display_type_main" => Some(DisplayType::DISPLAY_TYPE_MAIN),
        "cluster" | "display_type_cluster" => Some(DisplayType::DISPLAY_TYPE_CLUSTER),
        "aux" | "auxiliary" | "display_type_auxiliary" => Some(DisplayType::DISPLAY_TYPE_AUXILIARY),
        _ => None,
    }
}

impl std::str::FromStr for EvConnectorType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        <mitm::protos::EvConnectorType as protobuf::Enum>::from_str(s.trim())
            .ok_or_else(|| format!("Unknown EV connector type: {}", s))
    }
}

impl std::str::FromStr for DisplayType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_display_type_token(s)
            .or_else(|| <mitm::protos::DisplayType as protobuf::Enum>::from_str(s.trim()))
            .ok_or_else(|| format!("Unknown display type: {}", s))
    }
}

fn parse_video_codec_resolution_token(token: &str) -> Option<VideoCodecResolutionType> {
    match token.trim().to_ascii_lowercase().as_str() {
        "800x480" => Some(VideoCodecResolutionType::VIDEO_800x480),
        "1280x720" | "720p" => Some(VideoCodecResolutionType::VIDEO_1280x720),
        "1920x1080" | "1080p" => Some(VideoCodecResolutionType::VIDEO_1920x1080),
        "2560x1440" | "1440p" => Some(VideoCodecResolutionType::VIDEO_2560x1440),
        "3840x2160" | "2160p" | "4k" => Some(VideoCodecResolutionType::VIDEO_3840x2160),
        "720x1280" => Some(VideoCodecResolutionType::VIDEO_720x1280),
        "1080x1920" => Some(VideoCodecResolutionType::VIDEO_1080x1920),
        "1440x2560" => Some(VideoCodecResolutionType::VIDEO_1440x2560),
        "2160x3840" => Some(VideoCodecResolutionType::VIDEO_2160x3840),
        _ => None,
    }
}

impl std::str::FromStr for VideoCodecResolutionType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_video_codec_resolution_token(s)
            .or_else(|| {
                <mitm::protos::VideoCodecResolutionType as protobuf::Enum>::from_str(s.trim())
            })
            .ok_or_else(|| format!("Unknown video codec resolution type: {}", s))
    }
}


fn parse_video_frame_rate_token(token: &str) -> Option<VideoFrameRateType> {
    match token.trim().to_ascii_lowercase().as_str() {
        "60" | "60fps" | "fps60" | "video_fps_60" => Some(VideoFrameRateType::VIDEO_FPS_60),
        "30" | "30fps" | "fps30" | "video_fps_30" => Some(VideoFrameRateType::VIDEO_FPS_30),
        _ => None,
    }
}

impl std::str::FromStr for VideoFrameRateType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_video_frame_rate_token(s)
            .or_else(|| {
                <mitm::protos::VideoFrameRateType as protobuf::Enum>::from_str(s.trim())
            })
            .ok_or_else(|| format!("Unknown video frame rate type: {}", s))
    }
}

impl fmt::Display for DisplayType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl fmt::Display for EvConnectorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl fmt::Display for VideoCodecResolutionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl fmt::Display for VideoFrameRateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectClusterCodecResolution(pub VideoCodecResolutionType);

impl Default for InjectClusterCodecResolution {
    fn default() -> Self {
        Self(VideoCodecResolutionType::VIDEO_800x480)
    }
}

impl<'de> Deserialize<'de> for InjectClusterCodecResolution {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let resolution = s
            .parse::<VideoCodecResolutionType>()
            .map_err(de::Error::custom)?;
        Ok(Self(resolution))
    }
}

impl Serialize for InjectClusterCodecResolution {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl fmt::Display for InjectClusterCodecResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EvConnectorTypes(pub Option<Vec<EvConnectorType>>);

impl EvConnectorTypes {
    fn to_string_internal(&self) -> String {
        match &self.0 {
            Some(types) => types
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<String>>()
                .join(","),
            None => "".to_string(),
        }
    }
}

impl<'de> Deserialize<'de> for EvConnectorTypes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let mut types = Vec::new();
        if !s.is_empty() {
            for part in s.split(',') {
                let trimmed = part.trim();
                if !trimmed.is_empty() {
                    let connector_type = trimmed
                        .parse::<EvConnectorType>()
                        .map_err(de::Error::custom)?;
                    types.push(connector_type);
                }
            }
        }

        if types.is_empty() {
            Ok(EvConnectorTypes(None))
        } else {
            Ok(EvConnectorTypes(Some(types)))
        }
    }
}

impl Serialize for EvConnectorTypes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = self.to_string_internal();
        serializer.serialize_str(&s)
    }
}

impl fmt::Display for EvConnectorTypes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.to_string_internal();
        write!(f, "{}", s)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InjectDisplayTypes(pub Option<Vec<DisplayType>>);

impl InjectDisplayTypes {
    fn to_string_internal(&self) -> String {
        match &self.0 {
            Some(types) => types
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<String>>()
                .join(","),
            None => "".to_string(),
        }
    }
}

impl<'de> Deserialize<'de> for InjectDisplayTypes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let mut types = Vec::new();
        if !s.is_empty() {
            for part in s.split(',') {
                let trimmed = part.trim();
                if !trimmed.is_empty() {
                    let display_type = trimmed.parse::<DisplayType>().map_err(de::Error::custom)?;
                    if !types.contains(&display_type) {
                        types.push(display_type);
                    }
                }
            }
        }

        if types.is_empty() {
            Ok(InjectDisplayTypes(None))
        } else {
            Ok(InjectDisplayTypes(Some(types)))
        }
    }
}

impl Serialize for InjectDisplayTypes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = self.to_string_internal();
        serializer.serialize_str(&s)
    }
}

impl fmt::Display for InjectDisplayTypes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.to_string_internal();
        write!(f, "{}", s)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_display_types_parses_aliases_and_deduplicates() {
        let parsed: InjectDisplayTypes = serde_json::from_str("\"cluster,aux,cluster\"")
            .expect("valid inject display type list");

        assert_eq!(
            parsed,
            InjectDisplayTypes(Some(vec![
                DisplayType::DISPLAY_TYPE_CLUSTER,
                DisplayType::DISPLAY_TYPE_AUXILIARY,
            ]))
        );
    }

    #[test]
    fn inject_display_types_serializes_to_enum_names() {
        let value = InjectDisplayTypes(Some(vec![
            DisplayType::DISPLAY_TYPE_CLUSTER,
            DisplayType::DISPLAY_TYPE_AUXILIARY,
        ]));

        let serialized = serde_json::to_string(&value).expect("serialize inject display types");
        assert_eq!(
            serialized,
            "\"DISPLAY_TYPE_CLUSTER,DISPLAY_TYPE_AUXILIARY\""
        );
    }

    #[test]
    fn inject_cluster_codec_resolution_accepts_aliases() {
        let parsed: InjectClusterCodecResolution =
            serde_json::from_str("\"1280x720\"").expect("valid resolution alias");
        assert_eq!(parsed.0, VideoCodecResolutionType::VIDEO_1280x720);
    }

    #[test]
    fn inject_cluster_codec_resolution_serializes_to_enum_name() {
        let value = InjectClusterCodecResolution(VideoCodecResolutionType::VIDEO_1920x1080);
        let serialized =
            serde_json::to_string(&value).expect("serialize inject cluster codec resolution");
        assert_eq!(serialized, "\"VIDEO_1920x1080\"");
    }
}
