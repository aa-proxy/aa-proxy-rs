use crate::mitm::protos::{DisplayType, VideoCodecResolutionType, VideoFrameRateType};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;

fn default_true() -> bool {
    true
}

fn default_display_type() -> DisplayType {
    DisplayType::DISPLAY_TYPE_AUXILIARY
}

fn default_codec_resolution() -> VideoCodecResolutionType {
    VideoCodecResolutionType::VIDEO_1280x720
}

fn default_frame_rate() -> VideoFrameRateType {
    VideoFrameRateType::VIDEO_FPS_30
}

fn default_density() -> u32 {
    160
}

fn default_viewing_distance() -> u32 {
    300
}

fn default_touch_width() -> i32 {
    1280
}

fn default_touch_height() -> i32 {
    720
}

fn serialize_display_type<S>(
    value: &DisplayType,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn deserialize_display_type<'de, D>(deserializer: D) -> std::result::Result<DisplayType, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    DisplayType::from_str(&s).map_err(serde::de::Error::custom)
}

fn serialize_codec_resolution<S>(
    value: &VideoCodecResolutionType,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn deserialize_codec_resolution<'de, D>(
    deserializer: D,
) -> std::result::Result<VideoCodecResolutionType, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    VideoCodecResolutionType::from_str(&s).map_err(serde::de::Error::custom)
}

fn serialize_frame_rate<S>(
    value: &VideoFrameRateType,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn deserialize_frame_rate<'de, D>(
    deserializer: D,
) -> std::result::Result<VideoFrameRateType, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    VideoFrameRateType::from_str(&s).map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InjectDisplaysFile {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub displays: Vec<InjectDisplayProfile>,
}

impl Default for InjectDisplaysFile {
    fn default() -> Self {
        Self {
            enabled: true,
            displays: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InjectDisplayProfile {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(
        default = "default_display_type",
        serialize_with = "serialize_display_type",
        deserialize_with = "deserialize_display_type"
    )]
    pub display_type: DisplayType,
    #[serde(
        default = "default_codec_resolution",
        serialize_with = "serialize_codec_resolution",
        deserialize_with = "deserialize_codec_resolution"
    )]
    pub codec_resolution: VideoCodecResolutionType,
    #[serde(
        default = "default_frame_rate",
        serialize_with = "serialize_frame_rate",
        deserialize_with = "deserialize_frame_rate"
    )]
    pub frame_rate: VideoFrameRateType,
    pub width_margin: u32,
    pub height_margin: u32,
    #[serde(default = "default_density")]
    pub density: u32,
    #[serde(default = "default_viewing_distance")]
    pub viewing_distance: u32,
    #[serde(default = "default_touch_width")]
    pub touch_width: i32,
    #[serde(default = "default_touch_height")]
    pub touch_height: i32,
    pub input_source: bool,
}

impl Default for InjectDisplayProfile {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: true,
            display_type: default_display_type(),
            codec_resolution: default_codec_resolution(),
            frame_rate: default_frame_rate(),
            width_margin: 0,
            height_margin: 0,
            density: default_density(),
            viewing_distance: default_viewing_distance(),
            touch_width: default_touch_width(),
            touch_height: default_touch_height(),
            input_source: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InjectDisplaysResponse {
    pub enabled: bool,
    pub requires_reconnect: bool,
    pub display_id_mode: &'static str,
    pub file: String,
    pub displays: Vec<InjectDisplayProfile>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InjectDisplaysSettingsUpdate {
    pub enabled: Option<bool>,
}

fn display_type_id_prefix(display_type: DisplayType) -> &'static str {
    match display_type {
        DisplayType::DISPLAY_TYPE_MAIN => "main",
        DisplayType::DISPLAY_TYPE_CLUSTER => "cluster",
        DisplayType::DISPLAY_TYPE_AUXILIARY => "auxiliary",
    }
}

fn normalize_id(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;

    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }

    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "display".to_string()
    } else {
        trimmed
    }
}

fn generate_display_id(file: &InjectDisplaysFile, display_type: DisplayType) -> String {
    let prefix = display_type_id_prefix(display_type);
    let existing: HashSet<&str> = file.displays.iter().map(|p| p.id.as_str()).collect();

    for index in 1..=9999 {
        let candidate = format!("{}-{}", prefix, index);
        if !existing.contains(candidate.as_str()) {
            return candidate;
        }
    }

    format!("{}-{}", prefix, chrono::Local::now().timestamp())
}

fn validate_profile(profile: &InjectDisplayProfile) -> Result<()> {
    if profile.id.trim().is_empty() {
        return Err(anyhow!("display id must not be empty"));
    }

    if profile.input_source && profile.display_type == DisplayType::DISPLAY_TYPE_MAIN {
        return Err(anyhow!(
            "input_source is not supported for DISPLAY_TYPE_MAIN yet"
        ));
    }

    if profile.touch_width < 0 || profile.touch_height < 0 {
        return Err(anyhow!("touch dimensions must not be negative"));
    }

    Ok(())
}

fn validate_file(file: &InjectDisplaysFile) -> Result<()> {
    let mut ids = HashSet::new();
    for profile in &file.displays {
        validate_profile(profile)
            .with_context(|| format!("invalid injected display profile '{}'", profile.id))?;
        if !ids.insert(profile.id.as_str()) {
            return Err(anyhow!("duplicate injected display id: {}", profile.id));
        }
    }
    Ok(())
}

pub fn read_inject_displays_file_sync(path: &Path) -> Result<InjectDisplaysFile> {
    if !path.exists() {
        return Ok(InjectDisplaysFile::default());
    }

    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(InjectDisplaysFile::default());
    }

    let file: InjectDisplaysFile = toml_edit::de::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    validate_file(&file)?;
    Ok(file)
}

pub async fn read_inject_displays_file(path: &Path) -> Result<InjectDisplaysFile> {
    if !path.exists() {
        return Ok(InjectDisplaysFile::default());
    }

    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(InjectDisplaysFile::default());
    }

    let file: InjectDisplaysFile = toml_edit::de::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    validate_file(&file)?;
    Ok(file)
}

pub async fn write_inject_displays_file(path: &Path, file: &InjectDisplaysFile) -> Result<()> {
    validate_file(file)?;

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let raw = toml_edit::ser::to_string_pretty(file)
        .context("failed to serialize inject display profile file")?;
    tokio::fs::write(path, raw)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

pub fn response_for(path: &Path, file: InjectDisplaysFile) -> InjectDisplaysResponse {
    InjectDisplaysResponse {
        enabled: file.enabled,
        requires_reconnect: true,
        display_id_mode: "auto_max_plus_one",
        file: path.display().to_string(),
        displays: file.displays,
    }
}

pub async fn list_displays(path: PathBuf) -> Result<InjectDisplaysResponse> {
    let file = read_inject_displays_file(&path).await?;
    Ok(response_for(&path, file))
}

pub async fn update_settings(
    path: PathBuf,
    update: InjectDisplaysSettingsUpdate,
) -> Result<InjectDisplaysResponse> {
    let mut file = read_inject_displays_file(&path).await?;

    if let Some(enabled) = update.enabled {
        file.enabled = enabled;
    }

    write_inject_displays_file(&path, &file).await?;
    Ok(response_for(&path, file))
}

pub async fn add_display(
    path: PathBuf,
    mut profile: InjectDisplayProfile,
) -> Result<InjectDisplaysResponse> {
    let mut file = read_inject_displays_file(&path).await?;

    if profile.id.trim().is_empty() {
        profile.id = generate_display_id(&file, profile.display_type);
    } else {
        profile.id = normalize_id(&profile.id);
    }
    if profile.name.trim().is_empty() {
        profile.name = profile.id.clone();
    }

    if file.displays.iter().any(|p| p.id == profile.id) {
        return Err(anyhow!(
            "injected display id already exists: {}",
            profile.id
        ));
    }

    file.displays.push(profile);
    write_inject_displays_file(&path, &file).await?;
    Ok(response_for(&path, file))
}

pub async fn upsert_display(
    path: PathBuf,
    id: &str,
    mut profile: InjectDisplayProfile,
) -> Result<InjectDisplaysResponse> {
    let mut file = read_inject_displays_file(&path).await?;
    let id = normalize_id(id);
    profile.id = id.clone();
    if profile.name.trim().is_empty() {
        profile.name = profile.id.clone();
    }

    if let Some(existing) = file.displays.iter_mut().find(|p| p.id == id) {
        *existing = profile;
    } else {
        file.displays.push(profile);
    }

    write_inject_displays_file(&path, &file).await?;
    Ok(response_for(&path, file))
}

pub async fn delete_display(path: PathBuf, id: &str) -> Result<Option<InjectDisplaysResponse>> {
    let mut file = read_inject_displays_file(&path).await?;
    let before = file.displays.len();
    let id = normalize_id(id);
    file.displays.retain(|profile| profile.id != id);

    if file.displays.len() == before {
        return Ok(None);
    }

    write_inject_displays_file(&path, &file).await?;
    Ok(Some(response_for(&path, file)))
}
