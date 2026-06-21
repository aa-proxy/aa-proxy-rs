use crate::config::AppConfig;
use crate::mitm::protos::{
    AdditionalVideoConfig, DisplayType, Insets, ServiceDiscoveryResponse, UiConfig,
    VideoConfiguration, VideoInsets, VideoMarginConfig,
};
use crate::mitm::Packet;
use anyhow::{anyhow, Context, Result};
use chrono::Local;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use simplelog::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tokio::sync::mpsc::Sender;

const NAME: &str = "<i><bright-black> sdr-ui: </>";
const HASH_LEN: usize = 12;
const MAX_EDGE_VALUE: u32 = 2000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PhoneIdentity {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bt_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bt_mac_masked: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bt_mac_hash: Option<String>,
}

static CURRENT_PHONE: Mutex<Option<PhoneIdentity>> = Mutex::new(None);
static CURRENT_SDR_UI: Mutex<Option<SdrUiCurrent>> = Mutex::new(None);

fn default_true() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_true(value: &bool) -> bool {
    *value
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SdrUiProfilesFile {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub autocreate_profiles: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vehicles: Vec<SdrUiVehicleProfile>,
}

impl Default for SdrUiProfilesFile {
    fn default() -> Self {
        Self {
            enabled: true,
            autocreate_profiles: true,
            vehicles: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SdrUiVehicleProfile {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,
    pub info: SdrUiVehicleInfo,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub displays: Vec<SdrUiDisplayProfile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phones: Vec<SdrUiPhoneProfile>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SdrUiVehicleInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub make: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub year: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vehicle_id_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_position: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_unit_make: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_unit_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_unit_software_build: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_unit_software_version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SdrUiPhoneProfile {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,
    pub info: SdrUiPhoneInfo,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub displays: Vec<SdrUiDisplayProfile>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SdrUiPhoneInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bt_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bt_mac_masked: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bt_mac_hash: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SdrUiDisplayProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<i32>,
    pub display_id: u32,
    pub display_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub video_configs: Vec<SdrUiVideoConfigProfile>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SdrUiVideoConfigProfile {
    pub codec_resolution: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub video_codec_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub density: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub real_density: Option<u32>,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_insets: Option<SdrUiInsets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stable_content_insets: Option<SdrUiInsets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub margins: Option<SdrUiInsets>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SdrUiInsets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bottom: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SdrUiCurrent {
    pub profile_file: String,
    pub global_enabled: bool,
    pub file_enabled: bool,
    pub autocreate_profiles: bool,
    pub vehicle_id: String,
    pub vehicle_name: String,
    pub vehicle_info: SdrUiVehicleInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<PhoneIdentity>,
    pub profile_exists: bool,
    pub vehicle_profile_enabled: bool,
    pub phone_profile_exists: bool,
    pub phone_profile_enabled: bool,
    pub patch_applied: bool,
    pub patch_count: usize,
    pub detected_at: String,
    pub displays: Vec<SdrUiDisplayProfile>,
}

impl Default for SdrUiCurrent {
    fn default() -> Self {
        Self {
            profile_file: String::new(),
            global_enabled: false,
            file_enabled: true,
            autocreate_profiles: true,
            vehicle_id: String::new(),
            vehicle_name: String::new(),
            vehicle_info: SdrUiVehicleInfo::default(),
            phone: None,
            profile_exists: false,
            vehicle_profile_enabled: false,
            phone_profile_exists: false,
            phone_profile_enabled: false,
            patch_applied: false,
            patch_count: 0,
            detected_at: String::new(),
            displays: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SdrUiApplySummary {
    pub vehicle_id: String,
    pub vehicle_name: String,
    pub profile_exists: bool,
    pub vehicle_profile_enabled: bool,
    pub phone_profile_exists: bool,
    pub phone_profile_enabled: bool,
    pub patch_applied: bool,
    pub patch_count: usize,
}

pub fn set_current_phone_from_bt(mac: &str, name: Option<String>) {
    let normalized_mac = mac.trim().to_ascii_uppercase();
    if normalized_mac.is_empty() {
        return;
    }
    let normalized_name = name.clone().unwrap_or_default().trim().to_string();
    let id_source = if normalized_name.is_empty() {
        normalized_mac.clone()
    } else {
        format!(
            "{}|{}",
            normalized_mac,
            normalized_name.to_ascii_lowercase()
        )
    };
    let identity = PhoneIdentity {
        id: format!("phone_{}", short_hash(&id_source)),
        name: if normalized_name.is_empty() {
            format!("Bluetooth phone {}", mask_bt_mac(&normalized_mac))
        } else {
            normalized_name.clone()
        },
        bt_name: if normalized_name.is_empty() {
            None
        } else {
            Some(normalized_name)
        },
        bt_mac_masked: Some(mask_bt_mac(&normalized_mac)),
        bt_mac_hash: Some(short_hash(&normalized_mac)),
    };

    info!(
        "{} current phone identity set: id=<b>{}</> name=<b>{}</> mac={}",
        NAME,
        identity.id,
        identity.name,
        identity.bt_mac_masked.clone().unwrap_or_default()
    );

    if let Ok(mut guard) = CURRENT_PHONE.lock() {
        *guard = Some(identity);
    }
}

pub fn clear_current_phone() {
    if let Ok(mut guard) = CURRENT_PHONE.lock() {
        *guard = None;
    }
}

pub fn current_phone() -> Option<PhoneIdentity> {
    CURRENT_PHONE.lock().ok().and_then(|guard| guard.clone())
}

pub fn current_sdr_ui() -> Option<SdrUiCurrent> {
    CURRENT_SDR_UI.lock().ok().and_then(|guard| guard.clone())
}

pub async fn read_profiles_file(path: &Path) -> Result<SdrUiProfilesFile> {
    if !path.exists() {
        return Ok(SdrUiProfilesFile::default());
    }
    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(SdrUiProfilesFile::default());
    }
    let profiles: SdrUiProfilesFile = toml_edit::de::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(profiles)
}

pub async fn write_profiles_file(path: &Path, profiles: &SdrUiProfilesFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let raw = toml_edit::ser::to_string_pretty(profiles)
        .context("failed to serialize SDR UI profile file")?;
    tokio::fs::write(path, raw)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

pub async fn list_profiles(path: PathBuf) -> Result<SdrUiProfilesFile> {
    read_profiles_file(&path).await
}

pub async fn get_vehicle_profile(
    path: PathBuf,
    vehicle_id: &str,
) -> Result<Option<SdrUiVehicleProfile>> {
    let profiles = read_profiles_file(&path).await?;
    Ok(profiles.vehicles.into_iter().find(|v| v.id == vehicle_id))
}

pub async fn upsert_vehicle_profile(
    path: PathBuf,
    vehicle_id: &str,
    mut profile: SdrUiVehicleProfile,
) -> Result<SdrUiVehicleProfile> {
    let mut profiles = read_profiles_file(&path).await?;
    profile.id = vehicle_id.to_string();

    if let Some(existing) = profiles.vehicles.iter_mut().find(|v| v.id == vehicle_id) {
        *existing = profile.clone();
    } else {
        profiles.vehicles.push(profile.clone());
    }

    write_profiles_file(&path, &profiles).await?;
    Ok(profile)
}

pub async fn delete_vehicle_profile(path: PathBuf, vehicle_id: &str) -> Result<bool> {
    let mut profiles = read_profiles_file(&path).await?;
    let before = profiles.vehicles.len();
    profiles.vehicles.retain(|v| v.id != vehicle_id);
    let deleted = profiles.vehicles.len() != before;
    if deleted {
        write_profiles_file(&path, &profiles).await?;
    }
    Ok(deleted)
}

pub async fn process_service_discovery_response(
    msg: &mut ServiceDiscoveryResponse,
    cfg: &AppConfig,
) -> Result<SdrUiApplySummary> {
    let path = cfg.sdr_ui_override_file.clone();
    let vehicle_info = vehicle_info_from_sdr(msg);
    let vehicle_id = vehicle_fingerprint(&vehicle_info);
    let vehicle_name = vehicle_name(&vehicle_info);
    let phone = current_phone();
    let snapshot = snapshot_displays(msg);

    let mut profiles = read_profiles_file(&path).await?;
    let file_enabled = profiles.enabled;
    let autocreate = cfg.sdr_ui_override_autocreate_profiles && profiles.autocreate_profiles;
    let mut changed = false;

    let profile_exists_before = profiles.vehicles.iter().any(|v| v.id == vehicle_id);
    if autocreate {
        changed |= ensure_vehicle_profile(
            &mut profiles,
            &vehicle_id,
            &vehicle_name,
            &vehicle_info,
            &snapshot,
        );
        if let Some(phone) = &phone {
            changed |= ensure_phone_profile(&mut profiles, &vehicle_id, phone);
        }
    }

    let mut vehicle_profile_enabled = false;
    let mut phone_profile_exists = false;
    let mut phone_profile_enabled = false;
    let mut patch_count = 0usize;

    if cfg.sdr_ui_override_enabled && file_enabled {
        if let Some(vehicle_profile) = profiles.vehicles.iter().find(|v| v.id == vehicle_id) {
            vehicle_profile_enabled = vehicle_profile.enabled;
            if vehicle_profile.enabled {
                patch_count +=
                    apply_display_profiles(msg, &vehicle_profile.displays, "vehicle", cfg.dpi > 0)?;
            }

            if let Some(phone) = &phone {
                if let Some(phone_profile) =
                    vehicle_profile.phones.iter().find(|p| p.id == phone.id)
                {
                    phone_profile_exists = true;
                    phone_profile_enabled = phone_profile.enabled;
                    if vehicle_profile.enabled && phone_profile.enabled {
                        patch_count += apply_display_profiles(
                            msg,
                            &phone_profile.displays,
                            "phone",
                            cfg.dpi > 0,
                        )?;
                    }
                }
            }
        }
    }

    if changed {
        write_profiles_file(&path, &profiles).await?;
        info!(
            "{} auto-created/updated SDR UI profile file: <b>{}</>",
            NAME,
            path.display()
        );
    }

    let profile_exists =
        profile_exists_before || profiles.vehicles.iter().any(|v| v.id == vehicle_id);

    let current = SdrUiCurrent {
        profile_file: path.display().to_string(),
        global_enabled: cfg.sdr_ui_override_enabled,
        file_enabled,
        autocreate_profiles: autocreate,
        vehicle_id: vehicle_id.clone(),
        vehicle_name: vehicle_name.clone(),
        vehicle_info: vehicle_info.clone(),
        phone: phone.clone(),
        profile_exists,
        vehicle_profile_enabled,
        phone_profile_exists,
        phone_profile_enabled,
        patch_applied: patch_count > 0,
        patch_count,
        detected_at: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        displays: snapshot,
    };
    if let Ok(mut guard) = CURRENT_SDR_UI.lock() {
        *guard = Some(current);
    }

    Ok(SdrUiApplySummary {
        vehicle_id,
        vehicle_name,
        profile_exists,
        vehicle_profile_enabled,
        phone_profile_exists,
        phone_profile_enabled,
        patch_applied: patch_count > 0,
        patch_count,
    })
}

fn ensure_vehicle_profile(
    profiles: &mut SdrUiProfilesFile,
    vehicle_id: &str,
    vehicle_name: &str,
    vehicle_info: &SdrUiVehicleInfo,
    snapshot: &[SdrUiDisplayProfile],
) -> bool {
    if let Some(vehicle) = profiles.vehicles.iter_mut().find(|v| v.id == vehicle_id) {
        let mut changed = false;
        if vehicle.name.trim().is_empty() {
            vehicle.name = vehicle_name.to_string();
            changed = true;
        }
        if merge_missing_displays(&mut vehicle.displays, snapshot) {
            changed = true;
        }
        return changed;
    }

    profiles.vehicles.push(SdrUiVehicleProfile {
        id: vehicle_id.to_string(),
        name: vehicle_name.to_string(),
        enabled: false,
        info: vehicle_info.clone(),
        displays: snapshot.to_vec(),
        phones: Vec::new(),
    });
    true
}

fn ensure_phone_profile(
    profiles: &mut SdrUiProfilesFile,
    vehicle_id: &str,
    phone: &PhoneIdentity,
) -> bool {
    let Some(vehicle) = profiles.vehicles.iter_mut().find(|v| v.id == vehicle_id) else {
        return false;
    };
    if let Some(existing) = vehicle.phones.iter_mut().find(|p| p.id == phone.id) {
        let mut changed = false;
        if existing.name.trim().is_empty() || existing.name.starts_with("Bluetooth phone ") {
            existing.name = phone.name.clone();
            changed = true;
        }
        if existing.info.bt_name.is_none() && phone.bt_name.is_some() {
            existing.info.bt_name = phone.bt_name.clone();
            changed = true;
        }
        if existing.info.bt_mac_masked.is_none() && phone.bt_mac_masked.is_some() {
            existing.info.bt_mac_masked = phone.bt_mac_masked.clone();
            changed = true;
        }
        if existing.info.bt_mac_hash.is_none() && phone.bt_mac_hash.is_some() {
            existing.info.bt_mac_hash = phone.bt_mac_hash.clone();
            changed = true;
        }
        return changed;
    }

    vehicle.phones.push(SdrUiPhoneProfile {
        id: phone.id.clone(),
        name: phone.name.clone(),
        enabled: false,
        info: SdrUiPhoneInfo {
            bt_name: phone.bt_name.clone(),
            bt_mac_masked: phone.bt_mac_masked.clone(),
            bt_mac_hash: phone.bt_mac_hash.clone(),
        },
        displays: Vec::new(),
    });
    true
}

fn merge_missing_displays(
    target: &mut Vec<SdrUiDisplayProfile>,
    snapshot: &[SdrUiDisplayProfile],
) -> bool {
    let mut changed = false;
    for display in snapshot {
        if let Some(existing_display) = target.iter_mut().find(|d| {
            display_matches(
                d,
                display.service_id,
                display.display_id,
                &display.display_type,
            )
        }) {
            if existing_display.service_id.is_none() && display.service_id.is_some() {
                existing_display.service_id = display.service_id;
                changed = true;
            }
            for video in &display.video_configs {
                if !existing_display
                    .video_configs
                    .iter()
                    .any(|v| v.codec_resolution == video.codec_resolution)
                {
                    existing_display.video_configs.push(video.clone());
                    changed = true;
                }
            }
        } else {
            target.push(display.clone());
            changed = true;
        }
    }
    changed
}

fn apply_display_profiles(
    msg: &mut ServiceDiscoveryResponse,
    displays: &[SdrUiDisplayProfile],
    source: &str,
    global_main_dpi_active: bool,
) -> Result<usize> {
    let mut patched = 0usize;

    for svc in msg.services.iter_mut() {
        if svc.media_sink_service.video_configs.is_empty() {
            continue;
        }

        let service_id = svc.id();
        let sink_display_id = svc.media_sink_service.display_id();
        let sink_display_type_enum = svc.media_sink_service.display_type();
        let sink_display_type = format!("{:?}", sink_display_type_enum);
        let Some(display_profile) = displays
            .iter()
            .find(|d| display_matches(d, Some(service_id), sink_display_id, &sink_display_type))
        else {
            continue;
        };

        let skip_density_override =
            global_main_dpi_active && sink_display_type_enum == DisplayType::DISPLAY_TYPE_MAIN;

        let Some(sink) = svc.media_sink_service.as_mut() else {
            continue;
        };

        for video_cfg in sink.video_configs.iter_mut() {
            let Some(video_profile) = display_profile
                .video_configs
                .iter()
                .find(|v| video_matches(v, video_cfg))
            else {
                continue;
            };

            if !video_profile.enabled {
                continue;
            }

            let count =
                apply_video_profile(video_cfg, video_profile, source, skip_density_override)?;
            patched += count;
        }
    }

    Ok(patched)
}

fn apply_video_profile(
    video_cfg: &mut VideoConfiguration,
    profile: &SdrUiVideoConfigProfile,
    source: &str,
    skip_density_override: bool,
) -> Result<usize> {
    let mut patched = 0usize;
    let resolution = video_cfg.codec_resolution();
    let mut derived_margins: Option<(u32, u32)> = None;

    if video_cfg.ui_config.is_none() {
        video_cfg.ui_config = Some(UiConfig::new()).into();
    }
    let Some(ui_config) = video_cfg.ui_config.as_mut() else {
        return Err(anyhow!("failed to create ui_config"));
    };

    if let Some(insets) = &profile.content_insets {
        let mut current = ui_config
            .content_insets
            .as_ref()
            .cloned()
            .unwrap_or_else(Insets::new);
        if apply_insets(&mut current, insets, resolution, "content_insets") {
            ui_config.content_insets = Some(current).into();
            patched += 1;
        }
    }
    if let Some(insets) = &profile.stable_content_insets {
        let mut current = ui_config
            .stable_content_insets
            .as_ref()
            .cloned()
            .unwrap_or_else(Insets::new);
        if apply_insets(&mut current, insets, resolution, "stable_content_insets") {
            ui_config.stable_content_insets = Some(current).into();
            patched += 1;
        }
    }
    if let Some(insets) = &profile.margins {
        let mut current = ui_config
            .margins
            .as_ref()
            .cloned()
            .unwrap_or_else(Insets::new);
        if apply_insets(&mut current, insets, resolution, "margins") {
            let width_margin = current.left().saturating_add(current.right());
            let height_margin = current.top().saturating_add(current.bottom());
            ui_config.margins = Some(current).into();
            derived_margins = Some((width_margin, height_margin));
            patched += 1;
        }
    }

    if let Some((width_margin, height_margin)) = derived_margins {
        video_cfg.set_width_margin(width_margin);
        video_cfg.set_height_margin(height_margin);
    }

    if skip_density_override {
        if profile.density.is_some() || profile.real_density.is_some() {
            debug!(
                "{} skipped SDR UI density/real_density override from {} because global MAIN dpi is active",
                NAME, source
            );
        }
    } else {
        if let Some(density) = profile.density {
            let prev = video_cfg.density();
            if prev != density {
                video_cfg.set_density(density);
                debug!(
                    "{} SDR UI override: density <b>{}</> -> <b>{}</> ({})",
                    NAME, prev, density, source
                );
                patched += 1;
            }
        }
        if let Some(real_density) = profile.real_density {
            let prev = video_cfg.real_density();
            if prev != real_density {
                video_cfg.set_real_density(real_density);
                debug!(
                    "{} SDR UI override: real_density <b>{}</> -> <b>{}</> ({})",
                    NAME, prev, real_density, source
                );
                patched += 1;
            }
        }
    }

    if patched > 0 {
        info!(
            "{} applied {} SDR UI override(s) from {} for resolution=<b>{}</>",
            NAME, patched, source, profile.codec_resolution
        );
    }

    Ok(patched)
}

fn apply_insets(
    current: &mut Insets,
    requested: &SdrUiInsets,
    resolution: crate::mitm::protos::VideoCodecResolutionType,
    label: &str,
) -> bool {
    let before = (
        current.top(),
        current.bottom(),
        current.left(),
        current.right(),
    );
    if let Some(top) = requested.top {
        current.set_top(clamp_edge(top, label, "top"));
    }
    if let Some(bottom) = requested.bottom {
        current.set_bottom(clamp_edge(bottom, label, "bottom"));
    }
    if let Some(left) = requested.left {
        current.set_left(clamp_edge(left, label, "left"));
    }
    if let Some(right) = requested.right {
        current.set_right(clamp_edge(right, label, "right"));
    }

    keep_insets_inside_resolution(current, resolution, label);

    before
        != (
            current.top(),
            current.bottom(),
            current.left(),
            current.right(),
        )
}

fn clamp_edge(value: u32, label: &str, field: &str) -> u32 {
    if value > MAX_EDGE_VALUE {
        warn!(
            "{} {}.{}={} is too large; clamping to {}",
            NAME, label, field, value, MAX_EDGE_VALUE
        );
        MAX_EDGE_VALUE
    } else {
        value
    }
}

fn keep_insets_inside_resolution(
    insets: &mut Insets,
    resolution: crate::mitm::protos::VideoCodecResolutionType,
    label: &str,
) {
    let Some((width, height)) = resolution_size(format!("{:?}", resolution).as_str()) else {
        return;
    };

    if insets.left().saturating_add(insets.right()) >= width {
        let allowed_right = width
            .saturating_sub(1)
            .saturating_sub(insets.left().min(width.saturating_sub(1)));
        warn!(
            "{} {} left+right exceeds width {}; reducing right to {}",
            NAME, label, width, allowed_right
        );
        insets.set_right(allowed_right);
    }

    if insets.top().saturating_add(insets.bottom()) >= height {
        let allowed_bottom = height
            .saturating_sub(1)
            .saturating_sub(insets.top().min(height.saturating_sub(1)));
        warn!(
            "{} {} top+bottom exceeds height {}; reducing bottom to {}",
            NAME, label, height, allowed_bottom
        );
        insets.set_bottom(allowed_bottom);
    }
}

/// Pushes a freshly saved vehicle profile's margin overrides to a currently
/// connected phone, if any, so margin/inset changes take effect immediately
/// instead of requiring a reconnect. Returns the number of video channels
/// updated.
pub async fn push_live_margin_updates(
    tx: Sender<Packet>,
    vehicle_profile: &SdrUiVehicleProfile,
) -> usize {
    let phone = current_phone();
    let updates = resolve_live_margin_updates(vehicle_profile, phone.as_ref());
    let mut pushed = 0usize;
    for (channel, config) in updates {
        match crate::mitm::send_ui_config_update(tx.clone(), channel, config).await {
            Ok(()) => pushed += 1,
            Err(e) => warn!(
                "{} failed to push live UI config update on channel {:#04x}: {:#}",
                NAME, channel, e
            ),
        }
    }
    if pushed > 0 {
        info!(
            "{} pushed live margin update(s) to {} video channel(s) for vehicle=<b>{}</>",
            NAME, pushed, vehicle_profile.id
        );
    }
    pushed
}

/// Computes the runtime margin push payloads needed to apply a freshly saved
/// profile to a phone already connected, without requiring a reconnect.
/// Only displays/video configs whose profile sets `margins` are included --
/// content_insets/stable_content_insets have no equivalent in the verified
/// runtime wire schema (AdditionalVideoConfig only carries margin_configs).
fn resolve_live_margin_updates(
    vehicle_profile: &SdrUiVehicleProfile,
    phone: Option<&PhoneIdentity>,
) -> Vec<(u8, AdditionalVideoConfig)> {
    let Some(current) = current_sdr_ui() else {
        return Vec::new();
    };
    if current.vehicle_id != vehicle_profile.id || !vehicle_profile.enabled {
        return Vec::new();
    }

    let phone_profile = phone.and_then(|p| {
        vehicle_profile
            .phones
            .iter()
            .find(|ph| ph.id == p.id && ph.enabled)
    });

    let mut updates = Vec::new();

    for live_display in &current.displays {
        let Some(service_id) = live_display.service_id else {
            continue;
        };
        let Ok(channel) = u8::try_from(service_id) else {
            continue;
        };

        let vehicle_display = vehicle_profile.displays.iter().find(|d| {
            display_matches(
                d,
                live_display.service_id,
                live_display.display_id,
                &live_display.display_type,
            )
        });
        let phone_display = phone_profile.and_then(|pp| {
            pp.displays.iter().find(|d| {
                display_matches(
                    d,
                    live_display.service_id,
                    live_display.display_id,
                    &live_display.display_type,
                )
            })
        });

        for live_video in &live_display.video_configs {
            let vehicle_video = vehicle_display.and_then(|d| {
                d.video_configs
                    .iter()
                    .find(|v| v.enabled && v.codec_resolution == live_video.codec_resolution)
            });
            let phone_video = phone_display.and_then(|d| {
                d.video_configs
                    .iter()
                    .find(|v| v.enabled && v.codec_resolution == live_video.codec_resolution)
            });

            let vehicle_margins = vehicle_video.and_then(|v| v.margins.as_ref());
            let phone_margins = phone_video.and_then(|v| v.margins.as_ref());
            if vehicle_margins.is_none() && phone_margins.is_none() {
                continue;
            }

            let baseline = live_video.margins.clone().unwrap_or_default();
            let pick = |get: fn(&SdrUiInsets) -> Option<u32>, base: Option<u32>| -> u32 {
                phone_margins
                    .and_then(get)
                    .or_else(|| vehicle_margins.and_then(get))
                    .or(base)
                    .unwrap_or(0)
            };

            let label = format!("{}/{}", vehicle_profile.id, live_display.display_type);
            let left = clamp_edge(pick(|i| i.left, baseline.left), &label, "left");
            let top = clamp_edge(pick(|i| i.top, baseline.top), &label, "top");
            let right = clamp_edge(pick(|i| i.right, baseline.right), &label, "right");
            let bottom = clamp_edge(pick(|i| i.bottom, baseline.bottom), &label, "bottom");
            let (left, top, right, bottom) = clamp_margins_to_resolution(
                left,
                top,
                right,
                bottom,
                &live_video.codec_resolution,
                &label,
            );

            let mut insets = VideoInsets::new();
            insets.set_left(left);
            insets.set_top(top);
            insets.set_right(right);
            insets.set_bottom(bottom);

            let mut margin_config = VideoMarginConfig::new();
            margin_config.insets = Some(insets).into();

            let mut config = AdditionalVideoConfig::new();
            config.margin_configs.push(margin_config);

            updates.push((channel, config));
        }
    }

    updates
}

fn clamp_margins_to_resolution(
    left: u32,
    top: u32,
    right: u32,
    bottom: u32,
    codec_resolution: &str,
    label: &str,
) -> (u32, u32, u32, u32) {
    let Some((width, height)) = resolution_size(codec_resolution) else {
        return (left, top, right, bottom);
    };

    let mut right = right;
    if left.saturating_add(right) >= width {
        let allowed_right = width
            .saturating_sub(1)
            .saturating_sub(left.min(width.saturating_sub(1)));
        warn!(
            "{} {} left+right exceeds width {}; reducing right to {}",
            NAME, label, width, allowed_right
        );
        right = allowed_right;
    }

    let mut bottom = bottom;
    if top.saturating_add(bottom) >= height {
        let allowed_bottom = height
            .saturating_sub(1)
            .saturating_sub(top.min(height.saturating_sub(1)));
        warn!(
            "{} {} top+bottom exceeds height {}; reducing bottom to {}",
            NAME, label, height, allowed_bottom
        );
        bottom = allowed_bottom;
    }

    (left, top, right, bottom)
}

fn display_matches(
    profile: &SdrUiDisplayProfile,
    service_id: Option<i32>,
    display_id: u32,
    display_type: &str,
) -> bool {
    if let (Some(profile_service_id), Some(service_id)) = (profile.service_id, service_id) {
        if profile_service_id != service_id {
            return false;
        }
    }

    profile.display_id == display_id
        && (profile.display_type.is_empty() || profile.display_type == display_type)
}

fn video_matches(profile: &SdrUiVideoConfigProfile, video_cfg: &VideoConfiguration) -> bool {
    if profile.codec_resolution != format!("{:?}", video_cfg.codec_resolution()) {
        return false;
    }
    if let Some(video_codec_type) = &profile.video_codec_type {
        if video_codec_type != &format!("{:?}", video_cfg.video_codec_type()) {
            return false;
        }
    }
    // density/real_density are not match keys (so profiles still match after global DPI
    // rewrites them), but they are applied in apply_video_profile when set and not skipped.
    true
}

fn snapshot_displays(msg: &ServiceDiscoveryResponse) -> Vec<SdrUiDisplayProfile> {
    let mut displays = Vec::new();
    for svc in msg.services.iter() {
        if svc.media_sink_service.video_configs.is_empty() {
            continue;
        }

        let mut display = SdrUiDisplayProfile {
            service_id: Some(svc.id()),
            display_id: svc.media_sink_service.display_id(),
            display_type: format!("{:?}", svc.media_sink_service.display_type()),
            video_configs: Vec::new(),
        };

        for video_cfg in &svc.media_sink_service.video_configs {
            display.video_configs.push(snapshot_video_config(video_cfg));
        }

        displays.push(display);
    }
    displays
}

fn snapshot_video_config(video_cfg: &VideoConfiguration) -> SdrUiVideoConfigProfile {
    let ui = &video_cfg.ui_config;
    SdrUiVideoConfigProfile {
        codec_resolution: format!("{:?}", video_cfg.codec_resolution()),
        video_codec_type: Some(format!("{:?}", video_cfg.video_codec_type())),
        density: Some(video_cfg.density()),
        real_density: Some(video_cfg.real_density()),
        enabled: true,
        content_insets: Some(insets_from_proto(&ui.content_insets)),
        stable_content_insets: Some(insets_from_proto(&ui.stable_content_insets)),
        margins: Some(insets_from_proto(&ui.margins)),
    }
}

fn insets_from_proto(insets: &Insets) -> SdrUiInsets {
    SdrUiInsets {
        top: Some(insets.top()),
        bottom: Some(insets.bottom()),
        left: Some(insets.left()),
        right: Some(insets.right()),
    }
}

fn vehicle_info_from_sdr(msg: &ServiceDiscoveryResponse) -> SdrUiVehicleInfo {
    let hu = &msg.headunit_info;
    let vehicle_id = first_non_empty(&[hu.vehicle_id(), msg.vehicle_id()]);

    SdrUiVehicleInfo {
        make: first_non_empty(&[hu.make(), msg.make()]),
        model: first_non_empty(&[hu.model(), msg.model()]),
        year: first_non_empty(&[hu.year(), msg.year()]),
        vehicle_id_hash: vehicle_id.as_deref().map(short_hash),
        display_name: non_empty_string(msg.display_name()),
        driver_position: Some(format!("{:?}", msg.driver_position())),
        head_unit_make: first_non_empty(&[hu.head_unit_make(), msg.head_unit_make()]),
        head_unit_model: first_non_empty(&[hu.head_unit_model(), msg.head_unit_model()]),
        head_unit_software_build: first_non_empty(&[
            hu.head_unit_software_build(),
            msg.head_unit_software_build(),
        ]),
        head_unit_software_version: first_non_empty(&[
            hu.head_unit_software_version(),
            msg.head_unit_software_version(),
        ]),
    }
}

fn first_non_empty(values: &[&str]) -> Option<String> {
    values.iter().find_map(|value| non_empty_string(value))
}

fn non_empty_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn vehicle_fingerprint(info: &SdrUiVehicleInfo) -> String {
    let raw = [
        info.make.as_deref().unwrap_or(""),
        info.model.as_deref().unwrap_or(""),
        info.year.as_deref().unwrap_or(""),
        info.vehicle_id_hash.as_deref().unwrap_or(""),
        info.display_name.as_deref().unwrap_or(""),
        info.driver_position.as_deref().unwrap_or(""),
        info.head_unit_make.as_deref().unwrap_or(""),
        info.head_unit_model.as_deref().unwrap_or(""),
        info.head_unit_software_build.as_deref().unwrap_or(""),
        info.head_unit_software_version.as_deref().unwrap_or(""),
    ]
    .join("|")
    .to_ascii_lowercase();

    format!("veh_{}", short_hash(&raw))
}

fn vehicle_name(info: &SdrUiVehicleInfo) -> String {
    let mut parts = Vec::new();
    if let Some(make) = &info.make {
        parts.push(make.clone());
    }
    if let Some(model) = &info.model {
        parts.push(model.clone());
    }
    if let Some(display_name) = &info.display_name {
        if !parts.iter().any(|p| p == display_name) {
            parts.push(display_name.clone());
        }
    }
    if parts.is_empty() {
        "Unknown head unit".to_string()
    } else {
        parts.join(" / ")
    }
}

fn short_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let hex = hex::encode(digest);
    hex.chars().take(HASH_LEN).collect()
}

fn mask_bt_mac(mac: &str) -> String {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() == 6 {
        format!("**:**:**:**:{}:{}", parts[4], parts[5])
    } else {
        "**:**:**:**:**:**".to_string()
    }
}

fn resolution_size(codec_resolution: &str) -> Option<(u32, u32)> {
    let value = codec_resolution.trim().to_ascii_uppercase();
    if let Some(rest) = value.strip_prefix("VIDEO_") {
        let mut parts = rest.split('X');
        let width = parts.next()?.parse::<u32>().ok()?;
        let height = parts.next()?.parse::<u32>().ok()?;
        return Some((width, height));
    }
    None
}

#[allow(dead_code)]
fn remove_file_if_empty(path: &Path) {
    if let Ok(metadata) = fs::metadata(path) {
        if metadata.len() == 0 {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_video(resolution: &str, margins: Option<SdrUiInsets>) -> SdrUiVideoConfigProfile {
        SdrUiVideoConfigProfile {
            codec_resolution: resolution.to_string(),
            enabled: true,
            margins,
            ..Default::default()
        }
    }

    fn sample_display(margins: Option<SdrUiInsets>) -> SdrUiDisplayProfile {
        SdrUiDisplayProfile {
            service_id: Some(3),
            display_id: 0,
            display_type: "DISPLAY_TYPE_MAIN".to_string(),
            video_configs: vec![sample_video("VIDEO_800x480", margins)],
        }
    }

    #[test]
    fn live_margin_update_layers_phone_over_vehicle_and_clamps_to_resolution() {
        let baseline_display = sample_display(Some(SdrUiInsets {
            top: Some(0),
            bottom: Some(0),
            left: Some(0),
            right: Some(0),
        }));
        let current = SdrUiCurrent {
            vehicle_id: "veh_test".to_string(),
            displays: vec![baseline_display],
            ..Default::default()
        };
        *CURRENT_SDR_UI.lock().unwrap() = Some(current);

        let mut vehicle_display = sample_display(Some(SdrUiInsets {
            top: Some(10),
            bottom: Some(10),
            left: Some(10),
            right: Some(790), // intentionally exceeds width; should get clamped
        }));
        vehicle_display.video_configs[0].enabled = true;

        let phone_display = sample_display(Some(SdrUiInsets {
            top: Some(20),
            bottom: None,
            left: None,
            right: None,
        }));

        let vehicle_profile = SdrUiVehicleProfile {
            id: "veh_test".to_string(),
            enabled: true,
            displays: vec![vehicle_display],
            phones: vec![SdrUiPhoneProfile {
                id: "phone_test".to_string(),
                enabled: true,
                displays: vec![phone_display],
                ..Default::default()
            }],
            ..Default::default()
        };

        let phone = PhoneIdentity {
            id: "phone_test".to_string(),
            ..Default::default()
        };

        let updates = resolve_live_margin_updates(&vehicle_profile, Some(&phone));
        assert_eq!(updates.len(), 1);
        let (channel, config) = &updates[0];
        assert_eq!(*channel, 3);

        let insets = config.margin_configs[0].insets.as_ref().unwrap();
        assert_eq!(insets.top(), 20); // phone overrides vehicle
        assert_eq!(insets.bottom(), 10); // falls back to vehicle (phone leaves it unset)
        assert_eq!(insets.left(), 10); // vehicle value
        assert_eq!(insets.right(), 789); // clamped: width 800, left 10 -> max right 789

        *CURRENT_SDR_UI.lock().unwrap() = None;
    }

    #[test]
    fn no_live_update_when_no_session_matches_vehicle() {
        *CURRENT_SDR_UI.lock().unwrap() = None;
        let vehicle_profile = SdrUiVehicleProfile {
            id: "veh_other".to_string(),
            enabled: true,
            displays: vec![sample_display(Some(SdrUiInsets {
                top: Some(5),
                bottom: Some(5),
                left: Some(5),
                right: Some(5),
            }))],
            ..Default::default()
        };
        assert!(resolve_live_margin_updates(&vehicle_profile, None).is_empty());
    }
}
