use crate::config::AppConfig;
use crate::inject_displays::{read_inject_displays_file_sync, InjectDisplayProfile};
pub use crate::media_tap::{
    media_tcp_server, AudioStreamConfig, MediaSink, MediaStreamInfo, MediaStreamKind,
};
use crate::mitm::get_name;
use crate::mitm::protos::config::Status;
use crate::mitm::protos::Config as ProtoConfig;
use crate::mitm::protos::MediaMessageId::*;
use crate::mitm::protos::*;
use crate::mitm::ModifyContext;
use crate::mitm::Packet;
use crate::mitm::ProxyType;
use crate::mitm::{ENCRYPTED, FRAME_TYPE_FIRST, FRAME_TYPE_LAST, FRAME_TYPE_MASK};
use protobuf::Enum;
use protobuf::Message;
use simplelog::*;
use tokio::sync::mpsc::Sender;

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum InjectedMediaPhase {
    #[default]
    Idle,
    SetupSeen,
    FocusSent,
    Started,
    Streaming,
}

impl InjectedMediaPhase {
    fn can_stream(self) -> bool {
        matches!(self, Self::Started | Self::Streaming)
    }

    fn awaiting_focus(self) -> bool {
        matches!(self, Self::SetupSeen)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct InjectedMediaState {
    phase: InjectedMediaPhase,
    session_id: i32,
    ack_counter: u32,
    last_flags: u8,
    trace_after_start: u16,
}

#[derive(Clone, Debug)]
pub struct InjectedDisplayService {
    pub media_service_id: i32,
    pub input_service_id: Option<i32>,
    pub display_type: DisplayType,
    pub inject_display_id: String,
}

#[derive(Clone)]
struct DisplayProfile {
    inject_display_id: String,
    display_type: DisplayType,
    display_id: u32,
    codec_resolution: VideoCodecResolutionType,
    frame_rate: VideoFrameRateType,
    initial_content_keycode: Option<KeyCode>,
    width_margin: u32,
    height_margin: u32,
    density: u32,
    viewing_distance: u32,
    touch_width: i32,
    touch_height: i32,
    input_source: bool,
}

fn injected_display_label(display_type: DisplayType) -> &'static str {
    match display_type {
        DisplayType::DISPLAY_TYPE_MAIN => "main",
        DisplayType::DISPLAY_TYPE_CLUSTER => "cluster",
        DisplayType::DISPLAY_TYPE_AUXILIARY => "aux",
    }
}

fn max_existing_video_display_id(msg: &ServiceDiscoveryResponse) -> u32 {
    msg.services
        .iter()
        .filter(|svc| !svc.media_sink_service.video_configs.is_empty())
        .map(|svc| svc.media_sink_service.display_id())
        .max()
        .unwrap_or(0)
}

fn profile_from_config(
    cfg: &AppConfig,
    profile: &InjectDisplayProfile,
    display_id: u32,
) -> DisplayProfile {
    DisplayProfile {
        inject_display_id: profile.id.clone(),
        display_type: profile.display_type,
        display_id,
        codec_resolution: profile.codec_resolution,
        frame_rate: profile.frame_rate,
        initial_content_keycode: if profile.display_type == DisplayType::DISPLAY_TYPE_AUXILIARY {
            Some(profile.initial_content_keycode.unwrap_or(KeyCode::KEYCODE_NAVIGATION))
        } else {
            None
        },
        width_margin: profile.width_margin,
        height_margin: profile.height_margin,
        density: if cfg.dpi > 0 { cfg.dpi.into() } else { profile.density },
        viewing_distance: profile.viewing_distance,
        touch_width: profile.touch_width,
        touch_height: profile.touch_height,
        input_source: profile.input_source,
    }
}

fn display_profiles(msg: &ServiceDiscoveryResponse, cfg: &AppConfig) -> Vec<DisplayProfile> {
    let file = match read_inject_displays_file_sync(&cfg.inject_displays_file) {
        Ok(file) => file,
        Err(err) => {
            warn!(
                "<yellow>display injection:</> failed to read {}: {:#}",
                cfg.inject_displays_file.display(),
                err
            );
            return Vec::new();
        }
    };

    if !file.enabled {
        return Vec::new();
    }

    let mut next_display_id = max_existing_video_display_id(msg).saturating_add(1);
    let mut profiles = Vec::new();

    for profile in file.displays.iter().filter(|profile| profile.enabled) {
        profiles.push(profile_from_config(cfg, profile, next_display_id));
        next_display_id = next_display_id.saturating_add(1);
    }

    profiles
}

fn has_input_display(msg: &ServiceDiscoveryResponse, display_id: u32) -> bool {
    msg.services.iter().any(|svc| {
        svc.input_source_service.is_some() && svc.input_source_service.display_id() == display_id
    })
}

fn next_service_id(msg: &ServiceDiscoveryResponse) -> i32 {
    msg.services.iter().map(|s| s.id()).max().unwrap_or(0) + 1
}

fn create_media_sink_service(id: i32, profile: DisplayProfile) -> Service {
    let mut margins = Insets::new();
    margins.set_top(profile.height_margin / 2);
    margins.set_bottom(profile.height_margin / 2);
    margins.set_left(profile.width_margin / 2);
    margins.set_right(profile.width_margin / 2);

    let mut ui_config = UiConfig::new();
    ui_config.margins = Some(margins).into();
    ui_config.content_insets = Some(Insets::new()).into();
    ui_config.stable_content_insets = Some(Insets::new()).into();
    ui_config.set_ui_theme(UiTheme::UI_THEME_AUTOMATIC);

    let mut video_cfg = VideoConfiguration::new();
    video_cfg.set_codec_resolution(profile.codec_resolution);
    video_cfg.set_frame_rate(profile.frame_rate);
    video_cfg.set_width_margin(profile.width_margin);
    video_cfg.set_height_margin(profile.height_margin);
    video_cfg.set_density(profile.density);
    video_cfg.set_decoder_additional_depth(0);
    video_cfg.set_viewing_distance(profile.viewing_distance);
    video_cfg.set_pixel_aspect_ratio_e4(10000);
    video_cfg.set_real_density(profile.density);
    video_cfg.set_video_codec_type(MediaCodecType::MEDIA_CODEC_VIDEO_H264_BP);
    video_cfg.ui_config = Some(ui_config).into();

    let mut sink = MediaSinkService::new();
    sink.set_available_type(MediaCodecType::MEDIA_CODEC_VIDEO_H264_BP);
    sink.video_configs.push(video_cfg);
    sink.set_display_id(profile.display_id);
    sink.set_display_type(profile.display_type);
    if profile.display_type == DisplayType::DISPLAY_TYPE_AUXILIARY {
        if let Some(keycode) = profile.initial_content_keycode {
            sink.set_initial_content_keycode(keycode);
        }
    }

    let mut service = Service::new();
    service.set_id(id);
    service.media_sink_service = Some(sink).into();
    service
}

fn create_input_source_service(id: i32, profile: DisplayProfile) -> Service {
    let keycodes = match profile.display_type {
        DisplayType::DISPLAY_TYPE_CLUSTER => vec![19, 20, 21, 22, 23],
        DisplayType::DISPLAY_TYPE_AUXILIARY => {
            vec![3, 4, 5, 6, 84, 85, 87, 88, 126, 127, 65537, 65538, 65540]
        }
        DisplayType::DISPLAY_TYPE_MAIN => Vec::new(),
    };

    let mut source = InputSourceService::new();
    source.keycodes_supported = keycodes;
    if profile.display_type == DisplayType::DISPLAY_TYPE_AUXILIARY {
        let mut touchscreen = input_source_service::TouchScreen::new();
        touchscreen.set_width(profile.touch_width);
        touchscreen.set_height(profile.touch_height);
        touchscreen.set_type(TouchScreenType::RESISTIVE);
        touchscreen.set_is_secondary(true);
        source.touchscreen.push(touchscreen);
    }
    source.set_display_id(profile.display_id);

    let mut service = Service::new();
    service.set_id(id);
    service.input_source_service = Some(source).into();
    service
}

pub fn add_display_services(
    msg: &mut ServiceDiscoveryResponse,
    cfg: &AppConfig,
) -> Vec<InjectedDisplayService> {
    if !cfg.mitm {
        return Vec::new();
    }

    let mut injected = Vec::new();
    for profile in display_profiles(msg, cfg) {
        let media_service_id = next_service_id(msg);
        msg.services.push(create_media_sink_service(media_service_id, profile.clone()));

        let input_service_id = if profile.input_source && !has_input_display(msg, profile.display_id) {
            let input_service_id = next_service_id(msg);
            msg.services.push(create_input_source_service(input_service_id, profile.clone()));
            Some(input_service_id)
        } else {
            None
        };

        injected.push(InjectedDisplayService {
            media_service_id,
            input_service_id,
            display_type: profile.display_type,
            inject_display_id: profile.inject_display_id.clone(),
        });
    }

    injected
}

fn injected_max_unacked(display_type: DisplayType) -> u32 {
    match display_type {
        DisplayType::DISPLAY_TYPE_CLUSTER => 1,
        DisplayType::DISPLAY_TYPE_AUXILIARY => 2,
        _ => 1,
    }
}

fn first_fragment_message_id(pkt: &Packet) -> Option<u16> {
    if pkt.payload.len() < 2 {
        return None;
    }

    match pkt.flags & FRAME_TYPE_MASK {
        f if f == FRAME_TYPE_FIRST || f == (FRAME_TYPE_FIRST | FRAME_TYPE_LAST) => {
            Some(u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]))
        }
        _ => None,
    }
}

fn rewrite_media_config_ready(pkt: &mut Packet, max_unacked: u32) -> Result<()> {
    let mut cfg = ProtoConfig::new();
    cfg.set_status(Status::STATUS_READY);
    cfg.set_max_unacked(max_unacked);
    cfg.configuration_indices.push(0);

    let mut payload = cfg.write_to_bytes()?;
    payload.insert(0, ((MEDIA_MESSAGE_CONFIG as u16) >> 8) as u8);
    payload.insert(1, ((MEDIA_MESSAGE_CONFIG as u16) & 0xff) as u8);
    pkt.payload = payload;
    // Payload was rebuilt, so any old fragment metadata must be cleared.
    pkt.final_length = None;
    pkt.flags = (pkt.flags & !FRAME_TYPE_MASK) | FRAME_TYPE_FIRST | FRAME_TYPE_LAST;
    Ok(())
}

fn rewrite_media_ack(pkt: &mut Packet, session_id: i32, ack_counter: u32) -> Result<()> {
    let mut ack = Ack::new();
    ack.set_session_id(session_id);
    ack.set_ack(ack_counter);

    let mut payload = ack.write_to_bytes()?;
    payload.insert(0, ((MEDIA_MESSAGE_ACK as u16) >> 8) as u8);
    payload.insert(1, ((MEDIA_MESSAGE_ACK as u16) & 0xff) as u8);
    pkt.payload = payload;
    // Payload was rebuilt, so any old fragment metadata must be cleared.
    pkt.final_length = None;
    pkt.flags = (pkt.flags & !FRAME_TYPE_MASK) | FRAME_TYPE_FIRST | FRAME_TYPE_LAST;
    Ok(())
}

fn rewrite_video_focus_notification(
    pkt: &mut Packet,
    focus: VideoFocusMode,
    unsolicited: bool,
) -> Result<()> {
    let mut notification = VideoFocusNotification::new();
    notification.set_focus(focus);
    notification.set_unsolicited(unsolicited);

    let mut payload = notification.write_to_bytes()?;
    payload.insert(
        0,
        ((MEDIA_MESSAGE_VIDEO_FOCUS_NOTIFICATION as u16) >> 8) as u8,
    );
    payload.insert(
        1,
        ((MEDIA_MESSAGE_VIDEO_FOCUS_NOTIFICATION as u16) & 0xff) as u8,
    );
    pkt.payload = payload;
    // Payload was rebuilt, so any old fragment metadata must be cleared.
    pkt.final_length = None;
    pkt.flags = (pkt.flags & !FRAME_TYPE_MASK) | FRAME_TYPE_FIRST | FRAME_TYPE_LAST;
    Ok(())
}

pub fn maybe_emit_pending_injected_focus(
    proxy_type: ProxyType,
    ctx: &mut ModifyContext,
    cfg: &AppConfig,
    tx: &Sender<Packet>,
) -> Result<()> {
    let mut ready_channels: Vec<(u8, u8, bool, DisplayType)> = Vec::new();
    let mut projected_focus_channels: Vec<(u8, u8, DisplayType)> = Vec::new();
    let mut release_channels: Vec<(u8, u8, DisplayType)> = Vec::new();
    let mut connect_gen_updates: Vec<(u8, u64)> = Vec::new();
    let mut tap_presence_updates: Vec<(u8, bool)> = Vec::new();

    for (&channel, state) in &ctx.injected_media_state {
        let sink = ctx.media_channels.get(&channel);
        let has_tap_client = sink.map(|s| s.has_subscribers()).unwrap_or(false);
        let connect_gen = sink
            .map(|s| s.client_connect_generation())
            .unwrap_or_default();
        let seen_connect_gen = ctx
            .injected_media_connect_gen
            .get(&channel)
            .copied()
            .unwrap_or_default();
        let new_connection = connect_gen > seen_connect_gen;
        let had_tap_client = ctx
            .injected_media_had_tap_client
            .get(&channel)
            .copied()
            .unwrap_or(false);
        let lost_last_consumer = had_tap_client && !has_tap_client;

        connect_gen_updates.push((channel, connect_gen));
        tap_presence_updates.push((channel, has_tap_client));

        let Some(&display_type) = ctx.injected_media_display.get(&channel) else {
            continue;
        };
        let display_label = injected_display_label(display_type);

        if new_connection
            && has_tap_client
            && matches!(
                state.phase,
                InjectedMediaPhase::FocusSent
                    | InjectedMediaPhase::Started
                    | InjectedMediaPhase::Streaming
            )
        {
            projected_focus_channels.push((channel, state.last_flags, display_type));
        }

        // Reconnect into Idle: re-acquire projected focus so the phone restarts the stream.
        if new_connection && has_tap_client && state.phase == InjectedMediaPhase::Idle {
            info!(
                "{} <blue>injected media:</> new {} tap client on channel {:#04x} in idle phase; re-acquiring projected focus",
                get_name(proxy_type),
                display_label,
                channel
            );
            ready_channels.push((channel, state.last_flags, has_tap_client, display_type));
        }

        if lost_last_consumer
            && !cfg.inject_force_focus_without_tap
            && matches!(
                state.phase,
                InjectedMediaPhase::FocusSent
                    | InjectedMediaPhase::Started
                    | InjectedMediaPhase::Streaming
            )
        {
            release_channels.push((channel, state.last_flags, display_type));
        }

        if !state.phase.awaiting_focus() {
            continue;
        }

        debug!(
            "{} deferred_focus check: ch={:#04x} tap_client={} force={} media_channels_has_sink={} connect_gen={} seen_connect_gen={} new_connection={}",
            get_name(proxy_type),
            channel,
            has_tap_client,
            cfg.inject_force_focus_without_tap,
            ctx.media_channels.contains_key(&channel),
            connect_gen,
            seen_connect_gen,
            new_connection
        );

        if has_tap_client || cfg.inject_force_focus_without_tap {
            ready_channels.push((channel, state.last_flags, has_tap_client, display_type));
        }
    }

    // Reacquire projected focus on fresh injected-video tap connections even if we do not
    // currently have injected media runtime state for that channel.
    for (&channel, &display_type) in &ctx.injected_media_display {
        if ctx.injected_media_state.contains_key(&channel) {
            continue;
        }

        let Some(sink) = ctx.media_channels.get(&channel) else {
            continue;
        };

        let has_tap_client = sink.has_subscribers();
        let connect_gen = sink.client_connect_generation();
        let seen_connect_gen = ctx
            .injected_media_connect_gen
            .get(&channel)
            .copied()
            .unwrap_or_default();
        let new_connection = connect_gen > seen_connect_gen;

        connect_gen_updates.push((channel, connect_gen));
        tap_presence_updates.push((channel, has_tap_client));

        if new_connection && has_tap_client {
            debug!(
                "{} deferred_focus check: ch={:#04x} phase=absent tap_client=true force={} media_channels_has_sink=true connect_gen={} seen_connect_gen={} new_connection=true",
                get_name(proxy_type),
                channel,
                cfg.inject_force_focus_without_tap,
                connect_gen,
                seen_connect_gen,
            );
            projected_focus_channels.push((channel, ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST, display_type));
        }
    }

    for (channel, connect_gen) in connect_gen_updates {
        ctx.injected_media_connect_gen.insert(channel, connect_gen);
    }

    for (channel, has_tap_client) in tap_presence_updates {
        ctx.injected_media_had_tap_client
            .insert(channel, has_tap_client);
    }

    for (channel, flags, display_type) in release_channels {
        let mut release_focus_pkt = Packet {
            channel,
            flags,
            final_length: None,
            payload: Vec::new(),
        };
        rewrite_video_focus_notification(
            &mut release_focus_pkt,
            VideoFocusMode::VIDEO_FOCUS_NATIVE,
            true,
        )?;

        info!(
            "{} <blue>injected media:</> last {} tap client disconnected on channel <b>{:#04x}</>; releasing projected focus",
            get_name(proxy_type),
            injected_display_label(display_type),
            channel
        );

        match tx.try_send(release_focus_pkt) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    "{} <yellow>injected focus release backpressure:</> queue full while sending native focus for channel <b>{:#04x}</>; will retry",
                    get_name(proxy_type),
                    channel
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err("injected focus queue closed".into());
            }
        }
    }

    for (channel, flags, display_type) in projected_focus_channels {
        let mut project_focus_pkt = Packet {
            channel,
            flags,
            final_length: None,
            payload: Vec::new(),
        };
        rewrite_video_focus_notification(
            &mut project_focus_pkt,
            VideoFocusMode::VIDEO_FOCUS_PROJECTED,
            true,
        )?;

        info!(
            "{} <blue>injected media:</> {} tap client connected on channel <b>{:#04x}</>; sending projected VIDEO_FOCUS_NOTIFICATION",
            get_name(proxy_type),
            injected_display_label(display_type),
            channel
        );

        match tx.try_send(project_focus_pkt) {
            Ok(()) => {
                debug!(
                    "{} injected projected focus on channel <b>{:#04x}</>: display={}",
                    get_name(proxy_type),
                    channel,
                    injected_display_label(display_type)
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    "{} <yellow>injected projected focus backpressure:</> queue full while sending projected focus for channel <b>{:#04x}</>; will retry",
                    get_name(proxy_type),
                    channel
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err("injected focus queue closed".into());
            }
        }
    }

    for (channel, flags, has_tap_client, display_type) in ready_channels {
        let mut focus_pkt = Packet {
            channel,
            flags,
            final_length: None,
            payload: Vec::new(),
        };
        rewrite_video_focus_notification(
            &mut focus_pkt,
            VideoFocusMode::VIDEO_FOCUS_PROJECTED,
            true,
        )?;
        info!(
            "{} <blue>injected media:</> synthesized VIDEO_FOCUS_NOTIFICATION on channel <b>{:#04x}</> display={} tap_client={} force={}",
            get_name(proxy_type),
            channel,
            injected_display_label(display_type),
            has_tap_client,
            cfg.inject_force_focus_without_tap
        );

        match tx.try_send(focus_pkt) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    "{} <yellow>deferred focus backpressure:</> queue full while emitting focus for channel <b>{:#04x}</>; will retry",
                    get_name(proxy_type),
                    channel
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err("injected focus queue closed".into());
            }
        }
    }

    Ok(())
}

pub fn emulate_injected_media_packet(
    proxy_type: ProxyType,
    pkt: &mut Packet,
    ctx: &mut ModifyContext,
    reassembled_frame: Option<&[u8]>,
    has_fragment_state: bool,
) -> Result<bool> {
    let message_id = first_fragment_message_id(pkt)
        .or_else(|| {
            reassembled_frame.and_then(|frame| {
                if frame.len() >= 2 {
                    Some(u16::from_be_bytes([frame[0], frame[1]]))
                } else {
                    None
                }
            })
        })
        .or_else(|| {
            if has_fragment_state {
                Some(MEDIA_MESSAGE_DATA.value() as u16)
            } else {
                None
            }
        });

    let Some(message_id) = message_id else {
        return Ok(false);
    };

    let data = reassembled_frame
        .and_then(|frame| frame.get(2..))
        .or_else(|| pkt.payload.get(2..))
        .unwrap_or_default();
    let state = ctx.injected_media_state.entry(pkt.channel).or_default();
    let display_type = ctx
        .injected_media_display
        .get(&pkt.channel)
        .copied()
        .unwrap_or(DisplayType::DISPLAY_TYPE_CLUSTER);
    let max_unacked = injected_max_unacked(display_type);

    match MediaMessageId::from_i32(message_id.into()).unwrap_or(MEDIA_MESSAGE_DATA) {
        MEDIA_MESSAGE_SETUP => {
            state.phase = InjectedMediaPhase::SetupSeen;
            state.session_id = 0;
            state.ack_counter = 0;
            state.last_flags = pkt.flags;
            info!(
                "{} <blue>injected media:</> SETUP on channel <b>{:#04x}</> display={:?}",
                get_name(proxy_type),
                pkt.channel,
                display_type
            );
            // Virtual sink: immediately advertise readiness and keep unacked window tiny.
            rewrite_media_config_ready(pkt, max_unacked)?;
            Ok(true)
        }
        MEDIA_MESSAGE_START => {
            if let Ok(msg) = Start::parse_from_bytes(data) {
                state.session_id = msg.session_id();
                state.ack_counter = 0;
                state.phase = InjectedMediaPhase::Started;
                state.last_flags = pkt.flags;
                state.trace_after_start = 128;
                info!(
                    "{} <blue>injected media:</> START on channel <b>{:#04x}</> display={:?} session_id={} cfg_index={}",
                    get_name(proxy_type),
                    pkt.channel,
                    display_type,
                    msg.session_id(),
                    msg.configuration_index()
                );
            } else {
                warn!(
                    "{} <yellow>injected media:</> START parse failed on channel <b>{:#04x}</> display={:?}",
                    get_name(proxy_type),
                    pkt.channel,
                    display_type
                );
            }
            // Native sinks do not emit a control reply for START. Emitting CONFIG here
            // can stall phone-side control flow right after injected startup.
            Ok(false)
        }
        MEDIA_MESSAGE_DATA => {
            if reassembled_frame.is_none()
                && (has_fragment_state
                    || pkt.flags & FRAME_TYPE_MASK != (FRAME_TYPE_FIRST | FRAME_TYPE_LAST))
            {
                debug!(
                    "{} <blue>injected media:</> fragment_wait on channel <b>{:#04x}</> display={:?}",
                    get_name(proxy_type),
                    pkt.channel,
                    display_type
                );
                return Ok(false);
            }

            if state.phase.can_stream() {
                state.phase = InjectedMediaPhase::Streaming;
                state.ack_counter = state.ack_counter.saturating_add(1);
                rewrite_media_ack(pkt, state.session_id, state.ack_counter)?;
                if state.ack_counter == 1 || state.ack_counter % 256 == 0 {
                    info!(
                        "{} <blue>injected media:</> DATA ack on channel <b>{:#04x}</> display={:?} session_id={} ack={}",
                        get_name(proxy_type),
                        pkt.channel,
                        display_type,
                        state.session_id,
                        state.ack_counter
                    );
                }
                return Ok(true);
            }

            warn!(
                "{} <yellow>injected media:</> state_not_started on channel <b>{:#04x}</> display={:?}",
                get_name(proxy_type),
                pkt.channel,
                display_type
            );
            Ok(false)
        }
        MEDIA_MESSAGE_STOP => {
            info!(
                "{} <blue>injected media:</> STOP on channel <b>{:#04x}</> display={:?} session_id={} final_ack={}",
                get_name(proxy_type),
                pkt.channel,
                display_type,
                state.session_id,
                state.ack_counter
            );
            state.phase = InjectedMediaPhase::Idle;
            state.ack_counter = 0;
            state.session_id = 0;
            state.last_flags = pkt.flags;
            Ok(false)
        }
        MEDIA_MESSAGE_VIDEO_FOCUS_REQUEST => {
            let mut requested_focus = VideoFocusMode::VIDEO_FOCUS_PROJECTED;
            let mut reason = VideoFocusReason::UNKNOWN;
            if let Ok(msg) = VideoFocusRequestNotification::parse_from_bytes(data) {
                requested_focus = msg.mode();
                reason = msg.reason();
            } else {
                warn!(
                    "{} <yellow>injected media:</> VIDEO_FOCUS_REQUEST parse failed on channel <b>{:#04x}</> display={:?}",
                    get_name(proxy_type),
                    pkt.channel,
                    display_type
                );
            }

            info!(
                "{} <blue>injected media:</> VIDEO_FOCUS_REQUEST on channel <b>{:#04x}</> display={:?} focus={:?} reason={:?}",
                get_name(proxy_type),
                pkt.channel,
                display_type,
                requested_focus,
                reason
            );

            rewrite_video_focus_notification(pkt, requested_focus, false)?;
            state.phase = InjectedMediaPhase::FocusSent;
            Ok(true)
        }
        _ => {
            info!(
                "{} <blue>injected media:</> passthrough message_id=0x{:04X} on channel <b>{:#04x}</> display={:?}",
                get_name(proxy_type),
                message_id,
                pkt.channel,
                display_type
            );
            Ok(false)
        }
    }
}

