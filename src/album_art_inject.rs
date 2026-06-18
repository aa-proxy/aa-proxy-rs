use crate::config::AppConfig;
use crate::map_album_art::replacement_png_for_config;
use crate::mitm::{Packet, ENCRYPTED, FRAME_TYPE_FIRST, FRAME_TYPE_LAST, FRAME_TYPE_MASK};
use crate::packet_fragment::{
    clamp_first_fragment_payload_bytes, fragment_plain_payload, frame_base_flags,
    openauto_continuation_fragment_payload_bytes, PlainPayloadFragmentOptions,
    DEFAULT_FIRST_FRAGMENT_PAYLOAD_BYTES, MAX_FIRST_FRAGMENT_PAYLOAD_BYTES,
    MIN_FIRST_FRAGMENT_PAYLOAD_BYTES,
};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// MediaPlaybackStatusMessageId::MEDIA_PLAYBACK_METADATA.
/// Kept as a constant here so this helper only needs raw packet/protobuf bytes.
const MEDIA_PLAYBACK_METADATA_ID: i32 = 0x8003;
const NO_MEDIA_PLAYBACK_CHANNEL: u16 = u16::MAX;

static GLOBAL_MEDIA_PLAYBACK_CHANNEL: AtomicU16 = AtomicU16::new(NO_MEDIA_PLAYBACK_CHANNEL);
static GLOBAL_MEDIA_PLAYBACK_CHANNEL_GENERATION: AtomicU64 = AtomicU64::new(0);
static GLOBAL_METADATA_TEXT_PREFIX: Mutex<Option<String>> = Mutex::new(None);
static GLOBAL_METADATA_TEXT_PREFIX_GENERATION: AtomicU64 = AtomicU64::new(0);
static GLOBAL_METADATA_TEXT_PREFIX_UPDATED_MS: AtomicU64 = AtomicU64::new(0);

fn encode_channel(channel: Option<u8>) -> u16 {
    channel.map(u16::from).unwrap_or(NO_MEDIA_PLAYBACK_CHANNEL)
}

fn decode_channel(channel: u16) -> Option<u8> {
    if channel == NO_MEDIA_PLAYBACK_CHANNEL {
        None
    } else {
        u8::try_from(channel).ok()
    }
}

fn global_media_playback_channel() -> Option<u8> {
    decode_channel(GLOBAL_MEDIA_PLAYBACK_CHANNEL.load(Ordering::SeqCst))
}

fn global_media_playback_channel_generation() -> u64 {
    GLOBAL_MEDIA_PLAYBACK_CHANNEL_GENERATION.load(Ordering::SeqCst)
}

fn set_global_media_playback_channel(channel: Option<u8>) -> u64 {
    let encoded = encode_channel(channel);
    let previous = GLOBAL_MEDIA_PLAYBACK_CHANNEL.swap(encoded, Ordering::SeqCst);
    if previous != encoded {
        GLOBAL_MEDIA_PLAYBACK_CHANNEL_GENERATION.fetch_add(1, Ordering::SeqCst) + 1
    } else {
        global_media_playback_channel_generation()
    }
}

pub(crate) fn set_global_metadata_text_prefix(prefix: Option<String>) -> u64 {
    let normalized = prefix
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let mut guard = match GLOBAL_METADATA_TEXT_PREFIX.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    if *guard == normalized {
        if normalized.is_some() {
            GLOBAL_METADATA_TEXT_PREFIX_UPDATED_MS.store(now_millis(), Ordering::SeqCst);
        }
        return GLOBAL_METADATA_TEXT_PREFIX_GENERATION.load(Ordering::SeqCst);
    }

    let updated_ms = if normalized.is_some() { now_millis() } else { 0 };
    *guard = normalized;
    GLOBAL_METADATA_TEXT_PREFIX_UPDATED_MS.store(updated_ms, Ordering::SeqCst);
    GLOBAL_METADATA_TEXT_PREFIX_GENERATION.fetch_add(1, Ordering::SeqCst) + 1
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn global_metadata_text_prefix(cfg: &AppConfig) -> Option<String> {
    if album_art_ev_text_mode(cfg) == AlbumArtEvTextMode::AlbumArt {
        return None;
    }

    let prefix = match GLOBAL_METADATA_TEXT_PREFIX.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };

    if prefix.is_some() && cfg.map_album_art_ev_prefix_max_age_ms > 0 {
        let updated = GLOBAL_METADATA_TEXT_PREFIX_UPDATED_MS.load(Ordering::SeqCst);
        let now = now_millis();
        if updated == 0 || now.saturating_sub(updated) > cfg.map_album_art_ev_prefix_max_age_ms {
            return None;
        }
    }

    prefix
}

fn global_metadata_text_prefix_generation() -> u64 {
    GLOBAL_METADATA_TEXT_PREFIX_GENERATION.load(Ordering::SeqCst)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AlbumArtEvTextMode {
    /// Only replace/update the album-art image. Do not touch song/artist text.
    AlbumArt,
    /// Prefix song/title with the EV text.
    SongPrefix,
    /// Move original artist in front of song/title and write EV text into artist.
    ArtistField,
    /// Prefix artist with the EV text. Song/title is left unchanged.
    ArtistPrefix,
}

fn normalized_ev_text_mode(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace(' ', "_")
}

fn album_art_ev_text_mode(cfg: &AppConfig) -> AlbumArtEvTextMode {
    match normalized_ev_text_mode(&cfg.map_album_art_ev_text_mode).as_str() {
        "song_prefix" | "prefix" | "song" | "title_prefix" => AlbumArtEvTextMode::SongPrefix,
        "artist_field" | "artist" | "artist_slot" | "replace_artist" => {
            AlbumArtEvTextMode::ArtistField
        }
        "artist_prefix" | "prefix_artist" | "artist_title_prefix" => {
            AlbumArtEvTextMode::ArtistPrefix
        }
        "album_art" | "albumart" | "art" | "only_album_art" | "album_art_only" | "off" | "none"
        | "" => AlbumArtEvTextMode::AlbumArt,
        _ => AlbumArtEvTextMode::AlbumArt,
    }
}

#[derive(Default)]
pub(crate) struct MapAlbumArtInjector {
    states: HashMap<u8, AlbumArtRewriteState>,
    observe_states: HashMap<u8, MetadataObserveState>,
    last_metadata: Option<CachedMetadata>,
    media_playback_channel: Option<u8>,
    media_playback_channel_generation: u64,
    last_emitted_art_version: u64,
    last_emitted_prefix_generation: u64,
    last_missing_template_log_version: u64,
    duration_tick_flip: bool,
}

pub(crate) enum AlbumArtProcessResult {
    /// Leave the current packet untouched and let the normal forwarding path handle it.
    Forward,
    /// Drop the current original fragment. A rewritten message will be emitted when the last
    /// fragment arrives.
    Drop,
    /// Replace the original message with these complete, re-fragmented packets.
    Replace(Vec<Packet>),
}

struct AlbumArtRewriteState {
    payload: Vec<u8>,
    replacement: Vec<u8>,
    replacement_source: String,
    replacement_version: u64,
    base_flags: u8,
    first_final_length: Option<u32>,
    original_fragments: usize,
}

struct MetadataObserveState {
    payload: Vec<u8>,
    base_flags: u8,
}

#[derive(Clone, Debug)]
struct CachedMetadata {
    channel: u8,
    base_flags: u8,
    payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RewriteError {
    Malformed,
}

impl MapAlbumArtInjector {
    pub(crate) fn clear(&mut self) {
        self.states.clear();
        self.observe_states.clear();
    }

    pub(crate) fn set_media_playback_channel(&mut self, channel: Option<u8>) {
        self.sync_media_playback_channel_from_global();

        if self.media_playback_channel == channel && global_media_playback_channel() == channel {
            return;
        }

        info!(
            "map album art: media playback metadata channel changed from {:?} to {:?}; clearing cached metadata template",
            self.media_playback_channel, channel
        );
        self.media_playback_channel_generation = set_global_media_playback_channel(channel);
        self.media_playback_channel = channel;
        self.last_metadata = None;
        self.last_missing_template_log_version = 0;
        self.clear();
    }

    pub(crate) fn media_playback_channel(&self) -> Option<u8> {
        self.media_playback_channel
            .or_else(global_media_playback_channel)
    }

    fn sync_media_playback_channel_from_global(&mut self) {
        let generation = global_media_playback_channel_generation();
        if self.media_playback_channel_generation == generation {
            return;
        }

        let channel = global_media_playback_channel();
        if self.media_playback_channel != channel {
            info!(
                "map album art: media playback metadata channel synchronized from shared route {:?} -> {:?}; clearing cached metadata template",
                self.media_playback_channel, channel
            );
            self.media_playback_channel = channel;
            self.last_metadata = None;
            self.last_missing_template_log_version = 0;
            self.clear();
        }
        self.media_playback_channel_generation = generation;
    }

    /// Build a synthetic MediaPlaybackMetadata packet from the last metadata seen
    /// on the phone side when the runtime artwork store changes (for example via
    /// POST /map-album-art). The packets are plaintext/application payloads and
    /// should be sent through the normal MD -> HU replacement/forward path so the
    /// existing TLS encrypt + transmit code writes correct frame sizes.
    pub(crate) fn take_pending_metadata_emit(&mut self, cfg: &AppConfig) -> Option<Vec<Packet>> {
        if !cfg.map_album_art_enabled {
            self.clear();
            return None;
        }

        self.sync_media_playback_channel_from_global();

        let replacement = match load_png_replacement(cfg) {
            Some(replacement) => replacement,
            None => {
                // No runtime/file artwork is currently available for the selected source.
                // Do not synthesize metadata; leave the phone's metadata untouched until
                // a real PNG appears (REST/companion/rust_h264 upload or file source).
                self.last_emitted_art_version =
                    crate::map_album_art::global_album_art_store().version();
                return None;
            }
        };
        let prefix_generation = global_metadata_text_prefix_generation();
        if replacement.version == self.last_emitted_art_version
            && prefix_generation == self.last_emitted_prefix_generation
        {
            return None;
        }

        if let Some(cached) = self.last_metadata.clone() {
            match self.build_rewritten_packets(
                cached.channel,
                cached.base_flags,
                &cached.payload,
                &replacement.png,
                cfg,
            ) {
                Ok((packets, rewritten_payload_len)) => {
                    self.last_emitted_art_version = replacement.version;
                    self.last_emitted_prefix_generation = global_metadata_text_prefix_generation();
                    debug!(
                        "map album art: emitted cached MEDIA_PLAYBACK_METADATA after artwork update (source={} version={} channel={:#04x} payload={} replacement_png={} fragments={})",
                        replacement.source,
                        replacement.version,
                        cached.channel,
                        rewritten_payload_len,
                        replacement.png.len(),
                        packets.len()
                    );
                    return Some(packets);
                }
                Err(RewriteError::Malformed) => {
                    warn!(
                        "map album art: cached MEDIA_PLAYBACK_METADATA is malformed; falling back to synthetic artwork metadata"
                    );
                }
            }
        }

        let channel = match self.media_playback_channel {
            Some(channel) => channel,
            None => {
                if self.last_missing_template_log_version != replacement.version {
                    info!(
                        "map album art: runtime artwork version {} is pending but no MEDIA_PLAYBACK_METADATA template/channel has been cached from SDR yet",
                        replacement.version
                    );
                    self.last_missing_template_log_version = replacement.version;
                }
                return None;
            }
        };

        let duration_tick = self.take_duration_tick(cfg);
        let synthetic_payload = build_synthetic_metadata_payload(
            &replacement.png,
            cfg.map_album_art_duration_tick_enabled,
            duration_tick,
            cfg,
        );
        let rewritten_payload_len = synthetic_payload.len();
        let packets = self.fragment_metadata(
            channel,
            frame_base_flags(ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST),
            &synthetic_payload,
            cfg,
        );
        self.last_emitted_art_version = replacement.version;
        self.last_emitted_prefix_generation = global_metadata_text_prefix_generation();
        debug!(
            "map album art: emitted synthetic MEDIA_PLAYBACK_METADATA artwork update (source={} version={} channel={:#04x} payload={} replacement_png={} fragments={} duration_tick={})",
            replacement.source,
            replacement.version,
            channel,
            rewritten_payload_len,
            replacement.png.len(),
            packets.len(),
            cfg.map_album_art_duration_tick_enabled
        );
        Some(packets)
    }

    pub(crate) fn process_packet(
        &mut self,
        pkt: &Packet,
        message_id: i32,
        cfg: &AppConfig,
    ) -> AlbumArtProcessResult {
        if !cfg.map_album_art_enabled {
            self.clear();
            return AlbumArtProcessResult::Forward;
        }

        self.sync_media_playback_channel_from_global();

        let frame_kind = pkt.flags & FRAME_TYPE_MASK;
        let is_first =
            frame_kind == FRAME_TYPE_FIRST || frame_kind == (FRAME_TYPE_FIRST | FRAME_TYPE_LAST);
        let is_last =
            frame_kind == FRAME_TYPE_LAST || frame_kind == (FRAME_TYPE_FIRST | FRAME_TYPE_LAST);

        if self.media_playback_channel != Some(pkt.channel) {
            return AlbumArtProcessResult::Forward;
        }

        if is_first {
            // A new fragmented/standalone message starts on this channel. If an old
            // metadata message was still pending, abandon it rather than applying
            // offsets to an unrelated stream.
            if self.states.remove(&pkt.channel).is_some() {
                warn!(
                    "map album art: replacing incomplete metadata rewrite state on channel {:#04x}",
                    pkt.channel
                );
            }
            self.observe_states.remove(&pkt.channel);

            if message_id != MEDIA_PLAYBACK_METADATA_ID || pkt.payload.len() < 2 {
                return AlbumArtProcessResult::Forward;
            }

            let replacement = match load_png_replacement(cfg) {
                Some(replacement) => replacement,
                None => {
                    // No selected source has artwork to send. Do not override metadata and
                    // do not drop fragments. Still keep a passive copy of the latest metadata
                    // so a later REST/companion/rust_h264 update can emit immediately.
                    let base_flags = frame_base_flags(pkt.flags);
                    if is_last {
                        self.cache_metadata_template(pkt.channel, base_flags, pkt.payload.clone());
                    } else {
                        self.observe_states.insert(
                            pkt.channel,
                            MetadataObserveState {
                                payload: pkt.payload.clone(),
                                base_flags,
                            },
                        );
                    }
                    return AlbumArtProcessResult::Forward;
                }
            };

            let base_flags = frame_base_flags(pkt.flags);

            if is_last {
                return self.finish_rewrite(
                    pkt.channel,
                    base_flags,
                    pkt.payload.clone(),
                    replacement.png,
                    replacement.source,
                    replacement.version,
                    pkt.final_length,
                    1,
                    cfg,
                );
            }

            self.states.insert(
                pkt.channel,
                AlbumArtRewriteState {
                    payload: pkt.payload.clone(),
                    replacement: replacement.png,
                    replacement_source: replacement.source,
                    replacement_version: replacement.version,
                    base_flags,
                    first_final_length: pkt.final_length,
                    original_fragments: 1,
                },
            );
            return AlbumArtProcessResult::Drop;
        }

        if let Some(state) = self.states.get_mut(&pkt.channel) {
            state.payload.extend_from_slice(&pkt.payload);
            state.original_fragments = state.original_fragments.saturating_add(1);

            if is_last {
                if let Some(state) = self.states.remove(&pkt.channel) {
                    return self.finish_rewrite(
                        pkt.channel,
                        state.base_flags,
                        state.payload,
                        state.replacement,
                        state.replacement_source,
                        state.replacement_version,
                        state.first_final_length,
                        state.original_fragments,
                        cfg,
                    );
                }
            }

            return AlbumArtProcessResult::Drop;
        }

        if self.observe_states.contains_key(&pkt.channel) {
            if is_last {
                if let Some(mut state) = self.observe_states.remove(&pkt.channel) {
                    state.payload.extend_from_slice(&pkt.payload);
                    self.cache_metadata_template(pkt.channel, state.base_flags, state.payload);
                }
            } else if let Some(state) = self.observe_states.get_mut(&pkt.channel) {
                state.payload.extend_from_slice(&pkt.payload);
            }
            return AlbumArtProcessResult::Forward;
        }

        AlbumArtProcessResult::Forward
    }

    fn cache_metadata_template(&mut self, channel: u8, base_flags: u8, payload: Vec<u8>) {
        let payload_len = payload.len();
        let summary = summarize_metadata_payload(&payload);
        self.last_metadata = Some(CachedMetadata {
            channel,
            base_flags,
            payload,
        });

        if let Some(summary) = summary {
            info!(
                "map album art: cached REAL MEDIA_PLAYBACK_METADATA template channel={:#04x} payload={} song={:?} artist={:?} album={:?} playlist={:?} duration={:?} rating={:?} has_art={} art_bytes={:?}",
                channel,
                payload_len,
                summary.song,
                summary.artist,
                summary.album,
                summary.playlist,
                summary.duration_seconds,
                summary.rating,
                summary.has_album_art,
                summary.album_art_bytes
            );
        } else {
            info!(
                "map album art: cached REAL MEDIA_PLAYBACK_METADATA template channel={:#04x} payload={} summary=parse_failed",
                channel, payload_len
            );
        }
    }

    fn finish_rewrite(
        &mut self,
        channel: u8,
        base_flags: u8,
        original_payload: Vec<u8>,
        replacement: Vec<u8>,
        replacement_source: String,
        replacement_version: u64,
        first_final_length: Option<u32>,
        original_fragments: usize,
        cfg: &AppConfig,
    ) -> AlbumArtProcessResult {
        let original_payload_len = original_payload.len();

        // Cache the unmodified metadata as a template. When REST/companion/rust_h264
        // updates the PNG later, we can re-emit MediaPlaybackMetadata immediately
        // without waiting for the phone to send a new track metadata packet.
        self.cache_metadata_template(channel, base_flags, original_payload.clone());

        match self.build_rewritten_packets(
            channel,
            base_flags,
            &original_payload,
            &replacement,
            cfg,
        ) {
            Ok((rewritten, rewritten_payload_len)) => {
                let rewritten_final_length = Some(rewritten_payload_len as u32);
                self.last_emitted_art_version = replacement_version;
                self.last_emitted_prefix_generation = global_metadata_text_prefix_generation();
                info!(
                    "map album art: rewrote MEDIA_PLAYBACK_METADATA album_art on channel {:#04x} (source={} mode=dynamic version={} original_payload={} rewritten_payload={} replacement_png={} original_fragments={} rewritten_fragments={} chunk_bytes={} original_final_length={:?} rewritten_final_length={:?})",
                    channel,
                    replacement_source,
                    replacement_version,
                    original_payload_len,
                    rewritten_payload_len,
                    replacement.len(),
                    original_fragments,
                    rewritten.len(),
                    effective_chunk_bytes(cfg),
                    first_final_length,
                    rewritten_final_length
                );
                AlbumArtProcessResult::Replace(rewritten)
            }
            Err(RewriteError::Malformed) => {
                warn!(
                    "map album art: malformed MEDIA_PLAYBACK_METADATA protobuf on channel {:#04x}; replaying original metadata",
                    channel
                );
                let rewritten = self.fragment_metadata(channel, base_flags, &original_payload, cfg);
                self.last_emitted_art_version = replacement_version;
                self.last_emitted_prefix_generation = global_metadata_text_prefix_generation();
                AlbumArtProcessResult::Replace(rewritten)
            }
        }
    }

    fn build_rewritten_packets(
        &mut self,
        channel: u8,
        base_flags: u8,
        original_payload: &[u8],
        replacement: &[u8],
        cfg: &AppConfig,
    ) -> Result<(Vec<Packet>, usize), RewriteError> {
        let duration_tick = self.take_duration_tick(cfg);
        let rewritten_payload =
            rewrite_album_art_payload(original_payload, replacement, duration_tick, cfg)?;
        let rewritten_payload_len = rewritten_payload.len();
        let packets = self.fragment_metadata(channel, base_flags, &rewritten_payload, cfg);
        Ok((packets, rewritten_payload_len))
    }

    fn take_duration_tick(&mut self, cfg: &AppConfig) -> bool {
        if !cfg.map_album_art_duration_tick_enabled {
            return false;
        }

        self.duration_tick_flip = !self.duration_tick_flip;
        self.duration_tick_flip
    }

    fn fragment_metadata(
        &self,
        channel: u8,
        base_flags: u8,
        payload: &[u8],
        cfg: &AppConfig,
    ) -> Vec<Packet> {
        let chunk_bytes = effective_chunk_bytes(cfg);
        fragment_plain_payload(
            payload,
            PlainPayloadFragmentOptions {
                channel,
                base_flags,
                first_fragment_payload_bytes: chunk_bytes,
                continuation_fragment_payload_bytes: openauto_continuation_fragment_payload_bytes(
                    chunk_bytes,
                ),
                first_final_length: Some(payload.len() as u32),
            },
        )
    }
}

fn build_synthetic_metadata_payload(
    replacement: &[u8],
    duration_tick_enabled: bool,
    duration_tick: bool,
    cfg: &AppConfig,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(replacement.len().saturating_add(16));
    payload.push(((MEDIA_PLAYBACK_METADATA_ID as u16) >> 8) as u8);
    payload.push(((MEDIA_PLAYBACK_METADATA_ID as u16) & 0xff) as u8);

    let mut wrote_song_field = false;
    if let Some(ev_text) = global_metadata_text_prefix(cfg) {
        let field_no = match album_art_ev_text_mode(cfg) {
            AlbumArtEvTextMode::SongPrefix => 1,
            AlbumArtEvTextMode::ArtistField | AlbumArtEvTextMode::ArtistPrefix => 2,
            AlbumArtEvTextMode::AlbumArt => 0,
        };
        if field_no != 0 {
            write_varint((field_no << 3) | 2, &mut payload);
            write_varint(ev_text.len() as u64, &mut payload);
            payload.extend_from_slice(ev_text.as_bytes());
            wrote_song_field = field_no == 1;
        }
    }

    if !wrote_song_field {
        // Some HUs ignore artwork-only synthetic metadata until real playback
        // metadata arrives. A zero-width title makes the protobuf look like a
        // normal metadata update while remaining visually blank.
        const SYNTHETIC_PLACEHOLDER_TITLE: &str = "\u{200B}";
        write_varint((1 << 3) | 2, &mut payload);
        write_varint(SYNTHETIC_PLACEHOLDER_TITLE.len() as u64, &mut payload);
        payload.extend_from_slice(SYNTHETIC_PLACEHOLDER_TITLE.as_bytes());
    }

    if duration_tick_enabled {
        write_varint((6 << 3) | 0, &mut payload);
        write_varint(if duration_tick { 1 } else { 0 }, &mut payload);
    }

    write_varint((4 << 3) | 2, &mut payload);
    write_varint(replacement.len() as u64, &mut payload);
    payload.extend_from_slice(replacement);
    payload
}

fn load_png_replacement(cfg: &AppConfig) -> Option<crate::map_album_art::ResolvedAlbumArt> {
    replacement_png_for_config(cfg)
}

fn effective_chunk_bytes(cfg: &AppConfig) -> usize {
    let requested = if cfg.map_album_art_chunk_bytes == 0 {
        DEFAULT_FIRST_FRAGMENT_PAYLOAD_BYTES
    } else {
        cfg.map_album_art_chunk_bytes
    };

    let clamped = clamp_first_fragment_payload_bytes(requested);
    if clamped != requested {
        warn!(
            "map album art: map_album_art_chunk_bytes={} is outside supported range {}..={}; using {}",
            requested, MIN_FIRST_FRAGMENT_PAYLOAD_BYTES, MAX_FIRST_FRAGMENT_PAYLOAD_BYTES, clamped
        );
    }
    clamped
}

#[derive(Debug, Default)]
struct MetadataSummary {
    song: Option<String>,
    artist: Option<String>,
    album: Option<String>,
    playlist: Option<String>,
    duration_seconds: Option<u64>,
    rating: Option<u64>,
    has_album_art: bool,
    album_art_bytes: Option<usize>,
}

fn summarize_metadata_payload(payload: &[u8]) -> Option<MetadataSummary> {
    if payload.len() < 2 {
        return None;
    }

    let mut summary = MetadataSummary::default();
    let data = &payload[2..];
    let mut pos = 0usize;

    while pos < data.len() {
        let key = read_varint(data, &mut pos).ok()?;
        if key == 0 {
            return None;
        }
        let field_no = key >> 3;
        let wire_type = key & 0x07;

        match wire_type {
            0 => {
                let value = read_varint(data, &mut pos).ok()?;
                match field_no {
                    6 => summary.duration_seconds = Some(value),
                    7 => summary.rating = Some(value),
                    _ => {}
                }
            }
            1 => {
                if data.len().saturating_sub(pos) < 8 {
                    return None;
                }
                pos += 8;
            }
            2 => {
                let len = read_varint(data, &mut pos).ok()? as usize;
                if data.len().saturating_sub(pos) < len {
                    return None;
                }
                let value = &data[pos..pos + len];
                pos += len;

                match field_no {
                    1 => summary.song = String::from_utf8(value.to_vec()).ok(),
                    2 => summary.artist = String::from_utf8(value.to_vec()).ok(),
                    3 => summary.album = String::from_utf8(value.to_vec()).ok(),
                    4 => {
                        summary.has_album_art = true;
                        summary.album_art_bytes = Some(len);
                    }
                    5 => summary.playlist = String::from_utf8(value.to_vec()).ok(),
                    _ => {}
                }
            }
            5 => {
                if data.len().saturating_sub(pos) < 4 {
                    return None;
                }
                pos += 4;
            }
            _ => return None,
        }
    }

    Some(summary)
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, RewriteError> {
    let mut value = 0u64;
    let mut shift = 0u32;

    while *pos < data.len() {
        let byte = data[*pos];
        *pos += 1;
        value |= ((byte & 0x7F) as u64) << shift;

        if byte & 0x80 == 0 {
            return Ok(value);
        }

        shift += 7;
        if shift >= 64 {
            return Err(RewriteError::Malformed);
        }
    }

    Err(RewriteError::Malformed)
}

fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push(((value as u8) & 0x7F) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn skip_checked(data: &[u8], pos: &mut usize, len: usize) -> Result<(), RewriteError> {
    if data.len().saturating_sub(*pos) < len {
        return Err(RewriteError::Malformed);
    }
    *pos += len;
    Ok(())
}

fn read_metadata_text_field(payload: &[u8], target_field: u64) -> Option<Vec<u8>> {
    if payload.len() < 2 {
        return None;
    }

    let data = &payload[2..];
    let mut pos = 0usize;
    while pos < data.len() {
        let key = read_varint(data, &mut pos).ok()?;
        if key == 0 {
            return None;
        }

        let field_no = key >> 3;
        let wire_type = key & 0x07;
        match wire_type {
            0 => {
                let _ = read_varint(data, &mut pos).ok()?;
            }
            1 => {
                if data.len().saturating_sub(pos) < 8 {
                    return None;
                }
                pos += 8;
            }
            2 => {
                let len = read_varint(data, &mut pos).ok()? as usize;
                if data.len().saturating_sub(pos) < len {
                    return None;
                }
                if field_no == target_field {
                    return Some(data[pos..pos + len].to_vec());
                }
                pos += len;
            }
            5 => {
                if data.len().saturating_sub(pos) < 4 {
                    return None;
                }
                pos += 4;
            }
            _ => return None,
        }
    }

    None
}

fn rewrite_album_art_payload(
    payload: &[u8],
    replacement: &[u8],
    duration_tick: bool,
    cfg: &AppConfig,
) -> Result<Vec<u8>, RewriteError> {
    if payload.len() < 2 {
        return Err(RewriteError::Malformed);
    }

    let ev_text = global_metadata_text_prefix(cfg);
    let ev_text_mode = if ev_text.is_some() {
        album_art_ev_text_mode(cfg)
    } else {
        AlbumArtEvTextMode::AlbumArt
    };
    let original_artist = if matches!(
        ev_text_mode,
        AlbumArtEvTextMode::ArtistField | AlbumArtEvTextMode::ArtistPrefix
    ) {
        read_metadata_text_field(payload, 2)
    } else {
        None
    };
    let original_song = if ev_text_mode == AlbumArtEvTextMode::ArtistField {
        read_metadata_text_field(payload, 1)
    } else {
        None
    };

    let mut out = Vec::with_capacity(
        payload
            .len()
            .saturating_add(replacement.len())
            .saturating_add(ev_text.as_ref().map(|value| value.len() + 1).unwrap_or(0))
            .saturating_add(
                original_artist
                    .as_ref()
                    .map(|value| value.len() + 1)
                    .unwrap_or(0),
            )
            .saturating_add(16),
    );
    out.extend_from_slice(&payload[..2]);

    let data = &payload[2..];
    let mut pos = 0usize;
    let mut replaced = false;
    let mut song_written = false;
    let mut artist_written = false;

    while pos < data.len() {
        let field_start = pos;
        let key = read_varint(data, &mut pos)?;
        if key == 0 {
            return Err(RewriteError::Malformed);
        }

        let field_no = key >> 3;
        let wire_type = key & 0x07;

        match wire_type {
            // varint
            0 => {
                let value = read_varint(data, &mut pos)?;
                if field_no == 6 && duration_tick {
                    // Optional HU-cache workaround: only the outbound clone is touched.
                    // The cached phone metadata template stays unchanged, so the value
                    // alternates between the original duration and original+1.
                    write_varint(key, &mut out);
                    write_varint(value.saturating_add(1), &mut out);
                } else {
                    out.extend_from_slice(&data[field_start..pos]);
                }
            }
            // fixed64
            1 => {
                skip_checked(data, &mut pos, 8)?;
                out.extend_from_slice(&data[field_start..pos]);
            }
            // length-delimited
            2 => {
                let len = read_varint(data, &mut pos)? as usize;
                skip_checked(data, &mut pos, len)?;

                if field_no == 1 && !song_written {
                    match (ev_text_mode, ev_text.as_deref()) {
                        (AlbumArtEvTextMode::SongPrefix, Some(prefix)) => {
                            let original = &data[pos - len..pos];
                            let prefixed = build_prefixed_song(prefix, original);
                            write_varint(key, &mut out);
                            write_varint(prefixed.len() as u64, &mut out);
                            out.extend_from_slice(&prefixed);
                        }
                        (AlbumArtEvTextMode::ArtistField, Some(_)) => {
                            let original = &data[pos - len..pos];
                            let moved =
                                build_artist_song_prefix(original_artist.as_deref(), original);
                            write_varint(key, &mut out);
                            write_varint(moved.len() as u64, &mut out);
                            out.extend_from_slice(&moved);
                        }
                        _ => out.extend_from_slice(&data[field_start..pos]),
                    }
                    song_written = true;
                } else if field_no == 2
                    && !artist_written
                    && matches!(
                        ev_text_mode,
                        AlbumArtEvTextMode::ArtistField | AlbumArtEvTextMode::ArtistPrefix
                    )
                    && ev_text.is_some()
                {
                    let original = &data[pos - len..pos];
                    let text = match (ev_text_mode, ev_text.as_deref()) {
                        (AlbumArtEvTextMode::ArtistField, Some(text)) => text.as_bytes().to_vec(),
                        (AlbumArtEvTextMode::ArtistPrefix, Some(prefix)) => {
                            build_prefixed_song(prefix, original)
                        }
                        _ => original.to_vec(),
                    };
                    write_varint(key, &mut out);
                    write_varint(text.len() as u64, &mut out);
                    out.extend_from_slice(&text);
                    artist_written = true;
                } else if field_no == 4 && !replaced {
                    write_varint(key, &mut out);
                    write_varint(replacement.len() as u64, &mut out);
                    out.extend_from_slice(replacement);
                    replaced = true;
                } else {
                    out.extend_from_slice(&data[field_start..pos]);
                }
            }
            // fixed32
            5 => {
                skip_checked(data, &mut pos, 4)?;
                out.extend_from_slice(&data[field_start..pos]);
            }
            _ => return Err(RewriteError::Malformed),
        }
    }

    if !song_written {
        match (ev_text_mode, ev_text.as_deref()) {
            (AlbumArtEvTextMode::SongPrefix, Some(prefix)) => {
                let prefixed = build_prefixed_song(prefix, b"");
                write_varint((1 << 3) | 2, &mut out);
                write_varint(prefixed.len() as u64, &mut out);
                out.extend_from_slice(&prefixed);
            }
            (AlbumArtEvTextMode::ArtistField, Some(_)) => {
                let moved = build_artist_song_prefix(
                    original_artist.as_deref(),
                    original_song.as_deref().unwrap_or(b""),
                );
                if !moved.is_empty() {
                    write_varint((1 << 3) | 2, &mut out);
                    write_varint(moved.len() as u64, &mut out);
                    out.extend_from_slice(&moved);
                }
            }
            _ => {}
        }
    }

    if !artist_written
        && matches!(
            ev_text_mode,
            AlbumArtEvTextMode::ArtistField | AlbumArtEvTextMode::ArtistPrefix
        )
    {
        if let Some(text) = ev_text.as_deref() {
            let text = match ev_text_mode {
                AlbumArtEvTextMode::ArtistField => text.as_bytes().to_vec(),
                AlbumArtEvTextMode::ArtistPrefix => build_prefixed_song(text, b""),
                _ => Vec::new(),
            };
            write_varint((2 << 3) | 2, &mut out);
            write_varint(text.len() as u64, &mut out);
            out.extend_from_slice(&text);
        }
    }

    if !replaced {
        // Dynamic re-fragment mode can grow the protobuf, so an existing album_art
        // field is no longer required. Append field 4 when the cached template did
        // not contain artwork at all.
        write_varint((4 << 3) | 2, &mut out);
        write_varint(replacement.len() as u64, &mut out);
        out.extend_from_slice(replacement);
    }

    Ok(out)
}

fn build_prefixed_song(prefix: &str, original: &[u8]) -> Vec<u8> {
    let prefix = prefix.trim();
    if prefix.is_empty() {
        return original.to_vec();
    }

    let original = String::from_utf8_lossy(original);
    let original = original.trim();
    if original.is_empty() {
        prefix.as_bytes().to_vec()
    } else if original.starts_with(prefix) {
        original.as_bytes().to_vec()
    } else {
        format!("{} {}", prefix, original).into_bytes()
    }
}

fn build_artist_song_prefix(original_artist: Option<&[u8]>, original_song: &[u8]) -> Vec<u8> {
    let artist = original_artist
        .map(String::from_utf8_lossy)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let song = String::from_utf8_lossy(original_song).trim().to_string();

    match (artist, song.is_empty()) {
        (Some(artist), false) if song.starts_with(&artist) => song.into_bytes(),
        (Some(artist), false) => format!("{} {}", artist, song).into_bytes(),
        (Some(artist), true) => artist.into_bytes(),
        (None, false) => song.into_bytes(),
        (None, true) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, DEFAULT_MAP_ALBUM_ART_FILE};
    use crate::mitm::{ENCRYPTED, FRAME_TYPE_FIRST, FRAME_TYPE_LAST};

    fn packet(channel: u8, flags: u8, payload: Vec<u8>) -> Packet {
        Packet {
            channel,
            flags: ENCRYPTED | flags,
            final_length: None,
            payload,
        }
    }

    fn test_config() -> AppConfig {
        AppConfig {
            map_album_art_file: DEFAULT_MAP_ALBUM_ART_FILE.into(),
            map_album_art_max_bytes: 262_144,
            map_album_art_chunk_bytes: 16,
            ..AppConfig::default()
        }
    }

    fn metadata_payload(album_art: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x80, 0x03];
        payload.extend_from_slice(&[0x0A, 0x01, b'A']);
        payload.extend_from_slice(&[0x12, 0x01, b'B']);
        payload.extend_from_slice(&[0x1A, 0x01, b'C']);
        payload.push(0x22);
        write_varint(album_art.len() as u64, &mut payload);
        payload.extend_from_slice(album_art);
        payload.extend_from_slice(&[0x30, 0x0A]);
        payload
    }

    fn metadata_payload_without_album_art() -> Vec<u8> {
        let mut payload = vec![0x80, 0x03];
        payload.extend_from_slice(&[0x0A, 0x01, b'A']);
        payload.extend_from_slice(&[0x12, 0x01, b'B']);
        payload.extend_from_slice(&[0x1A, 0x01, b'C']);
        payload.extend_from_slice(&[0x30, 0x0A]);
        payload
    }

    fn extract_album_art(payload: &[u8]) -> Vec<u8> {
        let data = &payload[2..];
        let mut pos = 0usize;

        while pos < data.len() {
            let key = read_varint(data, &mut pos).unwrap();
            let field_no = key >> 3;
            let wire_type = key & 0x07;
            match wire_type {
                0 => {
                    let _ = read_varint(data, &mut pos).unwrap();
                }
                1 => pos += 8,
                2 => {
                    let len = read_varint(data, &mut pos).unwrap() as usize;
                    let value_start = pos;
                    pos += len;
                    if field_no == 4 {
                        return data[value_start..value_start + len].to_vec();
                    }
                }
                5 => pos += 4,
                _ => panic!("unexpected wire type"),
            }
        }
        panic!("album art not found")
    }

    fn extract_duration(payload: &[u8]) -> Option<u64> {
        let data = &payload[2..];
        let mut pos = 0usize;

        while pos < data.len() {
            let key = read_varint(data, &mut pos).unwrap();
            let field_no = key >> 3;
            let wire_type = key & 0x07;
            match wire_type {
                0 => {
                    let value = read_varint(data, &mut pos).unwrap();
                    if field_no == 6 {
                        return Some(value);
                    }
                }
                1 => pos += 8,
                2 => {
                    let len = read_varint(data, &mut pos).unwrap() as usize;
                    pos += len;
                }
                5 => pos += 4,
                _ => panic!("unexpected wire type"),
            }
        }
        None
    }

    #[test]
    fn rewrite_album_art_payload_uses_dynamic_replacement_length() {
        let original_art = vec![0x11; 3];
        let replacement = vec![0x89, b'P', b'N', b'G', 1, 2, 3, 4, 5, 6];
        let payload = metadata_payload(&original_art);

        let rewritten =
            rewrite_album_art_payload(&payload, &replacement, false, &AppConfig::default())
                .unwrap();

        assert_eq!(extract_album_art(&rewritten), replacement);
        assert!(rewritten.len() > payload.len());
    }

    #[test]
    fn rewrite_album_art_payload_adds_missing_album_art_field() {
        let replacement = vec![0x89, b'P', b'N', b'G', 1, 2, 3, 4, 5, 6];
        let payload = metadata_payload_without_album_art();

        let rewritten =
            rewrite_album_art_payload(&payload, &replacement, false, &AppConfig::default())
                .unwrap();

        assert_eq!(extract_album_art(&rewritten), replacement);
    }

    #[test]
    fn rewrite_album_art_payload_can_tick_duration_without_mutating_template() {
        let original_art = vec![0x11; 3];
        let replacement = vec![0x89, b'P', b'N', b'G', 1, 2, 3, 4, 5, 6];
        let payload = metadata_payload(&original_art);

        let rewritten =
            rewrite_album_art_payload(&payload, &replacement, true, &AppConfig::default()).unwrap();

        assert_eq!(extract_duration(&payload), Some(10));
        assert_eq!(extract_duration(&rewritten), Some(11));
    }

    #[test]
    fn openauto_fragment_utility_sets_first_final_length_only_for_multi_fragment_messages() {
        let payload = metadata_payload(&vec![0x55; 40]);
        let packets = fragment_plain_payload(
            &payload,
            PlainPayloadFragmentOptions {
                channel: 0x08,
                base_flags: ENCRYPTED,
                first_fragment_payload_bytes: 16,
                continuation_fragment_payload_bytes: 20,
                first_final_length: Some(payload.len() as u32),
            },
        );

        assert!(packets.len() > 1);
        assert_eq!(packets[0].flags & FRAME_TYPE_MASK, FRAME_TYPE_FIRST);
        assert_eq!(packets[0].final_length, Some(payload.len() as u32));
        assert_eq!(
            packets.last().unwrap().flags & FRAME_TYPE_MASK,
            FRAME_TYPE_LAST
        );
        assert_eq!(packets.last().unwrap().final_length, None);
    }

    #[test]
    fn process_packet_drops_original_fragments_and_emits_rewritten_metadata() {
        let replacement = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4];
        let original = metadata_payload(&vec![0x22; 8]);
        let first_payload = original[..10].to_vec();
        let last_payload = original[10..].to_vec();

        let mut injector = MapAlbumArtInjector::default();
        let mut cfg = test_config();
        let tmp_path = std::env::temp_dir().join(format!(
            "aa-proxy-map-album-art-test-{}.png",
            std::process::id()
        ));
        std::fs::write(&tmp_path, &replacement).unwrap();
        cfg.map_album_art_file = tmp_path.clone();

        let first = packet(0x08, FRAME_TYPE_FIRST, first_payload);
        match injector.process_packet(&first, MEDIA_PLAYBACK_METADATA_ID, &cfg) {
            AlbumArtProcessResult::Drop => {}
            _ => panic!("first original fragment should be dropped"),
        }

        let last = packet(0x08, FRAME_TYPE_LAST, last_payload);
        let rewritten_packets =
            match injector.process_packet(&last, MEDIA_PLAYBACK_METADATA_ID, &cfg) {
                AlbumArtProcessResult::Replace(packets) => packets,
                _ => panic!("last fragment should emit rewritten metadata"),
            };

        let mut reassembled = Vec::new();
        for pkt in rewritten_packets {
            reassembled.extend_from_slice(&pkt.payload);
        }

        assert_eq!(extract_album_art(&reassembled), replacement);
        let _ = std::fs::remove_file(tmp_path);
    }
}
