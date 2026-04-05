# Plan: Media Sink Stream Capture via TCP (Debug Tapping)

**TL;DR**: Add `media_dump_base_port` config option. The proxy assigns one TCP port per
`media_sink_service` (video by display_type, audio by audio_type) and broadcasts raw
decrypted media frames. `mitm = true` is a hard requirement — if not set, the feature is
refused with an error at startup. VLC or other tools can connect to chosen ports.

**CONSTRAINT**: Requires `mitm = true`. If `media_dump_base_port` is set but `mitm = false`,
log a prominent error and skip creating any listeners. Do not try to tap in passthrough mode.

---

## Port Allocation (fixed offsets from base_port)

Based on `display_type` for video services, and `audio_type` for audio services:

| Offset | Service type |
|--------|--------------|
| +0     | Video — DISPLAY_TYPE_MAIN      |
| +1     | Video — DISPLAY_TYPE_CLUSTER   |
| +2     | Video — DISPLAY_TYPE_AUXILIARY |
| +3     | Audio — AUDIO_STREAM_GUIDANCE (TTS) |
| +4     | Audio — AUDIO_STREAM_SYSTEM_AUDIO   |
| +5     | Audio — AUDIO_STREAM_MEDIA          |
| +6     | Audio — AUDIO_STREAM_TELEPHONY      |

---

## Steps

### Phase 1: Config (src/config.rs + config.toml) ✅
1. Add `pub media_dump_base_port: Option<u16>` to `AppConfig` struct (with `#[serde(default)]`)
2. Add `media_dump_base_port: None` to `impl Default for AppConfig`
3. Add commented `# media_dump_base_port = 12345` to config.toml
4. Add to `AppConfig::save()`

### Phase 2: MediaSink struct (src/mitm.rs) ✅
5. `#[derive(Clone)] pub struct MediaSink`:
   - `tx: tokio::sync::broadcast::Sender<Arc<Vec<u8>>>`
   - `codec_cfg: Arc<tokio::sync::Mutex<Option<Arc<Vec<u8>>>>>` — cached codec config
   - Methods: `new(capacity)`, `send_codec_config(data)`, `send_frame(data)`,
     `subscribe()`, `get_codec_cfg()`
6. `pub async fn media_tcp_server(port, label, sink)`:
   - Bind `TcpListener` on `0.0.0.0:{port}`, log VLC hint on startup
   - Per client: wait for next IDR, prepend SPS+PPS before every IDR, stream frames
   - Re-inject SPS+PPS before every IDR frame to prevent "non-existing PPS" errors
   - On lag: reset to unsynced state, wait for next IDR
7. `fn is_idr_frame(data)` — checks both 3-byte and 4-byte Annex-B start codes

### Phase 3: Extend ModifyContext (src/mitm.rs) ✅
8. Two separate maps on `ModifyContext`:
   - `media_sinks: HashMap<u8, MediaSink>` — offset (0-6) → sink, lookup-only at SDR time
   - `media_channels: HashMap<u8, MediaSink>` — channel_id → sink, used for tapping
9. Init both as empty in `ModifyContext` constructor

### Phase 4: Populate channel map from SDR (src/mitm.rs) ✅
10. In `MESSAGE_SERVICE_DISCOVERY_RESPONSE`, parse SDR in both proxy contexts:
    - `MobileDevice` proxy: populate `media_channels` from `media_sinks` by display/audio offset
    - `HeadUnit` proxy: apply SDR modifications as before, then return
    - Early return for MobileDevice comes AFTER channel map population

### Phase 5: Tap in pkt_modify_hook (src/mitm.rs) ✅
11. `proxy_type == MobileDevice` + channel in `media_channels`:
    - `MEDIA_MESSAGE_DATA`: strip 8-byte timestamp header, skip frames ≤ 8 bytes, forward NAL data
    - `MEDIA_MESSAGE_CODEC_CONFIG`: forward as-is (already Annex-B SPS+PPS)

### Phase 6: Wire up in io_loop (src/io_uring.rs) ✅
12. Create `MediaSink` + spawn `media_tcp_server` tasks **once** before the reconnect loop
    (not inside it — avoids "Address already in use" on reconnect)
13. Pass `persistent_media_sinks.clone()` to `proxy(MobileDevice)` each session
14. `proxy(HeadUnit)` receives empty `HashMap::new()`

---

## Known Issues / Outstanding Work

### Stream timing / VLC buffering loop
VLC's `ES_OUT_SET_(GROUP_)PCR is called too late` error occurs because the raw H264
elementary stream has no timestamps. VLC buffers, can't find PCR, resets, loops.

**Options:**
A. Wrap in MPEG-TS with PTS derived from the 8-byte AA timestamp header we currently strip.
   - Proper fix, makes VLC/ffplay fully happy
   - More complex: need miniature MPEG-TS muxer
B. Accept raw stream limitations — ffplay `-threads 1 -fflags nobuffer` works adequately

### "non-existing PPS 0 referenced" in ffplay (multithreaded decode)
ffplay's parallel H264 decoder can lose PPS context across thread boundaries.
SPS+PPS injection before every IDR mitigates but doesn't fully solve with `-threads > 1`.
Workaround: `ffplay -threads 1 -f h264 tcp://127.0.0.1:12345`

---

## Relevant Files
- `src/config.rs` — `AppConfig` struct, `Default` impl, `save()`
- `config.toml` — commented `media_dump_base_port` entry
- `src/mitm.rs` — `MediaSink`, `media_tcp_server`, `is_idr_frame`, `ModifyContext`,
  `pkt_modify_hook`, `proxy()`, SDR handler
- `src/io_uring.rs` — `io_loop`, persistent sink creation, proxy spawning

## Verification
1. Set `media_dump_base_port = 12345` + `mitm = true` in config.toml, `cargo build`
2. Start proxy — check logs for port binding and "video channel 0xNN → port offset 0"
3. Connect phone → `ffplay -threads 1 -f h264 tcp://127.0.0.1:12345`
4. Reconnect phone — verify no "Address already in use" errors
5. Set `mitm = false` with port set → verify error log and no listeners start

## Decisions
- TCP broadcast over FIFO — multiple clients, no pre-setup needed
- 8-byte timestamp header stripped from DATA frames (AA-specific framing)
- SPS+PPS re-injected before every IDR keyframe at TCP server layer
- Tapping direction: `proxy(MobileDevice)` rxr path only (phone → HU)
- Broadcast capacity 128 — lagging clients re-sync to next IDR, not dropped
