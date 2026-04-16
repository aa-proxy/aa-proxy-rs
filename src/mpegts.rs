/// Minimal MPEG-TS muxer for wrapping H.264 video or audio frames.
///
/// Topology:
///   PAT (PID 0x0000) – maps program 1 → PMT PID
///   PMT (PID 0x0100) – elementary stream descriptor (stream_type depends on kind)
///   ES  (PID 0x0101) – one PES per frame with PTS and PCR

const TS_PACKET_SIZE: usize = 188;
const PAT_PID: u16 = 0x0000;
const PMT_PID: u16 = 0x0100;
const ES_PID: u16 = 0x0101;

/// The kind of elementary stream being muxed.
#[derive(Clone, Copy, Debug)]
pub enum TsStreamKind {
    /// H.264 Annex-B video — PMT stream_type 0x1B, PES stream_id 0xE0.
    VideoH264,
    /// AAC audio in ADTS framing — PMT stream_type 0x0F, PES stream_id 0xC0.
    /// Used for both MEDIA_CODEC_AUDIO_AAC_LC (with caller-prepended ADTS headers)
    /// and MEDIA_CODEC_AUDIO_AAC_LC_ADTS (pass-through).
    AudioAacAdts,
    /// LPCM audio — PMT stream_type 0x83 (LPCM), PES stream_id 0xBD.
    /// Caller supplies payloads already formatted as LPCM access units
    /// (codec-specific header + big-endian samples).
    AudioPcm,
}

impl TsStreamKind {
    pub fn pmt_stream_type(self) -> u8 {
        match self {
            Self::VideoH264 => 0x1B,
            Self::AudioAacAdts => 0x0F,
            Self::AudioPcm => 0x83,
        }
    }

    fn pes_stream_id(self) -> u8 {
        match self {
            Self::VideoH264 => 0xE0,
            Self::AudioAacAdts => 0xC0,
            Self::AudioPcm => 0xBD,
        }
    }

    pub fn is_audio(self) -> bool {
        !matches!(self, Self::VideoH264)
    }
}

/// Standard MPEG-2 CRC-32 (polynomial 0x04C11DB7, MSB-first).
fn mpeg_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            if (crc >> 31) as u8 ^ bit != 0 {
                crc = (crc << 1) ^ 0x04C1_1DB7;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Encode a 33-bit PTS (in 90 kHz ticks) into the 5-byte PES representation.
fn encode_pts(pts_90k: u64) -> [u8; 5] {
    [
        0x21 | ((pts_90k >> 29) & 0x0E) as u8,
        ((pts_90k >> 22) & 0xFF) as u8,
        0x01 | ((pts_90k >> 14) & 0xFE) as u8,
        ((pts_90k >> 7) & 0xFF) as u8,
        0x01 | ((pts_90k << 1) & 0xFE) as u8,
    ]
}

/// Build one 188-byte TS packet.
///
/// `payload_chunk` must be ≤ 184 bytes.  If it is shorter, an adaptation field
/// with stuffing bytes (0xFF) is prepended so that the packet is always exactly
/// 188 bytes.
///
/// When `pcr` is `Some(pcr_90k)` an adaptation field containing the PCR is
/// included.  This forces `payload_chunk.len() ≤ 176` (8 bytes consumed by the
/// PCR adaptation field).  Callers must ensure this constraint.
fn make_ts_packet(
    pid: u16,
    pusi: bool,
    payload_chunk: &[u8],
    counter: u8,
    pcr: Option<u64>,
) -> [u8; TS_PACKET_SIZE] {
    let mut pkt = [0xFFu8; TS_PACKET_SIZE];
    pkt[0] = 0x47;
    pkt[1] = ((pusi as u8) << 6) | ((pid >> 8) as u8 & 0x1F);
    pkt[2] = (pid & 0xFF) as u8;

    // Compute how many stuffing bytes we need (excluding the adaptation field
    // header itself).
    let total_payload = TS_PACKET_SIZE - 4; // 184 bytes available after TS header

    // PCR adaptation field is 8 bytes (length + flags + 6 PCR bytes).
    let pcr_af_len: usize = if pcr.is_some() { 8 } else { 0 };
    let stuff_needed = total_payload - payload_chunk.len() - pcr_af_len;

    if pcr_af_len == 0 && stuff_needed == 0 {
        // No adaptation field needed.
        pkt[3] = 0x10 | (counter & 0x0F); // payload only
        pkt[4..4 + payload_chunk.len()].copy_from_slice(payload_chunk);
    } else {
        // adaptation_field_control = 0b11 (both adaptation and payload)
        pkt[3] = 0x30 | (counter & 0x0F);

        // Total adaptation field bytes (including the length byte itself):
        let af_total = pcr_af_len + stuff_needed;
        // adaptation_field_length = af_total - 1 (length byte not counted)
        pkt[4] = (af_total - 1) as u8;

        if let Some(pcr_90k) = pcr {
            // Flags byte: PCR_flag = 1, rest = 0
            pkt[5] = 0x10;
            // PCR base (33 bits) + reserved (6 bits) + PCR ext (9 bits = 0)
            let base = pcr_90k;
            pkt[6] = ((base >> 25) & 0xFF) as u8;
            pkt[7] = ((base >> 17) & 0xFF) as u8;
            pkt[8] = ((base >> 9) & 0xFF) as u8;
            pkt[9] = ((base >> 1) & 0xFF) as u8;
            pkt[10] = (((base & 1) << 7) | 0x7E) as u8; // reserved bits set
            pkt[11] = 0x00; // PCR extension = 0
                            // stuffing bytes (0xFF) already filled by the array initializer
                            // starting at pkt[12], for (stuff_needed) bytes.
        } else {
            // Flags byte = 0x00 (no special flags)
            pkt[5] = 0x00;
            // stuffing bytes (0xFF) already filled, starting at pkt[6]
        }

        let payload_start = 4 + af_total;
        pkt[payload_start..payload_start + payload_chunk.len()].copy_from_slice(payload_chunk);
    }

    pkt
}

/// Build a full 188-byte PAT TS packet.
fn make_pat(counter: u8) -> [u8; TS_PACKET_SIZE] {
    // PAT section (without CRC):
    //   table_id=0x00, section_syntax=1, private=0, reserved=11, section_length=13
    //   transport_stream_id=1, reserved=11, version=0, current=1
    //   section_number=0, last_section_number=0
    //   program_number=1, reserved=111, program_map_PID=PMT_PID
    let section: [u8; 12] = [
        0x00, // table_id
        0xB0,
        0x0D, // syntax + section_length = 13
        0x00,
        0x01, // transport_stream_id
        0xC1, // version=0, current=1
        0x00,
        0x00, // section/last_section numbers
        0x00,
        0x01,                                 // program_number = 1
        0xE0 | ((PMT_PID >> 8) & 0x1F) as u8, // reserved + PMT_PID high
        (PMT_PID & 0xFF) as u8,               // PMT_PID low
    ];
    let crc = mpeg_crc32(&section).to_be_bytes();

    // TS payload: pointer_field=0 + section + CRC + 0xFF padding
    let mut payload = [0xFFu8; 184];
    payload[0] = 0x00; // pointer_field
    payload[1..13].copy_from_slice(&section);
    payload[13..17].copy_from_slice(&crc);

    make_ts_packet(PAT_PID, true, &payload, counter, None)
}

/// Build a full 188-byte PMT TS packet.
fn make_pmt(counter: u8, stream_type: u8) -> [u8; TS_PACKET_SIZE] {
    // PMT section (without CRC):
    //   table_id=0x02, section_length=18
    //   program_number=1, version=0, current=1
    //   section_number=0, last_section_number=0
    //   PCR_PID=ES_PID, program_info_length=0
    //   stream_type (caller-supplied), elementary_PID=ES_PID, ES_info_length=0
    let section: [u8; 17] = [
        0x02, // table_id
        0xB0,
        0x12, // syntax + section_length = 18
        0x00,
        0x01, // program_number
        0xC1, // version=0, current=1
        0x00,
        0x00,                                // section/last_section numbers
        0xE0 | ((ES_PID >> 8) & 0x1F) as u8, // reserved + PCR_PID high
        (ES_PID & 0xFF) as u8,               // PCR_PID low
        0xF0,
        0x00,                                // reserved + program_info_length=0
        stream_type,                         // elementary stream type
        0xE0 | ((ES_PID >> 8) & 0x1F) as u8, // reserved + elementary_PID high
        (ES_PID & 0xFF) as u8,               // elementary_PID low
        0xF0,
        0x00, // reserved + ES_info_length=0
    ];
    let crc = mpeg_crc32(&section).to_be_bytes();

    let mut payload = [0xFFu8; 184];
    payload[0] = 0x00; // pointer_field
    payload[1..18].copy_from_slice(&section);
    payload[18..22].copy_from_slice(&crc);

    make_ts_packet(PMT_PID, true, &payload, counter, None)
}

/// Per-connection MPEG-TS muxer state.
pub struct MpegTsState {
    pat_counter: u8,
    pmt_counter: u8,
    es_counter: u8,
    kind: TsStreamKind,
    /// Raw timestamp of the first frame seen; used to normalise PTS values so
    /// they start near zero regardless of epoch (video only; audio uses µs directly).
    first_pts_raw: Option<u64>,
    prev_pts_raw: Option<u64>,
    inferred_timebase: Option<TimestampTimebase>,
}

#[derive(Clone, Copy)]
enum TimestampTimebase {
    Ticks90k,
    Milliseconds,
    Microseconds,
    Nanoseconds,
}

impl TimestampTimebase {
    fn raw_to_90k(self, raw: u64) -> u64 {
        match self {
            Self::Ticks90k => raw,
            Self::Milliseconds => raw.saturating_mul(90),
            Self::Microseconds => ((raw as u128 * 90) / 1_000) as u64,
            Self::Nanoseconds => ((raw as u128 * 90) / 1_000_000) as u64,
        }
    }

    fn infer_from_delta(delta: u64) -> Self {
        let candidates = [
            (Self::Ticks90k, delta),
            (Self::Milliseconds, delta.saturating_mul(90)),
            (Self::Microseconds, ((delta as u128 * 90) / 1_000) as u64),
            (Self::Nanoseconds, ((delta as u128 * 90) / 1_000_000) as u64),
        ];

        candidates
            .into_iter()
            .filter(|(_, pts_delta)| (900..=9000).contains(pts_delta))
            .min_by_key(|(_, pts_delta)| pts_delta.abs_diff(3_000))
            .map(|(timebase, _)| timebase)
            .unwrap_or(Self::Microseconds)
    }
}

impl MpegTsState {
    pub fn new() -> Self {
        Self::new_for_kind(TsStreamKind::VideoH264)
    }

    pub fn new_for_kind(kind: TsStreamKind) -> Self {
        Self {
            pat_counter: 0,
            pmt_counter: 0,
            es_counter: 0,
            kind,
            first_pts_raw: None,
            prev_pts_raw: None,
            inferred_timebase: None,
        }
    }

    fn next_pat(&mut self) -> u8 {
        let c = self.pat_counter;
        self.pat_counter = (self.pat_counter + 1) & 0x0F;
        c
    }

    fn next_pmt(&mut self) -> u8 {
        let c = self.pmt_counter;
        self.pmt_counter = (self.pmt_counter + 1) & 0x0F;
        c
    }

    fn next_es(&mut self) -> u8 {
        let c = self.es_counter;
        self.es_counter = (self.es_counter + 1) & 0x0F;
        c
    }

    /// Emit PAT + PMT packets.
    /// For video: call before every IDR.  For audio: call once at session start
    /// and periodically to allow mid-stream client joins.
    pub fn pat_pmt(&mut self) -> Vec<u8> {
        let pat = make_pat(self.next_pat());
        let pmt = make_pmt(self.next_pmt(), self.kind.pmt_stream_type());
        let mut out = Vec::with_capacity(2 * TS_PACKET_SIZE);
        out.extend_from_slice(&pat);
        out.extend_from_slice(&pmt);
        out
    }

    /// A single null TS packet (PID 0x1FFF) — use to keep the connection alive
    /// while the client waits for the first IDR frame, so VLC/ffplay can finish
    /// format probing without timing out.
    pub fn null_packet() -> [u8; TS_PACKET_SIZE] {
        let mut pkt = [0xFFu8; TS_PACKET_SIZE];
        pkt[0] = 0x47;
        pkt[1] = 0x1F; // PID high = 0x1F
        pkt[2] = 0xFF; // PID low  = 0xFF  → PID 0x1FFF (null packet)
        pkt[3] = 0x10; // payload only, counter = 0 (not significant for null PID)
                       // payload bytes already 0xFF
        pkt
    }

    /// Wrap Annex-B `data` in PES packets and fragment into 188-byte TS packets.
    ///
    /// `pts_raw` is the Android Auto presentation timestamp from the 8-byte
    /// frame header. The unit is inferred from early frame deltas so the muxer
    /// can handle ns/us/ms/90k timestamps without hard-coding a scale.
    /// A PCR is carried in the first TS packet of each PES to keep decoders
    /// (notably VLC) tightly synchronized even when keyframes are sparse.
    pub fn video_pes(&mut self, pts_raw: u64, data: &[u8], _is_idr: bool) -> Vec<u8> {
        // Infer timestamp scale from an observed frame delta so the stream keeps
        // advancing even if AA uses ns instead of µs.
        if self.inferred_timebase.is_none() {
            if let Some(prev_raw) = self.prev_pts_raw {
                let delta = pts_raw.saturating_sub(prev_raw);
                if delta > 0 {
                    self.inferred_timebase = Some(TimestampTimebase::infer_from_delta(delta));
                }
            }
        }

        let first = *self.first_pts_raw.get_or_insert(pts_raw);
        let rel_raw = pts_raw.saturating_sub(first);
        let timebase = self
            .inferred_timebase
            .unwrap_or(TimestampTimebase::Microseconds);

        // Convert the normalised timestamp to 90 kHz ticks, then mask to 33 bits.
        let pts_90k = timebase.raw_to_90k(rel_raw) & 0x1_FFFF_FFFF;
        self.prev_pts_raw = Some(pts_raw);
        let pts_bytes = encode_pts(pts_90k);

        // Build PES header (14 bytes):
        //   start_code(3) + stream_id(1) + PES_length(2) + flags(3) + PTS(5)
        let pes_header: [u8; 14] = [
            0x00,
            0x00,
            0x01, // start code
            0xE0, // stream_id: video
            0x00,
            0x00, // PES_packet_length = 0 (unbounded; valid for video)
            0x84, // marker=10, data-alignment-indicator=1 for AU-aligned PES
            0x80, // PTS_DTS_flags = PTS only
            0x05, // PES_header_data_length = 5
            pts_bytes[0],
            pts_bytes[1],
            pts_bytes[2],
            pts_bytes[3],
            pts_bytes[4],
        ];

        let total_data = pes_header.len() + data.len();
        let mut out = Vec::with_capacity((total_data / 184 + 2) * TS_PACKET_SIZE);

        let mut offset = 0;
        let mut first = true;

        while offset < total_data {
            let is_first_pkt = first;
            first = false;

            // PCR adaptation field costs 8 bytes, leaving 176 bytes for payload.
            let pcr = if is_first_pkt { Some(pts_90k) } else { None };
            let pcr_af_cost = if pcr.is_some() { 8 } else { 0 };
            let max_chunk = 184 - pcr_af_cost;

            // How many bytes of (pes_header + data) go into this packet?
            let available = max_chunk.min(total_data - offset);

            // Build the chunk by splicing pes_header and data together.
            let mut chunk = Vec::with_capacity(available);
            let hdr_remaining = pes_header.len().saturating_sub(offset);
            if hdr_remaining > 0 {
                let take = hdr_remaining.min(available);
                chunk.extend_from_slice(&pes_header[offset..offset + take]);
            }
            let data_start = offset.saturating_sub(pes_header.len());
            let data_taken = available - chunk.len();
            if data_taken > 0 {
                chunk.extend_from_slice(&data[data_start..data_start + data_taken]);
            }

            let counter = self.next_es();
            let pkt = make_ts_packet(ES_PID, is_first_pkt, &chunk, counter, pcr);
            out.extend_from_slice(&pkt);

            offset += available;
        }

        out
    }

    /// Wrap audio data in PES packets and fragment into 188-byte TS packets.
    ///
    /// AA audio timestamps are always µs; no timebase inference is performed.
    pub fn audio_pes(&mut self, pts_us: u64, data: &[u8]) -> Vec<u8> {
        // AA audio timestamps are µs; convert directly to 90 kHz ticks.
        let pts_90k = ((pts_us as u128 * 90) / 1_000) as u64 & 0x1_FFFF_FFFF;
        let pts_bytes = encode_pts(pts_90k);
        let stream_id = self.kind.pes_stream_id();

        // PES_packet_length = bytes after the length field itself:
        //   2 (flags) + 1 (hdr_data_len) + 5 (PTS) + payload
        let pes_pkt_len = (8u16).saturating_add(data.len() as u16);

        let pes_header: [u8; 14] = [
            0x00,
            0x00,
            0x01, // start code
            stream_id,
            (pes_pkt_len >> 8) as u8,   // PES_packet_length high
            (pes_pkt_len & 0xFF) as u8, // PES_packet_length low
            0x84,                       // marker=10, data_alignment_indicator=1
            0x80,                       // PTS_DTS_flags = PTS only
            0x05,                       // PES_header_data_length = 5
            pts_bytes[0],
            pts_bytes[1],
            pts_bytes[2],
            pts_bytes[3],
            pts_bytes[4],
        ];

        let total_data = pes_header.len() + data.len();
        let mut out = Vec::with_capacity((total_data / 184 + 2) * TS_PACKET_SIZE);

        let mut offset = 0;
        let mut first = true;

        while offset < total_data {
            let is_first_pkt = first;
            first = false;

            let pcr = if is_first_pkt { Some(pts_90k) } else { None };
            let pcr_af_cost = if pcr.is_some() { 8 } else { 0 };
            let max_chunk = 184 - pcr_af_cost;
            let available = max_chunk.min(total_data - offset);

            let mut chunk = Vec::with_capacity(available);
            let hdr_remaining = pes_header.len().saturating_sub(offset);
            if hdr_remaining > 0 {
                let take = hdr_remaining.min(available);
                chunk.extend_from_slice(&pes_header[offset..offset + take]);
            }
            let data_start = offset.saturating_sub(pes_header.len());
            let data_taken = available - chunk.len();
            if data_taken > 0 {
                chunk.extend_from_slice(&data[data_start..data_start + data_taken]);
            }

            let counter = self.next_es();
            let pkt = make_ts_packet(ES_PID, is_first_pkt, &chunk, counter, pcr);
            out.extend_from_slice(&pkt);

            offset += available;
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infers_nanosecond_timebase_from_video_frame_delta() {
        let timebase = TimestampTimebase::infer_from_delta(33_333_333);
        assert!(matches!(timebase, TimestampTimebase::Nanoseconds));
    }

    #[test]
    fn infers_microsecond_timebase_from_video_frame_delta() {
        let timebase = TimestampTimebase::infer_from_delta(33_333);
        assert!(matches!(timebase, TimestampTimebase::Microseconds));
    }

    #[test]
    fn infers_millisecond_timebase_from_video_frame_delta() {
        let timebase = TimestampTimebase::infer_from_delta(33);
        assert!(matches!(timebase, TimestampTimebase::Milliseconds));
    }
}
