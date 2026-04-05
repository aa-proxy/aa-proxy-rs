/// Minimal MPEG-TS muxer for wrapping H.264 Annex-B frames.
///
/// Produces a byte-exact MPEG-TS stream suitable for consumption by VLC and
/// other standard players.  Only the subset needed for a single H.264 video
/// elementary stream is implemented.
///
/// Topology:
///   PAT (PID 0x0000)  – maps program 1 → PMT PID
///   PMT (PID 0x0100)  – maps program 1's video ES → Video PID, PCR_PID = Video PID
///   Video PES (PID 0x0101) – one PES per frame, PTS from the AA timestamp

const TS_PACKET_SIZE: usize = 188;
const PAT_PID: u16 = 0x0000;
const PMT_PID: u16 = 0x0100;
const VIDEO_PID: u16 = 0x0101;

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
        pkt[payload_start..payload_start + payload_chunk.len()]
            .copy_from_slice(payload_chunk);
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
        0x00,                                   // table_id
        0xB0, 0x0D,                             // syntax + section_length = 13
        0x00, 0x01,                             // transport_stream_id
        0xC1,                                   // version=0, current=1
        0x00, 0x00,                             // section/last_section numbers
        0x00, 0x01,                             // program_number = 1
        0xE0 | ((PMT_PID >> 8) & 0x1F) as u8, // reserved + PMT_PID high
        (PMT_PID & 0xFF) as u8,                 // PMT_PID low
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
fn make_pmt(counter: u8) -> [u8; TS_PACKET_SIZE] {
    // PMT section (without CRC):
    //   table_id=0x02, section_length=18
    //   program_number=1, version=0, current=1
    //   section_number=0, last_section_number=0
    //   PCR_PID=VIDEO_PID, program_info_length=0
    //   stream_type=0x1B (H.264), elementary_PID=VIDEO_PID, ES_info_length=0
    let section: [u8; 17] = [
        0x02,                                       // table_id
        0xB0, 0x12,                                 // syntax + section_length = 18
        0x00, 0x01,                                 // program_number
        0xC1,                                       // version=0, current=1
        0x00, 0x00,                                 // section/last_section numbers
        0xE0 | ((VIDEO_PID >> 8) & 0x1F) as u8,   // reserved + PCR_PID high
        (VIDEO_PID & 0xFF) as u8,                   // PCR_PID low
        0xF0, 0x00,                                 // reserved + program_info_length=0
        0x1B,                                       // stream_type H.264
        0xE0 | ((VIDEO_PID >> 8) & 0x1F) as u8,   // reserved + elementary_PID high
        (VIDEO_PID & 0xFF) as u8,                   // elementary_PID low
        0xF0, 0x00,                                 // reserved + ES_info_length=0
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
    video_counter: u8,
}

impl MpegTsState {
    pub fn new() -> Self {
        Self {
            pat_counter: 0,
            pmt_counter: 0,
            video_counter: 0,
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

    fn next_video(&mut self) -> u8 {
        let c = self.video_counter;
        self.video_counter = (self.video_counter + 1) & 0x0F;
        c
    }

    /// Emit PAT + PMT packets (call before every IDR frame).
    pub fn pat_pmt(&mut self) -> Vec<u8> {
        let pat = make_pat(self.next_pat());
        let pmt = make_pmt(self.next_pmt());
        let mut out = Vec::with_capacity(2 * TS_PACKET_SIZE);
        out.extend_from_slice(&pat);
        out.extend_from_slice(&pmt);
        out
    }

    /// Wrap Annex-B `data` in PES packets and fragment into 188-byte TS packets.
    ///
    /// `pts_us` is the Android Auto presentation timestamp in microseconds
    /// (from the 8-byte frame header).  `is_idr` triggers inclusion of a PCR
    /// in the adaptation field of the first TS packet.
    pub fn video_pes(&mut self, pts_us: u64, data: &[u8], is_idr: bool) -> Vec<u8> {
        // Convert µs to 90 kHz ticks, then mask to 33 bits (the PTS field width).
        // Use u128 for the intermediate product to avoid overflow, then wrap into
        // the 33-bit PTS space (≈ 26.5-hour cycle) as MPEG-TS requires.
        let pts_90k = ((pts_us as u128 * 90 / 1000) & 0x1_FFFF_FFFF) as u64;
        let pts_bytes = encode_pts(pts_90k);

        // Build PES header (14 bytes):
        //   start_code(3) + stream_id(1) + PES_length(2) + flags(3) + PTS(5)
        let pes_header: [u8; 14] = [
            0x00, 0x00, 0x01,   // start code
            0xE0,               // stream_id: video
            0x00, 0x00,         // PES_packet_length = 0 (unbounded; valid for video)
            0x81,               // marker=10, no scrambling, no priority, no alignment
            0x80,               // PTS_DTS_flags = PTS only
            0x05,               // PES_header_data_length = 5
            pts_bytes[0], pts_bytes[1], pts_bytes[2], pts_bytes[3], pts_bytes[4],
        ];

        let total_data = pes_header.len() + data.len();
        let mut out = Vec::with_capacity((total_data / 184 + 2) * TS_PACKET_SIZE);

        let mut offset = 0;
        let mut first = true;

        while offset < total_data {
            let is_first_pkt = first;
            first = false;

            // PCR goes in the adaptation field of the very first TS packet of an IDR.
            // PCR adaptation field costs 8 bytes, leaving 176 bytes for payload.
            let pcr = if is_first_pkt && is_idr {
                Some(pts_90k)
            } else {
                None
            };
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

            let counter = self.next_video();
            let pkt = make_ts_packet(VIDEO_PID, is_first_pkt, &chunk, counter, pcr);
            out.extend_from_slice(&pkt);

            offset += available;
        }

        out
    }
}
