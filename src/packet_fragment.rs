use crate::mitm::{Packet, FRAME_TYPE_FIRST, FRAME_TYPE_LAST, FRAME_TYPE_MASK};

/// Default first-fragment plaintext payload size observed in AA streams.
///
/// This is the application/plaintext payload size before TLS encryption. The
/// outer AA frame payload size is written later by `Packet::transmit()` after
/// `Packet::encrypt_payload()` has produced the encrypted bytes.
pub(crate) const DEFAULT_FIRST_FRAGMENT_PAYLOAD_BYTES: usize = 16_120;
pub(crate) const MIN_FIRST_FRAGMENT_PAYLOAD_BYTES: usize = 512;
pub(crate) const MAX_FIRST_FRAGMENT_PAYLOAD_BYTES: usize = 16_120;

/// Continuation fragments have a 4-byte smaller outer header than FIRST
/// fragments. Keeping the plaintext continuation slice 4 bytes larger mirrors
/// OpenAuto/aasdk style framing and the native streams observed in logs:
/// FIRST plaintext ~= 16120, MIDDLE/LAST plaintext ~= 16124.
pub(crate) const DEFAULT_CONTINUATION_FRAGMENT_PAYLOAD_BONUS: usize = 4;

#[derive(Clone, Copy, Debug)]
pub(crate) struct PlainPayloadFragmentOptions {
    pub channel: u8,
    /// Frame-type bits are ignored. Encryption/message bits are preserved.
    pub base_flags: u8,
    pub first_fragment_payload_bytes: usize,
    pub continuation_fragment_payload_bytes: usize,
    /// Total plaintext/application payload length for a multi-fragment message.
    /// This maps to the extended FIRST-frame `final_length` field. It is not an
    /// encrypted/ciphertext length.
    pub first_final_length: Option<u32>,
}

pub(crate) fn frame_base_flags(flags: u8) -> u8 {
    flags & !FRAME_TYPE_MASK
}

pub(crate) fn clamp_first_fragment_payload_bytes(requested: usize) -> usize {
    requested.clamp(
        MIN_FIRST_FRAGMENT_PAYLOAD_BYTES,
        MAX_FIRST_FRAGMENT_PAYLOAD_BYTES,
    )
}

pub(crate) fn openauto_continuation_fragment_payload_bytes(
    first_fragment_payload_bytes: usize,
) -> usize {
    first_fragment_payload_bytes.saturating_add(DEFAULT_CONTINUATION_FRAGMENT_PAYLOAD_BONUS)
}

/// Re-fragment a plaintext/application payload into AA packets.
///
/// This utility is intentionally generic so other packet rewriters can reuse the
/// same dynamic replacement path later. The important OpenAuto/aasdk-inspired
/// split is:
///
/// * FIRST `final_length` = total plaintext/application payload length.
/// * Per-frame 2-byte payload size = encrypted payload length, handled later by
///   the normal encrypt + transmit path.
/// * Encryption flag is preserved from `base_flags`; it is never forced here.
pub(crate) fn fragment_plain_payload(
    payload: &[u8],
    opts: PlainPayloadFragmentOptions,
) -> Vec<Packet> {
    let first_chunk = opts.first_fragment_payload_bytes.max(1);
    let continuation_chunk = opts.continuation_fragment_payload_bytes.max(1);
    let base_flags = frame_base_flags(opts.base_flags);

    if payload.len() <= first_chunk {
        return vec![Packet {
            channel: opts.channel,
            flags: base_flags | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
            final_length: None,
            payload: payload.to_vec(),
        }];
    }

    let mut packets = Vec::with_capacity((payload.len() / continuation_chunk).saturating_add(2));

    packets.push(Packet {
        channel: opts.channel,
        flags: base_flags | FRAME_TYPE_FIRST,
        final_length: opts.first_final_length,
        payload: payload[..first_chunk].to_vec(),
    });

    let mut pos = first_chunk;
    while pos < payload.len() {
        let remaining = payload.len() - pos;
        let take = remaining.min(continuation_chunk);
        let last = pos + take >= payload.len();
        let flags = if last {
            base_flags | FRAME_TYPE_LAST
        } else {
            base_flags
        };

        packets.push(Packet {
            channel: opts.channel,
            flags,
            final_length: None,
            payload: payload[pos..pos + take].to_vec(),
        });

        pos += take;
    }

    packets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitm::ENCRYPTED;

    #[test]
    fn fragment_plain_payload_uses_openauto_style_sizes() {
        let payload = vec![0xAA; 55_251];
        let packets = fragment_plain_payload(
            &payload,
            PlainPayloadFragmentOptions {
                channel: 0x08,
                base_flags: ENCRYPTED,
                first_fragment_payload_bytes: 16_120,
                continuation_fragment_payload_bytes: 16_124,
                first_final_length: Some(payload.len() as u32),
            },
        );

        assert_eq!(packets.len(), 4);
        assert_eq!(packets[0].flags & FRAME_TYPE_MASK, FRAME_TYPE_FIRST);
        assert_eq!(packets[0].final_length, Some(payload.len() as u32));
        assert_eq!(packets[0].payload.len(), 16_120);
        assert_eq!(packets[1].flags & FRAME_TYPE_MASK, 0);
        assert_eq!(packets[1].payload.len(), 16_124);
        assert_eq!(packets[2].payload.len(), 16_124);
        assert_eq!(packets[3].flags & FRAME_TYPE_MASK, FRAME_TYPE_LAST);
        assert_eq!(packets[3].payload.len(), 6_883);
    }

    #[test]
    fn fragment_plain_payload_preserves_non_frame_flags_without_forcing_encryption() {
        let payload = vec![0x11; 10];
        let packets = fragment_plain_payload(
            &payload,
            PlainPayloadFragmentOptions {
                channel: 0x01,
                base_flags: 0x00,
                first_fragment_payload_bytes: 16,
                continuation_fragment_payload_bytes: 20,
                first_final_length: Some(payload.len() as u32),
            },
        );

        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].flags & ENCRYPTED, 0);
        assert_eq!(
            packets[0].flags & FRAME_TYPE_MASK,
            FRAME_TYPE_FIRST | FRAME_TYPE_LAST
        );
        assert_eq!(packets[0].final_length, None);
    }
}
