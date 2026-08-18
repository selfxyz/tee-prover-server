//! Recovers the original message from `ShaBytesDynamic`-style pre-padded SHA
//! input.
//!
//! The circuit's `ShaBytesDynamic` component hashes input that was SHA-padded
//! *off-circuit* by the caller — the circuit itself only ever sees padded
//! blocks. A native pre-check that wants to hash the same message with a
//! standard SHA implementation must first strip that padding back off: read
//! the message bit-length from the trailing 8 bytes, confirm the padding
//! between the message and that length field is well-formed (`0x80`
//! immediately after the message, then zeros), and return the message slice.
//!
//! As with the rest of this module, any inconsistency returns `None` rather
//! than a best guess — `None` becomes `Skipped` upstream, never a rejection.

/// Recovers the original (unpadded) message from `padded[..padded_len]`,
/// which is assumed to be standard SHA padding: `message || 0x80 || zeros* ||
/// be_u64(message_len_in_bits)`, padded out to a whole number of 64-byte
/// blocks.
///
/// Returns `None` if `padded_len` exceeds the buffer, `padded_len` isn't a
/// multiple of the 64-byte SHA block size, the buffer is too short to hold an
/// 8-byte length field, the encoded bit-length isn't a whole number of bytes,
/// the encoded length doesn't fit inside the buffer, the byte immediately
/// after the message isn't `0x80`, or any byte between that marker and the
/// length field isn't zero.
///
/// `padded_len` is an untrusted JSON field, not something this function
/// derives — a genuine SHA-padded document is always block-aligned, but a
/// crafted, non-aligned `padded_len` could otherwise pass every other check
/// by coincidence and produce a wrong-but-plausible message. The block-size
/// check closes that off before any of the rest run.
///
/// **This function is written for SHA-256's shape — 64-byte blocks, an
/// 8-byte big-endian length field — but four deployed circuits
/// (`register_sha512_*`, `register_id_sha512_*`) use `sha384_512Pad`
/// instead: 128-byte blocks with a 16-byte length field.** It handles that
/// shape too, but only because of two facts that both happen to hold, not
/// because it was written for it:
///
/// 1. 128 is a multiple of 64, so `padded_len % 64 != 0` never rejects a
///    genuinely 128-byte-block-aligned buffer.
/// 2. The 128-bit length field is big-endian, so its trailing 8 bytes are
///    the *low* 64 bits of the true bit-length, and its leading 8 bytes are
///    the *high* 64 bits — which are all zero for any message under
///    2^64 bits (i.e. every real document). This function reads only the
///    trailing 8 bytes as `bit_len`, which is therefore the correct value,
///    and it treats the 8 leading (high-order, zero) bytes of the 16-byte
///    length field as ordinary zero *padding* — indistinguishable from the
///    zeros between the `0x80` marker and the length field, and covered by
///    the same "any byte between the marker and the length field must be
///    zero" check.
///
/// If a future change tightened the block-alignment check to `% 128` for a
/// 512-bit hash, or shortened the zero-padding tolerance, it would break
/// this coincidence and falsely reject every SHA-384/512 circuit. See
/// `recovers_a_message_from_sha384_512_style_padding` below, which pins the
/// 128/16 shape directly rather than relying on this reasoning alone.
pub fn recover_message(padded: &[u8], padded_len: usize) -> Option<&[u8]> {
    if padded_len > padded.len() {
        return None;
    }
    if padded_len % 64 != 0 {
        return None;
    }
    let buf = &padded[..padded_len];
    if buf.len() < 8 {
        return None;
    }
    let (msg_and_pad, len_bytes) = buf.split_at(buf.len() - 8);
    let bit_len = u64::from_be_bytes(len_bytes.try_into().ok()?);
    if bit_len % 8 != 0 {
        return None;
    }
    let msg_len = usize::try_from(bit_len / 8).ok()?;
    if msg_len >= msg_and_pad.len() {
        // No room left for the 0x80 marker (and, ordinarily, at least one
        // zero byte) before the length field.
        return None;
    }
    if msg_and_pad[msg_len] != 0x80 {
        return None;
    }
    if msg_and_pad[msg_len + 1..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(&buf[..msg_len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_a_message_from_sha384_512_style_padding() {
        // sha384_512Pad's shape: 128-byte blocks, a 16-byte big-endian
        // length field (vs. SHA-256's 64-byte blocks / 8-byte field). Builds
        // the length field as 8 zero bytes (the high 64 bits, zero for any
        // real message) followed by the true bit-length's 8 bytes -- exactly
        // what four deployed circuits (register_sha512_*, register_id_
        // sha512_*) produce. This is the test the doc comment on
        // recover_message points to: it must keep passing even if someone
        // "cleans up" the 64/8 logic, because that logic is what recovers
        // this shape too.
        let msg = b"a message long enough to span more than one 128-byte block boundary, \
                    to make sure the block-alignment and bounds checks both see real data";
        let mut padded = msg.to_vec();
        padded.push(0x80);
        // Pad to a whole number of 128-byte blocks, leaving room for the
        // 16-byte length field.
        while (padded.len() + 16) % 128 != 0 {
            padded.push(0);
        }
        let bit_len = (msg.len() as u64) * 8;
        padded.extend_from_slice(&[0u8; 8]); // high 64 bits: zero for any real-sized message
        padded.extend_from_slice(&bit_len.to_be_bytes()); // low 64 bits: the true bit length
        let len = padded.len();
        assert_eq!(len % 128, 0, "test construction should be 128-byte-block aligned");
        assert_eq!(recover_message(&padded, len), Some(&msg[..]));
    }

    #[test]
    fn recovers_a_message_from_sha256_padding() {
        let msg = b"hello world";
        let mut padded = msg.to_vec();
        padded.push(0x80);
        while (padded.len() + 8) % 64 != 0 {
            padded.push(0);
        }
        padded.extend_from_slice(&((msg.len() as u64) * 8).to_be_bytes());
        let len = padded.len();
        assert_eq!(recover_message(&padded, len), Some(&msg[..]));
    }

    #[test]
    fn rejects_padding_with_a_missing_0x80_marker() {
        let mut padded = b"hello".to_vec();
        padded.push(0x00); // should be 0x80
        while (padded.len() + 8) % 64 != 0 {
            padded.push(0);
        }
        padded.extend_from_slice(&(40u64).to_be_bytes());
        let len = padded.len();
        assert_eq!(recover_message(&padded, len), None);
    }

    #[test]
    fn rejects_a_padded_len_that_is_not_block_aligned() {
        // A genuine SHA-padded document is always a multiple of the 64-byte
        // block size. padded_len is an untrusted JSON field though, and a
        // non-aligned value could otherwise sail through every remaining
        // check (bounds, 0x80 marker, trailing zeros) by coincidence and
        // produce a wrong-but-plausible message. Build an otherwise-valid
        // padding and just report a padded_len 1 short of the true length.
        let msg = b"hello world";
        let mut padded = msg.to_vec();
        padded.push(0x80);
        while (padded.len() + 8) % 64 != 0 {
            padded.push(0);
        }
        padded.extend_from_slice(&((msg.len() as u64) * 8).to_be_bytes());
        let len = padded.len() - 1;
        assert_eq!(recover_message(&padded, len), None);
    }

    #[test]
    fn rejects_a_bit_length_that_is_not_a_multiple_of_8() {
        // u64::MAX % 8 == 7, so this is rejected by the "whole number of
        // bytes" check, not the bounds check on where the message ends — see
        // `rejects_a_length_field_that_legitimately_exceeds_the_buffer` for a
        // %8-aligned value that actually reaches that bounds check.
        let mut padded = vec![0x80];
        while (padded.len() + 8) % 64 != 0 {
            padded.push(0);
        }
        padded.extend_from_slice(&(u64::MAX).to_be_bytes());
        let len = padded.len();
        assert_eq!(recover_message(&padded, len), None);
    }

    #[test]
    fn rejects_a_length_field_that_legitimately_exceeds_the_buffer() {
        // bit_len = 8000 is %8-aligned (msg_len = 1000 bytes), so it clears
        // the "whole number of bytes" check and reaches the bounds check —
        // but a single 64-byte block only leaves 56 bytes of room for a
        // message plus its 0x80/zero padding, nowhere near 1000.
        let mut padded = vec![0x80];
        while (padded.len() + 8) % 64 != 0 {
            padded.push(0);
        }
        padded.extend_from_slice(&(8000u64).to_be_bytes());
        let len = padded.len();
        assert_eq!(recover_message(&padded, len), None);
    }

    #[test]
    fn rejects_a_padded_len_too_short_to_hold_a_length_field() {
        // Any padded_len < 9 can't hold both a message byte and the 8-byte
        // trailing length field. 0 is the only such value that also clears
        // the new block-alignment check, so it's the one that reaches this
        // function's body at all — and it's rejected immediately once inside.
        let padded: Vec<u8> = vec![];
        assert_eq!(recover_message(&padded, 0), None);
    }

    #[test]
    fn rejects_a_stray_nonzero_byte_between_the_marker_and_the_length_field() {
        // Distinct from the missing-marker case: the 0x80 marker is present
        // and correctly placed, but a byte further into the zero-padding
        // region is corrupted.
        let msg = b"hello world";
        let mut padded = msg.to_vec();
        padded.push(0x80);
        while (padded.len() + 8) % 64 != 0 {
            padded.push(0);
        }
        padded.extend_from_slice(&((msg.len() as u64) * 8).to_be_bytes());
        let corrupt_idx = msg.len() + 3; // strictly between the marker and the length field
        padded[corrupt_idx] = 0x01;
        let len = padded.len();
        assert_eq!(recover_message(&padded, len), None);
    }
}
