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
/// be_u64(message_len_in_bits)`.
///
/// Returns `None` if `padded_len` exceeds the buffer, the buffer is too short
/// to hold an 8-byte length field, the encoded bit-length isn't a whole
/// number of bytes, the encoded length doesn't fit inside the buffer, the
/// byte immediately after the message isn't `0x80`, or any byte between that
/// marker and the length field isn't zero.
pub fn recover_message(padded: &[u8], padded_len: usize) -> Option<&[u8]> {
    if padded_len > padded.len() {
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
    fn rejects_a_length_field_longer_than_the_buffer() {
        let mut padded = vec![0x80];
        while (padded.len() + 8) % 64 != 0 {
            padded.push(0);
        }
        padded.extend_from_slice(&(u64::MAX).to_be_bytes());
        let len = padded.len();
        assert_eq!(recover_message(&padded, len), None);
    }
}
