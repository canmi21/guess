/* src/protocols/stun.rs */

/// Detects STUN protocol (Session Traversal Utilities for NAT).
///
/// STUN messages have a fixed 20-byte header:
/// - [0..2]: STUN Message Type (first 2 bits must be 00)
/// - [2..4]: Message Length (excludes header, must be a multiple of 4)
/// - [4..8]: Magic Cookie (0x2112A442)
/// - [8..20]: Transaction ID (12 bytes)
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	// A valid STUN packet must be at least 20 bytes (header only).
	if data.len() < 20 {
		return false;
	}

	// 1. Validate Magic Cookie (most specific check)
	if &data[4..8] != &[0x21, 0x12, 0xA4, 0x42] {
		return false;
	}

	// 2. Validate Message Type prefix (first 2 bits must be 0)
	if (data[0] & 0xC0) != 0 {
		return false;
	}

	// 3. Validate Message Length (must be a multiple of 4 per RFC 5389)
	let msg_len = u16::from_be_bytes([data[2], data[3]]);
	if msg_len % 4 != 0 {
		return false;
	}

	// Note: We could validate the Transaction ID or typical Message Types,
	// but the Magic Cookie + Bits + Length alignment is already highly specific.
	true
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_stun_binding_request() {
		let mut data = [0u8; 20];
		data[1] = 0x01; // Binding Request
		data[2] = 0x00; // Length 0
		data[3] = 0x00;
		data[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // Magic Cookie
		// data[8..20] is random Transaction ID
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_stun_with_attributes() {
		let mut data = [0u8; 28];
		data[1] = 0x01;
		data[3] = 0x08; // Length 8 (multiple of 4)
		data[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_invalid_magic_cookie() {
		let mut data = [0u8; 20];
		data[4..8].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_invalid_prefix_bits() {
		let mut data = [0u8; 20];
		data[0] = 0x80; // First bit set (10xx...)
		data[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_unaligned_length() {
		let mut data = [0u8; 20];
		data[3] = 0x02; // Length 2 (not multiple of 4)
		data[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_short_data() {
		let data = [0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42]; // 8 bytes only
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_random_data() {
		assert!(!detect(&[0x42; 64]));
	}
}
