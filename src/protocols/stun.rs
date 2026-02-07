/* src/protocols/stun.rs */

/// Detects STUN protocol (Session Traversal Utilities for NAT).
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 20 {
		return false;
	}

	if data[4..8] != [0x21, 0x12, 0xA4, 0x42] {
		return false;
	}

	if (data[0] & 0xC0) != 0 {
		return false;
	}

	let msg_len = u16::from_be_bytes([data[2], data[3]]);
	if !msg_len.is_multiple_of(4) {
		return false;
	}

	true
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_stun_binding_request() {
		let mut data = [0u8; 20];
		data[1] = 0x01;
		data[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_stun_with_attributes() {
		let mut data = [0u8; 28];
		data[1] = 0x01;
		data[3] = 0x08;
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
		data[0] = 0x80;
		data[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_unaligned_length() {
		let mut data = [0u8; 20];
		data[3] = 0x02;
		data[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_short_data() {
		let data = [0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42];
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_random_data() {
		assert!(!detect(&[0x42; 64]));
	}
}
