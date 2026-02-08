/* src/protocols/quic.rs */

/// Detects QUIC protocol (UDP).
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 7 {
		return false;
	}

	let first_byte = data[0];

	if (first_byte & 0xC0) != 0xC0 {
		return false;
	}

	let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

	let is_valid_version = version == 1
		|| version == 0
		|| version == 0x6b3343cf
		|| (0xff000000..=0xff0000ff).contains(&version);

	if !is_valid_version {
		return false;
	}

	let dcid_len = data[5] as usize;
	if dcid_len > 20 {
		return false;
	}

	if data.len() <= 6 + dcid_len {
		return true;
	}

	let scid_len = data[6 + dcid_len] as usize;
	scid_len <= 20
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_quic_v1_initial() {
		let mut data = [0u8; 64];
		data[0] = 0xC0;
		data[4] = 0x01;
		data[5] = 0x08;
		data[14] = 0x08;
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_quic_v1_handshake() {
		let mut data = [0u8; 64];
		data[0] = 0xE0;
		data[4] = 0x01;
		data[5] = 0x00;
		data[6] = 0x00;
		assert!(detect(&data));
	}

	#[test]
	fn test_accept_header_protected_bits() {
		// After QUIC header protection, lower 4 bits may be non-zero
		let mut data = [0u8; 64];
		data[0] = 0xCF; // 1100 1111 — lower bits set by header protection
		data[4] = 0x01; // version 1
		data[5] = 0x08; // DCID length
		data[14] = 0x08; // SCID length
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_quic_version_negotiation_random_bits() {
		let mut data = [0u8; 64];
		data[0] = 0xFF;
		data[5] = 0x00;
		data[6] = 0x00;
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_quic_v2() {
		let mut data = [0u8; 64];
		data[0] = 0xC0;
		let v2 = 0x6b3343cfu32.to_be_bytes();
		data[1..5].copy_from_slice(&v2);
		data[5] = 0x00;
		data[6] = 0x00;
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_invalid_fixed_bit() {
		let mut data = [0u8; 64];
		data[0] = 0x80;
		data[4] = 0x01;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_invalid_version() {
		let mut data = [0u8; 64];
		data[0] = 0xC0;
		data[4] = 0x03;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_too_long_cid() {
		let mut data = [0u8; 64];
		data[0] = 0xC0;
		data[4] = 0x01;
		data[5] = 21;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_sslv2_collision() {
		let mut data = [0u8; 64];
		data[0] = 0x80;
		data[1] = 0x1F;
		data[2] = 0x01;
		assert!(!detect(&data));
	}

	#[test]
	fn test_short_data() {
		assert!(!detect(&[0xC0, 0x00, 0x00, 0x00, 0x01, 0x00]));
	}

	#[test]
	fn test_random_data() {
		assert!(!detect(&[0x42; 64]));
	}
}
