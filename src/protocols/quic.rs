/* src/protocols/quic.rs */

/// Detects QUIC protocol (UDP).
///
/// Focuses on Long Header packets (Initial, Handshake, 0-RTT, Retry, Version Negotiation),
/// which are used at the start of a connection.
///
/// Long Header Format (RFC 9000):
/// - First byte: Header Form (1), Fixed Bit (1), Type (2), Reserved (2), Packet Number Length (2)
/// - Version: 4 bytes
/// - DCID Len: 1 byte
/// - DCID: 0..20 bytes
/// - SCID Len: 1 byte
/// - SCID: 0..20 bytes
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	// Minimum 7 bytes to see Header(1), Version(4), DCID Len(1), and SCID Len(1).
	if data.len() < 7 {
		return false;
	}

	let first_byte = data[0];

	// Long Header must have the Header Form bit (0x80) and the Fixed Bit (0x40) set.
	// This also helps distinguish it from SSLv2 which has the high bit set but
	// bit 6 is typically 0 (since it's part of the length field).
	if (first_byte & 0xC0) != 0xC0 {
		return false;
	}

	// Byte 1-4: Version
	let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

	// Valid Versions:
	// - 0x00000000: Version Negotiation
	// - 0x00000001: QUIC v1
	// - 0x6b3343cf: QUIC v2 (RFC 9369)
	// - 0xff0000xx: Draft versions
	let is_valid_version = version == 1
		|| version == 0
		|| version == 0x6b3343cf
		|| (version >= 0xff000000 && version <= 0xff0000ff);

	if !is_valid_version {
		return false;
	}

	// For non-Version Negotiation packets, we can perform stricter checks on the first byte.
	if version != 0 {
		// Long Packet Type (bits 2-3, mask 0x30):
		// 00: Initial, 01: 0-RTT, 10: Handshake, 11: Retry.
		// Reserved Bits (bits 4-5, mask 0x0C): MUST be 0.
		//
		// We validate the reserved bits to significantly reduce false positives.
		if (first_byte & 0x0C) != 0 {
			return false;
		}

		// Higher precision: Most connections start with an Initial packet (type 00).
		// While we accept other Long Header types, checking (first_byte & 0x30) == 0
		// would define an "Initial-only" detector. Here we remain slightly broader
		// but the reserved bits check already provides high robustness.
	}

	// Destination Connection ID Length (1 byte)
	let dcid_len = data[5] as usize;
	// Source Connection ID Length (1 byte)
	if dcid_len > 20 {
		return false;
	}

	// Check if we have enough data for SCID length field
	if data.len() <= 6 + dcid_len {
		return true;
	}

	let scid_len = data[6 + dcid_len] as usize;
	if scid_len > 20 {
		return false;
	}

	true
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_quic_v1_initial() {
		let mut data = [0u8; 64];
		data[0] = 0xC0; // Long Header, Fixed Bit, Type=Initial(00), Reserved=00
		data[4] = 0x01; // Version 1
		data[5] = 0x08; // DCID Len
		data[14] = 0x08; // SCID Len
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_quic_v1_handshake() {
		let mut data = [0u8; 64];
		data[0] = 0xE0; // Long Header, Fixed Bit, Type=Handshake(10), Reserved=00
		data[4] = 0x01;
		data[5] = 0x00;
		data[6] = 0x00;
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_invalid_reserved_bits() {
		let mut data = [0u8; 64];
		data[0] = 0xCC; // Long Header (80), Fixed Bit (40), Reserved bits (0C) set to 1.
		data[4] = 0x01;
		assert!(!detect(&data));
	}

	#[test]
	fn test_detect_quic_version_negotiation_random_bits() {
		let mut data = [0u8; 64];
		data[0] = 0xFF; // Header Form (80), Fixed Bit (40), Random bits (3F)
		// Version is 0x00000000
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
		data[0] = 0x80; // Long Header set, but Fixed Bit (40) not set
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
