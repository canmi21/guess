/* src/protocols/mysql.rs */

/// Detects MySQL protocol.
///
/// This implementation focuses on the Initial Handshake Packet sent by the server.
/// Packet structure:
/// - [0..3]: Payload Length (3 bytes, Little-Endian)
/// - [3]: Sequence ID (1 byte, should be 0 for the first packet)
/// - [4]: Protocol Version (1 byte, typically 0x0A for MySQL 10)
/// - [5..]: NUL-terminated Server Version String
/// - [idx]: NUL terminator
/// - [idx+1..idx+5]: Connection ID (4 bytes)
/// - [idx+5..idx+13]: Auth-plugin-data-part-1 (8 bytes)
/// - [idx+13]: Filler (1 byte, 0x00)
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	// Minimum 10 bytes: Header(4) + Proto(1) + MinVersion(1) + NUL(1) + ConnID(4)
	// Actually, the version string is usually longer (e.g. "8.0.21"), and we want to see the filler.
	if data.len() < 10 {
		return false;
	}

	// 1. Validate Header
	let payload_len = u32::from_le_bytes([data[0], data[1], data[2], 0]);
	// Handshake packets are typically 60-200 bytes. We allow a reasonable range.
	if payload_len < 30 || payload_len > 1024 {
		return false;
	}

	// Sequence ID must be 0 for the initial handshake.
	if data[3] != 0 {
		return false;
	}

	// 2. Protocol Version
	if data[4] != 0x0A {
		return false;
	}

	// 3. Server Version String (starts at data[5])
	// Find the NUL terminator.
	let mut nul_pos = None;
	// The version string is usually short, we look up to 48 bytes in (well within our 64-byte window).
	let search_limit = data.len().min(48);
	for i in 5..search_limit {
		if data[i] == 0 {
			nul_pos = Some(i);
			break;
		}
		// Characters should be printable ASCII.
		if data[i] < 32 || data[i] > 126 {
			return false;
		}
	}

	let Some(idx) = nul_pos else {
		// If we haven't found a NUL but we have enough data to have seen one, reject.
		// If data is short, we might accept on the prefix alone, but for high confidence
		// we prefer seeing the NUL.
		return data.len() < 20;
	};

	// After NUL (idx), we expect:
	// - Connection ID (4 bytes) at [idx+1..idx+5]
	// - Auth-plugin-data-part-1 (8 bytes) at [idx+5..idx+13]
	// - Filler (1 byte, 0x00) at [idx+13]

	if data.len() > idx + 13 {
		// Check the filler byte at offset idx + 13.
		if data[idx + 13] != 0 {
			return false;
		}
	}

	// If we have data up to the reserved bytes, we could check them (10 bytes of 0x00).
	// However, the idx+13 filler is already a very strong signal.

	true
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_mysql_8_0() {
		let mut data = [0u8; 64];
		// Length 78 (0x4E)
		data[0] = 0x4E;
		data[1] = 0x00;
		data[2] = 0x00;
		data[3] = 0x00; // Seq
		data[4] = 0x0A; // Proto
		let version = b"8.0.21";
		data[5..5 + version.len()].copy_from_slice(version);
		let idx = 5 + version.len();
		data[idx] = 0x00; // NUL
		// ConnID (4), Auth1 (8)
		data[idx + 13] = 0x00; // Filler
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_mysql_5_7() {
		let mut data = [0u8; 64];
		// Length 90 (0x5A)
		data[0] = 0x5A;
		data[3] = 0x00;
		data[4] = 0x0A;
		let version = b"5.7.30";
		data[5..5 + version.len()].copy_from_slice(version);
		let idx = 5 + version.len();
		data[idx] = 0x00;
		data[idx + 13] = 0x00; // Filler
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_wrong_protocol() {
		let mut data = [0u8; 64];
		data[0] = 0x4E;
		data[3] = 0x00;
		data[4] = 0x0B; // Wrong proto version
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_wrong_sequence() {
		let mut data = [0u8; 64];
		data[0] = 0x4E;
		data[3] = 0x01; // Should be 0
		data[4] = 0x0A;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_bad_version_string() {
		let mut data = [0u8; 64];
		data[0] = 0x4E;
		data[3] = 0x00;
		data[4] = 0x0A;
		// Non-printable character in version string
		data[5] = 0x01;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_bad_filler() {
		let mut data = [0u8; 64];
		data[0] = 0x4E;
		data[3] = 0x00;
		data[4] = 0x0A;
		let version = b"8.0.21";
		data[5..5 + version.len()].copy_from_slice(version);
		let idx = 5 + version.len();
		data[idx] = 0x00;
		data[idx + 13] = 0xFF; // Bad filler
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_http() {
		assert!(!detect(b"GET / HTTP/1.1\r\n"));
	}

	#[test]
	fn test_reject_short_data() {
		assert!(!detect(&[0x0A; 4]));
	}

	#[test]
	fn test_reject_random_data() {
		assert!(!detect(&[0x42; 64]));
	}
}
