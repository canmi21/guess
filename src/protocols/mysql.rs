/* src/protocols/mysql.rs */

/// Detects `MySQL` protocol.
///
/// This implementation focuses on the Initial Handshake Packet sent by the server.
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 10 {
		return false;
	}

	let payload_len = u32::from_le_bytes([data[0], data[1], data[2], 0]);
	if !(30..=1024).contains(&payload_len) {
		return false;
	}

	if data[3] != 0 {
		return false;
	}

	if data[4] != 0x0A {
		return false;
	}

	let mut nul_pos = None;
	let search_limit = data.len().min(48);
	for (i, &b) in data.iter().enumerate().take(search_limit).skip(5) {
		if b == 0 {
			nul_pos = Some(i);
			break;
		}
		if !(32..=126).contains(&b) {
			return false;
		}
	}

	let Some(idx) = nul_pos else {
		return data.len() < 20;
	};

	if data.len() > idx + 13 && data[idx + 13] != 0 {
		return false;
	}

	true
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_mysql_8_0() {
		let mut data = [0u8; 64];
		data[0] = 0x4E;
		data[1] = 0x00;
		data[2] = 0x00;
		data[3] = 0x00;
		data[4] = 0x0A;
		let version = b"8.0.21";
		data[5..5 + version.len()].copy_from_slice(version);
		let idx = 5 + version.len();
		data[idx] = 0x00;
		data[idx + 13] = 0x00;
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_mysql_5_7() {
		let mut data = [0u8; 64];
		data[0] = 0x5A;
		data[3] = 0x00;
		data[4] = 0x0A;
		let version = b"5.7.30";
		data[5..5 + version.len()].copy_from_slice(version);
		let idx = 5 + version.len();
		data[idx] = 0x00;
		data[idx + 13] = 0x00;
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_wrong_protocol() {
		let mut data = [0u8; 64];
		data[0] = 0x4E;
		data[3] = 0x00;
		data[4] = 0x0B;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_wrong_sequence() {
		let mut data = [0u8; 64];
		data[0] = 0x4E;
		data[3] = 0x01;
		data[4] = 0x0A;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_bad_version_string() {
		let mut data = [0u8; 64];
		data[0] = 0x4E;
		data[3] = 0x00;
		data[4] = 0x0A;
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
		data[idx + 13] = 0xFF;
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
