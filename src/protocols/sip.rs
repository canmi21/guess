/* src/protocols/sip.rs */

/// Detects SIP protocol (Session Initiation Protocol).
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 12 {
		return false;
	}

	if data.starts_with(b"SIP/2.0 ") {
		return validate_sip_line(data, true);
	}

	if is_sip_request(data) {
		return validate_sip_line(data, false);
	}

	false
}

/// Checks if the data starts with a known SIP method.
#[inline(always)]
fn is_sip_request(data: &[u8]) -> bool {
	match data[0] {
		b'I' => data.starts_with(b"INVITE ") || data.starts_with(b"INFO "),
		b'A' => data.starts_with(b"ACK "),
		b'B' => data.starts_with(b"BYE "),
		b'C' => data.starts_with(b"CANCEL "),
		b'O' => data.starts_with(b"OPTIONS "),
		b'R' => data.starts_with(b"REGISTER ") || data.starts_with(b"REFER "),
		b'P' => data.starts_with(b"PRACK ") || data.starts_with(b"PUBLISH "),
		b'U' => data.starts_with(b"UPDATE "),
		b'S' => data.starts_with(b"SUBSCRIBE "),
		b'N' => data.starts_with(b"NOTIFY "),
		b'M' => data.starts_with(b"MESSAGE "),
		_ => false,
	}
}

/// Validates that the line is printable ASCII and contains "SIP/2.0".
#[inline(always)]
fn validate_sip_line(data: &[u8], is_response: bool) -> bool {
	let limit = data.len().min(64);
	let mut found_version = is_response;
	let mut end_of_line = limit;

	for (i, &b) in data.iter().enumerate().take(limit) {
		if b == b'\n' || b == b'\r' {
			end_of_line = i;
			break;
		}
		if !(32..=126).contains(&b) {
			return false;
		}
	}

	if !found_version && end_of_line > 8 {
		let line = &data[..end_of_line];
		for i in 0..=(line.len() - 8) {
			if &line[i..i + 8] == b" SIP/2.0" {
				found_version = true;
				break;
			}
		}
	}

	found_version
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_sip_response() {
		assert!(detect(b"SIP/2.0 200 OK\r\n"));
		assert!(detect(b"SIP/2.0 100 Trying\n"));
		assert!(detect(b"SIP/2.0 404 Not Found\r\n"));
	}

	#[test]
	fn test_detect_sip_requests() {
		assert!(detect(b"INVITE sip:bob@example.com SIP/2.0\r\n"));
		assert!(detect(b"REGISTER sip:example.com SIP/2.0\n"));
		assert!(detect(b"ACK sip:alice@192.168.1.1 SIP/2.0\r\n"));
		assert!(detect(b"OPTIONS * SIP/2.0\r\n"));
	}

	#[test]
	fn test_detect_sip_partial() {
		assert!(detect(b"INVITE sip:someone@somewhere.com SIP/2.0"));
	}

	#[test]
	fn test_reject_http_collision() {
		assert!(!detect(b"GET /index.html HTTP/1.1\r\n"));
		assert!(!detect(b"HTTP/1.1 200 OK\r\n"));
	}

	#[test]
	fn test_reject_wrong_method() {
		assert!(!detect(b"INSTALL /path/to/file SIP/2.0\r\n"));
	}

	#[test]
	fn test_reject_non_ascii() {
		let mut data = [0u8; 20];
		data[..8].copy_from_slice(b"SIP/2.0 ");
		data[8..15].copy_from_slice(&[0xFF, 0x00, 0x12, 0x34, 0x56, 0x78, 0x90]);
		assert!(!detect(&data));
	}

	#[test]
	fn test_short_data() {
		assert!(!detect(b"SIP/2.0"));
		assert!(!detect(b"INVITE"));
	}

	#[test]
	fn test_random_data() {
		assert!(!detect(&[0x42; 64]));
	}
}
