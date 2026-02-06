/* src/protocols/rtsp.rs */

/// Detects RTSP protocol (Real-Time Streaming Protocol).
///
/// RTSP messages are text-based and start with either a Request-Line or a Status-Line.
/// Status-Line: "RTSP/1.0 200 OK\r\n"
/// Request-Line: "DESCRIBE rtsp://example.com/media.mp4 RTSP/1.0\r\n"
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	// Minimum length for a basic status line or request: "RTSP/1.0 200 OK\n" (16 bytes)
	if data.len() < 14 {
		return false;
	}

	// 1. Detect Status-Line (Server Response)
	if data.starts_with(b"RTSP/1.0 ") || data.starts_with(b"RTSP/2.0 ") {
		return validate_rtsp_line(data, true);
	}

	// 2. Detect Request-Line (Client Request)
	if is_rtsp_request(data) {
		return validate_rtsp_line(data, false);
	}

	false
}

#[inline(always)]
fn is_rtsp_request(data: &[u8]) -> bool {
	match data[0] {
		b'O' => data.starts_with(b"OPTIONS "),
		b'D' => data.starts_with(b"DESCRIBE "),
		b'S' => data.starts_with(b"SETUP ") || data.starts_with(b"SET_PARAMETER "),
		b'P' => data.starts_with(b"PLAY ") || data.starts_with(b"PAUSE "),
		b'T' => data.starts_with(b"TEARDOWN "),
		b'G' => data.starts_with(b"GET_PARAMETER "),
		b'R' => data.starts_with(b"REDIRECT ") || data.starts_with(b"RECORD "),
		b'A' => data.starts_with(b"ANNOUNCE "),
		_ => false,
	}
}

/// Validates that the line is printable ASCII and contains "RTSP/1.0" or "RTSP/2.0".
#[inline(always)]
fn validate_rtsp_line(data: &[u8], is_response: bool) -> bool {
	let limit = data.len().min(64);
	let mut found_version = is_response;
	let mut end_of_line = limit;

	for i in 0..limit {
		let b = data[i];
		if b == b'\n' || b == b'\r' {
			end_of_line = i;
			break;
		}
		if b < 32 || b > 126 {
			return false;
		}
	}

	if !found_version {
		let line = &data[..end_of_line];
		// Search for " RTSP/1.0" or " RTSP/2.0" suffix in the request line.
		if line.len() > 9 {
			for i in 0..=(line.len() - 9) {
				let sub = &line[i..i + 9];
				if sub == b" RTSP/1.0" || sub == b" RTSP/2.0" {
					found_version = true;
					break;
				}
			}
		}
	}

	found_version
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_rtsp_response() {
		assert!(detect(b"RTSP/1.0 200 OK\r\n"));
		assert!(detect(b"RTSP/2.0 200 OK\n"));
		assert!(detect(b"RTSP/1.0 404 Not Found\r\n"));
	}

	#[test]
	fn test_detect_rtsp_requests() {
		assert!(detect(b"OPTIONS * RTSP/1.0\r\n"));
		assert!(detect(b"DESCRIBE rtsp://example.com/stream RTSP/1.0\r\n"));
		assert!(detect(b"SETUP rtsp://example.com/stream/track1 RTSP/1.0\n"));
		assert!(detect(b"PLAY rtsp://example.com/stream RTSP/1.0\r\n"));
	}

	#[test]
	fn test_detect_rtsp_partial() {
		assert!(detect(b"DESCRIBE rtsp://server.com/media RTSP/1.0"));
	}

	#[test]
	fn test_reject_http_collision() {
		assert!(!detect(b"GET /index.html HTTP/1.1\r\n"));
		assert!(!detect(b"HTTP/1.1 200 OK\r\n"));
	}

	#[test]
	fn test_reject_sip_collision() {
		assert!(!detect(b"INVITE sip:bob@example.com SIP/2.0\r\n"));
		assert!(!detect(b"SIP/2.0 200 OK\r\n"));
	}

	#[test]
	fn test_reject_non_ascii() {
		let mut data = [0u8; 20];
		data[..9].copy_from_slice(b"RTSP/1.0 ");
		data[9..].copy_from_slice(&[
			0xFF, 0x00, 0x12, 0x34, 0x56, 0x78, 0x90, 0x11, 0x22, 0x33, 0x44,
		]);
		assert!(!detect(&data));
	}

	#[test]
	fn test_short_data() {
		assert!(!detect(b"RTSP/1.0"));
		assert!(!detect(b"SETUP"));
	}

	#[test]
	fn test_random_data() {
		assert!(!detect(&[0x42; 64]));
	}
}
