/* src/protocols/postgres.rs */

/// Detects PostgreSQL protocol.
///
/// PostgreSQL connections start with either an SSLRequest or a StartupMessage.
/// Both start with a 4-byte big-endian length, followed by a 4-byte message code.
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	// Minimum message (SSLRequest) is 8 bytes.
	if data.len() < 8 {
		return false;
	}

	let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
	let code = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

	// 1. Check for SSLRequest (Length 8, Code 80877103 / 0x04D2162F)
	if length == 8 && code == 0x04D2162F {
		return true;
	}

	// 2. Check for StartupMessage (Protocol 3.0: 0x00030000)
	// Startup messages must be at least 8 bytes and length must match the header.
	if length >= 8 && length <= 4096 && code == 0x00030000 {
		// Further validation: StartupMessages contain NUL-terminated key-value pairs.
		// Usually start with "user\0", "database\0", or "client_encoding\0".
		if data.len() >= 12 {
			// Scan for at least one NUL terminator in the payload.
			let payload = &data[8..data.len().min(64)];
			let mut found_nul = false;
			for &b in payload {
				if b == 0 {
					found_nul = true;
					break;
				}
				// Keys and values should be printable ASCII.
				if b < 32 || b > 126 {
					return false;
				}
			}
			return found_nul;
		}
		return true;
	}

	false
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_postgres_ssl_request() {
		let data = [0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F];
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_postgres_startup_message() {
		// Length 40, Protocol 3.0, "user\0postgres\0\0"
		let mut data = [0u8; 40];
		data[3] = 40;
		data[5] = 0x03; // Protocol 3.0 (0x00030000)
		data[8..13].copy_from_slice(b"user\0");
		data[13..22].copy_from_slice(b"postgres\0");
		data[22] = 0x00;
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_invalid_length_ssl() {
		// Code is correct, but length is not 8
		let data = [0x00, 0x00, 0x00, 0x09, 0x04, 0xD2, 0x16, 0x2F, 0x00];
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_invalid_protocol() {
		let data = [0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00];
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_garbage_startup() {
		let mut data = [0u8; 12];
		data[3] = 12;
		data[5] = 0x03;
		data[8] = 0x01; // Non-printable in payload
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_http() {
		assert!(!detect(b"GET / HTTP/1.1\r\n"));
	}

	#[test]
	fn test_reject_short_data() {
		assert!(!detect(&[0x00, 0x00, 0x00, 0x08]));
	}
}
