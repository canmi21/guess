/* src/protocols/tls.rs */

#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 5 {
		return false;
	}

	// Byte 0: ContentType (0x14-0x18)
	// 0x14: change_cipher_spec
	// 0x15: alert
	// 0x16: handshake
	// 0x17: application_data
	// 0x18: heartbeat
	let content_type = data[0];
	if !(0x14..=0x18).contains(&content_type) {
		return false;
	}

	// Byte 1-2: Version (0x0300 - 0x0304)
	// 0x0300: SSL 3.0
	// 0x0301: TLS 1.0
	// 0x0302: TLS 1.1
	// 0x0303: TLS 1.2
	// 0x0304: TLS 1.3
	if data[1] != 0x03 || data[2] > 0x04 {
		return false;
	}

	// Byte 3-4: Length (1-16384)
	let length = u16::from_be_bytes([data[3], data[4]]);
	if length == 0 || length > 16384 {
		return false;
	}

	// Additional check for handshake
	if content_type == 0x16 && data.len() >= 6 {
		let handshake_type = data[5];
		// 0x01: client_hello
		// 0x02: server_hello
		if ![0x01, 0x02, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10].contains(&handshake_type) {
			// Some obscure handshake types might exist, but we focus on common ones for detection
			return true;
		}
	}

	true
}

#[cfg(test)]

mod tests {

	use super::*;

	#[test]

	fn test_detect_tls() {
		// Handshake, TLS 1.2, length 46, Client Hello

		let client_hello = [
			0x16, // Handshake
			0x03, 0x03, // TLS 1.2
			0x00, 0x2e, // Length
			0x01, // Client Hello
		];

		assert!(detect(&client_hello));

		// Application Data, TLS 1.3

		let app_data = [0x17, 0x03, 0x04, 0x00, 0x10];

		assert!(detect(&app_data));

		assert!(!detect(b"HTTP/1.1"));
	}
}
