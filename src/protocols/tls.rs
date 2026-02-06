/* src/protocols/tls.rs */

#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 5 {
		return false;
	}

	// SSLv2 ClientHello uses a different record format with the high bit set.
	if data[0] & 0x80 != 0 {
		return detect_sslv2(data);
	}

	detect_tls_record(data)
}

/// Detects TLS/SSLv3+ record layer.
///
/// Record format: ContentType(1) + Version(2) + Length(2) + Payload(...)
#[inline(always)]
fn detect_tls_record(data: &[u8]) -> bool {
	let content_type = data[0];

	// ContentType: 0x14(CCS), 0x15(alert), 0x16(handshake), 0x17(app_data)
	// Excludes 0x18(heartbeat) and 0x19(tls12_cid): extremely rare as first
	// record on a connection, and accepting them widens the false positive window.
	if !(0x14..=0x17).contains(&content_type) {
		return false;
	}

	// Version major byte must be 0x03 (covers SSLv3 through TLS 1.3).
	if data[1] != 0x03 {
		return false;
	}

	// Version minor: 0x00(SSLv3) through 0x04.
	// TLS 1.3 uses 0x0301 or 0x0303 in the record layer, but 0x0304 is
	// allowed by the spec for middlebox compatibility negotiation.
	if data[2] > 0x04 {
		return false;
	}

	// Record length: 1 to 16384 (2^14) per RFC 8446 Section 5.1.
	let record_length = u16::from_be_bytes([data[3], data[4]]);
	if record_length == 0 || record_length > 16384 {
		return false;
	}

	match content_type {
		0x16 => validate_handshake(data, record_length),
		0x14 => record_length == 1,
		0x15 => record_length == 2,
		_ => true, // 0x17 app_data is encrypted, no structure to validate
	}
}

/// Validates a handshake record's type and internal length consistency.
#[inline(always)]
fn validate_handshake(data: &[u8], record_length: u16) -> bool {
	// Handshake header is 4 bytes: type(1) + length(3).
	if record_length < 4 {
		return false;
	}

	// If we lack the handshake type byte, accept on record header alone.
	if data.len() < 6 {
		return true;
	}

	let hs_type = data[5];
	if !is_valid_handshake_type(hs_type) {
		return false;
	}

	// Cross-validate handshake body length when we have the full 4-byte header.
	if data.len() >= 9 {
		let hs_body_len = u32::from_be_bytes([0, data[6], data[7], data[8]]);

		match hs_type {
			0x01 | 0x02 => {
				// client_hello and server_hello need at least 34 bytes (2 version + 32 random).
				if hs_body_len < 34 {
					return false;
				}
				// The internal version (at the start of the body) should also be 0x03xx.
				if data.len() >= 10 && data[9] != 0x03 {
					return false;
				}
			}
			0x0b => {
				// certificate: needs at least 3 bytes for the certificates list length.
				if hs_body_len < 3 {
					return false;
				}
			}
			0x00 | 0x0e => {
				// hello_request and server_hello_done always have empty bodies.
				if hs_body_len != 0 {
					return false;
				}
			}
			_ => {}
		}
	}

	true
}

/// Returns `true` for IANA-registered TLS handshake type values.
#[inline(always)]
fn is_valid_handshake_type(ht: u8) -> bool {
	matches!(
		ht,
		0x00 // hello_request
		| 0x01 // client_hello
		| 0x02 // server_hello
		| 0x04 // new_session_ticket
		| 0x05 // end_of_early_data
		| 0x06 // hello_retry_request
		| 0x08 // encrypted_extensions
		| 0x0b // certificate
		| 0x0c // server_key_exchange
		| 0x0d // certificate_request
		| 0x0e // server_hello_done
		| 0x0f // certificate_verify
		| 0x10 // client_key_exchange
		| 0x14 // finished
		| 0x18 // key_update
		| 0x19 // compressed_certificate
		| 0xfe // message_hash
	)
}

/// Detects SSLv2 ClientHello (legacy, 2-byte header format).
///
/// Format: `(length_hi | 0x80)(length_lo)` + `msg_type(1)` + `version(2)`
///         + `cipher_spec_len(2)` + `session_id_len(2)` + `challenge_len(2)`
#[inline(always)]
fn detect_sslv2(data: &[u8]) -> bool {
	// Need 11 bytes: 2 header + 1 type + 2 version + 6 length fields.
	if data.len() < 11 {
		return false;
	}

	// Must be CLIENT-HELLO (0x01).
	if data[2] != 0x01 {
		return false;
	}

	// Version: SSLv2 (0x0002) or SSLv3+/TLS compat (0x0300-0x0304).
	let valid_version = (data[3] == 0x00 && data[4] == 0x02) || (data[3] == 0x03 && data[4] <= 0x04);
	if !valid_version {
		return false;
	}

	// Record length (2-byte header, high bit already confirmed set).
	let record_length = (u16::from(data[0] & 0x7F) << 8) | u16::from(data[1]);
	// Minimum: msg_type(1) + version(2) + 3 length fields(6) = 9.
	if record_length < 9 {
		return false;
	}

	// SSLv2 cipher specs are 3 bytes each, so length must be a positive multiple of 3.
	let cipher_spec_len = u16::from_be_bytes([data[5], data[6]]);
	if cipher_spec_len == 0 || cipher_spec_len % 3 != 0 {
		return false;
	}

	// Challenge must be present.
	let session_id_len = u16::from_be_bytes([data[7], data[8]]);
	let challenge_len = u16::from_be_bytes([data[9], data[10]]);
	if challenge_len == 0 {
		return false;
	}

	// Cross-validate: variable-length fields must exactly fill the record body.
	// record_length = 9 (fixed fields) + cipher_specs + session_id + challenge
	let body_total =
		u32::from(cipher_spec_len) + u32::from(session_id_len) + u32::from(challenge_len);
	if body_total != u32::from(record_length) - 9 {
		return false;
	}

	true
}

#[cfg(test)]
mod tests {
	use super::*;

	// Handshake Detection

	#[test]
	fn test_tls10_client_hello() {
		let data = [
			0x16, 0x03, 0x01, // handshake, TLS 1.0
			0x00, 0x5C, // record length 92
			0x01, // client_hello
			0x00, 0x00, 0x58, // hs body length 88
			0x03, 0x01, // client version TLS 1.0
		];
		assert!(detect(&data));
	}

	#[test]
	fn test_tls11_client_hello() {
		let data = [
			0x16, 0x03, 0x02, // handshake, TLS 1.1
			0x00, 0x5C, // record length 92
			0x01, // client_hello
			0x00, 0x00, 0x58, // hs body length 88
			0x03, 0x02, // client version TLS 1.1
		];
		assert!(detect(&data));
	}

	#[test]
	fn test_tls12_client_hello() {
		let data = [
			0x16, 0x03, 0x01, // handshake, TLS 1.0 (common record version for 1.2)
			0x00, 0xF1, // record length 241
			0x01, // client_hello
			0x00, 0x00, 0xED, // hs body length 237
			0x03, 0x03, // client version TLS 1.2
		];
		assert!(detect(&data));
	}

	#[test]
	fn test_tls13_client_hello() {
		// TLS 1.3 uses 0x0301 in the record layer; actual version is in extensions.
		let data = [
			0x16, 0x03, 0x01, // handshake, TLS 1.0 record version
			0x02, 0x00, // record length 512
			0x01, // client_hello
			0x00, 0x01, 0xFC, // hs body length 508
			0x03, 0x03, // legacy client version TLS 1.2
		];
		assert!(detect(&data));
	}

	#[test]
	fn test_sslv3_client_hello() {
		let data = [
			0x16, 0x03, 0x00, // handshake, SSLv3
			0x00, 0x41, // record length 65
			0x01, // client_hello
			0x00, 0x00, 0x3D, // hs body length 61
			0x03, 0x00, // client version SSLv3
		];
		assert!(detect(&data));
	}

	#[test]
	fn test_server_hello() {
		let data = [
			0x16, 0x03, 0x03, // handshake, TLS 1.2
			0x00, 0x31, // record length 49
			0x02, // server_hello
			0x00, 0x00, 0x2D, // hs body length 45
			0x03, 0x03, // server version TLS 1.2
		];
		assert!(detect(&data));
	}

	#[test]
	fn test_other_handshake_types() {
		// certificate (0x0b)
		let cert = [0x16, 0x03, 0x03, 0x0B, 0xB8, 0x0b, 0x00, 0x0B, 0xB4];
		assert!(detect(&cert));

		// server_key_exchange (0x0c)
		let ske = [0x16, 0x03, 0x03, 0x01, 0x4D, 0x0c, 0x00, 0x01, 0x49];
		assert!(detect(&ske));

		// server_hello_done (0x0e) — empty body
		let shd = [0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00];
		assert!(detect(&shd));

		// finished (0x14)
		let fin = [0x16, 0x03, 0x03, 0x00, 0x10, 0x14, 0x00, 0x00, 0x0C];
		assert!(detect(&fin));

		// key_update (0x18)
		let ku = [0x16, 0x03, 0x03, 0x00, 0x05, 0x18, 0x00, 0x00, 0x01];
		assert!(detect(&ku));

		// hello_request (0x00) — empty body
		let hr = [0x16, 0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
		assert!(detect(&hr));
	}

	#[test]
	fn test_reject_invalid_handshake_internal_version() {
		// ClientHello (0x01) but internal version is 0x0400 instead of 0x03xx
		let data = [
			0x16, 0x03, 0x01, // handshake, TLS 1.0
			0x00, 0x5C, // record length 92
			0x01, // client_hello
			0x00, 0x00, 0x58, // hs body length 88
			0x04, 0x00, // INVALID internal version
		];
		assert!(!detect(&data));

		// ServerHello (0x02) but internal version is 0x0200
		let data2 = [
			0x16, 0x03, 0x01, 0x00, 0x5C, 0x02, // server_hello
			0x00, 0x00, 0x58, 0x02, 0x00, // INVALID internal version
		];
		assert!(!detect(&data2));
	}

	#[test]
	fn test_reject_invalid_certificate_length() {
		// certificate (0x0b) with body length 2 (should be at least 3)
		let data = [0x16, 0x03, 0x03, 0x00, 0x06, 0x0b, 0x00, 0x00, 0x02];
		assert!(!detect(&data));
	}

	#[test]
	fn test_accept_valid_certificate_empty() {
		// certificate (0x0b) with body length 3 (empty list)
		let data = [
			0x16, 0x03, 0x03, 0x00, 0x07, 0x0b, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
		];
		assert!(detect(&data));
	}

	// Other Content Types

	#[test]
	fn test_change_cipher_spec() {
		let data = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
		assert!(detect(&data));
	}

	#[test]
	fn test_alert() {
		// fatal handshake_failure
		let data = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
		assert!(detect(&data));
		// warning close_notify
		let warn = [0x15, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00];
		assert!(detect(&warn));
	}

	#[test]
	fn test_application_data() {
		let data = [0x17, 0x03, 0x03, 0x00, 0x20];
		assert!(detect(&data));
		// TLS 1.3 record layer version (0x0303) with app data
		let tls13 = [0x17, 0x03, 0x03, 0x01, 0x00];
		assert!(detect(&tls13));
	}

	// SSLv2 Detection

	#[test]
	fn test_sslv2_client_hello_tls_compat() {
		// cipher_spec_len=6, session_id_len=0, challenge_len=16
		// record_length = 9 + 6 + 0 + 16 = 31
		let mut data = [0u8; 33];
		data[0] = 0x80; // high bit + length MSB
		data[1] = 0x1F; // length LSB = 31
		data[2] = 0x01; // CLIENT-HELLO
		data[3] = 0x03; // version major (TLS)
		data[4] = 0x01; // version minor (1.0)
		data[5] = 0x00;
		data[6] = 0x06; // cipher_spec_len = 6
		data[7] = 0x00;
		data[8] = 0x00; // session_id_len = 0
		data[9] = 0x00;
		data[10] = 0x10; // challenge_len = 16
		assert!(detect(&data));
	}

	#[test]
	fn test_sslv2_client_hello_pure() {
		// Pure SSLv2: version 0x0002
		// cipher_spec_len=3, session_id_len=0, challenge_len=16
		// record_length = 9 + 3 + 0 + 16 = 28
		let mut data = [0u8; 30];
		data[0] = 0x80;
		data[1] = 0x1C; // length 28
		data[2] = 0x01; // CLIENT-HELLO
		data[3] = 0x00;
		data[4] = 0x02; // SSLv2
		data[5] = 0x00;
		data[6] = 0x03; // cipher_spec_len = 3
		data[7] = 0x00;
		data[8] = 0x00; // session_id_len = 0
		data[9] = 0x00;
		data[10] = 0x10; // challenge_len = 16
		assert!(detect(&data));
	}

	// Version Acceptance

	#[test]
	fn test_all_valid_versions() {
		for minor in 0x00..=0x04 {
			let data = [0x17, 0x03, minor, 0x00, 0x10];
			assert!(detect(&data), "version 0x03{minor:02X} should be accepted");
		}
	}

	// Minimum Data

	#[test]
	fn test_minimum_5_bytes() {
		// Exactly 5 bytes (record header only)
		assert!(detect(&[0x17, 0x03, 0x03, 0x00, 0x10]));
		// Handshake with only record header: record_length >= 4
		assert!(detect(&[0x16, 0x03, 0x03, 0x00, 0x28]));
	}

	#[test]
	fn test_handshake_6_bytes_valid_type() {
		// 6 bytes: record header + handshake type, but no body length
		assert!(detect(&[0x16, 0x03, 0x03, 0x00, 0x28, 0x01]));
	}

	// False Positive Prevention: Invalid Records

	#[test]
	fn test_reject_short_data() {
		assert!(!detect(&[]));
		assert!(!detect(&[0x16]));
		assert!(!detect(&[0x16, 0x03]));
		assert!(!detect(&[0x16, 0x03, 0x03]));
		assert!(!detect(&[0x16, 0x03, 0x03, 0x00]));
	}

	#[test]
	fn test_reject_invalid_content_type() {
		assert!(!detect(&[0x13, 0x03, 0x03, 0x00, 0x10]));
		assert!(!detect(&[0x18, 0x03, 0x03, 0x00, 0x03])); // heartbeat
		assert!(!detect(&[0x19, 0x03, 0x03, 0x00, 0x10])); // tls12_cid
		assert!(!detect(&[0x00, 0x03, 0x03, 0x00, 0x10]));
		assert!(!detect(&[0xFF, 0x03, 0x03, 0x00, 0x10]));
	}

	#[test]
	fn test_reject_invalid_version() {
		// Major byte not 0x03
		assert!(!detect(&[
			0x16, 0x02, 0x00, 0x00, 0x28, 0x01, 0x00, 0x00, 0x24
		]));
		assert!(!detect(&[
			0x16, 0x04, 0x00, 0x00, 0x28, 0x01, 0x00, 0x00, 0x24
		]));
		assert!(!detect(&[
			0x16, 0x00, 0x03, 0x00, 0x28, 0x01, 0x00, 0x00, 0x24
		]));
		// Minor byte too high
		assert!(!detect(&[
			0x16, 0x03, 0x05, 0x00, 0x28, 0x01, 0x00, 0x00, 0x24
		]));
		assert!(!detect(&[
			0x16, 0x03, 0xFF, 0x00, 0x28, 0x01, 0x00, 0x00, 0x24
		]));
	}

	#[test]
	fn test_reject_invalid_length() {
		// Zero length
		assert!(!detect(&[0x16, 0x03, 0x03, 0x00, 0x00]));
		// Length > 16384 (0x4001)
		assert!(!detect(&[0x16, 0x03, 0x03, 0x40, 0x01]));
		assert!(!detect(&[0x16, 0x03, 0x03, 0xFF, 0xFF]));
	}

	#[test]
	fn test_reject_invalid_handshake_type() {
		// Unregistered handshake type 0x03
		assert!(!detect(&[
			0x16, 0x03, 0x03, 0x00, 0x28, 0x03, 0x00, 0x00, 0x24
		]));
		// 0x07 is not registered
		assert!(!detect(&[
			0x16, 0x03, 0x03, 0x00, 0x28, 0x07, 0x00, 0x00, 0x24
		]));
		// 0xFF is not registered
		assert!(!detect(&[
			0x16, 0x03, 0x03, 0x00, 0x28, 0xFF, 0x00, 0x00, 0x24
		]));
	}

	#[test]
	fn test_reject_handshake_length_mismatch() {
		// ClientHello with body length < 34
		assert!(!detect(&[
			0x16, 0x03, 0x03, 0x00, 0x07, 0x01, 0x00, 0x00, 0x03
		]));
		// ServerHello with body length < 34
		assert!(!detect(&[
			0x16, 0x03, 0x03, 0x00, 0x07, 0x02, 0x00, 0x00, 0x03
		]));
		// hello_request with non-zero body
		assert!(!detect(&[
			0x16, 0x03, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01
		]));
		// server_hello_done with non-zero body
		assert!(!detect(&[
			0x16, 0x03, 0x03, 0x00, 0x05, 0x0e, 0x00, 0x00, 0x01
		]));
	}

	#[test]
	fn test_reject_handshake_record_too_short() {
		// record_length < 4 (can't hold handshake header)
		assert!(!detect(&[0x16, 0x03, 0x03, 0x00, 0x03, 0x01, 0x00, 0x00]));
		assert!(!detect(&[0x16, 0x03, 0x03, 0x00, 0x01]));
	}

	#[test]
	fn test_reject_ccs_wrong_length() {
		assert!(!detect(&[0x14, 0x03, 0x03, 0x00, 0x02]));
		assert!(!detect(&[0x14, 0x03, 0x03, 0x00, 0x00]));
		assert!(!detect(&[0x14, 0x03, 0x03, 0x01, 0x00]));
	}

	#[test]
	fn test_reject_alert_wrong_length() {
		assert!(!detect(&[0x15, 0x03, 0x03, 0x00, 0x01]));
		assert!(!detect(&[0x15, 0x03, 0x03, 0x00, 0x03]));
		assert!(!detect(&[0x15, 0x03, 0x03, 0x00, 0x00]));
	}

	// False Positive Prevention: Other Protocols

	#[test]
	fn test_reject_text_protocols() {
		assert!(!detect(b"GET / HTTP/1.1\r\n"));
		assert!(!detect(b"HTTP/1.1 200 OK\r\n"));
		assert!(!detect(b"SSH-2.0-OpenSSH\r\n"));
		assert!(!detect(b"HELO smtp.example.com\r\n"));
		assert!(!detect(b"*3\r\n$3\r\nSET\r\n"));
	}

	#[test]
	fn test_reject_binary_protocols() {
		// MySQL: packet_len(3 LE) + seq(0) + protocol(10)
		assert!(!detect(&[0x4A, 0x00, 0x00, 0x00, 0x0A]));
		// PostgreSQL: length(4 BE) + version 3.0
		assert!(!detect(&[0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00]));
		// MQTT CONNECT
		assert!(!detect(&[0x10, 0x1A, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54]));
	}

	#[test]
	fn test_reject_quic_initial() {
		// QUIC long header (high bit set) enters SSLv2 path but fails checks
		assert!(!detect(&[
			0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00
		]));
	}

	// False Positive Prevention: SSLv2 Edge Cases

	#[test]
	fn test_reject_sslv2_wrong_msg_type() {
		let mut data = [0u8; 11];
		data[0] = 0x80;
		data[1] = 0x1C;
		data[2] = 0x02; // SERVER-HELLO, not CLIENT-HELLO
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_sslv2_invalid_version() {
		let mut data = [0u8; 11];
		data[0] = 0x80;
		data[1] = 0x1C;
		data[2] = 0x01;
		data[3] = 0x04; // invalid major
		data[4] = 0x00;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_sslv2_cipher_spec_not_mod3() {
		let mut data = [0u8; 11];
		data[0] = 0x80;
		data[1] = 0x1C;
		data[2] = 0x01;
		data[3] = 0x03;
		data[4] = 0x01;
		data[5] = 0x00;
		data[6] = 0x04; // cipher_spec_len = 4, not divisible by 3
		data[9] = 0x00;
		data[10] = 0x10;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_sslv2_length_mismatch() {
		// cipher_spec=6 + session_id=0 + challenge=16 = 22, but record says 30 (9+21)
		let mut data = [0u8; 11];
		data[0] = 0x80;
		data[1] = 0x1E; // length 30
		data[2] = 0x01;
		data[3] = 0x03;
		data[4] = 0x01;
		data[5] = 0x00;
		data[6] = 0x06; // cipher_spec_len = 6
		data[7] = 0x00;
		data[8] = 0x00; // session_id_len = 0
		data[9] = 0x00;
		data[10] = 0x10; // challenge_len = 16
		// body = 6+0+16 = 22, record_length - 9 = 21. Mismatch.
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_sslv2_short_data() {
		// Only 10 bytes, need 11
		assert!(!detect(&[
			0x80, 0x1C, 0x01, 0x03, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00
		]));
	}

	// Edge Cases

	#[test]
	fn test_all_zeros() {
		assert!(!detect(&[0x00, 0x00, 0x00, 0x00, 0x00]));
		assert!(!detect(&[0x00; 64]));
	}

	#[test]
	fn test_all_ones() {
		assert!(!detect(&[0xFF; 5]));
		assert!(!detect(&[0xFF; 64]));
	}

	#[test]
	fn test_random_looking_collision() {
		// Bytes that satisfy content_type + version but fail on length=0
		assert!(!detect(&[0x16, 0x03, 0x03, 0x00, 0x00]));
		// Valid record header shape but handshake type 0x03 is unregistered
		assert!(!detect(&[0x16, 0x03, 0x03, 0x00, 0x10, 0x03]));
	}

	#[test]
	fn test_max_valid_record_length() {
		// 16384 = 0x4000 is the maximum valid record length
		assert!(detect(&[0x17, 0x03, 0x03, 0x40, 0x00]));
		// 16385 = 0x4001 exceeds maximum
		assert!(!detect(&[0x17, 0x03, 0x03, 0x40, 0x01]));
	}
}
