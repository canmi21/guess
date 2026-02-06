/* src/protocols/dns.rs */

/// Detects DNS protocol (UDP or TCP).
///
/// For UDP, it expects the 12-byte DNS header at the start.
/// For TCP, it expects a 2-byte length prefix followed by the DNS header.
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	// Minimum UDP DNS packet is 12 bytes (header only).
	if data.len() < 12 {
		return false;
	}

	// 1. Try UDP DNS detection.
	if validate_dns_header(&data[..12]) {
		// Further validation: the first label in the question section (if any).
		if data.len() >= 13 {
			let qdcount = u16::from_be_bytes([data[4], data[5]]);
			if qdcount > 0 {
				let first_label_len = data[12];
				// Label length must be <= 63.
				if first_label_len > 63 {
					return false;
				}
			}
		}
		return true;
	}

	// 2. Try TCP DNS detection.
	// Minimum TCP DNS packet is 14 bytes (2 bytes length + 12 bytes header).
	if data.len() >= 14 {
		let tcp_len = u16::from_be_bytes([data[0], data[1]]);
		// A DNS message must be at least 12 bytes.
		// We also check if the header at offset 2 is valid.
		if tcp_len >= 12 && validate_dns_header(&data[2..14]) {
			// Further validation: first label check.
			if data.len() >= 15 {
				let qdcount = u16::from_be_bytes([data[6], data[7]]);
				if qdcount > 0 {
					let first_label_len = data[14];
					if first_label_len > 63 {
						return false;
					}
				}
			}
			return true;
		}
	}

	false
}

/// Validates a 12-byte DNS header.
#[inline(always)]
fn validate_dns_header(header: &[u8]) -> bool {
	// header is exactly 12 bytes.
	// Byte 2: QR(1) Opcode(4) AA(1) TC(1) RD(1)
	let qr_opcode_etc = header[2];
	let opcode = (qr_opcode_etc >> 3) & 0x0F;

	// Opcodes: 0 (Query), 1 (IQuery), 2 (Status), 4 (Notify), 5 (Update)
	if !matches!(opcode, 0 | 1 | 2 | 4 | 5) {
		return false;
	}

	// Byte 3: RA(1) Z(3) RCODE(4)
	let ra_z_rcode = header[3];
	let z = (ra_z_rcode >> 4) & 0x07;

	// The Z bits MUST be zero unless specific extensions are used that we might
	// not want to accept as "obvious" DNS if we are being strict.
	// However, some modern DNS use these for other purposes.
	// For high-confidence detection, we expect Z=0.
	if z != 0 {
		return false;
	}

	let qdcount = u16::from_be_bytes([header[4], header[5]]);
	let ancount = u16::from_be_bytes([header[6], header[7]]);
	let nscount = u16::from_be_bytes([header[8], header[9]]);
	let arcount = u16::from_be_bytes([header[10], header[11]]);

	// In a query (QR=0), ANCOUNT and NSCOUNT are usually 0.
	// ARCOUNT is often 0 or 1 (EDNS).
	let qr = (qr_opcode_etc >> 7) & 0x01;
	if qr == 0 {
		// Tighten rules for queries:
		// Most queries have 1 question.
		if qdcount == 0 || qdcount > 10 {
			return false;
		}
		// ANCOUNT and NSCOUNT should be 0 in a standard query.
		if ancount > 0 || nscount > 0 {
			return false;
		}
		// ARCOUNT can be > 0 (EDNS), but usually small.
		if arcount > 5 {
			return false;
		}
	} else {
		// In a response (QR=1):
		// ANCOUNT or RCODE might be non-zero.
		// If RCODE is 0 (NoError), we often expect ANCOUNT > 0, but not always (e.g. empty subdomains).
		if qdcount > 10 || ancount > 200 || nscount > 100 || arcount > 100 {
			return false;
		}
	}

	// Total sections should be reasonable for a DNS packet we might encounter in first bytes.
	if (qdcount as u32 + ancount as u32 + nscount as u32 + arcount as u32) == 0 {
		return false;
	}

	true
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_dns_udp_query() {
		// google.com A query
		let data = [
			0x12, 0x34, // ID
			0x01, 0x00, // Flags: Standard Query, RD
			0x00, 0x01, // QDCOUNT: 1
			0x00, 0x00, // ANCOUNT: 0
			0x00, 0x00, // NSCOUNT: 0
			0x00, 0x00, // ARCOUNT: 0
			0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
			0x01,
		];
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_dns_tcp_query() {
		// google.com A query with TCP prefix (0x001C = 28 bytes)
		let data = [
			0x00, 0x1C, // TCP Length
			0x12, 0x34, // ID
			0x01, 0x00, // Flags
			0x00, 0x01, // QDCOUNT
			0x00, 0x00, // ANCOUNT
			0x00, 0x00, // NSCOUNT
			0x00, 0x00, // ARCOUNT
			0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
			0x01,
		];
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_dns_response() {
		let data = [
			0x12, 0x34, // ID
			0x81, 0x80, // Flags: Response, Standard Query, RD, RA, NoError
			0x00, 0x01, // QDCOUNT: 1
			0x00, 0x01, // ANCOUNT: 1
			0x00, 0x00, // NSCOUNT: 0
			0x00, 0x00, // ARCOUNT: 0
		];
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_invalid_opcode() {
		let mut data = [0u8; 12];
		data[2] = 0x30; // Opcode 6 (Invalid)
		data[5] = 0x01; // QDCOUNT 1
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_nonzero_z() {
		let mut data = [0u8; 12];
		data[2] = 0x01; // Standard Query
		data[3] = 0x10; // Z=1 (Invalid for strict detection)
		data[5] = 0x01; // QDCOUNT 1
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_suspicious_counts_query() {
		let mut data = [0u8; 12];
		data[2] = 0x01; // Query
		data[5] = 0x01; // QDCOUNT 1
		data[7] = 0x01; // ANCOUNT 1 (Suspicious for query)
		assert!(!detect(&data));

		let mut data2 = [0u8; 12];
		data2[2] = 0x01;
		data2[5] = 0x0B; // QDCOUNT 11 (Too high)
		assert!(!detect(&data2));
	}

	#[test]
	fn test_reject_invalid_label_length() {
		let data = [
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x40, // Label length 64 (Invalid, max 63)
		];
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_zero_counts() {
		let data = [0u8; 12]; // All counts zero
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_http() {
		assert!(!detect(b"GET / HTTP/1.1\r\n"));
	}

	#[test]
	fn test_reject_tls() {
		let tls = [0x16, 0x03, 0x01, 0x00, 0xA5];
		assert!(!detect(&tls));
	}

	#[test]
	fn test_reject_ssh() {
		assert!(!detect(b"SSH-2.0-OpenSSH_8.9\r\n"));
	}

	#[test]
	fn test_minimum_valid_query() {
		// Root query
		let data = [
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, // Label length 0 (Root)
		];
		assert!(detect(&data));
	}
}
