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
	let qr_opcode_etc = header[2];
	let opcode = (qr_opcode_etc >> 3) & 0x0F;

	if !matches!(opcode, 0 | 1 | 2 | 4 | 5) {
		return false;
	}

	let ra_z_rcode = header[3];
	let z = (ra_z_rcode >> 6) & 0x01;

	if z != 0 {
		return false;
	}

	let qdcount = u16::from_be_bytes([header[4], header[5]]);
	let ancount = u16::from_be_bytes([header[6], header[7]]);
	let nscount = u16::from_be_bytes([header[8], header[9]]);
	let arcount = u16::from_be_bytes([header[10], header[11]]);

	let qr = (qr_opcode_etc >> 7) & 0x01;
	if qr == 0 {
		if qdcount == 0 || qdcount > 10 {
			return false;
		}
		if ancount > 0 || nscount > 0 {
			return false;
		}
		if arcount > 5 {
			return false;
		}
	} else if qdcount > 10 || ancount > 200 || nscount > 100 || arcount > 100 {
		return false;
	}

	(qdcount as u32 + ancount as u32 + nscount as u32 + arcount as u32) != 0
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_dns_udp_query() {
		let data = [
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
	fn test_detect_dns_tcp_query() {
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
			0x81, 0x80, // Flags
			0x00, 0x01, // QDCOUNT
			0x00, 0x01, // ANCOUNT
			0x00, 0x00, // NSCOUNT
			0x00, 0x00, // ARCOUNT
		];
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_invalid_opcode() {
		let mut data = [0u8; 12];
		data[2] = 0x30;
		data[5] = 0x01;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_nonzero_z() {
		let mut data = [0u8; 12];
		data[2] = 0x01;
		data[3] = 0x40; // actual Z bit (bit 6)
		data[5] = 0x01;
		assert!(!detect(&data));
	}

	#[test]
	fn test_accept_dnssec_ad_flag() {
		// AD bit set (bit 5 of byte 3) — common in DNSSEC responses
		let mut data = [0u8; 13];
		data[2] = 0x81; // QR=1, RD=1
		data[3] = 0x20; // AD=1
		data[5] = 0x01; // QDCOUNT=1
		data[7] = 0x01; // ANCOUNT=1
		data[12] = 0x00; // root label
		assert!(detect(&data));
	}

	#[test]
	fn test_accept_dnssec_cd_flag() {
		// CD bit set (bit 4 of byte 3) — Checking Disabled
		let mut data = [0u8; 13];
		data[2] = 0x01; // RD=1
		data[3] = 0x10; // CD=1
		data[5] = 0x01; // QDCOUNT=1
		data[12] = 0x00; // root label
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_suspicious_counts_query() {
		let mut data = [0u8; 12];
		data[2] = 0x01;
		data[5] = 0x01;
		data[7] = 0x01;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_invalid_label_length() {
		let data = [
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
		];
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_zero_counts() {
		let data = [0u8; 12];
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
		let data = [
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		];
		assert!(detect(&data));
	}
}
