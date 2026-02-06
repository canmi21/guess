/* src/protocols/dns.rs */

#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	// Try UDP DNS first (12 bytes)
	if detect_udp(data) {
		return true;
	}

	// Try TCP DNS (14 bytes, first 2 bytes are length)
	if data.len() >= 14 {
		let length = u16::from_be_bytes([data[0], data[1]]) as usize;
		// The length prefix should be reasonable and consistent with data length
		if length > 0 && length <= 65535 && (length + 2 >= data.len() || data.len() >= 14) {
			return detect_udp(&data[2..]);
		}
	}

	false
}

#[inline(always)]
fn detect_udp(data: &[u8]) -> bool {
	if data.len() < 12 {
		return false;
	}

	// Byte 2-3 Flags
	// Byte 2: QR(1) Opcode(4) AA(1) TC(1) RD(1)
	// Opcode is bits 1-4 (0x78 mask shifted)
	let opcode = (data[2] >> 3) & 0x0F;
	if opcode > 5 {
		return false;
	}

	// Byte 3: RA(1) Z(3) RCODE(4)
	// Z bit (bits 1-3) should be 0 in most cases
	let z = (data[3] >> 4) & 0x07;
	if z != 0 {
		return false;
	}

	// Byte 4-5 QDCOUNT (1-20 is a reasonable range for a single packet)
	let qdcount = u16::from_be_bytes([data[4], data[5]]);
	if qdcount == 0 || qdcount > 20 {
		return false;
	}

	// Byte 6-11 ANCOUNT+NSCOUNT+ARCOUNT
	let ancount = u16::from_be_bytes([data[6], data[7]]);
	let nscount = u16::from_be_bytes([data[8], data[9]]);
	let arcount = u16::from_be_bytes([data[10], data[11]]);

	if ancount > 100 || nscount > 100 || arcount > 100 {
		return false;
	}

	true
}

#[cfg(test)]

mod tests {

	use super::*;

	#[test]

	fn test_detect_dns_udp() {
		let mut dns = [0u8; 12];

		dns[2] = 0x01; // Flags: Standard query

		dns[5] = 0x01; // QDCOUNT: 1

		assert!(detect(&dns));
	}

	#[test]

	fn test_detect_dns_tcp() {
		let mut dns = [0u8; 14];

		dns[1] = 12; // Length prefix

		dns[4] = 0x01; // Flags: Standard query

		dns[7] = 0x01; // QDCOUNT: 1

		assert!(detect(&dns));
	}
}
