/* src/protocols/postgres.rs */

#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 8 {
		return false;
	}

	// Byte 0-3: Length (big-endian)
	let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
	if !(8..=1024).contains(&length) {
		return false;
	}
	// Byte 4-7: Protocol version or Special code
	// 0x00030000: Protocol 3.0 (PostgreSQL 7.4+)
	// 0x04D2162F (80877103): SSLRequest
	// 0x04D21630 (80877104): GSSENCRequest
	let code = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

	code == 0x00030000 || code == 80877103 || code == 80877104
}
