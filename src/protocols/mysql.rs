/* src/protocols/mysql.rs */

#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 5 {
		return false;
	}

	// Byte 0-2: Packet Length (little-endian)

	let length = u32::from_le_bytes([data[0], data[1], data[2], 0]);

	if !(10..=1024 * 1024).contains(&length) {
		// MySQL packets can be large, but for initial detection 10-1MB is reasonable

		return false;
	}

	// Byte 3: Packet Number (usually 0 for the first packet in a connection)
	if data[3] != 0 {
		return false;
	}

	// Byte 4: Protocol Version (usually 10 for MySQL 3.21.0+)
	if data[4] != 10 {
		return false;
	}

	true
}
