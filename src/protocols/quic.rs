/* src/protocols/quic.rs */

#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 5 {
		return false;
	}

	// Byte 0: Header Form (bit 7)
	// Long Header: bit 7 = 1
	// Short Header: bit 7 = 0
	let first_byte = data[0];

	if (first_byte & 0x80) != 0 {
		// Long Header
		// Byte 1-4: Version
		let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

		// 0x00000001: Version 1
		// 0x00000002: Version 2
		// 0x6b3343cf: Draft version (example)
		if version == 1 || version == 2 || (version & 0xff000000) == 0x51000000 || version == 0x00000000
		{
			return true;
		}
	} else {
		// Short Header
		// Fixed bits for QUIC v1 (bit 6 must be 1, bit 5 must be 0)
		// This is less reliable for detection than Long Header
		if (first_byte & 0x40) != 0 && (first_byte & 0x20) == 0 {
			// This might be QUIC, but we usually expect a Long Header (Initial packet)
			// for the very first packet in a connection.
			return false;
		}
	}

	false
}
