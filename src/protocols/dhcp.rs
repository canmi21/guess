/* src/protocols/dhcp.rs */

/// Detects DHCP protocol (UDP).
///
/// DHCP is based on BOOTP and uses a 240-byte header.
/// This function identifies DHCP by validating the fixed header fields
/// available within the first 64 bytes, and the magic cookie if available.
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	// Minimum 44 bytes to inspect up to the hardware address padding.
	if data.len() < 44 {
		return false;
	}

	// op: BOOTREQUEST (1) or BOOTREPLY (2)
	let op = data[0];
	if op != 1 && op != 2 {
		return false;
	}

	// htype (Hardware Type) and hlen (Hardware Address Length)
	// Most common is Ethernet (htype=1, hlen=6)
	let htype = data[1];
	let hlen = data[2];

	match htype {
		1 | 6 => {
			// Ethernet or IEEE 802
			if hlen != 6 {
				return false;
			}
			// For Ethernet, the 16-byte chaddr field (starting at offset 28)
			// uses only the first 6 bytes. The remaining 10 bytes should be zeroed
			// in standard implementations.
			for &byte in &data[34..44] {
				if byte != 0 {
					return false;
				}
			}
		}
		// Other types are rare; we validate hlen is within reasonable bounds (1-16)
		_ => {
			if hlen == 0 || hlen > 16 {
				return false;
			}
		}
	}

	// hops: usually 0, should not exceed 16 per RFC 2131
	if data[3] > 16 {
		return false;
	}

	// flags: 16-bit field. Only the most significant bit (Broadcast) is defined.
	// The rest MUST be zero (MBZ).
	// flags are at offset 10 and 11.
	// [B][MBZ...7bits] [MBZ...8bits]
	if (data[10] & 0x7F) != 0 || data[11] != 0 {
		return false;
	}

	// If we have enough data to see the magic cookie at offset 236, check it.
	// Magic cookie: 0x63 0x82 0x53 0x63
	if data.len() >= 240 {
		return data[236..240] == [0x63, 0x82, 0x53, 0x63];
	}

	// Since we often only have 64 bytes, we rely on the header consistency above.
	// A DHCP packet header is very structured compared to random data.
	true
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_dhcp_discover() {
		let mut data = [0u8; 64];
		data[0] = 1; // op: request
		data[1] = 1; // htype: ethernet
		data[2] = 6; // hlen: 6
		data[28..34].copy_from_slice(&[0x00, 0x0c, 0x29, 0x3e, 0x53, 0x07]); // chaddr
		// data[34..44] remains 0
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_dhcp_offer() {
		let mut data = [0u8; 240];
		data[0] = 2; // op: reply
		data[1] = 1; // htype: ethernet
		data[2] = 6; // hlen: 6
		data[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]); // magic cookie
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_invalid_op() {
		let data = [
			3u8, 1, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		];
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_invalid_hlen() {
		let data = [
			1u8, 1, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		];
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_invalid_flags() {
		let mut data = [0u8; 64];
		data[0] = 1;
		data[1] = 1;
		data[2] = 6;
		data[11] = 1; // MBZ low byte set
		assert!(!detect(&data));

		let mut data2 = [0u8; 64];
		data2[0] = 1;
		data2[1] = 1;
		data2[2] = 6;
		data2[10] = 0x01; // MBZ high byte bit set
		assert!(!detect(&data2));
	}

	#[test]
	fn test_reject_bad_chaddr_padding() {
		let mut data = [0u8; 64];
		data[0] = 1;
		data[1] = 1;
		data[2] = 6;
		data[34] = 1; // padding byte in chaddr should be 0 for Ethernet
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_mismatched_magic_cookie() {
		let mut data = [0u8; 240];
		data[0] = 1;
		data[1] = 1;
		data[2] = 6;
		data[236..240].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]); // wrong cookie
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_random_data() {
		assert!(!detect(&[0x42; 64]));
	}

	#[test]
	fn test_short_data() {
		assert!(!detect(&[0u8; 10]));
	}
}
