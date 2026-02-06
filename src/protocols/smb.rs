/* src/protocols/smb.rs */

/// Detects SMB protocol (Server Message Block).
///
/// Supports SMBv1 (\xffSMB) and SMBv2/v3 (\xfeSMB).
/// Also handles SMB over Direct TCP (port 445) which adds a 4-byte length prefix.
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	// Minimum 4 bytes for raw SMB magic.
	if data.len() < 4 {
		return false;
	}

	// 1. Detect Raw SMB magic at offset 0
	let magic = &data[0..4];
	if magic == b"\xffSMB" || magic == b"\xfeSMB" {
		return true;
	}

	// 2. Detect SMB over Direct TCP (RFC 1001/1002 style encapsulation)
	// Byte 0: 0x00 (Session Message)
	// Byte 1-3: Length (Big-Endian, 24 bits)
	// Byte 4-7: SMB Magic
	if data.len() >= 8 && data[0] == 0x00 {
		let len = u32::from_be_bytes([0, data[1], data[2], data[3]]);
		let inner_magic = &data[4..8];

		if inner_magic == b"\xffSMB" {
			// SMB1 header is exactly 32 bytes.
			return len >= 32;
		} else if inner_magic == b"\xfeSMB" {
			// SMB2/3 header is exactly 64 bytes.
			return len >= 64;
		}
	}

	false
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_raw_smbv1() {
		let mut data = [0u8; 64];
		data[0..4].copy_from_slice(b"\xffSMB");
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_raw_smbv2() {
		let mut data = [0u8; 64];
		data[0..4].copy_from_slice(b"\xfeSMB");
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_encapsulated_smbv2() {
		let mut data = [0u8; 64];
		data[0] = 0x00;
		data[3] = 64; // Declared length 64
		data[4..8].copy_from_slice(b"\xfeSMB");
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_encapsulated_smbv1() {
		let mut data = [0u8; 64];
		data[0] = 0x00;
		data[3] = 32; // Declared length 32
		data[4..8].copy_from_slice(b"\xffSMB");
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_encapsulated_smbv2_too_short() {
		let mut data = [0u8; 64];
		data[0] = 0x00;
		data[3] = 48; // Declared 48, but SMB2 needs 64
		data[4..8].copy_from_slice(b"\xfeSMB");
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_encapsulated_smbv1_too_short() {
		let mut data = [0u8; 64];
		data[0] = 0x00;
		data[3] = 20; // Declared 20, but SMB1 needs 32
		data[4..8].copy_from_slice(b"\xffSMB");
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_invalid_magic() {
		assert!(!detect(b"\xfdSMB"));
	}

	#[test]
	fn test_reject_random_data() {
		assert!(!detect(&[0x42; 64]));
	}
}
