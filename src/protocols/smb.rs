/* src/protocols/smb.rs */

/// Detects SMB protocol (Server Message Block).
///
/// Supports `SMBv1` (\xffSMB) and SMBv2/v3 (\xfeSMB).
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 4 {
		return false;
	}

	let magic = &data[0..4];
	if magic == b"\xffSMB" || magic == b"\xfeSMB" {
		return true;
	}

	if data.len() >= 8 && data[0] == 0x00 {
		let len = u32::from_be_bytes([0, data[1], data[2], data[3]]);
		let inner_magic = &data[4..8];

		if inner_magic == b"\xffSMB" {
			return len >= 32;
		} else if inner_magic == b"\xfeSMB" {
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
		data[3] = 64;
		data[4..8].copy_from_slice(b"\xfeSMB");
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_encapsulated_smbv1() {
		let mut data = [0u8; 64];
		data[0] = 0x00;
		data[3] = 32;
		data[4..8].copy_from_slice(b"\xffSMB");
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_encapsulated_smbv2_too_short() {
		let mut data = [0u8; 64];
		data[0] = 0x00;
		data[3] = 48;
		data[4..8].copy_from_slice(b"\xfeSMB");
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_encapsulated_smbv1_too_short() {
		let mut data = [0u8; 64];
		data[0] = 0x00;
		data[3] = 20;
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
