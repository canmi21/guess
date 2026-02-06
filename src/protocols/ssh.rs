/* src/protocols/ssh.rs */

/// Detects SSH protocol (Secure Shell).
///
/// SSH starts with an identification string: "SSH-protoversion-softwareversion [SP comments] CR LF".
/// Example: "SSH-2.0-OpenSSH_8.9p1\r\n"
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	// Minimum possible identification string: "SSH-2.0-x\n" (10 bytes)
	// But we allow detection from "SSH-" (4 bytes) if that's all we have.
	if data.len() < 4 || !data.starts_with(b"SSH-") {
		return false;
	}

	// If we have at least 8 bytes, we can check for standard version prefixes.
	if data.len() >= 8 {
		let is_v2 = data.starts_with(b"SSH-2.0-") || data.starts_with(b"SSH-1.99-");
		let is_v1 = data.starts_with(b"SSH-1.5-");

		if !is_v2 && !is_v1 {
			return false;
		}

		// Validation: The identification string must consist of printable US-ASCII
		// characters (32-126) and be terminated by CR LF or just LF.
		// We check up to the first 64 bytes.
		let limit = data.len().min(64);
		let mut found_terminator = false;

		for &b in &data[4..limit] {
			if b == b'\n' {
				found_terminator = true;
				break;
			}
			// Allow CR, but otherwise must be printable ASCII.
			if b != b'\r' && (b < 32 || b > 126) {
				return false;
			}
		}

		// If we are at the end of the 64-byte window and haven't found \n,
		// but all characters were valid ASCII, we still accept it as a partial match.
		if !found_terminator && data.len() < 64 {
			// If the packet is shorter than 64 bytes and has no \n, it might be
			// incomplete or not a valid SSH string. However, for protocol detection
			// on first bytes, a valid prefix is often enough.
			// We'll be slightly lenient here to allow fragmented identification strings.
		}
	} else {
		// data.len() is 4..7 and starts with "SSH-".
		// We could check if the 5th byte (if present) is '1' or '2'.
		if data.len() >= 5 && data[4] != b'1' && data[4] != b'2' {
			return false;
		}
	}

	true
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_ssh_openssh() {
		assert!(detect(b"SSH-2.0-OpenSSH_8.9p1\r\n"));
		assert!(detect(b"SSH-2.0-OpenSSH_7.4\n"));
	}

	#[test]
	fn test_detect_ssh_versions() {
		assert!(detect(b"SSH-1.99-Standard\r\n"));
		assert!(detect(b"SSH-1.5-Legacy\n"));
	}

	#[test]
	fn test_detect_ssh_partial() {
		assert!(detect(b"SSH-2.0-"));
		assert!(detect(b"SSH-"));
	}

	#[test]
	fn test_reject_invalid_prefix() {
		assert!(!detect(b"SSHH-2.0"));
		assert!(!detect(b"GET / SSH-2.0"));
	}

	#[test]
	fn test_reject_invalid_version() {
		// Not a standard SSH version
		assert!(!detect(b"SSH-3.0-Unknown\n"));
		assert!(!detect(b"SSH-2.1-Unknown\n"));
	}

	#[test]
	fn test_reject_non_ascii() {
		// Random binary data starting with SSH-2.0-
		let data = *b"SSH-2.0-";
		let mut full_data = [0u8; 12];
		full_data[..8].copy_from_slice(&data);
		full_data[8..].copy_from_slice(&[0xFF, 0x00, 0x12, 0x34]);
		assert!(!detect(&full_data));
	}

	#[test]
	fn test_reject_binary_protocols() {
		// TLS record
		assert!(!detect(&[0x16, 0x03, 0x01, 0x00, 0xA5]));
		// MySQL
		assert!(!detect(&[0x4A, 0x00, 0x00, 0x00, 0x0A]));
	}

	#[test]
	fn test_long_identification_string() {
		// A very long identification string should still be detected
		let mut long_ssh =
			b"SSH-2.0-VeryLongSoftwareNameThatExceedsNormalLimitsButIsStillValidASCII".to_vec();
		long_ssh.push(b'\n');
		assert!(detect(&long_ssh));
	}

	#[test]
	fn test_short_data() {
		assert!(!detect(b"SSH"));
		assert!(!detect(b""));
	}
}
