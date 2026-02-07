/* src/protocols/ftp.rs */

/// Detects FTP protocol (File Transfer Protocol).
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 5 {
		return false;
	}

	if data.starts_with(b"220 ") || data.starts_with(b"220-") {
		return validate_line(data);
	}

	if is_command(data, b"USER")
		|| is_command(data, b"PASS")
		|| is_command(data, b"AUTH")
		|| is_command(data, b"SYST")
		|| is_command(data, b"FEAT")
		|| is_command(data, b"QUIT")
		|| is_command(data, b"PASV")
		|| is_command(data, b"EPSV")
		|| is_command(data, b"TYPE")
		|| is_command(data, b"PWD")
	{
		return validate_line(data);
	}

	false
}

/// Checks if the data starts with a specific command followed by a separator.
#[inline(always)]
fn is_command(data: &[u8], cmd: &[u8]) -> bool {
	if !data.starts_with(cmd) {
		return false;
	}
	let len = cmd.len();
	if data.len() == len {
		return true;
	}
	let next = data[len];
	next == b' ' || next == b'\r' || next == b'\n'
}

/// Validates that the data looks like a printable ASCII line.
#[inline(always)]
fn validate_line(data: &[u8]) -> bool {
	let limit = data.len().min(64);
	let mut found_newline = false;

	for &b in &data[..limit] {
		if b == b'\n' {
			found_newline = true;
			break;
		}
		if b != b'\r' && b != b'\t' && !(32..=126).contains(&b) {
			return false;
		}
	}

	found_newline || data.len() >= 16
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_ftp_greeting() {
		assert!(detect(b"220 Service ready for new user.\r\n"));
		assert!(detect(b"220-FileZilla Server\r\n220 Please log in.\r\n"));
		assert!(detect(b"220 Welcome to FTP service.\n"));
	}

	#[test]
	fn test_detect_ftp_client_commands() {
		assert!(detect(b"USER anonymous\r\n"));
		assert!(detect(b"PASS guest\r\n"));
		assert!(detect(b"SYST\r\n"));
		assert!(detect(b"FEAT\r\n"));
		assert!(detect(b"QUIT\n"));
		assert!(detect(b"AUTH TLS\r\n"));
	}

	#[test]
	fn test_detect_ftp_partial() {
		assert!(detect(
			b"220 Welcome to the very long greeting of an FTP server"
		));
		assert!(detect(b"USER some-long-username-that-is-partial"));
	}

	#[test]
	fn test_reject_wrong_prefix() {
		assert!(!detect(b"550 Permission denied\r\n"));
		assert!(!detect(b"HTTP/1.1 200 OK\r\n"));
	}

	#[test]
	fn test_reject_non_ascii() {
		let mut data = [0u8; 10];
		data[..4].copy_from_slice(b"220 ");
		data[4..10].copy_from_slice(&[0xFF, 0x00, 0x12, 0x34, 0x56, 0x78]);
		assert!(!detect(&data));
	}

	#[test]
	fn test_short_data() {
		assert!(!detect(b"220"));
		assert!(!detect(b"USER"));
	}
}
