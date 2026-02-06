/* src/protocols/smtp.rs */

/// Detects SMTP protocol (Simple Mail Transfer Protocol).
///
/// SMTP communication typically starts with a server greeting (220)
/// or client initiation commands (EHLO/HELO/MAIL FROM).
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	// Minimum length for a basic greeting or command: "220 \n" (5 bytes)
	if data.len() < 5 {
		return false;
	}

	// 1. Detect Server Greeting (220)
	// Format: "220 <domain> [Service ready/ESMTP] \r\n"
	if data.starts_with(b"220 ") || data.starts_with(b"220-") {
		return validate_line(data);
	}

	// 2. Detect Client Commands
	// We check for common SMTP commands that appear at the start of a session
	// or in a command pipeline.
	if is_command(data, b"EHLO")
		|| is_command(data, b"HELO")
		|| data.starts_with(b"MAIL FROM:")
		|| data.starts_with(b"RCPT TO:")
		|| is_command(data, b"DATA")
		|| is_command(data, b"QUIT")
		|| is_command(data, b"STARTTLS")
		|| is_command(data, b"VRFY")
		|| is_command(data, b"EXPN")
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
	// Command must be followed by a space, CR, or LF.
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
		if b != b'\r' && b != b'\t' && (b < 32 || b > 126) {
			return false;
		}
	}

	found_newline || data.len() >= 16
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_smtp_greeting() {
		assert!(detect(b"220 smtp.example.com ESMTP Postfix\r\n"));
		assert!(detect(b"220-smtp.example.com ESMTP Postfix\r\n"));
	}

	#[test]
	fn test_detect_smtp_core_commands() {
		assert!(detect(b"EHLO client.example.com\r\n"));
		assert!(detect(b"HELO localhost\n"));
		assert!(detect(b"MAIL FROM:<user@example.com>\r\n"));
	}

	#[test]
	fn test_detect_smtp_extended_commands() {
		assert!(detect(b"RCPT TO:<admin@example.com>\r\n"));
		assert!(detect(b"DATA\r\n"));
		assert!(detect(b"QUIT\n"));
		assert!(detect(b"STARTTLS\r\n"));
		assert!(detect(b"VRFY user\r\n"));
	}

	#[test]
	fn test_detect_smtp_partial() {
		assert!(detect(b"220 smtp.gmail.com ESMTP"));
		assert!(detect(b"EHLO some-long-domain-name"));
	}

	#[test]
	fn test_reject_wrong_prefix() {
		assert!(!detect(b"550 Access denied\r\n"));
		assert!(!detect(b"DATABASE connection\r\n")); // Starts with DATA but not followed by separator
	}

	#[test]
	fn test_reject_non_ascii() {
		let mut data = [0u8; 10];
		data[..4].copy_from_slice(b"220 ");
		data[4..].copy_from_slice(&[0xFF, 0x00, 0x12, 0x34, 0x56, 0x78]);
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_binary_protocols() {
		assert!(!detect(&[0x16, 0x03, 0x01, 0x00, 0x05]));
		assert!(!detect(b"+OK\r\n"));
	}

	#[test]
	fn test_short_data() {
		assert!(!detect(b"220"));
		assert!(!detect(b"EHLO"));
	}
}
