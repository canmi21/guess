/* src/protocols/pop3.rs */

/// Detects POP3 protocol (Post Office Protocol version 3).
///
/// POP3 typically starts with a server greeting: "+OK POP3 server ready <timestamp>\r\n".
/// Client commands like USER, PASS, STAT also follow a predictable ASCII pattern.
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	// Minimum length for a basic greeting: "+OK \n" (5 bytes)
	if data.len() < 5 {
		return false;
	}

	// 1. Detect Server Response
	// POP3 server greetings and positive responses MUST start with "+OK ".
	// Negative responses start with "-ERR ".
	// Note: We require the space after the prefix to distinguish from Redis RESP simple strings.
	if data.starts_with(b"+OK ") || data.starts_with(b"-ERR ") {
		return validate_line(data);
	}

	// 2. Detect Client Commands
	// Common commands used at the start of a session.
	if is_command(data, b"USER")
		|| is_command(data, b"PASS")
		|| is_command(data, b"STAT")
		|| is_command(data, b"LIST")
		|| is_command(data, b"RETR")
		|| is_command(data, b"QUIT")
		|| is_command(data, b"CAPA")
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
		// Must be printable ASCII, CR, or Tab.
		if b != b'\r' && b != b'\t' && (b < 32 || b > 126) {
			return false;
		}
	}

	// For protocol detection, a valid prefix with printable content is strong.
	found_newline || data.len() >= 16
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_pop3_greeting() {
		assert!(detect(b"+OK POP3 server ready\r\n"));
		assert!(detect(b"+OK Hello there\n"));
		assert!(detect(b"-ERR Invalid command\r\n"));
	}

	#[test]
	fn test_detect_pop3_client_commands() {
		assert!(detect(b"USER alice\r\n"));
		assert!(detect(b"PASS secret\r\n"));
		assert!(detect(b"STAT\r\n"));
		assert!(detect(b"QUIT\n"));
		assert!(detect(b"CAPA\r\n"));
	}

	#[test]
	fn test_detect_pop3_partial() {
		assert!(detect(b"+OK Welcome to our POP3 server, please login"));
		assert!(detect(b"USER some-very-long-username-that-is-partial"));
	}

	#[test]
	fn test_reject_redis_collision() {
		// Redis simple string "+OK\r\n" lacks the space required for POP3 greeting.
		assert!(!detect(b"+OK\r\n"));
		// Redis error "-ERR\r\n" lacks the space.
		assert!(!detect(b"-ERR\r\n"));
	}

	#[test]
	fn test_reject_wrong_prefix() {
		assert!(!detect(b"220 smtp.example.com\r\n"));
		assert!(!detect(b"HTTP/1.1 200 OK\r\n"));
	}

	#[test]
	fn test_reject_non_ascii() {
		let mut data = [0u8; 10];
		data[..4].copy_from_slice(b"+OK ");
		data[4..].copy_from_slice(&[0xFF, 0x00, 0x12, 0x34, 0x56, 0x78]);
		assert!(!detect(&data));
	}

	#[test]
	fn test_short_data() {
		assert!(!detect(b"+OK"));
		assert!(!detect(b"USER"));
	}
}
