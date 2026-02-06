/* src/protocols/imap.rs */

/// Detects IMAP protocol (Internet Message Access Protocol).
///
/// IMAP starts with a server greeting or a client tagged command.
/// Server Greeting: "* OK ...", "* PREAUTH ...", "* BYE ..."
/// Client Command: "A001 CAPABILITY", "1 LOGIN user pass"
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 5 {
		return false;
	}

	// 1. Detect Server Greeting or Untagged Response
	if data.starts_with(b"* ") {
		let after_star = &data[2..];
		if after_star.starts_with(b"OK ")
			|| after_star.starts_with(b"PREAUTH ")
			|| after_star.starts_with(b"BYE ")
			|| after_star.starts_with(b"NO ")
			|| after_star.starts_with(b"BAD ")
		{
			return validate_line(data);
		}
	}

	// 2. Detect Client Tagged Command
	// Format: <tag> <command> ...
	// Tag is an alphanumeric string (can include '.', '_', '-').
	let mut i = 0;
	while i < data.len() && i < 20 && is_tag_char(data[i]) {
		i += 1;
	}

	// Tag must be followed by a space and then a command.
	if i > 0 && i + 1 < data.len() && data[i] == b' ' {
		let cmd_start = i + 1;
		let mut j = cmd_start;
		// IMAP commands are usually uppercase letters.
		while j < data.len() && j < cmd_start + 16 && data[j].is_ascii_uppercase() {
			j += 1;
		}

		let cmd_len = j - cmd_start;
		if cmd_len >= 2 {
			let cmd = &data[cmd_start..j];
			if is_imap_command(cmd) {
				return validate_line(data);
			}
		}
	}

	false
}

#[inline(always)]
fn is_tag_char(b: u8) -> bool {
	b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-'
}

#[inline(always)]
fn is_imap_command(cmd: &[u8]) -> bool {
	matches!(
		cmd,
		b"LOGIN"
			| b"LOGOUT"
			| b"CAPABILITY"
			| b"NOOP"
			| b"STARTTLS"
			| b"AUTHENTICATE"
			| b"SELECT"
			| b"EXAMINE"
			| b"CREATE"
			| b"DELETE"
			| b"RENAME"
			| b"SUBSCRIBE"
			| b"UNSUBSCRIBE"
			| b"LIST"
			| b"LSUB"
			| b"STATUS"
			| b"APPEND"
			| b"CHECK"
			| b"CLOSE"
			| b"EXPUNGE"
			| b"SEARCH"
			| b"FETCH"
			| b"STORE"
			| b"COPY"
			| b"UID"
			| b"ID"
			| b"ENABLE"
			| b"IDLE"
			| b"NAMESPACE"
	)
}

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
	fn test_detect_imap_greeting() {
		assert!(detect(b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n"));
		assert!(detect(b"* PREAUTH [CAPABILITY IMAP4rev1] Logged in\n"));
		assert!(detect(b"* BYE Shutdown\r\n"));
	}

	#[test]
	fn test_detect_imap_client_commands() {
		assert!(detect(b"A001 LOGIN user pass\r\n"));
		assert!(detect(b"1 CAPABILITY\n"));
		assert!(detect(b"abcd.123_ SELECT INBOX\r\n"));
	}

	#[test]
	fn test_detect_imap_partial() {
		assert!(detect(b"* OK IMAP server ready and waiting for you"));
		assert!(detect(b"A001 FETCH 1:* (FLAGS)"));
	}

	#[test]
	fn test_reject_redis_array_collision() {
		// Redis uses *<count>\r\n, IMAP uses * <TYPE>
		assert!(!detect(b"*3\r\n$3\r\nGET\r\n"));
	}

	#[test]
	fn test_reject_non_imap() {
		assert!(!detect(b"GET / HTTP/1.1\r\n"));
		assert!(!detect(b"220 smtp.example.com\r\n"));
		assert!(!detect(b"+OK POP3 ready\r\n"));
	}

	#[test]
	fn test_reject_non_ascii() {
		let mut data = [0u8; 12];
		data[..5].copy_from_slice(b"* OK ");
		data[5..].copy_from_slice(&[0xFF, 0x00, 0x12, 0x34, 0x56, 0x78, 0x90]);
		assert!(!detect(&data));
	}

	#[test]
	fn test_short_data() {
		assert!(!detect(b"* OK"));
		assert!(!detect(b"A1 LO"));
	}
}
