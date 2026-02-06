/* src/protocols/redis.rs */

/// Detects Redis (RESP) protocol.
///
/// Supports RESP2/RESP3 prefixes (+, -, :, $, *, _, ,, #, !, =, (, %, ~, >)
/// and basic inline commands (PING).
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.is_empty() {
		return false;
	}

	match data[0] {
		// RESP prefixes
		b'+' | b'-' | b':' | b'$' | b'*' | b'_' | b',' | b'#' | b'!' | b'=' | b'(' | b'%' | b'~'
		| b'>' => validate_resp(data),

		// Common inline commands (must be terminated by \r\n)
		b'P' => {
			(data.starts_with(b"PING\r\n") || data.starts_with(b"PING\n"))
				|| (data.starts_with(b"PONG\r\n") || data.starts_with(b"PONG\n"))
		}
		b'S' => data.starts_with(b"SET ") || data.starts_with(b"SELECT "),
		// For 'G', we must be careful not to match "GET /" (HTTP)
		b'G' => data.starts_with(b"GET ") && !data.starts_with(b"GET /"),

		_ => false,
	}
}

/// Validates the structure of a RESP message.
#[inline(always)]
fn validate_resp(data: &[u8]) -> bool {
	if data.len() < 3 {
		return false;
	}

	let prefix = data[0];
	let payload = &data[1..];

	// Find the first occurrence of \n.
	let mut term_idx = None;
	for i in 0..payload.len() {
		if payload[i] == b'\n' {
			term_idx = Some(i);
			break;
		}
	}

	let Some(idx) = term_idx else {
		// If no terminator is found, we only accept if the partial data is perfectly consistent.
		return match prefix {
			b':' | b'$' | b'*' => is_all_digits_or_minus(payload),
			_ => false,
		};
	};

	let line = if idx > 0 && payload[idx - 1] == b'\r' {
		&payload[..idx - 1]
	} else {
		&payload[..idx]
	};

	match prefix {
		// Simple Strings (+), Errors (-), Verbatim (=), Big Numbers (()
		b'+' | b'-' | b'=' | b'(' => !line.is_empty() && is_printable_ascii(line),

		// Integers (:)
		b':' => !line.is_empty() && is_all_digits_or_minus(line),

		// Doubles (,), Booleans (#), Nulls (_)
		b',' | b'#' | b'_' => {
			if prefix == b'#' {
				line == b"t" || line == b"f"
			} else if prefix == b'_' {
				line.is_empty()
			} else if prefix == b',' {
				!line.is_empty() // Could validate float format here
			} else {
				true
			}
		}

		// Bulk Strings ($), Bulk Errors (!)
		b'$' | b'!' => {
			if line == b"-1" {
				return true;
			}
			let Some(len) = parse_u32(line) else {
				return false;
			};

			let after_term = &payload[idx + 1..];
			if !after_term.is_empty() {
				let len = len as usize;
				if after_term.len() >= len + 1 {
					return true;
				}
			}
			true
		}

		// Arrays (*), Maps (%), Sets (~), Pushes (>)
		b'*' | b'%' | b'~' | b'>' => {
			if line == b"-1" {
				return true;
			}
			let Some(count) = parse_u32(line) else {
				return false;
			};

			let after_term = &payload[idx + 1..];
			if count > 0 && !after_term.is_empty() {
				return is_resp_prefix(after_term[0]);
			}
			true
		}

		_ => false,
	}
}

#[inline(always)]
fn is_resp_prefix(b: u8) -> bool {
	matches!(
		b,
		b'+' | b'-' | b':' | b'$' | b'*' | b'_' | b',' | b'#' | b'!' | b'=' | b'(' | b'%' | b'~' | b'>'
	)
}

#[inline(always)]
fn is_printable_ascii(data: &[u8]) -> bool {
	for &b in data {
		if b < 32 || b > 126 {
			return false;
		}
	}
	true
}

#[inline(always)]
fn is_all_digits_or_minus(data: &[u8]) -> bool {
	if data.is_empty() {
		return false;
	}
	for (i, &b) in data.iter().enumerate() {
		if b == b'-' && i == 0 {
			continue;
		}
		if !b.is_ascii_digit() {
			return false;
		}
	}
	true
}

#[inline(always)]
fn parse_u32(data: &[u8]) -> Option<u32> {
	if data.is_empty() {
		return None;
	}
	let mut res = 0u32;
	for &b in data {
		if !b.is_ascii_digit() {
			return None;
		}
		res = res.checked_mul(10)?.checked_add((b - b'0') as u32)?;
	}
	Some(res)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_redis_simple_string() {
		assert!(detect(b"+OK\r\n"));
		assert!(detect(b"+PONG\r\n"));
	}

	#[test]
	fn test_detect_redis_error() {
		assert!(detect(b"-ERR unknown command 'foobar'\r\n"));
	}

	#[test]
	fn test_detect_redis_integer() {
		assert!(detect(b":1000\r\n"));
		assert!(detect(b":-1\r\n"));
	}

	#[test]
	fn test_detect_redis_bulk_string() {
		assert!(detect(b"$6\r\nfoobar\r\n"));
		assert!(detect(b"$0\r\n\r\n"));
		assert!(detect(b"$-1\r\n"));
	}

	#[test]
	fn test_detect_redis_array() {
		assert!(detect(b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"));
		assert!(detect(b"*0\r\n"));
		assert!(detect(b"*-1\r\n"));
	}

	#[test]
	fn test_detect_redis_resp3() {
		assert!(detect(b"_\r\n")); // Null
		assert!(detect(b"#t\r\n")); // Boolean true
		assert!(detect(b",1.23\r\n")); // Double
	}

	#[test]
	fn test_detect_redis_inline() {
		assert!(detect(b"PING\r\n"));
		assert!(detect(b"SET foo bar\r\n"));
		assert!(detect(b"GET foo\r\n"));
	}

	#[test]
	fn test_reject_invalid_resp() {
		assert!(!detect(b":abc\r\n"));
		assert!(!detect(b"$abc\r\n"));
		assert!(!detect(b"+OK")); // Too short, no terminator
	}

	#[test]
	fn test_reject_non_redis() {
		assert!(!detect(b"GET / HTTP/1.1\r\n"));
		assert!(!detect(b"SSH-2.0-OpenSSH_8.9\r\n"));
		assert!(!detect(&[0x16, 0x03, 0x01, 0x00, 0x05])); // TLS
	}

	#[test]
	fn test_partial_bulk_string() {
		// Even if truncated, $6\r\n is enough if it matches the pattern
		assert!(detect(b"$6\r\nfoo"));
	}

	#[test]
	fn test_empty_data() {
		assert!(!detect(b""));
	}
}
