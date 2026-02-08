/* src/protocols/redis.rs */
use crate::{DetectionStatus, ProtocolVersion};

/// Probes for Redis (RESP) protocol and version.
///
/// Validates both the type prefix byte and the second byte to reduce
/// false positives against protocols like POP3 (`+OK`) or shell comments (`#`).
#[inline(always)]
pub(crate) fn probe(data: &[u8]) -> (DetectionStatus, ProtocolVersion<'_>) {
	if data.len() < 2 {
		if data.is_empty() {
			return (DetectionStatus::Incomplete, ProtocolVersion::Unknown);
		}
		return match data[0] {
			b'+' | b'-' | b':' | b'$' | b'*' | b'_' | b',' | b'#' | b'!' | b'=' | b'(' | b'%' | b'~'
			| b'>' => (DetectionStatus::Incomplete, ProtocolVersion::Unknown),
			_ => (DetectionStatus::NoMatch, ProtocolVersion::Unknown),
		};
	}

	let first = data[0];
	let second = data[1];

	let resp_ver = match first {
		b'+' | b'-' => {
			// Simple String / Error: printable ASCII or \r
			if !(32..=126).contains(&second) && second != b'\r' {
				return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
			}
			2
		}
		b':' | b'$' | b'*' => {
			// Integer / Bulk String / Array: digit or '-'
			if !second.is_ascii_digit() && second != b'-' {
				return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
			}
			2
		}
		b'#' => {
			// RESP3 Boolean: must be 't' or 'f'
			if second != b't' && second != b'f' {
				return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
			}
			3
		}
		b'_' => {
			// RESP3 Null: must be '\r'
			if second != b'\r' {
				return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
			}
			3
		}
		b',' => {
			// RESP3 Double: digit, sign, or inf/nan prefix
			if !second.is_ascii_digit() && !matches!(second, b'-' | b'+' | b'i' | b'n') {
				return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
			}
			3
		}
		b'(' => {
			// RESP3 Big Number: digit or '-'
			if !second.is_ascii_digit() && second != b'-' {
				return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
			}
			3
		}
		b'!' | b'=' | b'%' | b'~' | b'>' => {
			// RESP3 Blob Error / Verbatim / Map / Set / Push: digit (length)
			if !second.is_ascii_digit() {
				return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
			}
			3
		}
		_ => return (DetectionStatus::NoMatch, ProtocolVersion::Unknown),
	};

	(DetectionStatus::Match, ProtocolVersion::Redis(resp_ver))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_resp2_simple_string() {
		assert_eq!(
			probe(b"+OK\r\n"),
			(DetectionStatus::Match, ProtocolVersion::Redis(2))
		);
	}

	#[test]
	fn test_detect_resp2_error() {
		assert_eq!(
			probe(b"-ERR unknown\r\n"),
			(DetectionStatus::Match, ProtocolVersion::Redis(2))
		);
	}

	#[test]
	fn test_detect_resp2_integer() {
		assert_eq!(
			probe(b":1000\r\n"),
			(DetectionStatus::Match, ProtocolVersion::Redis(2))
		);
	}

	#[test]
	fn test_detect_resp2_bulk_string() {
		assert_eq!(
			probe(b"$6\r\nfoobar\r\n"),
			(DetectionStatus::Match, ProtocolVersion::Redis(2))
		);
	}

	#[test]
	fn test_detect_resp2_array() {
		assert_eq!(
			probe(b"*3\r\n$3\r\nSET\r\n"),
			(DetectionStatus::Match, ProtocolVersion::Redis(2))
		);
	}

	#[test]
	fn test_detect_resp2_negative() {
		assert_eq!(
			probe(b":-1\r\n"),
			(DetectionStatus::Match, ProtocolVersion::Redis(2))
		);
		assert_eq!(
			probe(b"$-1\r\n"),
			(DetectionStatus::Match, ProtocolVersion::Redis(2))
		);
	}

	#[test]
	fn test_detect_resp3_boolean() {
		assert_eq!(
			probe(b"#t\r\n"),
			(DetectionStatus::Match, ProtocolVersion::Redis(3))
		);
		assert_eq!(
			probe(b"#f\r\n"),
			(DetectionStatus::Match, ProtocolVersion::Redis(3))
		);
	}

	#[test]
	fn test_detect_resp3_null() {
		assert_eq!(
			probe(b"_\r\n"),
			(DetectionStatus::Match, ProtocolVersion::Redis(3))
		);
	}

	#[test]
	fn test_detect_resp3_double() {
		assert_eq!(
			probe(b",3.14\r\n"),
			(DetectionStatus::Match, ProtocolVersion::Redis(3))
		);
		assert_eq!(
			probe(b",inf\r\n"),
			(DetectionStatus::Match, ProtocolVersion::Redis(3))
		);
	}

	#[test]
	fn test_reject_invalid_second_byte() {
		// '#' followed by non-boolean char
		assert_eq!(probe(b"#comment\r\n").0, DetectionStatus::NoMatch);
		// '>' followed by non-digit
		assert_eq!(probe(b">some text\r\n").0, DetectionStatus::NoMatch);
		// '*' followed by non-digit
		assert_eq!(probe(b"*text\r\n").0, DetectionStatus::NoMatch);
		// '_' followed by non-\r
		assert_eq!(probe(b"_x\r\n").0, DetectionStatus::NoMatch);
	}

	#[test]
	fn test_incomplete_single_byte() {
		assert_eq!(probe(b"").0, DetectionStatus::Incomplete);
		assert_eq!(probe(b"+").0, DetectionStatus::Incomplete);
		assert_eq!(probe(b"*").0, DetectionStatus::Incomplete);
		assert_eq!(probe(b"#").0, DetectionStatus::Incomplete);
	}

	#[test]
	fn test_reject_non_resp_prefix() {
		assert_eq!(probe(b"GET /index.html").0, DetectionStatus::NoMatch);
		assert_eq!(probe(b"SSH-2.0-OpenSSH").0, DetectionStatus::NoMatch);
	}
}
