/* src/protocols/http.rs */
use crate::{DetectionStatus, ProtocolVersion};

/// Probes for HTTP protocol and version.
#[inline(always)]
pub(crate) fn probe(data: &[u8]) -> (DetectionStatus, ProtocolVersion<'_>) {
	if data.len() < 4 {
		return (DetectionStatus::Incomplete, ProtocolVersion::Unknown);
	}

	// HTTP/2 Connection Preface
	if data.starts_with(b"PRI ") {
		if data.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
			return (DetectionStatus::Match, ProtocolVersion::Http("2.0"));
		}
		if b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".starts_with(data) {
			return (DetectionStatus::Incomplete, ProtocolVersion::Unknown);
		}
	}

	// HTTP/1.x Methods
	let is_method = matches!(data[0], b'G' | b'P' | b'D' | b'H' | b'O' | b'C' | b'T');
	if is_method {
		let limit = data.len().min(64);
		let mut eol = limit;
		for (i, &b) in data.iter().enumerate().take(limit) {
			if b == b'\n' {
				eol = i;
				break;
			}
		}

		let line = &data[..eol];
		if let Some(pos) = find_sub(line, b" HTTP/1.") {
			if line.len() > pos + 8 {
				let version = match line[pos + 8] {
					b'1' => "1.1",
					b'0' => "1.0",
					_ => "1.x",
				};
				return (DetectionStatus::Match, ProtocolVersion::Http(version));
			}
			return (DetectionStatus::Incomplete, ProtocolVersion::Unknown);
		}

		if is_likely_http_method(data) {
			return (DetectionStatus::Incomplete, ProtocolVersion::Unknown);
		}
	}

	(DetectionStatus::NoMatch, ProtocolVersion::Unknown)
}

/// Helper to check for common HTTP methods.
#[inline(always)]
fn is_likely_http_method(data: &[u8]) -> bool {
	data.starts_with(b"GET ")
		|| data.starts_with(b"POST ")
		|| data.starts_with(b"PUT ")
		|| data.starts_with(b"DELETE ")
		|| data.starts_with(b"HEAD ")
		|| data.starts_with(b"OPTIONS ")
		|| data.starts_with(b"CONNECT ")
}

/// Helper to find a substring in a byte slice.
#[inline(always)]
fn find_sub(data: &[u8], sub: &[u8]) -> Option<usize> {
	if sub.len() > data.len() {
		return None;
	}
	for i in 0..=(data.len() - sub.len()) {
		if &data[i..i + sub.len()] == sub {
			return Some(i);
		}
	}
	None
}
