/* src/protocols/http.rs */

#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 4 {
		return false;
	}

	match &data[..4] {
		b"GET " | b"PUT " => is_valid_request_target(data, 4),
		b"POST" => check_method_and_target(data, b"POST "),
		b"HEAD" => check_method_and_target(data, b"HEAD "),
		b"DELE" => check_method_and_target(data, b"DELETE "),
		b"OPTI" => check_method_and_target(data, b"OPTIONS "),
		b"PATC" => check_method_and_target(data, b"PATCH "),
		b"CONN" => check_method_and_target(data, b"CONNECT "),
		b"PRI " => data.starts_with(b"PRI * HTTP/2"),
		b"HTTP" => detect_response(data),
		_ => false,
	}
}

/// Validates that the byte at `offset` is a valid start of an HTTP request-target.
///
/// Valid starts: `/` (origin-form), `*` (asterisk-form), or alphanumeric
/// (absolute-form like `http://...` or authority-form like `host:port`).
///
/// If there is not enough data to check, returns `true` (tentative accept).
/// In packet capture scenarios, the first packet may only contain partial data.
/// A matched method with trailing space (e.g. `GET `) is already a strong HTTP
/// signal, so we accept it rather than wait for more data.
#[inline(always)]
fn is_valid_request_target(data: &[u8], offset: usize) -> bool {
	if data.len() <= offset {
		return true;
	}
	let b = data[offset];
	b == b'/' || b == b'*' || b.is_ascii_alphanumeric()
}

/// Checks that data starts with the given method (including trailing space),
/// then validates the request-target start byte.
#[inline(always)]
fn check_method_and_target(data: &[u8], method_with_space: &[u8]) -> bool {
	let len = method_with_space.len();
	if data.len() < len {
		return false;
	}
	if !data.starts_with(method_with_space) {
		return false;
	}
	is_valid_request_target(data, len)
}

/// Detects HTTP response status lines.
///
/// Matches `HTTP/1.0 D`, `HTTP/1.1 D`, `HTTP/2 D`, or `HTTP/2.0 D`
/// where D is the first digit of the status code.
#[inline(always)]
fn detect_response(data: &[u8]) -> bool {
	// HTTP/1.x: "HTTP/1.X D" = 10 bytes minimum
	if data.len() >= 10 {
		let tail = &data[4..9];
		if (tail == b"/1.0 " || tail == b"/1.1 ") && data[9].is_ascii_digit() {
			return true;
		}
	}
	// HTTP/2: "HTTP/2 D" = 8 bytes or "HTTP/2.0 D" = 10 bytes
	if data.len() >= 8 && data[4] == b'/' && data[5] == b'2' {
		if data[6] == b' ' && data[7].is_ascii_digit() {
			return true;
		}
		if data.len() >= 10 && &data[6..9] == b".0 " && data[9].is_ascii_digit() {
			return true;
		}
	}
	false
}

#[cfg(test)]
mod tests {
	use super::*;

	// HTTP Request Detection

	#[test]
	fn test_get_request() {
		assert!(detect(b"GET / HTTP/1.1\r\n"));
		assert!(detect(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"));
		assert!(detect(b"GET /path?query=1 HTTP/1.0\r\n"));
		assert!(detect(b"GET * HTTP/1.1\r\n"));
		assert!(detect(b"GET http://example.com/ HTTP/1.1\r\n"));
	}

	#[test]
	fn test_post_request() {
		assert!(detect(b"POST /api/data HTTP/1.1\r\n"));
		assert!(detect(b"POST /submit HTTP/1.1\r\nContent-Length: 10\r\n"));
	}

	#[test]
	fn test_put_request() {
		assert!(detect(b"PUT /resource HTTP/1.1\r\n"));
	}

	#[test]
	fn test_delete_request() {
		assert!(detect(b"DELETE /resource/123 HTTP/1.1\r\n"));
	}

	#[test]
	fn test_head_request() {
		assert!(detect(b"HEAD / HTTP/1.1\r\n"));
	}

	#[test]
	fn test_options_request() {
		assert!(detect(b"OPTIONS * HTTP/1.1\r\n"));
		assert!(detect(b"OPTIONS / HTTP/1.1\r\n"));
	}

	#[test]
	fn test_patch_request() {
		assert!(detect(b"PATCH /resource HTTP/1.1\r\n"));
	}

	#[test]
	fn test_connect_request() {
		assert!(detect(b"CONNECT example.com:443 HTTP/1.1\r\n"));
		assert!(detect(b"CONNECT 192.168.1.1:8080 HTTP/1.1\r\n"));
	}

	// HTTP Response Detection

	#[test]
	fn test_http10_response() {
		assert!(detect(b"HTTP/1.0 200 OK\r\n"));
		assert!(detect(b"HTTP/1.0 404 Not Found\r\n"));
		assert!(detect(b"HTTP/1.0 301 Moved\r\n"));
	}

	#[test]
	fn test_http11_response() {
		assert!(detect(b"HTTP/1.1 200 OK\r\n"));
		assert!(detect(b"HTTP/1.1 404 Not Found\r\n"));
		assert!(detect(b"HTTP/1.1 500 Internal Server Error\r\n"));
		assert!(detect(b"HTTP/1.1 302 Found\r\n"));
		assert!(detect(b"HTTP/1.1 100 Continue\r\n"));
	}

	#[test]
	fn test_http2_response() {
		assert!(detect(b"HTTP/2 200 OK\r\n"));
		assert!(detect(b"HTTP/2.0 200 OK\r\n"));
	}

	// HTTP/2 Connection Preface

	#[test]
	fn test_h2_connection_preface() {
		assert!(detect(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
		assert!(detect(b"PRI * HTTP/2.0\r\n"));
	}

	// Minimum Data

	#[test]
	fn test_minimum_data_accepted() {
		assert!(detect(b"GET "));
		assert!(detect(b"GET /"));
		assert!(detect(b"PUT /"));
		assert!(detect(b"POST /"));
	}

	#[test]
	fn test_minimum_data_rejected() {
		assert!(!detect(b"GET"));
		assert!(!detect(b"GE"));
		assert!(!detect(b"G"));
		assert!(!detect(b""));
		assert!(!detect(b"POST"));
		assert!(!detect(b"HEAD"));
		assert!(!detect(b"HTTP"));
	}

	// False Positive Prevention: Other Protocols

	#[test]
	fn test_reject_other_protocols() {
		assert!(!detect(b"NOT_HTTP"));
		assert!(!detect(b"HELO smtp.example.com\r\n"));
		assert!(!detect(b"USER anonymous\r\n"));
		assert!(!detect(b"SSH-2.0-OpenSSH\r\n"));
		assert!(!detect(b"*3\r\n$3\r\nSET\r\n"));
	}

	// False Positive Prevention: Similar Prefixes

	#[test]
	fn test_reject_method_without_space() {
		assert!(!detect(b"POSTAL service"));
		assert!(!detect(b"POSTMAN runner"));
		assert!(!detect(b"HEADING north"));
		assert!(!detect(b"HEADERS list"));
		assert!(!detect(b"DELETION log"));
		assert!(!detect(b"OPTIONAL feature"));
		assert!(!detect(b"PATCHWORK quilt"));
		assert!(!detect(b"CONNECTION reset"));
	}

	#[test]
	fn test_reject_method_invalid_target() {
		assert!(!detect(b"GET \r\nHost: x\r\n"));
		assert!(!detect(b"GET \nHost: x\r\n"));
		assert!(!detect(b"PUT  /resource"));
	}

	#[test]
	fn test_reject_invalid_response() {
		assert!(!detect(b"HTTP is a protocol"));
		assert!(!detect(b"HTTP/1.2 200 OK\r\n"));
		assert!(!detect(b"HTTP/3 200 OK\r\n"));
		assert!(!detect(b"HTTP/1.1 OK\r\n"));
		assert!(!detect(b"HTTP/1.1  200\r\n"));
		assert!(!detect(b"HTTPS://example.com"));
	}

	#[test]
	fn test_reject_partial_h2_preface() {
		assert!(!detect(b"PRI "));
		assert!(!detect(b"PRI method"));
		assert!(!detect(b"PRIVATE data"));
	}

	// Edge Cases

	#[test]
	fn test_binary_data() {
		assert!(!detect(&[0x00, 0x01, 0x02, 0x03]));
		assert!(!detect(&[0xFF, 0xFE, 0xFD, 0xFC]));
		assert!(!detect(&[0x16, 0x03, 0x03, 0x00]));
	}

	#[test]
	fn test_case_sensitivity() {
		assert!(!detect(b"get / HTTP/1.1\r\n"));
		assert!(!detect(b"Get / HTTP/1.1\r\n"));
		assert!(!detect(b"post /data HTTP/1.1\r\n"));
		assert!(!detect(b"http/1.1 200 OK\r\n"));
		assert!(!detect(b"Http/1.1 200 OK\r\n"));
	}

	#[test]
	fn test_adversarial_inputs() {
		assert!(!detect(b"GETTER /path HTTP/1.1"));
		assert!(!detect(b"PUTTER /path HTTP/1.1"));
		assert!(!detect(b"HTTP/1.1\x00200 OK"));
		assert!(!detect(b"HTTP/1.1\t200 OK"));
	}

	#[test]
	fn test_repetitive_data() {
		assert!(!detect(&b"G".repeat(1000)));
		assert!(!detect(&b"P".repeat(1000)));
		assert!(!detect(&b"H".repeat(1000)));
	}

	#[test]
	fn test_null_byte_injection() {
		assert!(!detect(b"GET\x00/ HTTP/1.1"));
		assert!(!detect(b"POST\x00/ HTTP/1.1"));
		assert!(!detect(b"HTTP/1.1\x00200 OK"));
	}

	#[test]
	fn test_non_ascii_request_target() {
		// Non-ASCII byte as first char of request target is rejected
		assert!(!detect(b"GET \xC3\xA9 HTTP/1.1"));
		assert!(!detect(b"GET \xE4\xB8\xAD HTTP/1.1"));
		// But a valid path starting with / followed by non-ASCII is accepted
		// (we only validate the first byte of the target)
		assert!(detect(b"GET /\xC3\xA9 HTTP/1.1"));
	}
}
