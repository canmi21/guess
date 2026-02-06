/* src/protocols/http.rs */

#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 4 {
		return false;
	}

	match &data[0..4] {
		b"GET " | b"POST" | b"PUT " | b"HEAD" => true,
		b"DELE" => data.starts_with(b"DELETE "),
		b"OPTI" => data.starts_with(b"OPTIONS"),
		b"PATC" => data.starts_with(b"PATCH "),
		b"CONN" => data.starts_with(b"CONNECT"),
		b"HTTP" => {
			data.starts_with(b"HTTP/1.0") || data.starts_with(b"HTTP/1.1") || data.starts_with(b"HTTP/2")
		}
		_ => false,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_http() {
		assert!(detect(b"GET / HTTP/1.1\r\n"));
		assert!(detect(b"POST /data HTTP/1.1\r\n"));
		assert!(detect(b"HTTP/1.1 200 OK\r\n"));
		assert!(detect(b"HTTP/2 200 OK\r\n"));
		assert!(!detect(b"NOT_HTTP"));
		assert!(!detect(b"GE"));
	}
}
