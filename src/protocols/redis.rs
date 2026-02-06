/* src/protocols/redis.rs */

#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.is_empty() {
		return false;
	}

	// Redis RESP protocols usually start with:
	// * : Arrays
	// + : Simple Strings
	// - : Errors
	// : : Integers
	// $ : Bulk Strings
	match data[0] {
		b'*' | b'+' | b'-' | b':' | b'$' => {
			// Check if it ends with \r\n or has common patterns
			if data.len() >= 4 {
				// Common commands like *1\r\n$4\r\nPING\r\n
				return data.contains(&b'\r') && data.contains(&b'\n');
			}
			true
		}
		// Also check for inline commands (less common now but possible)
		b'P' => data.starts_with(b"PING") || data.starts_with(b"PSUBSCRIBE"),
		b'S' => {
			data.starts_with(b"SET") || data.starts_with(b"SELECT") || data.starts_with(b"SUBSCRIBE")
		}
		b'G' => data.starts_with(b"GET"),
		_ => false,
	}
}
