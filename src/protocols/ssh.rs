/* src/protocols/ssh.rs */

#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 4 {
		return false;
	}

	if &data[0..4] != b"SSH-" {
		return false;
	}

	if data.len() >= 8 {
		return data.starts_with(b"SSH-2.0-")
			|| data.starts_with(b"SSH-1.99-")
			|| data.starts_with(b"SSH-1.5-");
	}

	true
}

#[cfg(test)]

mod tests {

	use super::*;

	#[test]

	fn test_detect_ssh() {
		assert!(detect(b"SSH-2.0-OpenSSH_8.9p1\r\n"));

		assert!(detect(b"SSH-1.99-SomeClient\n"));

		assert!(detect(b"SSH-"));

		assert!(!detect(b"GET / HTTP/1.1"));
	}
}
