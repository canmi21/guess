/* src/protocols/ntp.rs */

/// Detects NTP protocol (UDP).
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 48 {
		return false;
	}

	let first_byte = data[0];
	let vn = (first_byte >> 3) & 0x07;
	let mode = first_byte & 0x07;

	if !(1..=4).contains(&vn) {
		return false;
	}

	if !(1..=7).contains(&mode) {
		return false;
	}

	let stratum = data[1];
	if stratum > 16 {
		return false;
	}

	let poll = data[2];
	if poll > 20 {
		return false;
	}

	let precision = data[3] as i8;
	if !(-32..=16).contains(&precision) {
		return false;
	}

	let mut all_zero_transmit = true;
	for &b in &data[40..48] {
		if b != 0 {
			all_zero_transmit = false;
			break;
		}
	}
	if all_zero_transmit {
		return false;
	}

	true
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_ntp_client_v4() {
		let mut data = [0u8; 48];
		data[0] = 0x23;
		data[40] = 0xE5;
		data[47] = 0x01;
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_ntp_server_v4() {
		let mut data = [0u8; 48];
		data[0] = 0x24;
		data[1] = 2;
		data[40] = 0xE5;
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_ntp_v3() {
		let mut data = [0u8; 48];
		data[0] = 0x1B;
		data[40] = 0x11;
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_invalid_version() {
		let mut data = [0u8; 48];
		data[0] = 0x03;
		data[40] = 0x11;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_invalid_mode() {
		let mut data = [0u8; 48];
		data[0] = 0x20;
		data[40] = 0x11;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_invalid_stratum() {
		let mut data = [0u8; 48];
		data[0] = 0x23;
		data[1] = 17;
		data[40] = 0x11;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_zero_transmit_timestamp() {
		let mut data = [0u8; 48];
		data[0] = 0x23;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_random_data() {
		assert!(!detect(&[0x42; 48]));
	}

	#[test]
	fn test_short_data() {
		assert!(!detect(&[0x23; 10]));
	}
}
