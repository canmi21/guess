/* src/protocols/ntp.rs */

/// Detects NTP protocol (UDP).
///
/// NTP packets have a fixed 48-byte header.
/// This function validates the LI, VN, Mode, Stratum, and reasonable ranges
/// for Poll/Precision, and ensures the Transmit Timestamp is non-zero.
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	// NTP header is exactly 48 bytes.
	if data.len() < 48 {
		return false;
	}

	let first_byte = data[0];
	// let li = (first_byte >> 6) & 0x03; // Leap Indicator (always 0-3)
	let vn = (first_byte >> 3) & 0x07; // Version Number
	let mode = first_byte & 0x07; // Mode

	// Version should be 1-4.
	if !(1..=4).contains(&vn) {
		return false;
	}

	// Mode:
	// 1: symmetric active, 2: symmetric passive, 3: client, 4: server,
	// 5: broadcast, 6: control, 7: private.
	if !(1..=7).contains(&mode) {
		return false;
	}

	let stratum = data[1];
	// Stratum: 0 (unspecified), 1 (primary), 2-15 (secondary), 16 (unsync).
	if stratum > 16 {
		return false;
	}

	// Poll: log2 interval between messages. Usually 4 (16s) to 17 (36h).
	// We'll allow 0 to 20 for robustness.
	let poll = data[2];
	if poll > 20 {
		return false;
	}

	// Precision: log2 precision of the local clock.
	// Usually -6 to -20 (represented as signed i8, so 0xFA to 0xEC).
	let precision = data[3] as i8;
	if !(-32..=16).contains(&precision) {
		return false;
	}

	// Transmit Timestamp (Bytes 40-47) is the time at which the reply
	// left the server, or the time at which the request left the client.
	// It should NEVER be zero in a valid NTP packet.
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

	// For server responses (Mode 4), Root Delay and Root Dispersion (Bytes 4-11)
	// are usually non-zero and small. In client requests (Mode 3), they are often zero.

	true
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_ntp_client_v4() {
		let mut data = [0u8; 48];
		data[0] = 0x23; // LI=0, VN=4, Mode=3 (Client)
		data[1] = 0; // Stratum
		data[2] = 4; // Poll
		data[3] = 0xE8; // Precision (-24)
		data[40] = 0xE5; // Transmit Timestamp (some random non-zero value)
		data[47] = 0x01;
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_ntp_server_v4() {
		let mut data = [0u8; 48];
		data[0] = 0x24; // LI=0, VN=4, Mode=4 (Server)
		data[1] = 2; // Stratum 2
		data[2] = 4;
		data[3] = 0xE8;
		data[40] = 0xE5;
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_ntp_v3() {
		let mut data = [0u8; 48];
		data[0] = 0x1B; // LI=0, VN=3, Mode=3
		data[40] = 0x11;
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_invalid_version() {
		let mut data = [0u8; 48];
		data[0] = 0x03; // LI=0, VN=0, Mode=3 (Invalid VN)
		data[40] = 0x11;
		assert!(!detect(&data));

		data[0] = 0x2B; // LI=0, VN=5, Mode=3 (Invalid VN)
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_invalid_mode() {
		let mut data = [0u8; 48];
		data[0] = 0x20; // LI=0, VN=4, Mode=0 (Reserved)
		data[40] = 0x11;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_invalid_stratum() {
		let mut data = [0u8; 48];
		data[0] = 0x23;
		data[1] = 17; // Invalid Stratum
		data[40] = 0x11;
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_zero_transmit_timestamp() {
		let mut data = [0u8; 48];
		data[0] = 0x23;
		// data[40..48] remains 0
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
