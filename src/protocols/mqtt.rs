/* src/protocols/mqtt.rs */

/// Detects MQTT protocol (Message Queuing Telemetry Transport).
///
/// This implementation focuses on the MQTT CONNECT packet.
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 12 {
		return false;
	}

	if data[0] != 0x10 {
		return false;
	}

	let mut offset = 1;
	let mut remaining_length: u32 = 0;
	let mut multiplier: u32 = 1;
	let mut found_len = false;

	while offset < 5 && offset < data.len() {
		let b = data[offset];
		remaining_length += ((b & 0x7F) as u32) * multiplier;
		offset += 1;
		if (b & 0x80) == 0 {
			found_len = true;
			break;
		}
		multiplier *= 128;
	}

	if !found_len || data.len() < offset + 2 {
		return false;
	}

	let name_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;

	if (remaining_length as usize) < name_len + 6 {
		return false;
	}

	offset += 2;

	if name_len != 4 && name_len != 6 {
		return false;
	}

	if data.len() < offset + name_len + 1 {
		return false;
	}

	let name = &data[offset..offset + name_len];
	let level = data[offset + name_len];

	match name {
		b"MQTT" => level == 4 || level == 5,
		b"MQIsdp" => level == 3,
		_ => false,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_mqtt_311() {
		let data = [
			0x10, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c,
		];
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_mqtt_50() {
		let data = [
			0x10, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x05, 0x02, 0x00, 0x3c,
		];
		assert!(detect(&data));
	}

	#[test]
	fn test_detect_mqtt_31() {
		let data = [
			0x10, 0x0e, 0x00, 0x06, b'M', b'Q', b'I', b's', b'd', b'p', 0x03, 0x02, 0x00, 0x3c,
		];
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_impossible_remaining_length() {
		let data = [
			0x10, 0x05, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c,
		];
		assert!(!detect(&data));
	}

	#[test]
	fn test_detect_mqtt_long_remaining_length() {
		let mut data = [0u8; 150];
		data[0] = 0x10;
		data[1] = 0x80;
		data[2] = 0x01;
		data[3] = 0x00;
		data[4] = 0x04;
		data[5..9].copy_from_slice(b"MQTT");
		data[9] = 0x04;
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_invalid_packet_type() {
		let data = [0x20; 12];
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_invalid_protocol_name() {
		let data = [
			0x10, 0x0c, 0x00, 0x04, b'F', b'A', b'K', b'E', 0x04, 0x02, 0x00, 0x3c,
		];
		assert!(!detect(&data));
	}

	#[test]
	fn test_reject_short_data() {
		assert!(!detect(b""));
		assert!(!detect(&[0x10]));
		assert!(!detect(&[0x10, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T']));
	}

	#[test]
	fn test_reject_binary_protocols() {
		assert!(!detect(&[0x16, 0x03, 0x01, 0x00, 0x05]));
		assert!(!detect(b"GET / HTTP/1.1\r\n"));
	}
}
