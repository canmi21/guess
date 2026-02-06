/* src/protocols/mqtt.rs */

/// Detects MQTT protocol (Message Queuing Telemetry Transport).
///
/// This implementation focuses on the MQTT CONNECT packet, which MUST be the
/// first packet sent by a client to the server.
///
/// CONNECT Packet Structure:
/// - Fixed Header: Byte 0 (0x10 for CONNECT), Byte 1+ (Remaining Length, variable byte integer)
/// - Variable Header: Protocol Name Length (2 bytes), Protocol Name ("MQTT" or "MQIsdp"),
///   Protocol Level (1 byte), Connect Flags (1 byte), Keep Alive (2 bytes)
#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	// Minimum length for a CONNECT packet:
	// Fixed Header (2) + Name Header (2) + "MQTT" (4) + Level (1) + Flags (1) + KeepAlive (2) = 12 bytes
	if data.len() < 12 {
		return false;
	}

	// 1. Fixed Header: Control Packet Type (CONNECT = 1, bits 7-4) and Reserved (0, bits 3-0)
	if data[0] != 0x10 {
		return false;
	}

	// 2. Parse Remaining Length (Variable Byte Integer, 1..4 bytes)
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

	// Basic structural check: must have found a valid length and have room for Name Length (2 bytes).
	if !found_len || data.len() < offset + 2 {
		return false;
	}

	// 3. Protocol Name Length (Big-Endian)
	let name_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;

	// Cross-validate Remaining Length:
	// For CONNECT, it must be at least: Name Length (2) + Name (N) + Level (1) + Flags (1) + Keep Alive (2)
	// which simplifies to: Remaining Length >= name_len + 6
	if (remaining_length as usize) < name_len + 6 {
		return false;
	}

	offset += 2;

	// Validate name length (MQTT=4, MQIsdp=6)
	if name_len != 4 && name_len != 6 {
		return false;
	}

	// 4. Protocol Name and Level
	if data.len() < offset + name_len + 1 {
		return false;
	}

	let name = &data[offset..offset + name_len];
	let level = data[offset + name_len];

	match name {
		b"MQTT" => {
			// v3.1.1 (4) or v5.0 (5)
			level == 4 || level == 5
		}
		b"MQIsdp" => {
			// v3.1 (3)
			level == 3
		}
		_ => false,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_mqtt_311() {
		// Remaining Length 12 (0x0c) >= 4 + 6. OK.
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
		// Remaining Length 14 (0x0e) >= 6 + 6. OK.
		let data = [
			0x10, 0x0e, 0x00, 0x06, b'M', b'Q', b'I', b's', b'd', b'p', 0x03, 0x02, 0x00, 0x3c,
		];
		assert!(detect(&data));
	}

	#[test]
	fn test_reject_impossible_remaining_length() {
		// Remaining Length says 5, but MQTT name length (4) + 6 needs 10.
		let data = [
			0x10, 0x05, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c,
		];
		assert!(!detect(&data));
	}

	#[test]
	fn test_detect_mqtt_long_remaining_length() {
		// Remaining length encoded in 2 bytes (0x80 0x01 = 128). 128 >= 10. OK.
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
