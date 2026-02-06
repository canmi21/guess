/* src/protocols/mqtt.rs */

#[inline(always)]
pub(crate) fn detect(data: &[u8]) -> bool {
	if data.len() < 7 {
		// 2 bytes header + "MQTT" or "MQIsdp"
		return false;
	}

	// Byte 0: Packet Type (4 bits) + Flags (4 bits)
	// 0x10 is CONNECT
	if data[0] != 0x10 {
		return false;
	}

	// Byte 1: Remaining Length (Variable Byte Integer)
	// We don't fully parse it, but it should be > 0
	if data[1] == 0 {
		return false;
	}

	// Byte 2-3: Protocol Name Length (usually 4 for "MQTT")
	// Byte 4-7: Protocol Name ("MQTT" in v3.1.1 and v5.0)
	if data.starts_with(&[0x10, data[1], 0x00, 0x04]) && &data[4..8] == b"MQTT" {
		return true;
	}

	// v3.1 used "MQIsdp" (length 6)
	if data.len() >= 9 && data.starts_with(&[0x10, data[1], 0x00, 0x06]) && &data[4..10] == b"MQIsdp"
	{
		return true;
	}

	false
}
