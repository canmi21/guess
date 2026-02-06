/* src/protocols/tls.rs */

use crate::{DetectionStatus, ProtocolVersion};

#[inline(always)]
pub(crate) fn probe(data: &[u8]) -> (DetectionStatus, ProtocolVersion<'_>) {
	if data.len() < 5 {
		return (DetectionStatus::Incomplete, ProtocolVersion::Unknown);
	}

	if data[0] & 0x80 != 0 {
		return (
			if detect_sslv2(data) {
				DetectionStatus::Match
			} else {
				DetectionStatus::NoMatch
			},
			ProtocolVersion::Unknown,
		);
	}

	// ContentType: 0x14-0x17
	if !(0x14..=0x17).contains(&data[0]) {
		return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
	}

	// Version Major must be 3
	if data[1] != 0x03 {
		return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
	}

	let record_version = match data[2] {
		0x00 => "3.0",
		0x01 => "1.0",
		0x02 => "1.1",
		0x03 => "1.2", // Also used for TLS 1.3 in record layer
		0x04 => "1.3",
		_ => return (DetectionStatus::NoMatch, ProtocolVersion::Unknown),
	};

	let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
	if record_len == 0 || record_len > 16384 {
		return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
	}

	// For Handshake (0x16), try to see ClientHello version
	if data[0] == 0x16 && data.len() >= 11 {
		let hs_type = data[5];
		if hs_type == 0x01 {
			// ClientHello
			// The version in ClientHello is at offset 9
			let client_version = match (data[9], data[10]) {
				(0x03, 0x03) => "1.2",
				(0x03, 0x04) => "1.3",
				(0x03, 0x02) => "1.1",
				(0x03, 0x01) => "1.0",
				(0x03, 0x00) => "3.0",
				_ => record_version,
			};
			return (DetectionStatus::Match, ProtocolVersion::Tls(client_version));
		}
	}

	(DetectionStatus::Match, ProtocolVersion::Tls(record_version))
}

fn detect_sslv2(data: &[u8]) -> bool {
	if data.len() < 11 {
		return false;
	}
	if data[2] != 0x01 {
		return false;
	}
	let record_length = (u16::from(data[0] & 0x7F) << 8) | u16::from(data[1]);
	if record_length < 9 {
		return false;
	}
	true
}

pub(crate) fn detect(data: &[u8]) -> bool {
	matches!(probe(data).0, DetectionStatus::Match)
}
