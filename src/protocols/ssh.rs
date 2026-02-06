/* src/protocols/ssh.rs */

use crate::{DetectionStatus, ProtocolVersion};

#[inline(always)]
pub(crate) fn probe(data: &[u8]) -> (DetectionStatus, ProtocolVersion<'_>) {
	if data.len() < 4 {
		return (DetectionStatus::Incomplete, ProtocolVersion::Unknown);
	}

	if !data.starts_with(b"SSH-") {
		return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
	}

	if data.len() < 8 {
		return (DetectionStatus::Incomplete, ProtocolVersion::Unknown);
	}

	// Extract version: SSH-2.0-... or SSH-1.99-...
	let version_str = if data.starts_with(b"SSH-2.0-") {
		"2.0"
	} else if data.starts_with(b"SSH-1.99-") {
		"2.0"
	} else if data.starts_with(b"SSH-1.5-") {
		"1.5"
	} else {
		return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
	};

	// Validate the rest of the line is ASCII
	let limit = data.len().min(64);
	let mut found_nl = false;
	for &b in &data[4..limit] {
		if b == b'\n' {
			found_nl = true;
			break;
		}
		if b != b'\r' && (b < 32 || b > 126) {
			return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
		}
	}

	if found_nl || data.len() >= 16 {
		(DetectionStatus::Match, ProtocolVersion::Ssh(version_str))
	} else {
		(DetectionStatus::Incomplete, ProtocolVersion::Unknown)
	}
}

pub(crate) fn detect(data: &[u8]) -> bool {
	matches!(probe(data).0, DetectionStatus::Match)
}
