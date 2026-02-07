/* src/protocols/ssh.rs */
use crate::{DetectionStatus, ProtocolVersion};

/// Probes for SSH protocol and version.
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

	let version_str = if data.starts_with(b"SSH-2.0-") || data.starts_with(b"SSH-1.99-") {
		"2.0"
	} else if data.starts_with(b"SSH-1.5-") {
		"1.5"
	} else {
		return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
	};

	let limit = data.len().min(64);
	let mut found_nl = false;
	for &b in &data[4..limit] {
		if b == b'\n' {
			found_nl = true;
			break;
		}
		if b != b'\r' && !(32..=126).contains(&b) {
			return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
		}
	}

	if found_nl || data.len() >= 16 {
		(DetectionStatus::Match, ProtocolVersion::Ssh(version_str))
	} else {
		(DetectionStatus::Incomplete, ProtocolVersion::Unknown)
	}
}
