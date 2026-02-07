/* src/protocols/redis.rs */
use crate::{DetectionStatus, ProtocolVersion};

/// Probes for Redis (RESP) protocol and version.
#[inline(always)]
pub(crate) fn probe(data: &[u8]) -> (DetectionStatus, ProtocolVersion<'_>) {
	if data.is_empty() {
		return (DetectionStatus::Incomplete, ProtocolVersion::Unknown);
	}

	let first = data[0];
	let resp_ver = match first {
		b'+' | b'-' | b':' | b'$' | b'*' => 2,
		b'_' | b',' | b'#' | b'!' | b'=' | b'(' | b'%' | b'~' | b'>' => 3,
		_ => return (DetectionStatus::NoMatch, ProtocolVersion::Unknown),
	};

	if data.len() >= 2 {
		(DetectionStatus::Match, ProtocolVersion::Redis(resp_ver))
	} else {
		(DetectionStatus::Incomplete, ProtocolVersion::Unknown)
	}
}
