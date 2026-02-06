/* src/protocols/redis.rs */

use crate::{DetectionStatus, ProtocolVersion};

#[inline(always)]
pub(crate) fn probe(data: &[u8]) -> (DetectionStatus, ProtocolVersion<'_>) {
	if data.is_empty() {
		return (DetectionStatus::Incomplete, ProtocolVersion::Unknown);
	}

	let first = data[0];
	let resp_ver = match first {
		// RESP2/3 prefixes
		b'+' | b'-' | b':' | b'$' | b'*' => 2,
		// RESP3 specific
		b'_' | b',' | b'#' | b'!' | b'=' | b'(' | b'%' | b'~' | b'>' => 3,
		_ => return (DetectionStatus::NoMatch, ProtocolVersion::Unknown),
	};

	// For Redis, even 1 or 2 bytes are often enough to be certain if the prefix is valid
	// and the data doesn't conflict with other protocols.
	// To fix the "custom chain" bug where Incomplete blocks lower priority matches,
	// we should return Match if we are confident.
	if data.len() >= 2 {
		// If we have at least 2 bytes and it starts with a Redis prefix,
		// it's highly likely to be Redis.
		(DetectionStatus::Match, ProtocolVersion::Redis(resp_ver))
	} else {
		(DetectionStatus::Incomplete, ProtocolVersion::Unknown)
	}
}

pub(crate) fn detect(data: &[u8]) -> bool {
	matches!(probe(data).0, DetectionStatus::Match)
}
