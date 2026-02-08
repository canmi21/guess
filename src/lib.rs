/* src/lib.rs */
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

//! # Guess
//!
//! High-performance zero-copy network protocol detection with version awareness.

/// Protocol detector builder module.
mod builder;
/// Custom protocol detection chain module.
#[cfg(feature = "std")]
mod chain;
/// Main protocol detector implementation.
mod detector;
/// Individual protocol detection logic.
mod protocols;

pub use builder::ProtocolDetectorBuilder;
#[cfg(feature = "std")]
pub use chain::ProtocolChainBuilder;
pub use detector::{ProtocolDetector, Tcp, Udp, Unknown};
use thiserror::Error;

/// Maximum bytes to inspect for protocol detection by default.
pub const MAX_INSPECT_BYTES: usize = 64;

/// Detection status for a single protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionStatus {
	/// Confirmed match.
	Match,
	/// Confirmed no match.
	NoMatch,
	/// Prefix matches, but more data is needed for confirmation.
	Incomplete,
}

/// Protocol version information (Zero-copy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProtocolVersion<'a> {
	/// HTTP version (e.g., "1.1", "2.0")
	Http(&'a str),
	/// TLS version (e.g., "1.2", "1.3")
	Tls(&'a str),
	/// SSH version (e.g., "2.0")
	Ssh(&'a str),
	/// Redis RESP version (2 or 3)
	Redis(u8),
	/// Version unknown or not applicable
	Unknown,
}

/// Detailed protocol information including version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolInfo<'a> {
	/// The detected protocol.
	pub protocol: Protocol,
	/// The detected version.
	pub version: ProtocolVersion<'a>,
}

/// Errors that can occur during protocol detection.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DetectionError {
	/// Data is insufficient to perform the detection.
	#[error("insufficient data: need more bytes to confirm protocol")]
	InsufficientData,
	/// The requested protocol is not enabled.
	#[error("protocol {0:?} is not enabled")]
	ProtocolNotEnabled(Protocol),
}

/// Result type for protocol detection operations.
pub type DetectionResult<T> = Result<T, DetectionError>;

/// Supported protocols for detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Protocol {
	/// HTTP protocol.
	#[cfg(feature = "http")]
	Http,
	/// TLS protocol.
	#[cfg(feature = "tls")]
	Tls,
	/// SSH protocol.
	#[cfg(feature = "ssh")]
	Ssh,
	/// DNS protocol.
	#[cfg(feature = "dns")]
	Dns,
	/// QUIC protocol.
	#[cfg(feature = "quic")]
	Quic,
	/// `MySQL` protocol.
	#[cfg(feature = "mysql")]
	Mysql,
	/// `PostgreSQL` protocol.
	#[cfg(feature = "postgres")]
	Postgres,
	/// Redis protocol.
	#[cfg(feature = "redis")]
	Redis,
	/// MQTT protocol.
	#[cfg(feature = "mqtt")]
	Mqtt,
	/// SMTP protocol.
	#[cfg(feature = "smtp")]
	Smtp,
	/// POP3 protocol.
	#[cfg(feature = "pop3")]
	Pop3,
	/// IMAP protocol.
	#[cfg(feature = "imap")]
	Imap,
	/// FTP protocol.
	#[cfg(feature = "ftp")]
	Ftp,
	/// SMB protocol.
	#[cfg(feature = "smb")]
	Smb,
	/// STUN protocol.
	#[cfg(feature = "stun")]
	Stun,
	/// SIP protocol.
	#[cfg(feature = "sip")]
	Sip,
	/// RTSP protocol.
	#[cfg(feature = "rtsp")]
	Rtsp,
	/// DHCP protocol.
	#[cfg(feature = "dhcp")]
	Dhcp,
	/// NTP protocol.
	#[cfg(feature = "ntp")]
	Ntp,
}

impl Protocol {
	/// Checks if the provided data matches this protocol.
	#[inline(always)]
	pub fn detect(&self, data: &[u8]) -> DetectionResult<bool> {
		Ok(matches!(self.probe(data), DetectionStatus::Match))
	}

	/// Probes the data and returns the detection status.
	#[inline(always)]
	#[must_use]
	pub fn probe(&self, data: &[u8]) -> DetectionStatus {
		match self.probe_info(data) {
			(DetectionStatus::Match, _) => DetectionStatus::Match,
			(status, _) => status,
		}
	}

	/// Probes the data and returns status plus version info.
	#[inline(always)]
	#[must_use]
	#[allow(unused_variables)]
	pub fn probe_info<'a>(&self, data: &'a [u8]) -> (DetectionStatus, ProtocolVersion<'a>) {
		if data.len() < self.min_bytes() {
			return (DetectionStatus::Incomplete, ProtocolVersion::Unknown);
		}
		match self {
			#[cfg(feature = "http")]
			Self::Http => protocols::http::probe(data),
			#[cfg(feature = "tls")]
			Self::Tls => protocols::tls::probe(data),
			#[cfg(feature = "ssh")]
			Self::Ssh => protocols::ssh::probe(data),
			#[cfg(feature = "redis")]
			Self::Redis => protocols::redis::probe(data),
			#[cfg(feature = "dns")]
			Self::Dns => (
				bool_to_status(protocols::dns::detect(data)),
				ProtocolVersion::Unknown,
			),
			#[cfg(feature = "quic")]
			Self::Quic => (
				bool_to_status(protocols::quic::detect(data)),
				ProtocolVersion::Unknown,
			),
			#[cfg(feature = "mysql")]
			Self::Mysql => (
				bool_to_status(protocols::mysql::detect(data)),
				ProtocolVersion::Unknown,
			),
			#[cfg(feature = "postgres")]
			Self::Postgres => (
				bool_to_status(protocols::postgres::detect(data)),
				ProtocolVersion::Unknown,
			),
			#[cfg(feature = "mqtt")]
			Self::Mqtt => (
				bool_to_status(protocols::mqtt::detect(data)),
				ProtocolVersion::Unknown,
			),
			#[cfg(feature = "smtp")]
			Self::Smtp => (
				bool_to_status(protocols::smtp::detect(data)),
				ProtocolVersion::Unknown,
			),
			#[cfg(feature = "pop3")]
			Self::Pop3 => (
				bool_to_status(protocols::pop3::detect(data)),
				ProtocolVersion::Unknown,
			),
			#[cfg(feature = "imap")]
			Self::Imap => (
				bool_to_status(protocols::imap::detect(data)),
				ProtocolVersion::Unknown,
			),
			#[cfg(feature = "ftp")]
			Self::Ftp => (
				bool_to_status(protocols::ftp::detect(data)),
				ProtocolVersion::Unknown,
			),
			#[cfg(feature = "smb")]
			Self::Smb => (
				bool_to_status(protocols::smb::detect(data)),
				ProtocolVersion::Unknown,
			),
			#[cfg(feature = "stun")]
			Self::Stun => (
				bool_to_status(protocols::stun::detect(data)),
				ProtocolVersion::Unknown,
			),
			#[cfg(feature = "sip")]
			Self::Sip => (
				bool_to_status(protocols::sip::detect(data)),
				ProtocolVersion::Unknown,
			),
			#[cfg(feature = "rtsp")]
			Self::Rtsp => (
				bool_to_status(protocols::rtsp::detect(data)),
				ProtocolVersion::Unknown,
			),
			#[cfg(feature = "dhcp")]
			Self::Dhcp => (
				bool_to_status(protocols::dhcp::detect(data)),
				ProtocolVersion::Unknown,
			),
			#[cfg(feature = "ntp")]
			Self::Ntp => (
				bool_to_status(protocols::ntp::detect(data)),
				ProtocolVersion::Unknown,
			),
			#[allow(unreachable_patterns)]
			_ => (DetectionStatus::NoMatch, ProtocolVersion::Unknown),
		}
	}

	/// Returns the minimum number of bytes required to identify this protocol.
	#[inline(always)]
	#[must_use]
	pub const fn min_bytes(&self) -> usize {
		match self {
			#[cfg(feature = "http")]
			Self::Http => 4,
			#[cfg(feature = "tls")]
			Self::Tls => 5,
			#[cfg(feature = "ssh")]
			Self::Ssh => 4,
			#[cfg(feature = "dns")]
			Self::Dns => 12,
			#[cfg(feature = "quic")]
			Self::Quic => 7,
			#[cfg(feature = "mysql")]
			Self::Mysql => 10,
			#[cfg(feature = "postgres")]
			Self::Postgres => 8,
			#[cfg(feature = "redis")]
			Self::Redis => 1,
			#[cfg(feature = "mqtt")]
			Self::Mqtt => 12,
			#[cfg(feature = "smtp")]
			Self::Smtp => 5,
			#[cfg(feature = "pop3")]
			Self::Pop3 => 5,
			#[cfg(feature = "imap")]
			Self::Imap => 5,
			#[cfg(feature = "ftp")]
			Self::Ftp => 5,
			#[cfg(feature = "smb")]
			Self::Smb => 4,
			#[cfg(feature = "stun")]
			Self::Stun => 20,
			#[cfg(feature = "sip")]
			Self::Sip => 12,
			#[cfg(feature = "rtsp")]
			Self::Rtsp => 14,
			#[cfg(feature = "dhcp")]
			Self::Dhcp => 44,
			#[cfg(feature = "ntp")]
			Self::Ntp => 48,
			#[allow(unreachable_patterns)]
			_ => 1,
		}
	}
}

/// Helper to convert boolean to detection status.
#[inline(always)]
#[allow(dead_code)]
fn bool_to_status(b: bool) -> DetectionStatus {
	if b {
		DetectionStatus::Match
	} else {
		DetectionStatus::NoMatch
	}
}

#[cfg(test)]
mod tests {
	#[allow(unused_imports)]
	use super::*;

	// ── Correct paths ──

	#[test]
	#[cfg(feature = "http")]
	fn detect_returns_true_for_valid_http() {
		let data = b"GET / HTTP/1.1\r\n";
		assert_eq!(Protocol::Http.detect(data), Ok(true));
	}

	#[test]
	#[cfg(feature = "http")]
	fn probe_returns_match_for_valid_http() {
		let data = b"GET / HTTP/1.1\r\n";
		assert_eq!(Protocol::Http.probe(data), DetectionStatus::Match);
	}

	#[test]
	#[cfg(feature = "http")]
	fn probe_info_returns_version_for_http11() {
		let data = b"GET / HTTP/1.1\r\n";
		let (status, version) = Protocol::Http.probe_info(data);
		assert_eq!(status, DetectionStatus::Match);
		assert_eq!(version, ProtocolVersion::Http("1.1"));
	}

	#[test]
	#[cfg(feature = "http")]
	fn min_bytes_http() {
		assert_eq!(Protocol::Http.min_bytes(), 4);
	}

	#[test]
	#[cfg(feature = "tls")]
	fn min_bytes_tls() {
		assert_eq!(Protocol::Tls.min_bytes(), 5);
	}

	#[test]
	#[cfg(feature = "ssh")]
	fn min_bytes_ssh() {
		assert_eq!(Protocol::Ssh.min_bytes(), 4);
	}

	#[test]
	#[cfg(feature = "redis")]
	fn min_bytes_redis() {
		assert_eq!(Protocol::Redis.min_bytes(), 1);
	}

	// ── Error paths ──

	#[test]
	#[cfg(feature = "http")]
	fn detect_returns_false_for_empty_data() {
		assert_eq!(Protocol::Http.detect(b""), Ok(false));
	}

	#[test]
	#[cfg(feature = "http")]
	fn probe_returns_incomplete_for_empty_data() {
		assert_eq!(Protocol::Http.probe(b""), DetectionStatus::Incomplete);
	}

	#[test]
	#[cfg(feature = "http")]
	fn probe_returns_no_match_for_garbage() {
		assert_eq!(
			Protocol::Http.probe(b"\xff\xff\xff\xff\xff"),
			DetectionStatus::NoMatch
		);
	}

	#[test]
	#[cfg(feature = "http")]
	fn probe_info_returns_incomplete_for_short_data() {
		let (status, version) = Protocol::Http.probe_info(&[0u8; 1]);
		assert_eq!(status, DetectionStatus::Incomplete);
		assert_eq!(version, ProtocolVersion::Unknown);
	}

	#[test]
	#[cfg(feature = "tls")]
	fn probe_info_returns_incomplete_for_short_tls_data() {
		let (status, version) = Protocol::Tls.probe_info(&[0x16, 0x03]);
		assert_eq!(status, DetectionStatus::Incomplete);
		assert_eq!(version, ProtocolVersion::Unknown);
	}

	#[test]
	#[cfg(feature = "ssh")]
	fn probe_returns_match_for_valid_ssh() {
		let data = b"SSH-2.0-OpenSSH_8.9\r\n";
		assert_eq!(Protocol::Ssh.probe(data), DetectionStatus::Match);
	}

	#[test]
	#[cfg(feature = "ssh")]
	fn probe_info_returns_ssh_version() {
		let data = b"SSH-2.0-OpenSSH_8.9\r\n";
		let (status, version) = Protocol::Ssh.probe_info(data);
		assert_eq!(status, DetectionStatus::Match);
		assert_eq!(version, ProtocolVersion::Ssh("2.0"));
	}

	#[test]
	#[cfg(feature = "tls")]
	fn probe_returns_match_for_valid_tls12_client_hello() {
		// TLS 1.2 ClientHello
		let data: &[u8] = &[
			0x16, 0x03, 0x01, 0x00, 0x05, // record header
			0x01, 0x00, 0x00, 0x01, // handshake header
			0x03, 0x03, // client version: TLS 1.2
		];
		let (status, version) = Protocol::Tls.probe_info(data);
		assert_eq!(status, DetectionStatus::Match);
		assert_eq!(version, ProtocolVersion::Tls("1.2"));
	}
}
