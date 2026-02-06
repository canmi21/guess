/* src/lib.rs */

#![deny(missing_docs)]
/* src/lib.rs */
#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

//! # Guess
//!
//! High-performance zero-copy network protocol detection from first bytes.
//!
//! `guess` is designed for scenarios where you need to identify the application-layer
//! protocol of a new connection as quickly as possible, typically by inspecting only
//! the first 64 bytes of data.

mod builder;
#[cfg(feature = "std")]
mod chain;
mod detector;
mod protocols;

pub use builder::ProtocolDetectorBuilder;
#[cfg(feature = "std")]
pub use chain::ProtocolChainBuilder;
pub use detector::{ProtocolDetector, Tcp, Udp, Unknown};
use thiserror::Error;

/// Maximum bytes to inspect for protocol detection by default.
pub const MAX_INSPECT_BYTES: usize = 64;

/// Errors that can occur during protocol detection.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DetectionError {
	/// Data is insufficient to perform the detection.
	#[error("insufficient data: need at least {required} bytes, but got {got}")]
	InsufficientData {
		/// The minimum number of bytes required for detection.
		required: usize,
		/// The number of bytes actually provided.
		got: usize,
	},
	/// The requested protocol is not enabled in the current detector or build.
	#[error("protocol {0:?} is not enabled")]
	ProtocolNotEnabled(Protocol),
}

/// Result type for protocol detection operations.
pub type DetectionResult<T> = Result<T, DetectionError>;

/// Supported protocols for detection.
///
/// Each variant corresponds to a feature flag. If the feature is not enabled,
/// the variant will be unavailable at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Protocol {
	/// HTTP protocol (matches GET, POST, etc., or HTTP/1.x, HTTP/2 response headers).
	#[cfg(feature = "http")]
	Http,
	/// IMAP protocol (Internet Message Access Protocol).
	#[cfg(feature = "imap")]
	Imap,
	/// TLS protocol (SSL/TLS record layer detection).
	#[cfg(feature = "tls")]
	Tls,
	/// SSH protocol (matches SSH-2.0 or SSH-1.99 identification strings).
	#[cfg(feature = "ssh")]
	Ssh,
	/// STUN protocol (Session Traversal Utilities for NAT).
	#[cfg(feature = "stun")]
	Stun,
	/// DNS protocol (matches both UDP and TCP DNS headers).
	#[cfg(feature = "dns")]
	Dns,
	/// FTP protocol (File Transfer Protocol).
	#[cfg(feature = "ftp")]
	Ftp,
	/// DHCP protocol (matches BOOTP/DHCP header).
	#[cfg(feature = "dhcp")]
	Dhcp,
	/// NTP protocol (Network Time Protocol).
	#[cfg(feature = "ntp")]
	Ntp,
	/// QUIC protocol (matches Initial packets with Long Header).
	#[cfg(feature = "quic")]
	Quic,
	/// MySQL protocol (matches initial Handshake phase).
	#[cfg(feature = "mysql")]
	Mysql,
	/// PostgreSQL protocol (matches StartupMessage or SSLRequest).
	#[cfg(feature = "postgres")]
	Postgres,
	/// Redis protocol (RESP).
	#[cfg(feature = "redis")]
	Redis,
	/// SMB protocol (Server Message Block).
	#[cfg(feature = "smb")]
	Smb,
	/// SIP protocol (Session Initiation Protocol).
	#[cfg(feature = "sip")]
	Sip,
	/// RTSP protocol (Real-Time Streaming Protocol).
	#[cfg(feature = "rtsp")]
	Rtsp,
	/// MQTT protocol (matches CONNECT packets).
	#[cfg(feature = "mqtt")]
	Mqtt,
	/// SMTP protocol (Simple Mail Transfer Protocol).
	#[cfg(feature = "smtp")]
	Smtp,
	/// POP3 protocol (Post Office Protocol version 3).
	#[cfg(feature = "pop3")]
	Pop3,
}

impl Protocol {
	/// Checks if the provided data matches this protocol.
	///
	/// This is a low-level API for verifying a single protocol without creating a detector.
	///
	/// # Errors
	///
	/// Returns [`DetectionError::InsufficientData`] if the data is shorter than [`Self::min_bytes`].
	#[inline(always)]
	pub fn detect(&self, data: &[u8]) -> DetectionResult<bool> {
		let min = self.min_bytes();
		if data.len() < min {
			return Err(DetectionError::InsufficientData {
				required: min,
				got: data.len(),
			});
		}

		let matched = match self {
			#[cfg(feature = "http")]
			Self::Http => protocols::http::detect(data),
			#[cfg(feature = "imap")]
			Self::Imap => protocols::imap::detect(data),
			#[cfg(feature = "tls")]
			Self::Tls => protocols::tls::detect(data),
			#[cfg(feature = "ssh")]
			Self::Ssh => protocols::ssh::detect(data),
			#[cfg(feature = "stun")]
			Self::Stun => protocols::stun::detect(data),
			#[cfg(feature = "dns")]
			Self::Dns => protocols::dns::detect(data),
			#[cfg(feature = "ftp")]
			Self::Ftp => protocols::ftp::detect(data),
			#[cfg(feature = "dhcp")]
			Self::Dhcp => protocols::dhcp::detect(data),
			#[cfg(feature = "ntp")]
			Self::Ntp => protocols::ntp::detect(data),
			#[cfg(feature = "quic")]
			Self::Quic => protocols::quic::detect(data),
			#[cfg(feature = "mysql")]
			Self::Mysql => protocols::mysql::detect(data),
			#[cfg(feature = "postgres")]
			Self::Postgres => protocols::postgres::detect(data),
			#[cfg(feature = "redis")]
			Self::Redis => protocols::redis::detect(data),
			#[cfg(feature = "smb")]
			Self::Smb => protocols::smb::detect(data),
			#[cfg(feature = "sip")]
			Self::Sip => protocols::sip::detect(data),
			#[cfg(feature = "rtsp")]
			Self::Rtsp => protocols::rtsp::detect(data),
			#[cfg(feature = "mqtt")]
			Self::Mqtt => protocols::mqtt::detect(data),
			#[cfg(feature = "smtp")]
			Self::Smtp => protocols::smtp::detect(data),
			#[cfg(feature = "pop3")]
			Self::Pop3 => protocols::pop3::detect(data),
			#[allow(unreachable_patterns)]
			_ => false,
		};

		Ok(matched)
	}

	/// Returns the minimum number of bytes required to identify this protocol.
	///
	/// For most protocols, this is between 4 and 12 bytes.
	#[inline(always)]
	#[must_use]
	pub const fn min_bytes(&self) -> usize {
		match self {
			#[cfg(feature = "http")]
			Self::Http => 4,
			#[cfg(feature = "imap")]
			Self::Imap => 5,
			#[cfg(feature = "tls")]
			Self::Tls => 5,
			#[cfg(feature = "ssh")]
			Self::Ssh => 4,
			#[cfg(feature = "stun")]
			Self::Stun => 20,
			#[cfg(feature = "dns")]
			Self::Dns => 12, // For UDP, TCP needs 14 but we handle it
			#[cfg(feature = "ftp")]
			Self::Ftp => 5,
			#[cfg(feature = "dhcp")]
			Self::Dhcp => 44,
			#[cfg(feature = "ntp")]
			Self::Ntp => 48,
			#[cfg(feature = "quic")]
			Self::Quic => 5,
			#[cfg(feature = "mysql")]
			Self::Mysql => 5,
			#[cfg(feature = "postgres")]
			Self::Postgres => 8,
			#[cfg(feature = "redis")]
			Self::Redis => 1,
			#[cfg(feature = "smb")]
			Self::Smb => 4,
			#[cfg(feature = "sip")]
			Self::Sip => 12,
			#[cfg(feature = "rtsp")]
			Self::Rtsp => 14,
			#[cfg(feature = "mqtt")]
			Self::Mqtt => 7,
			#[cfg(feature = "smtp")]
			Self::Smtp => 5,
			#[cfg(feature = "pop3")]
			Self::Pop3 => 5,
			#[allow(unreachable_patterns)]
			_ => 1, // Fallback for when no features are enabled
		}
	}
}
