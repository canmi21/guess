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
	/// TLS protocol (SSL/TLS record layer detection).
	#[cfg(feature = "tls")]
	Tls,
	/// SSH protocol (matches SSH-2.0 or SSH-1.99 identification strings).
	#[cfg(feature = "ssh")]
	Ssh,
	/// DNS protocol (matches both UDP and TCP DNS headers).
	#[cfg(feature = "dns")]
	Dns,
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
	/// MQTT protocol (matches CONNECT packets).
	#[cfg(feature = "mqtt")]
	Mqtt,
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
			#[cfg(feature = "tls")]
			Self::Tls => protocols::tls::detect(data),
			#[cfg(feature = "ssh")]
			Self::Ssh => protocols::ssh::detect(data),
			#[cfg(feature = "dns")]
			Self::Dns => protocols::dns::detect(data),
			#[cfg(feature = "quic")]
			Self::Quic => protocols::quic::detect(data),
			#[cfg(feature = "mysql")]
			Self::Mysql => protocols::mysql::detect(data),
			#[cfg(feature = "postgres")]
			Self::Postgres => protocols::postgres::detect(data),
			#[cfg(feature = "redis")]
			Self::Redis => protocols::redis::detect(data),
			#[cfg(feature = "mqtt")]
			Self::Mqtt => protocols::mqtt::detect(data),
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
			#[cfg(feature = "tls")]
			Self::Tls => 5,
			#[cfg(feature = "ssh")]
			Self::Ssh => 4,
			#[cfg(feature = "dns")]
			Self::Dns => 12, // For UDP, TCP needs 14 but we handle it
			#[cfg(feature = "quic")]
			Self::Quic => 5,
			#[cfg(feature = "mysql")]
			Self::Mysql => 5,
			#[cfg(feature = "postgres")]
			Self::Postgres => 8,
			#[cfg(feature = "redis")]
			Self::Redis => 1,
			#[cfg(feature = "mqtt")]
			Self::Mqtt => 7,
			#[allow(unreachable_patterns)]
			_ => 1, // Fallback for when no features are enabled
		}
	}
}
