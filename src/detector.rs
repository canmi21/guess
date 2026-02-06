/* src/detector.rs */

use crate::{DetectionResult, Protocol};
use core::marker::PhantomData;

/// Marker for TCP transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tcp;
/// Marker for UDP transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Udp;
/// Marker for unknown or mixed transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unknown;

/// Protocol detector with type-state for transport layer.
///
/// Use [`ProtocolDetector::builder()`] to create a new instance tailored for TCP or UDP.
#[derive(Debug, Clone)]
pub struct ProtocolDetector<Transport = Unknown> {
	pub(crate) enabled: ProtocolSet,
	#[cfg(feature = "std")]
	pub(crate) priority_order: Option<Vec<Protocol>>,
	pub(crate) max_inspect_bytes: usize,
	_transport: PhantomData<Transport>,
}

#[derive(Default, Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct ProtocolSet {
	pub http: bool,
	pub tls: bool,
	pub ssh: bool,
	pub dns: bool,
	pub quic: bool,
	pub mysql: bool,
	pub postgres: bool,
	pub redis: bool,
	pub mqtt: bool,
}

impl ProtocolSet {
	/// Returns the maximum bytes required to check any of the enabled protocols.
	pub(crate) fn max_bytes_required(&self) -> usize {
		let _ = self;
		let mut max = 0;
		let _ = &mut max;

		#[cfg(feature = "http")]
		if self.http {
			max = max.max(Protocol::Http.min_bytes());
		}
		#[cfg(feature = "tls")]
		if self.tls {
			max = max.max(Protocol::Tls.min_bytes());
		}
		#[cfg(feature = "ssh")]
		if self.ssh {
			max = max.max(Protocol::Ssh.min_bytes());
		}
		#[cfg(feature = "dns")]
		if self.dns {
			max = max.max(Protocol::Dns.min_bytes());
		}
		#[cfg(feature = "quic")]
		if self.quic {
			max = max.max(Protocol::Quic.min_bytes());
		}
		#[cfg(feature = "mysql")]
		if self.mysql {
			max = max.max(Protocol::Mysql.min_bytes());
		}
		#[cfg(feature = "postgres")]
		if self.postgres {
			max = max.max(Protocol::Postgres.min_bytes());
		}
		#[cfg(feature = "redis")]
		if self.redis {
			max = max.max(Protocol::Redis.min_bytes());
		}
		#[cfg(feature = "mqtt")]
		if self.mqtt {
			max = max.max(Protocol::Mqtt.min_bytes());
		}

		if max == 0 { 1 } else { max }
	}
}

impl ProtocolDetector<Unknown> {
	/// Creates a new builder for configuring the detector.
	#[must_use]
	pub fn builder() -> crate::ProtocolDetectorBuilder<Unknown> {
		crate::ProtocolDetectorBuilder::new()
	}

	/// Creates a new custom chain builder to define a specific detection order.
	#[cfg(feature = "std")]
	#[must_use]
	pub fn chain() -> crate::ProtocolChainBuilder {
		crate::ProtocolChainBuilder::new()
	}

	/// Creates a detector containing all protocols enabled at compile time.
	#[must_use]
	pub fn all_protocols() -> Self {
		Self::builder().all().build()
	}

	/// Creates a detector containing common protocols (HTTP, TLS, SSH, DNS).
	#[must_use]
	pub fn common_protocols() -> Self {
		let enabled = ProtocolSet {
			#[cfg(feature = "http")]
			http: true,
			#[cfg(feature = "tls")]
			tls: true,
			#[cfg(feature = "ssh")]
			ssh: true,
			#[cfg(feature = "dns")]
			dns: true,
			..ProtocolSet::default()
		};
		Self::new(enabled, crate::MAX_INSPECT_BYTES)
	}

	/// Detects the protocol from the given data by checking all enabled protocols.
	///
	/// Only inspects up to `max_inspect_bytes` (default 64). If the data is longer,
	/// it will be truncated for detection purposes.
	///
	/// # Errors
	///
	/// Returns [`DetectionError::InsufficientData`](crate::DetectionError::InsufficientData)
	/// if the data is shorter than the minimum bytes required for any enabled protocol.
	pub fn detect(&self, data: &[u8]) -> DetectionResult<Option<Protocol>> {
		let _ = self;
		let limit = data.len().min(self.max_inspect_bytes);
		let data = &data[..limit];

		#[cfg(feature = "tracing")]
		tracing::trace!(
			len = data.len(),
			max_inspect = self.max_inspect_bytes,
			"starting protocol detection (any)"
		);

		#[cfg(feature = "std")]
		if let Some(order) = &self.priority_order {
			for protocol in order {
				if protocol.detect(data)? {
					#[cfg(feature = "tracing")]
					tracing::debug!(protocol = ?protocol, "protocol detected via custom order");
					return Ok(Some(*protocol));
				}
			}
			return Ok(None);
		}

		// Default optimized order
		#[allow(unused_imports)]
		use crate::protocols::*;

		#[cfg(feature = "ssh")]
		if self.enabled.ssh && ssh::detect(data) {
			return Ok(Some(Protocol::Ssh));
		}
		#[cfg(feature = "tls")]
		if self.enabled.tls && tls::detect(data) {
			return Ok(Some(Protocol::Tls));
		}
		#[cfg(feature = "http")]
		if self.enabled.http && http::detect(data) {
			return Ok(Some(Protocol::Http));
		}
		#[cfg(feature = "dns")]
		if self.enabled.dns && dns::detect(data) {
			return Ok(Some(Protocol::Dns));
		}
		#[cfg(feature = "quic")]
		if self.enabled.quic && quic::detect(data) {
			return Ok(Some(Protocol::Quic));
		}
		#[cfg(feature = "mysql")]
		if self.enabled.mysql && mysql::detect(data) {
			return Ok(Some(Protocol::Mysql));
		}
		#[cfg(feature = "postgres")]
		if self.enabled.postgres && postgres::detect(data) {
			return Ok(Some(Protocol::Postgres));
		}
		#[cfg(feature = "redis")]
		if self.enabled.redis && redis::detect(data) {
			return Ok(Some(Protocol::Redis));
		}
		#[cfg(feature = "mqtt")]
		if self.enabled.mqtt && mqtt::detect(data) {
			return Ok(Some(Protocol::Mqtt));
		}

		let _ = data; // Prevent unused_variables warning
		Ok(None)
	}

	/// Detects all matching protocols from the given data.
	///
	/// Useful for debugging when multiple protocols might match a prefix.
	#[cfg(feature = "std")]
	#[must_use]
	pub fn detect_all(&self, data: &[u8]) -> Vec<Protocol> {
		let _ = self;
		let mut results = Vec::new();
		let _ = &mut results;
		let limit = data.len().min(self.max_inspect_bytes);
		let data = &data[..limit];

		#[cfg(feature = "ssh")]
		if Protocol::Ssh.detect(data) == Ok(true) {
			results.push(Protocol::Ssh);
		}
		#[cfg(feature = "tls")]
		if Protocol::Tls.detect(data) == Ok(true) {
			results.push(Protocol::Tls);
		}
		#[cfg(feature = "http")]
		if Protocol::Http.detect(data) == Ok(true) {
			results.push(Protocol::Http);
		}
		#[cfg(feature = "dns")]
		if Protocol::Dns.detect(data) == Ok(true) {
			results.push(Protocol::Dns);
		}
		#[cfg(feature = "quic")]
		if Protocol::Quic.detect(data) == Ok(true) {
			results.push(Protocol::Quic);
		}
		#[cfg(feature = "mysql")]
		if Protocol::Mysql.detect(data) == Ok(true) {
			results.push(Protocol::Mysql);
		}
		#[cfg(feature = "postgres")]
		if Protocol::Postgres.detect(data) == Ok(true) {
			results.push(Protocol::Postgres);
		}
		#[cfg(feature = "redis")]
		if Protocol::Redis.detect(data) == Ok(true) {
			results.push(Protocol::Redis);
		}
		#[cfg(feature = "mqtt")]
		if Protocol::Mqtt.detect(data) == Ok(true) {
			results.push(Protocol::Mqtt);
		}

		let _ = data;
		results
	}
}

impl<T> ProtocolDetector<T> {
	pub(crate) fn new(enabled: ProtocolSet, max_inspect_bytes: usize) -> Self {
		Self {
			enabled,
			#[cfg(feature = "std")]
			priority_order: None,
			max_inspect_bytes,
			_transport: PhantomData,
		}
	}

	#[cfg(feature = "std")]
	pub(crate) fn with_order(order: Vec<Protocol>, max_inspect_bytes: usize) -> Self {
		let mut enabled = ProtocolSet::default();
		let _ = &mut enabled;
		for p in &order {
			match p {
				#[cfg(feature = "http")]
				Protocol::Http => enabled.http = true,
				#[cfg(feature = "tls")]
				Protocol::Tls => enabled.tls = true,
				#[cfg(feature = "ssh")]
				Protocol::Ssh => enabled.ssh = true,
				#[cfg(feature = "dns")]
				Protocol::Dns => enabled.dns = true,
				#[cfg(feature = "quic")]
				Protocol::Quic => enabled.quic = true,
				#[cfg(feature = "mysql")]
				Protocol::Mysql => enabled.mysql = true,
				#[cfg(feature = "postgres")]
				Protocol::Postgres => enabled.postgres = true,
				#[cfg(feature = "redis")]
				Protocol::Redis => enabled.redis = true,
				#[cfg(feature = "mqtt")]
				Protocol::Mqtt => enabled.mqtt = true,
				#[allow(unreachable_patterns)]
				_ => {}
			}
		}

		Self {
			enabled,
			priority_order: Some(order),
			max_inspect_bytes,
			_transport: PhantomData,
		}
	}

	/// Gets the minimum bytes required for detection among enabled protocols.
	#[must_use]
	pub fn min_bytes_required(&self) -> usize {
		self.enabled.max_bytes_required()
	}
}

impl ProtocolDetector<Tcp> {
	/// Detects the protocol from the given data. Returns the first match.
	///
	/// Only inspects up to `max_inspect_bytes` (default 64). If the data is longer,
	/// it will be truncated for detection purposes.
	///
	/// # Errors
	///
	/// Returns [`DetectionError::InsufficientData`](crate::DetectionError::InsufficientData)
	/// if the data is shorter than the minimum bytes required.
	pub fn detect(&self, data: &[u8]) -> DetectionResult<Option<Protocol>> {
		let _ = self;
		let limit = data.len().min(self.max_inspect_bytes);
		let data = &data[..limit];

		#[cfg(feature = "tracing")]
		tracing::trace!(
			len = data.len(),
			max_inspect = self.max_inspect_bytes,
			"detecting TCP protocol"
		);

		#[cfg(feature = "std")]
		if let Some(order) = &self.priority_order {
			for protocol in order {
				if protocol.detect(data)? {
					return Ok(Some(*protocol));
				}
			}
			return Ok(None);
		}

		#[allow(unused_imports)]
		use crate::protocols::*;

		#[cfg(feature = "ssh")]
		if self.enabled.ssh && ssh::detect(data) {
			return Ok(Some(Protocol::Ssh));
		}
		#[cfg(feature = "tls")]
		if self.enabled.tls && tls::detect(data) {
			return Ok(Some(Protocol::Tls));
		}
		#[cfg(feature = "http")]
		if self.enabled.http && http::detect(data) {
			return Ok(Some(Protocol::Http));
		}
		#[cfg(feature = "mysql")]
		if self.enabled.mysql && mysql::detect(data) {
			return Ok(Some(Protocol::Mysql));
		}
		#[cfg(feature = "postgres")]
		if self.enabled.postgres && postgres::detect(data) {
			return Ok(Some(Protocol::Postgres));
		}
		#[cfg(feature = "redis")]
		if self.enabled.redis && redis::detect(data) {
			return Ok(Some(Protocol::Redis));
		}
		#[cfg(feature = "mqtt")]
		if self.enabled.mqtt && mqtt::detect(data) {
			return Ok(Some(Protocol::Mqtt));
		}

		let _ = data;
		Ok(None)
	}

	/// Creates a detector for common TCP protocols (HTTP, TLS, SSH).
	#[cfg(all(feature = "http", feature = "tls", feature = "ssh"))]
	#[must_use]
	pub fn common() -> Self {
		let enabled = ProtocolSet {
			http: true,
			tls: true,
			ssh: true,
			..ProtocolSet::default()
		};
		Self::new(enabled, crate::MAX_INSPECT_BYTES)
	}
}

impl ProtocolDetector<Udp> {
	/// Detects the protocol from the given data. Returns the first match.
	///
	/// Only inspects up to `max_inspect_bytes` (default 64). If the data is longer,
	/// it will be truncated for detection purposes.
	///
	/// # Errors
	///
	/// Returns [`DetectionError::InsufficientData`](crate::DetectionError::InsufficientData)
	/// if the data is shorter than the minimum bytes required.
	pub fn detect(&self, data: &[u8]) -> DetectionResult<Option<Protocol>> {
		let _ = self;
		let limit = data.len().min(self.max_inspect_bytes);
		let data = &data[..limit];

		#[cfg(feature = "tracing")]
		tracing::trace!(
			len = data.len(),
			max_inspect = self.max_inspect_bytes,
			"detecting UDP protocol"
		);

		#[cfg(feature = "std")]
		if let Some(order) = &self.priority_order {
			for protocol in order {
				if protocol.detect(data)? {
					return Ok(Some(*protocol));
				}
			}
			return Ok(None);
		}

		#[allow(unused_imports)]
		use crate::protocols::*;

		#[cfg(feature = "dns")]
		if self.enabled.dns && dns::detect(data) {
			return Ok(Some(Protocol::Dns));
		}
		#[cfg(feature = "quic")]
		if self.enabled.quic && quic::detect(data) {
			return Ok(Some(Protocol::Quic));
		}

		let _ = data;
		Ok(None)
	}

	/// Creates a detector for common UDP protocols (DNS, QUIC).
	#[cfg(all(feature = "dns", feature = "quic"))]
	#[must_use]
	pub fn common() -> Self {
		let enabled = ProtocolSet {
			dns: true,
			quic: true,
			..ProtocolSet::default()
		};
		Self::new(enabled, crate::MAX_INSPECT_BYTES)
	}
}
