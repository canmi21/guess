/* src/builder.rs */

use crate::detector::{ProtocolDetector, ProtocolSet, Tcp, Udp, Unknown};
use core::marker::PhantomData;

/// Builder for ProtocolDetector.
#[derive(Debug, Clone, Copy)]
pub struct ProtocolDetectorBuilder<Transport = Unknown> {
	enabled: ProtocolSet,
	max_inspect_bytes: usize,
	_transport: PhantomData<Transport>,
}

impl ProtocolDetectorBuilder<Unknown> {
	pub(crate) fn new() -> Self {
		Self {
			enabled: ProtocolSet::default(),
			max_inspect_bytes: crate::MAX_INSPECT_BYTES,
			_transport: PhantomData,
		}
	}

	/// Sets the maximum bytes to inspect.
	#[must_use]
	pub fn max_inspect_bytes(mut self, bytes: usize) -> Self {
		self.max_inspect_bytes = bytes;
		self
	}

	/// Specifies TCP transport layer.
	#[must_use]
	pub fn tcp(self) -> ProtocolDetectorBuilder<Tcp> {
		ProtocolDetectorBuilder {
			enabled: self.enabled,
			max_inspect_bytes: self.max_inspect_bytes,
			_transport: PhantomData,
		}
	}

	/// Specifies UDP transport layer.
	#[must_use]
	pub fn udp(self) -> ProtocolDetectorBuilder<Udp> {
		ProtocolDetectorBuilder {
			enabled: self.enabled,
			max_inspect_bytes: self.max_inspect_bytes,
			_transport: PhantomData,
		}
	}

	/// Enables all compiled protocols.
	#[must_use]
	pub fn all(mut self) -> Self {
		let _ = &mut self; // Suppress unused_mut if no protocols enabled
		#[cfg(feature = "http")]
		{
			self.enabled.http = true;
		}
		#[cfg(feature = "tls")]
		{
			self.enabled.tls = true;
		}
		#[cfg(feature = "ssh")]
		{
			self.enabled.ssh = true;
		}
		#[cfg(feature = "dns")]
		{
			self.enabled.dns = true;
		}
		#[cfg(feature = "quic")]
		{
			self.enabled.quic = true;
		}
		#[cfg(feature = "mysql")]
		{
			self.enabled.mysql = true;
		}
		#[cfg(feature = "postgres")]
		{
			self.enabled.postgres = true;
		}
		#[cfg(feature = "redis")]
		{
			self.enabled.redis = true;
		}
		#[cfg(feature = "mqtt")]
		{
			self.enabled.mqtt = true;
		}
		self
	}

	/// Builds the detector.
	#[must_use]
	pub fn build(self) -> ProtocolDetector<Unknown> {
		ProtocolDetector::new(self.enabled, self.max_inspect_bytes)
	}
}

impl ProtocolDetectorBuilder<Tcp> {
	/// Enables HTTP protocol.
	#[cfg(feature = "http")]
	#[must_use]
	pub fn http(mut self) -> Self {
		self.enabled.http = true;
		self
	}

	/// Enables TLS protocol.
	#[cfg(feature = "tls")]
	#[must_use]
	pub fn tls(mut self) -> Self {
		self.enabled.tls = true;
		self
	}

	/// Enables SSH protocol.
	#[cfg(feature = "ssh")]
	#[must_use]
	pub fn ssh(mut self) -> Self {
		self.enabled.ssh = true;
		self
	}

	/// Enables MySQL protocol.
	#[cfg(feature = "mysql")]
	#[must_use]
	pub fn mysql(mut self) -> Self {
		self.enabled.mysql = true;
		self
	}

	/// Enables PostgreSQL protocol.
	#[cfg(feature = "postgres")]
	#[must_use]
	pub fn postgres(mut self) -> Self {
		self.enabled.postgres = true;
		self
	}

	/// Enables Redis protocol.
	#[cfg(feature = "redis")]
	#[must_use]
	pub fn redis(mut self) -> Self {
		self.enabled.redis = true;
		self
	}

	/// Enables MQTT protocol.
	#[cfg(feature = "mqtt")]
	#[must_use]
	pub fn mqtt(mut self) -> Self {
		self.enabled.mqtt = true;
		self
	}

	/// Enables all common TCP protocols.
	#[must_use]
	pub fn all_tcp(mut self) -> Self {
		let _ = &mut self;
		#[cfg(feature = "ssh")]
		{
			self.enabled.ssh = true;
		}
		#[cfg(feature = "tls")]
		{
			self.enabled.tls = true;
		}
		#[cfg(feature = "http")]
		{
			self.enabled.http = true;
		}
		#[cfg(feature = "redis")]
		{
			self.enabled.redis = true;
		}
		#[cfg(feature = "mysql")]
		{
			self.enabled.mysql = true;
		}
		#[cfg(feature = "postgres")]
		{
			self.enabled.postgres = true;
		}
		#[cfg(feature = "mqtt")]
		{
			self.enabled.mqtt = true;
		}
		self
	}

	/// Enables all database protocols.
	#[cfg(feature = "db")]
	#[must_use]
	pub fn all_db(mut self) -> Self {
		#[cfg(feature = "mysql")]
		{
			self.enabled.mysql = true;
		}
		#[cfg(feature = "postgres")]
		{
			self.enabled.postgres = true;
		}
		#[cfg(feature = "redis")]
		{
			self.enabled.redis = true;
		}
		self
	}

	/// Builds the TCP detector.
	#[must_use]
	pub fn build(self) -> ProtocolDetector<Tcp> {
		ProtocolDetector::new(self.enabled, self.max_inspect_bytes)
	}
}

impl ProtocolDetectorBuilder<Udp> {
	/// Enables DNS protocol.
	#[cfg(feature = "dns")]
	#[must_use]
	pub fn dns(mut self) -> Self {
		self.enabled.dns = true;
		self
	}

	/// Enables QUIC protocol.
	#[cfg(feature = "quic")]
	#[must_use]
	pub fn quic(mut self) -> Self {
		self.enabled.quic = true;
		self
	}

	/// Enables all common UDP protocols.
	#[must_use]
	pub fn all_udp(mut self) -> Self {
		let _ = &mut self;
		#[cfg(feature = "dns")]
		{
			self.enabled.dns = true;
		}
		#[cfg(feature = "quic")]
		{
			self.enabled.quic = true;
		}
		self
	}

	/// Builds the UDP detector.
	#[must_use]
	pub fn build(self) -> ProtocolDetector<Udp> {
		ProtocolDetector::new(self.enabled, self.max_inspect_bytes)
	}
}
