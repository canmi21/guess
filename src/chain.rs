/* src/chain.rs */

#[cfg(feature = "std")]
use crate::{Protocol, ProtocolDetector, Unknown};

/// Builder for creating a custom detection chain with a specific order.
#[cfg(feature = "std")]
#[derive(Debug, Default, Clone)]
pub struct ProtocolChainBuilder {
	/// Ordered list of protocols to check.
	order: Vec<Protocol>,
	/// Maximum bytes to inspect.
	max_inspect_bytes: usize,
}

#[cfg(feature = "std")]
impl ProtocolChainBuilder {
	/// Creates a new empty `ProtocolChainBuilder`.
	#[must_use]
	pub fn new() -> Self {
		Self {
			order: Vec::new(),
			max_inspect_bytes: crate::MAX_INSPECT_BYTES,
		}
	}

	/// Sets the maximum bytes to inspect.
	#[must_use]
	pub fn max_inspect_bytes(mut self, bytes: usize) -> Self {
		self.max_inspect_bytes = bytes;
		self
	}

	/// Adds HTTP to the detection chain.
	#[cfg(feature = "http")]
	#[must_use]
	pub fn http(mut self) -> Self {
		self.order.push(Protocol::Http);
		self
	}

	/// Adds TLS to the detection chain.
	#[cfg(feature = "tls")]
	#[must_use]
	pub fn tls(mut self) -> Self {
		self.order.push(Protocol::Tls);
		self
	}

	/// Adds SSH to the detection chain.
	#[cfg(feature = "ssh")]
	#[must_use]
	pub fn ssh(mut self) -> Self {
		self.order.push(Protocol::Ssh);
		self
	}

	/// Adds DNS to the detection chain.
	#[cfg(feature = "dns")]
	#[must_use]
	pub fn dns(mut self) -> Self {
		self.order.push(Protocol::Dns);
		self
	}

	/// Adds QUIC to the detection chain.
	#[cfg(feature = "quic")]
	#[must_use]
	pub fn quic(mut self) -> Self {
		self.order.push(Protocol::Quic);
		self
	}

	/// Adds `MySQL` to the detection chain.
	#[cfg(feature = "mysql")]
	#[must_use]
	pub fn mysql(mut self) -> Self {
		self.order.push(Protocol::Mysql);
		self
	}

	/// Adds `PostgreSQL` to the detection chain.
	#[cfg(feature = "postgres")]
	#[must_use]
	pub fn postgres(mut self) -> Self {
		self.order.push(Protocol::Postgres);
		self
	}

	/// Adds Redis to the detection chain.
	#[cfg(feature = "redis")]
	#[must_use]
	pub fn redis(mut self) -> Self {
		self.order.push(Protocol::Redis);
		self
	}

	/// Adds MQTT to the detection chain.
	#[cfg(feature = "mqtt")]
	#[must_use]
	pub fn mqtt(mut self) -> Self {
		self.order.push(Protocol::Mqtt);
		self
	}

	/// Adds all compiled TCP protocols in the default optimized order.
	#[must_use]
	pub fn all_tcp(mut self) -> Self {
		let _ = &mut self;
		#[cfg(feature = "ssh")]
		{
			self.order.push(Protocol::Ssh);
		}
		#[cfg(feature = "tls")]
		{
			self.order.push(Protocol::Tls);
		}
		#[cfg(feature = "http")]
		{
			self.order.push(Protocol::Http);
		}
		#[cfg(feature = "redis")]
		{
			self.order.push(Protocol::Redis);
		}
		#[cfg(feature = "mysql")]
		{
			self.order.push(Protocol::Mysql);
		}
		#[cfg(feature = "postgres")]
		{
			self.order.push(Protocol::Postgres);
		}
		#[cfg(feature = "mqtt")]
		{
			self.order.push(Protocol::Mqtt);
		}
		self
	}

	/// Adds all compiled UDP protocols.
	#[must_use]
	pub fn all_udp(mut self) -> Self {
		let _ = &mut self;
		#[cfg(feature = "dns")]
		{
			self.order.push(Protocol::Dns);
		}
		#[cfg(feature = "quic")]
		{
			self.order.push(Protocol::Quic);
		}
		self
	}

	/// Adds all compiled database protocols.
	#[must_use]
	pub fn all_db(mut self) -> Self {
		let _ = &mut self;
		#[cfg(feature = "redis")]
		{
			self.order.push(Protocol::Redis);
		}
		#[cfg(feature = "mysql")]
		{
			self.order.push(Protocol::Mysql);
		}
		#[cfg(feature = "postgres")]
		{
			self.order.push(Protocol::Postgres);
		}
		self
	}

	/// Adds all compiled Web protocols (HTTP, TLS, QUIC).
	#[must_use]
	pub fn all_web(mut self) -> Self {
		let _ = &mut self;
		#[cfg(feature = "http")]
		{
			self.order.push(Protocol::Http);
		}
		#[cfg(feature = "tls")]
		{
			self.order.push(Protocol::Tls);
		}
		#[cfg(feature = "quic")]
		{
			self.order.push(Protocol::Quic);
		}
		self
	}

	/// Builds the chain from a slice of protocols.
	#[must_use]
	pub fn from_slice(protocols: &[Protocol]) -> Self {
		Self {
			order: protocols.to_vec(),
			max_inspect_bytes: crate::MAX_INSPECT_BYTES,
		}
	}

	/// Builds the detector.
	#[must_use]
	pub fn build(self) -> ProtocolDetector<Unknown> {
		ProtocolDetector::with_order(self.order, self.max_inspect_bytes)
	}
}
