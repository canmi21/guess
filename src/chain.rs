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
		#[cfg(feature = "smtp")]
		{
			self.order.push(Protocol::Smtp);
		}
		#[cfg(feature = "pop3")]
		{
			self.order.push(Protocol::Pop3);
		}
		#[cfg(feature = "imap")]
		{
			self.order.push(Protocol::Imap);
		}
		#[cfg(feature = "ftp")]
		{
			self.order.push(Protocol::Ftp);
		}
		#[cfg(feature = "smb")]
		{
			self.order.push(Protocol::Smb);
		}
		#[cfg(feature = "sip")]
		{
			self.order.push(Protocol::Sip);
		}
		#[cfg(feature = "rtsp")]
		{
			self.order.push(Protocol::Rtsp);
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
		#[cfg(feature = "dhcp")]
		{
			self.order.push(Protocol::Dhcp);
		}
		#[cfg(feature = "ntp")]
		{
			self.order.push(Protocol::Ntp);
		}
		#[cfg(feature = "stun")]
		{
			self.order.push(Protocol::Stun);
		}
		#[cfg(feature = "sip")]
		{
			self.order.push(Protocol::Sip);
		}
		#[cfg(feature = "rtsp")]
		{
			self.order.push(Protocol::Rtsp);
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::DetectionError;

	// ── Correct paths ──

	#[test]
	#[cfg(all(feature = "ssh", feature = "http"))]
	fn chain_respects_ordering_ssh_first() {
		let detector = ProtocolChainBuilder::new().ssh().http().build();
		let ssh_data = b"SSH-2.0-OpenSSH_8.9\r\n";
		assert_eq!(detector.detect(ssh_data).unwrap(), Some(Protocol::Ssh));

		let http_data = b"GET / HTTP/1.1\r\n";
		assert_eq!(detector.detect(http_data).unwrap(), Some(Protocol::Http));
	}

	#[test]
	#[cfg(feature = "http")]
	fn all_tcp_detects_http() {
		let detector = ProtocolChainBuilder::new().all_tcp().build();
		let data = b"GET / HTTP/1.1\r\n";
		assert_eq!(detector.detect(data).unwrap(), Some(Protocol::Http));
	}

	#[test]
	#[cfg(feature = "ssh")]
	fn all_tcp_detects_ssh() {
		let detector = ProtocolChainBuilder::new().all_tcp().build();
		let data = b"SSH-2.0-OpenSSH_8.9\r\n";
		assert_eq!(detector.detect(data).unwrap(), Some(Protocol::Ssh));
	}

	#[test]
	#[cfg(feature = "dns")]
	fn all_udp_includes_dns() {
		let detector = ProtocolChainBuilder::new().all_udp().build();
		// Minimal DNS-like query
		let data: &[u8] = &[
			0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		];
		// Just verify it doesn't panic
		let _ = detector.detect(data);
	}

	#[test]
	#[cfg(feature = "redis")]
	fn all_db_detects_redis() {
		let detector = ProtocolChainBuilder::new().all_db().build();
		let data = b"*1\r\n$4\r\nPING\r\n";
		assert_eq!(detector.detect(data).unwrap(), Some(Protocol::Redis));
	}

	#[test]
	#[cfg(feature = "http")]
	fn all_web_detects_http() {
		let detector = ProtocolChainBuilder::new().all_web().build();
		let data = b"GET / HTTP/1.1\r\n";
		assert_eq!(detector.detect(data).unwrap(), Some(Protocol::Http));
	}

	#[test]
	#[cfg(feature = "http")]
	fn from_slice_creates_chain() {
		let detector = ProtocolChainBuilder::from_slice(&[Protocol::Http]).build();
		let data = b"GET / HTTP/1.1\r\n";
		assert_eq!(detector.detect(data).unwrap(), Some(Protocol::Http));
	}

	#[test]
	#[cfg(feature = "http")]
	fn max_inspect_bytes_is_respected() {
		let detector = ProtocolChainBuilder::new()
			.max_inspect_bytes(128)
			.http()
			.build();
		let data = b"GET / HTTP/1.1\r\n";
		assert_eq!(detector.detect(data).unwrap(), Some(Protocol::Http));
	}

	// ── Error paths ──

	#[test]
	fn empty_chain_returns_none() {
		let detector = ProtocolChainBuilder::new().build();
		assert_eq!(detector.detect(b"GET / HTTP/1.1\r\n").unwrap(), None);
		assert_eq!(detector.detect(&[0x42; 256]).unwrap(), None);
		assert_eq!(detector.detect(b"").unwrap(), None);
	}

	#[test]
	#[cfg(feature = "http")]
	fn max_inspect_bytes_zero_returns_insufficient_data() {
		let detector = ProtocolChainBuilder::new()
			.max_inspect_bytes(0)
			.http()
			.build();
		assert_eq!(
			detector.detect(b"GET / HTTP/1.1\r\n"),
			Err(DetectionError::InsufficientData)
		);
	}

	#[test]
	#[cfg(feature = "http")]
	fn chain_with_garbage_data_returns_none() {
		let detector = ProtocolChainBuilder::new().http().build();
		assert_eq!(detector.detect(&[0xFF; 256]).unwrap(), None);
	}
}
