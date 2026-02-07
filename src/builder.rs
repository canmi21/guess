/* src/builder.rs */
use crate::{
	ProtocolDetector, Unknown,
	detector::{ProtocolSet, ProtocolVersionSet},
};
use core::marker::PhantomData;

/// Builder for `ProtocolDetector`.
#[derive(Debug)]
pub struct ProtocolDetectorBuilder<Transport = Unknown> {
	/// Enabled protocols.
	pub(crate) enabled: ProtocolSet,
	/// Maximum bytes to inspect.
	pub(crate) max_inspect_bytes: usize,
	/// Expected protocol versions.
	pub(crate) expected_versions: ProtocolVersionSet,
	/// Transport type marker.
	pub(crate) _transport: PhantomData<Transport>,
}

impl<T> ProtocolDetectorBuilder<T> {
	/// Creates a new `ProtocolDetectorBuilder`.
	pub(crate) fn new() -> Self {
		Self {
			enabled: ProtocolSet::default(),
			max_inspect_bytes: crate::MAX_INSPECT_BYTES,
			expected_versions: ProtocolVersionSet::default(),
			_transport: PhantomData,
		}
	}

	/// Enables all protocols.
	#[must_use]
	#[allow(unused_mut)]
	pub fn all(mut self) -> Self {
		#[cfg(feature = "http")]
		{
			self.enabled.http = true;
		}
		#[cfg(feature = "imap")]
		{
			self.enabled.imap = true;
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
		#[cfg(feature = "ftp")]
		{
			self.enabled.ftp = true;
		}
		#[cfg(feature = "dhcp")]
		{
			self.enabled.dhcp = true;
		}
		#[cfg(feature = "ntp")]
		{
			self.enabled.ntp = true;
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
		#[cfg(feature = "smtp")]
		{
			self.enabled.smtp = true;
		}
		#[cfg(feature = "pop3")]
		{
			self.enabled.pop3 = true;
		}
		#[cfg(feature = "smb")]
		{
			self.enabled.smb = true;
		}
		#[cfg(feature = "sip")]
		{
			self.enabled.sip = true;
		}
		#[cfg(feature = "rtsp")]
		{
			self.enabled.rtsp = true;
		}
		#[cfg(feature = "stun")]
		{
			self.enabled.stun = true;
		}
		self
	}

	#[cfg(feature = "http")]
	/// Expect a specific HTTP version.
	#[must_use]
	pub fn http_version(mut self, version: &'static str) -> Self {
		self.enabled.http = true;
		self.expected_versions.http = Some(version);
		self
	}

	#[cfg(feature = "redis")]
	/// Expect a specific Redis RESP version.
	#[must_use]
	pub fn redis_version(mut self, version: u8) -> Self {
		self.enabled.redis = true;
		self.expected_versions.redis = Some(version);
		self
	}

	#[cfg(feature = "tls")]
	/// Expect a specific TLS version.
	#[must_use]
	pub fn tls_version(mut self, version: &'static str) -> Self {
		self.enabled.tls = true;
		self.expected_versions.tls = Some(version);
		self
	}

	#[cfg(feature = "ssh")]
	/// Expect a specific SSH version.
	#[must_use]
	pub fn ssh_version(mut self, version: &'static str) -> Self {
		self.enabled.ssh = true;
		self.expected_versions.ssh = Some(version);
		self
	}

	/// Switches to TCP transport.
	#[must_use]
	pub fn tcp(self) -> ProtocolDetectorBuilder<crate::Tcp> {
		ProtocolDetectorBuilder {
			enabled: self.enabled,
			max_inspect_bytes: self.max_inspect_bytes,
			expected_versions: self.expected_versions,
			_transport: PhantomData,
		}
	}

	/// Switches to UDP transport.
	#[must_use]
	pub fn udp(self) -> ProtocolDetectorBuilder<crate::Udp> {
		ProtocolDetectorBuilder {
			enabled: self.enabled,
			max_inspect_bytes: self.max_inspect_bytes,
			expected_versions: self.expected_versions,
			_transport: PhantomData,
		}
	}

	/// Enables all common TCP protocols.
	#[must_use]
	#[allow(unused_mut)]
	pub fn all_tcp(mut self) -> Self {
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
		#[cfg(feature = "smtp")]
		{
			self.enabled.smtp = true;
		}
		#[cfg(feature = "pop3")]
		{
			self.enabled.pop3 = true;
		}
		#[cfg(feature = "imap")]
		{
			self.enabled.imap = true;
		}
		#[cfg(feature = "ftp")]
		{
			self.enabled.ftp = true;
		}
		#[cfg(feature = "smb")]
		{
			self.enabled.smb = true;
		}
		#[cfg(feature = "sip")]
		{
			self.enabled.sip = true;
		}
		#[cfg(feature = "rtsp")]
		{
			self.enabled.rtsp = true;
		}
		self
	}

	#[cfg(feature = "http")]
	/// Enables HTTP.
	#[must_use]
	pub fn http(mut self) -> Self {
		self.enabled.http = true;
		self
	}

	#[cfg(feature = "tls")]
	/// Enables TLS.
	#[must_use]
	pub fn tls(mut self) -> Self {
		self.enabled.tls = true;
		self
	}

	#[cfg(feature = "ssh")]
	/// Enables SSH.
	#[must_use]
	pub fn ssh(mut self) -> Self {
		self.enabled.ssh = true;
		self
	}

	#[cfg(feature = "dns")]
	/// Enables DNS.
	#[must_use]
	pub fn dns(mut self) -> Self {
		self.enabled.dns = true;
		self
	}

	#[cfg(feature = "quic")]
	/// Enables QUIC.
	#[must_use]
	pub fn quic(mut self) -> Self {
		self.enabled.quic = true;
		self
	}

	#[cfg(feature = "mysql")]
	/// Enables `MySQL`.
	#[must_use]
	pub fn mysql(mut self) -> Self {
		self.enabled.mysql = true;
		self
	}

	#[cfg(feature = "postgres")]
	/// Enables `PostgreSQL`.
	#[must_use]
	pub fn postgres(mut self) -> Self {
		self.enabled.postgres = true;
		self
	}

	#[cfg(feature = "redis")]
	/// Enables Redis.
	#[must_use]
	pub fn redis(mut self) -> Self {
		self.enabled.redis = true;
		self
	}

	#[cfg(feature = "mqtt")]
	/// Enables MQTT.
	#[must_use]
	pub fn mqtt(mut self) -> Self {
		self.enabled.mqtt = true;
		self
	}

	#[cfg(feature = "smtp")]
	/// Enables SMTP.
	#[must_use]
	pub fn smtp(mut self) -> Self {
		self.enabled.smtp = true;
		self
	}

	#[cfg(feature = "pop3")]
	/// Enables POP3.
	#[must_use]
	pub fn pop3(mut self) -> Self {
		self.enabled.pop3 = true;
		self
	}

	#[cfg(feature = "imap")]
	/// Enables IMAP.
	#[must_use]
	pub fn imap(mut self) -> Self {
		self.enabled.imap = true;
		self
	}

	#[cfg(feature = "ftp")]
	/// Enables FTP.
	#[must_use]
	pub fn ftp(mut self) -> Self {
		self.enabled.ftp = true;
		self
	}

	#[cfg(feature = "smb")]
	/// Enables SMB.
	#[must_use]
	pub fn smb(mut self) -> Self {
		self.enabled.smb = true;
		self
	}

	#[cfg(feature = "stun")]
	/// Enables STUN.
	#[must_use]
	pub fn stun(mut self) -> Self {
		self.enabled.stun = true;
		self
	}

	#[cfg(feature = "sip")]
	/// Enables SIP.
	#[must_use]
	pub fn sip(mut self) -> Self {
		self.enabled.sip = true;
		self
	}

	#[cfg(feature = "rtsp")]
	/// Enables RTSP.
	#[must_use]
	pub fn rtsp(mut self) -> Self {
		self.enabled.rtsp = true;
		self
	}

	#[cfg(feature = "dhcp")]
	/// Enables DHCP.
	#[must_use]
	pub fn dhcp(mut self) -> Self {
		self.enabled.dhcp = true;
		self
	}

	#[cfg(feature = "ntp")]
	/// Enables NTP.
	#[must_use]
	pub fn ntp(mut self) -> Self {
		self.enabled.ntp = true;
		self
	}

	/// Builds the detector.
	#[must_use]
	pub fn build(self) -> ProtocolDetector<T> {
		ProtocolDetector {
			enabled: self.enabled,
			#[cfg(feature = "std")]
			priority_order: None,
			max_inspect_bytes: self.max_inspect_bytes,
			expected_versions: self.expected_versions,
			_transport: self._transport,
		}
	}
}
