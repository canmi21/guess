/* src/builder.rs */

use crate::{
	ProtocolDetector, Unknown,
	detector::{ProtocolSet, ProtocolVersionSet},
};
use core::marker::PhantomData;

/// Builder for ProtocolDetector.
#[derive(Debug)]
pub struct ProtocolDetectorBuilder<Transport = Unknown> {
	enabled: ProtocolSet,
	max_inspect_bytes: usize,
	expected_versions: ProtocolVersionSet,
	_transport: PhantomData<Transport>,
}

impl<T> ProtocolDetectorBuilder<T> {
	pub(crate) fn new() -> Self {
		Self {
			enabled: ProtocolSet::default(),
			max_inspect_bytes: crate::MAX_INSPECT_BYTES,
			expected_versions: ProtocolVersionSet::default(),
			_transport: PhantomData,
		}
	}

	/// Enables all protocols.
	pub fn all(mut self) -> Self {
		self.enabled = ProtocolSet {
			http: true,
			tls: true,
			ssh: true,
			dns: true,
			quic: true,
			mysql: true,
			postgres: true,
			redis: true,
			mqtt: true,
			smtp: true,
			pop3: true,
			imap: true,
			ftp: true,
			smb: true,
			stun: true,
			sip: true,
			rtsp: true,
			dhcp: true,
			ntp: true,
		};
		self
	}

	#[cfg(feature = "http")]
	/// Expect a specific HTTP version.
	pub fn http_version(mut self, version: &'static str) -> Self {
		self.enabled.http = true;
		self.expected_versions.http = Some(version);
		self
	}

	#[cfg(feature = "redis")]
	/// Expect a specific Redis RESP version.
	pub fn redis_version(mut self, version: u8) -> Self {
		self.enabled.redis = true;
		self.expected_versions.redis = Some(version);
		self
	}

	#[cfg(feature = "tls")]
	/// Expect a specific TLS version.
	pub fn tls_version(mut self, version: &'static str) -> Self {
		self.enabled.tls = true;
		self.expected_versions.tls = Some(version);
		self
	}

	#[cfg(feature = "ssh")]
	/// Expect a specific SSH version.
	pub fn ssh_version(mut self, version: &'static str) -> Self {
		self.enabled.ssh = true;
		self.expected_versions.ssh = Some(version);
		self
	}

	/// Switches to TCP transport.
	pub fn tcp(self) -> ProtocolDetectorBuilder<crate::Tcp> {
		ProtocolDetectorBuilder {
			enabled: self.enabled,
			max_inspect_bytes: self.max_inspect_bytes,
			expected_versions: self.expected_versions,
			_transport: PhantomData,
		}
	}

	/// Switches to UDP transport.
	pub fn udp(self) -> ProtocolDetectorBuilder<crate::Udp> {
		ProtocolDetectorBuilder {
			enabled: self.enabled,
			max_inspect_bytes: self.max_inspect_bytes,
			expected_versions: self.expected_versions,
			_transport: PhantomData,
		}
	}

	/// Enables all TCP protocols.
	pub fn all_tcp(mut self) -> Self {
		self.enabled.http = true;
		self.enabled.tls = true;
		self.enabled.ssh = true;
		self.enabled.mysql = true;
		self.enabled.postgres = true;
		self.enabled.redis = true;
		self.enabled.mqtt = true;
		self.enabled.smtp = true;
		self.enabled.pop3 = true;
		self.enabled.imap = true;
		self.enabled.ftp = true;
		self.enabled.smb = true;
		self.enabled.sip = true;
		self.enabled.rtsp = true;
		self
	}

	#[cfg(feature = "http")]
	/// Enables HTTP.
	pub fn http(mut self) -> Self {
		self.enabled.http = true;
		self
	}

	#[cfg(feature = "tls")]
	/// Enables TLS.
	pub fn tls(mut self) -> Self {
		self.enabled.tls = true;
		self
	}

	#[cfg(feature = "ssh")]
	/// Enables SSH.
	pub fn ssh(mut self) -> Self {
		self.enabled.ssh = true;
		self
	}

	#[cfg(feature = "dns")]
	/// Enables DNS.
	pub fn dns(mut self) -> Self {
		self.enabled.dns = true;
		self
	}

	#[cfg(feature = "quic")]
	/// Enables QUIC.
	pub fn quic(mut self) -> Self {
		self.enabled.quic = true;
		self
	}

	#[cfg(feature = "mysql")]
	/// Enables MySQL.
	pub fn mysql(mut self) -> Self {
		self.enabled.mysql = true;
		self
	}

	#[cfg(feature = "postgres")]
	/// Enables PostgreSQL.
	pub fn postgres(mut self) -> Self {
		self.enabled.postgres = true;
		self
	}

	#[cfg(feature = "redis")]
	/// Enables Redis.
	pub fn redis(mut self) -> Self {
		self.enabled.redis = true;
		self
	}

	#[cfg(feature = "mqtt")]
	/// Enables MQTT.
	pub fn mqtt(mut self) -> Self {
		self.enabled.mqtt = true;
		self
	}

	#[cfg(feature = "smtp")]
	/// Enables SMTP.
	pub fn smtp(mut self) -> Self {
		self.enabled.smtp = true;
		self
	}

	#[cfg(feature = "pop3")]
	/// Enables POP3.
	pub fn pop3(mut self) -> Self {
		self.enabled.pop3 = true;
		self
	}

	#[cfg(feature = "imap")]
	/// Enables IMAP.
	pub fn imap(mut self) -> Self {
		self.enabled.imap = true;
		self
	}

	#[cfg(feature = "ftp")]
	/// Enables FTP.
	pub fn ftp(mut self) -> Self {
		self.enabled.ftp = true;
		self
	}

	#[cfg(feature = "smb")]
	/// Enables SMB.
	pub fn smb(mut self) -> Self {
		self.enabled.smb = true;
		self
	}

	#[cfg(feature = "stun")]
	/// Enables STUN.
	pub fn stun(mut self) -> Self {
		self.enabled.stun = true;
		self
	}

	#[cfg(feature = "sip")]
	/// Enables SIP.
	pub fn sip(mut self) -> Self {
		self.enabled.sip = true;
		self
	}

	#[cfg(feature = "rtsp")]
	/// Enables RTSP.
	pub fn rtsp(mut self) -> Self {
		self.enabled.rtsp = true;
		self
	}

	#[cfg(feature = "dhcp")]
	/// Enables DHCP.
	pub fn dhcp(mut self) -> Self {
		self.enabled.dhcp = true;
		self
	}

	#[cfg(feature = "ntp")]
	/// Enables NTP.
	pub fn ntp(mut self) -> Self {
		self.enabled.ntp = true;
		self
	}

	/// Builds the detector.
	pub fn build(self) -> ProtocolDetector<T> {
		ProtocolDetector {
			enabled: self.enabled,
			#[cfg(feature = "std")]
			priority_order: None,
			max_inspect_bytes: self.max_inspect_bytes,
			expected_versions: self.expected_versions,
			_transport: PhantomData,
		}
	}
}
