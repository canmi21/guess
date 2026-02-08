/* src/detector.rs */
use crate::{
	DetectionError, DetectionResult, DetectionStatus, Protocol, ProtocolInfo, ProtocolVersion,
};
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
#[derive(Debug, Clone)]
pub struct ProtocolDetector<Transport = Unknown> {
	/// Enabled protocols for this detector.
	#[allow(dead_code)]
	pub(crate) enabled: ProtocolSet,
	/// Optional custom priority order for detection.
	#[cfg(feature = "std")]
	pub(crate) priority_order: Option<Vec<Protocol>>,
	/// Maximum bytes to inspect.
	pub(crate) max_inspect_bytes: usize,
	/// Version constraints for detection.
	#[allow(dead_code)]
	pub(crate) expected_versions: ProtocolVersionSet,
	/// Transport type marker.
	pub(crate) _transport: PhantomData<Transport>,
}

/// A set of enabled protocols.
#[derive(Default, Clone, Copy, Debug)]
pub(crate) struct ProtocolSet {
	/// HTTP enabled.
	#[cfg(feature = "http")]
	pub http: bool,
	/// IMAP enabled.
	#[cfg(feature = "imap")]
	pub imap: bool,
	/// TLS enabled.
	#[cfg(feature = "tls")]
	pub tls: bool,
	/// SSH enabled.
	#[cfg(feature = "ssh")]
	pub ssh: bool,
	/// DNS enabled.
	#[cfg(feature = "dns")]
	pub dns: bool,
	/// FTP enabled.
	#[cfg(feature = "ftp")]
	pub ftp: bool,
	/// DHCP enabled.
	#[cfg(feature = "dhcp")]
	pub dhcp: bool,
	/// NTP enabled.
	#[cfg(feature = "ntp")]
	pub ntp: bool,
	/// QUIC enabled.
	#[cfg(feature = "quic")]
	pub quic: bool,
	/// `MySQL` enabled.
	#[cfg(feature = "mysql")]
	pub mysql: bool,
	/// `PostgreSQL` enabled.
	#[cfg(feature = "postgres")]
	pub postgres: bool,
	/// Redis enabled.
	#[cfg(feature = "redis")]
	pub redis: bool,
	/// MQTT enabled.
	#[cfg(feature = "mqtt")]
	pub mqtt: bool,
	/// SMTP enabled.
	#[cfg(feature = "smtp")]
	pub smtp: bool,
	/// POP3 enabled.
	#[cfg(feature = "pop3")]
	pub pop3: bool,
	/// SMB enabled.
	#[cfg(feature = "smb")]
	pub smb: bool,
	/// SIP enabled.
	#[cfg(feature = "sip")]
	pub sip: bool,
	/// RTSP enabled.
	#[cfg(feature = "rtsp")]
	pub rtsp: bool,
	/// STUN enabled.
	#[cfg(feature = "stun")]
	pub stun: bool,
}

/// A set of expected protocol versions.
#[derive(Default, Clone, Debug)]
pub(crate) struct ProtocolVersionSet {
	/// Expected HTTP version.
	#[cfg(feature = "http")]
	pub http: Option<&'static str>,
	/// Expected TLS version.
	#[cfg(feature = "tls")]
	pub tls: Option<&'static str>,
	/// Expected SSH version.
	#[cfg(feature = "ssh")]
	pub ssh: Option<&'static str>,
	/// Expected Redis version.
	#[cfg(feature = "redis")]
	pub redis: Option<u8>,
}

impl<Transport> ProtocolDetector<Transport> {
	/// Detects the protocol and returns its information.
	///
	/// # Errors
	///
	/// Returns `InsufficientData` if more bytes are needed to confirm a protocol.
	#[allow(unused_variables, unused_mut)]
	pub fn detect_info<'a>(&self, data: &'a [u8]) -> DetectionResult<Option<ProtocolInfo<'a>>> {
		let limit = data.len().min(self.max_inspect_bytes);
		let data = &data[..limit];

		let mut any_incomplete = false;

		#[cfg(feature = "std")]
		if let Some(order) = &self.priority_order {
			for protocol in order {
				match self.check_protocol(*protocol, data) {
					(DetectionStatus::Match, version) => {
						return Ok(Some(ProtocolInfo {
							protocol: *protocol,
							version,
						}));
					}
					(DetectionStatus::Incomplete, _) => any_incomplete = true,
					(DetectionStatus::NoMatch, _) => {}
				}
			}
			return if any_incomplete {
				Err(DetectionError::InsufficientData)
			} else {
				Ok(None)
			};
		}

		// Default detection logic (no Vec allocation)
		#[cfg(feature = "ssh")]
		if self.enabled.ssh {
			match self.check_protocol(Protocol::Ssh, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Ssh,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "sip")]
		if self.enabled.sip {
			match self.check_protocol(Protocol::Sip, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Sip,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "rtsp")]
		if self.enabled.rtsp {
			match self.check_protocol(Protocol::Rtsp, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Rtsp,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "imap")]
		if self.enabled.imap {
			match self.check_protocol(Protocol::Imap, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Imap,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "tls")]
		if self.enabled.tls {
			match self.check_protocol(Protocol::Tls, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Tls,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "http")]
		if self.enabled.http {
			match self.check_protocol(Protocol::Http, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Http,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "dns")]
		if self.enabled.dns {
			match self.check_protocol(Protocol::Dns, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Dns,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "smtp")]
		if self.enabled.smtp {
			match self.check_protocol(Protocol::Smtp, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Smtp,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "ftp")]
		if self.enabled.ftp {
			match self.check_protocol(Protocol::Ftp, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Ftp,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "dhcp")]
		if self.enabled.dhcp {
			match self.check_protocol(Protocol::Dhcp, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Dhcp,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "ntp")]
		if self.enabled.ntp {
			match self.check_protocol(Protocol::Ntp, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Ntp,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "quic")]
		if self.enabled.quic {
			match self.check_protocol(Protocol::Quic, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Quic,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "mysql")]
		if self.enabled.mysql {
			match self.check_protocol(Protocol::Mysql, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Mysql,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "postgres")]
		if self.enabled.postgres {
			match self.check_protocol(Protocol::Postgres, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Postgres,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "redis")]
		if self.enabled.redis {
			match self.check_protocol(Protocol::Redis, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Redis,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "mqtt")]
		if self.enabled.mqtt {
			match self.check_protocol(Protocol::Mqtt, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Mqtt,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "pop3")]
		if self.enabled.pop3 {
			match self.check_protocol(Protocol::Pop3, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Pop3,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "smb")]
		if self.enabled.smb {
			match self.check_protocol(Protocol::Smb, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Smb,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}
		#[cfg(feature = "stun")]
		if self.enabled.stun {
			match self.check_protocol(Protocol::Stun, data) {
				(DetectionStatus::Match, version) => {
					return Ok(Some(ProtocolInfo {
						protocol: Protocol::Stun,
						version,
					}));
				}
				(DetectionStatus::Incomplete, _) => any_incomplete = true,
				(DetectionStatus::NoMatch, _) => {}
			}
		}

		if any_incomplete {
			Err(DetectionError::InsufficientData)
		} else {
			Ok(None)
		}
	}

	/// Internal helper to check a single protocol with version constraints.
	#[allow(dead_code, clippy::collapsible_if, clippy::unused_self)]
	fn check_protocol<'a>(
		&self,
		protocol: Protocol,
		data: &'a [u8],
	) -> (DetectionStatus, ProtocolVersion<'a>) {
		let (status, version) = protocol.probe_info(data);
		if status == DetectionStatus::Match {
			match (protocol, &version) {
				#[cfg(feature = "http")]
				(Protocol::Http, ProtocolVersion::Http(v)) => {
					if let Some(expected) = self.expected_versions.http {
						if *v != expected {
							return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
						}
					}
				}
				#[cfg(feature = "tls")]
				(Protocol::Tls, ProtocolVersion::Tls(v)) => {
					if let Some(expected) = self.expected_versions.tls {
						if *v != expected {
							return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
						}
					}
				}
				#[cfg(feature = "ssh")]
				(Protocol::Ssh, ProtocolVersion::Ssh(v)) => {
					if let Some(expected) = self.expected_versions.ssh {
						if *v != expected {
							return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
						}
					}
				}
				#[cfg(feature = "redis")]
				(Protocol::Redis, ProtocolVersion::Redis(v)) => {
					if let Some(expected) = self.expected_versions.redis {
						if *v != expected {
							return (DetectionStatus::NoMatch, ProtocolVersion::Unknown);
						}
					}
				}
				_ => {}
			}
		}
		(status, version)
	}

	/// Backwards compatible detect method.
	///
	/// # Errors
	///
	/// Returns `InsufficientData` if more bytes are needed.
	pub fn detect(&self, data: &[u8]) -> DetectionResult<Option<Protocol>> {
		self
			.detect_info(data)
			.map(|opt| opt.map(|info| info.protocol))
	}

	/// Internal constructor for custom chains.
	#[cfg(feature = "std")]
	#[allow(unused_mut)]
	pub(crate) fn with_order(order: Vec<Protocol>, max_inspect_bytes: usize) -> Self {
		let mut enabled = ProtocolSet::default();
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
				#[cfg(feature = "smtp")]
				Protocol::Smtp => enabled.smtp = true,
				#[cfg(feature = "pop3")]
				Protocol::Pop3 => enabled.pop3 = true,
				#[cfg(feature = "imap")]
				Protocol::Imap => enabled.imap = true,
				#[cfg(feature = "ftp")]
				Protocol::Ftp => enabled.ftp = true,
				#[cfg(feature = "smb")]
				Protocol::Smb => enabled.smb = true,
				#[cfg(feature = "stun")]
				Protocol::Stun => enabled.stun = true,
				#[cfg(feature = "sip")]
				Protocol::Sip => enabled.sip = true,
				#[cfg(feature = "rtsp")]
				Protocol::Rtsp => enabled.rtsp = true,
				#[cfg(feature = "dhcp")]
				Protocol::Dhcp => enabled.dhcp = true,
				#[cfg(feature = "ntp")]
				Protocol::Ntp => enabled.ntp = true,
				#[allow(unreachable_patterns)]
				_ => {}
			}
		}
		Self {
			enabled,
			priority_order: Some(order),
			max_inspect_bytes,
			expected_versions: ProtocolVersionSet::default(),
			_transport: PhantomData,
		}
	}
}

impl ProtocolDetector<Unknown> {
	/// Creates a new builder.
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
}

impl ProtocolDetector<Tcp> {}

impl ProtocolDetector<Udp> {}
