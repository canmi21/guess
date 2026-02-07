/* src/protocols/mod.rs */

/// DHCP protocol detection.
#[cfg(feature = "dhcp")]
pub(crate) mod dhcp;
/// DNS protocol detection.
#[cfg(feature = "dns")]
pub(crate) mod dns;
/// FTP protocol detection.
#[cfg(feature = "ftp")]
pub(crate) mod ftp;
/// HTTP protocol detection.
#[cfg(feature = "http")]
pub(crate) mod http;
/// IMAP protocol detection.
#[cfg(feature = "imap")]
pub(crate) mod imap;
/// MQTT protocol detection.
#[cfg(feature = "mqtt")]
pub(crate) mod mqtt;
/// `MySQL` protocol detection.
#[cfg(feature = "mysql")]
pub(crate) mod mysql;
/// NTP protocol detection.
#[cfg(feature = "ntp")]
pub(crate) mod ntp;
/// POP3 protocol detection.
#[cfg(feature = "pop3")]
pub(crate) mod pop3;
/// `PostgreSQL` protocol detection.
#[cfg(feature = "postgres")]
pub(crate) mod postgres;
/// QUIC protocol detection.
#[cfg(feature = "quic")]
pub(crate) mod quic;
/// Redis protocol detection.
#[cfg(feature = "redis")]
pub(crate) mod redis;
/// RTSP protocol detection.
#[cfg(feature = "rtsp")]
pub(crate) mod rtsp;
/// SIP protocol detection.
#[cfg(feature = "sip")]
pub(crate) mod sip;
/// SMB protocol detection.
#[cfg(feature = "smb")]
pub(crate) mod smb;
/// SMTP protocol detection.
#[cfg(feature = "smtp")]
pub(crate) mod smtp;
/// SSH protocol detection.
#[cfg(feature = "ssh")]
pub(crate) mod ssh;
/// STUN protocol detection.
#[cfg(feature = "stun")]
pub(crate) mod stun;
/// TLS protocol detection.
#[cfg(feature = "tls")]
pub(crate) mod tls;
