/* examples/tcp_detect.rs */

//! Example of TCP protocol detection.
#[cfg(all(feature = "http", feature = "tls", feature = "ssh"))]
use guess::ProtocolDetector;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	#[cfg(all(feature = "http", feature = "tls", feature = "ssh"))]
	{
		use guess::Protocol;

		// Create a TCP protocol detector for common web protocols
		let detector = ProtocolDetector::builder().tcp().http().tls().ssh().build();

		// Sample HTTP data
		let http_data = b"GET / index.html HTTP/1.1\r\nHost: localhost\r\n\r\n";
		let protocol = detector.detect(http_data)?;
		println!("Detected protocol: {:?}", protocol);
		assert_eq!(protocol, Some(Protocol::Http));

		// Sample TLS data
		let tls_data = [0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
		let protocol = detector.detect(&tls_data)?;
		println!("Detected protocol: {:?}", protocol);
		assert_eq!(protocol, Some(Protocol::Tls));

		// Sample SSH data
		let ssh_data = b"SSH-2.0-OpenSSH_8.9p1\r\n";
		let protocol = detector.detect(ssh_data)?;
		println!("Detected protocol: {:?}", protocol);
		assert_eq!(protocol, Some(Protocol::Ssh));

		// Unknown data
		let unknown_data = b"Random binary data that doesn't match any protocol";
		let protocol = detector.detect(unknown_data)?;
		println!("Detected protocol: {:?}", protocol);
		assert_eq!(protocol, None);
	}

	#[cfg(not(all(feature = "http", feature = "tls", feature = "ssh")))]
	println!("Required features (http, tls, ssh) are not fully enabled.");

	Ok(())
}
