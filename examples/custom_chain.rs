/* examples/custom_chain.rs */

//! Example of custom detection chain.
#[cfg(all(feature = "std", feature = "ssh", feature = "db", feature = "web"))]
use guess::ProtocolDetector;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	#[cfg(all(feature = "std", feature = "ssh", feature = "db", feature = "web"))]
	{
		use guess::Protocol;

		// Define a custom detection order
		let detector = ProtocolDetector::chain()
			.all_web() // HTTP, TLS, QUIC
			.all_db() // Redis, MySQL, Postgres
			.ssh()
			.max_inspect_bytes(128)
			.build();

		let data = b"SSH-2.0-OpenSSH_8.9p1\r\n";
		let protocol = detector.detect(data)?;

		println!("Detected protocol via custom chain: {:?}", protocol);
		assert_eq!(protocol, Some(Protocol::Ssh));
	}

	#[cfg(not(all(feature = "std", feature = "ssh", feature = "db", feature = "web")))]
	println!("Required features (std, ssh, db, web) are not fully enabled.");

	Ok(())
}
