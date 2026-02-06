/* examples/with_tracing.rs */

//! Example of integrating with the tracing crate for debugging.

fn main() -> Result<(), Box<dyn std::error::Error>> {
	#[cfg(all(feature = "std", feature = "tracing"))]
	{
		use guess::ProtocolDetector;

		// Initialize tracing subscriber to see output from the guess crate
		// You can control the output level via RUST_LOG environment variable
		// e.g., RUST_LOG=guess=trace cargo run --example with_tracing
		tracing_subscriber::fmt()
			.with_max_level(tracing::Level::TRACE)
			.init();

		println!("Starting detection with tracing enabled...");

		let detector = ProtocolDetector::builder().tcp().all_tcp().build();

		// Sample HTTP data
		let data = b"GET / HTTP/1.1\r\n";
		let _ = detector.detect(data)?;

		// Sample unknown data to see trace logs for non-matches
		let unknown = b"Not a protocol";
		let _ = detector.detect(unknown)?;

		println!("Detection finished. Check your terminal for trace logs.");
	}

	#[cfg(not(all(feature = "std", feature = "tracing")))]
	println!("Required features (std, tracing) are not enabled.");

	Ok(())
}
