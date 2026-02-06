/* examples/single_protocol.rs */

//! Example of single protocol detection.
#[cfg(feature = "http")]
use guess::Protocol;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	#[cfg(feature = "http")]
	{
		let data = b"GET / HTTP/1.1\r\n";

		// Quick verification against a specific protocol
		match Protocol::Http.detect(data) {
			Ok(true) => println!("Confirmed: This is HTTP"),
			Ok(false) => println!("Nope: This is not HTTP"),
			Err(e) => eprintln!("Error: {}", e),
		}

		// Checking for insufficient data
		let short_data = b"GE";
		match Protocol::Http.detect(short_data) {
			Err(e) => println!("Got expected error for short data: {}", e),
			_ => panic!("Should have failed"),
		}
	}

	#[cfg(not(feature = "http"))]
	println!("HTTP feature is not enabled. Run with --features=http to see this example in action.");

	Ok(())
}
