# Guess

High-performance zero-copy network protocol detection with version awareness.

`guess` is designed for scenarios where you need to identify the application-layer protocol of a new connection as quickly as possible, typically by inspecting only the first 64 bytes of data. It supports version extraction and refined filtering for modern network stacks.

## Features

- **Zero-Copy Detection**: Inspects data without any heap allocation or copying, maximizing performance.
- **Version Awareness**: Extracts protocol versions for HTTP (1.0, 1.1, 2.0), SSH, TLS, and Redis (RESP2/3).
- **Customizable Priority**: Define your own detection chain order to optimize for your specific traffic patterns.
- **Refined Filtering**: Configure detectors to only match specific protocol versions (e.g., "accept only HTTP/2.0").
- **Transport Aware**: Type-safe builders tailored for TCP or UDP protocol sets.
- **No-std Support**: Core detection logic works in `no-std` environments for embedded use.

## Usage Examples

Check the `examples` directory for runnable code:

- **Single Protocol**: [`examples/single_protocol.rs`](examples/single_protocol.rs) - Simple check for a specific protocol.
- **TCP Detection**: [`examples/tcp_detect.rs`](examples/tcp_detect.rs) - Using the TCP-specific detector for common services.
- **Custom Chain**: [`examples/custom_chain.rs`](examples/custom_chain.rs) - Defining a specific order for protocol identification.
- **Tracing**: [`examples/with_tracing.rs`](examples/with_tracing.rs) - Protocol detection with detailed tracing logs.

## Installation

```toml
[dependencies]
guess = { version = "0.2", features = ["full"] }
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `std` | Standard library support (for custom chains). |
| `tcp` | All common TCP-based protocols. |
| `udp` | All common UDP-based protocols. |
| `web` | Includes `http`, `tls`, `quic`. |
| `db` | Includes `mysql`, `postgres`, `redis`. |
| `http` | HTTP & version extraction (1.0, 1.1, 2.0). |
| `tls` | TLS (SSL) & version extraction (1.0-1.3). |
| `ssh` | SSH & version extraction (1.5, 2.0). |
| `redis` | Redis (RESP2/3) & version extraction. |
| `dns` | DNS (UDP/TCP) headers. |
| `quic` | QUIC Initial packets. |
| `mysql` | MySQL server handshake. |
| `postgres` | PostgreSQL startup & SSLRequest. |
| `mqtt` | MQTT CONNECT packets. |
| `smtp` | SMTP greeting & commands. |
| `pop3` | POP3 greeting & commands. |
| `imap` | IMAP greeting & tagged commands. |
| `ftp` | FTP greeting & commands. |
| `smb` | SMB (v1/v2/v3) & Direct TCP. |
| `sip` | SIP request & status lines. |
| `rtsp` | RTSP request & status lines. |
| `stun` | STUN (NAT traversal). |
| `dhcp` | DHCP (BOOTP) & magic cookies. |
| `ntp` | NTP (Network Time Protocol). |
| `tracing` | Optional instrumentation using `tracing` crate. |
| `full` | Enables all features above. |

## License

Released under the MIT License © 2026 [Canmi](https://github.com/canmi21)
