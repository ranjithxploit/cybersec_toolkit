# Network Scanner - Rust Implementation

A fast, multi-threaded network port scanner written in Rust, inspired by nmap. This tool allows you to quickly scan a range of ports on a target host to identify open ports.

## Features

- **Fast Port Scanning**: Multi-threaded scanning for rapid port enumeration
- **Flexible Port Ranges**: Supports individual ports and ranges (e.g., `80,443,1000-2000`)
- **Configurable Threads**: Adjust parallelism for optimal performance
- **Custom Timeouts**: Set connection timeout per port
- **Verbose Output**: Real-time progress feedback with color-coded results
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Requirements

- **Rust 1.70+**: Install from [https://rustup.rs/](https://rustup.rs/)

## Installation

### 1. Install Rust

```shell
# On Windows, download and run the installer from:
# https://rustup.rs/
```

### 2. Build the Project

```shell
cargo build --release
```

The compiled binary will be at: `target/release/scanner.exe` (Windows) or `target/release/scanner` (Linux/macOS)

## Usage

### Basic Scan

```shell
cargo run --release -- <TARGET_IP>
```

### Scan Specific Ports

```shell
cargo run --release -- <TARGET_IP> --ports 80,443,8080
```

### Scan Port Range

```shell
cargo run --release -- <TARGET_IP> --ports 1-10000
```

### Advanced Options

```shell
cargo run --release -- <TARGET_IP> ^
  --ports 1-65535 ^
  --threads 500 ^
  --timeout 2 ^
  --verbose
```

### Command Line Options

- `TARGET`: Target IP address (required)
- `-p, --ports <PORTS>`: Ports to scan (default: `1-1000`)
  - Single port: `80`
  - Multiple ports: `80,443,8080`
  - Port range: `1-1000` or `20000-30000`
  - Combined: `80,443,1000-2000`
- `-t, --threads <THREADS>`: Number of parallel threads (default: `100`)
- `--timeout <TIMEOUT>`: Connection timeout in seconds (default: `1`)
- `-v, --verbose`: Show detailed scanning progress

## Examples

### Scan Common Web Ports on localhost

```shell
cargo run --release -- 127.0.0.1 -p 80,443,8080,3000
```

### Scan Full Port Range on Remote Host

```shell
cargo run --release -- 192.168.1.1 -p 1-65535 -t 500 --timeout 2
```

### Quick Scan with Verbose Output

```shell
cargo run --release -- 10.0.0.1 -p 1-10000 --verbose
```

## Performance Tips

- **Increase threads** for larger port ranges (100-1000 threads)
- **Decrease timeout** for faster scanning on responsive hosts
- **Run in release mode** for 10-100x performance boost

## Building for Distribution

```shell
cargo build --release
```

The binary will be available at `target/release/scanner.exe` (Windows) or `target/release/scanner` (Unix).

## Technical Details

- **Protocol**: TCP connect scan (SYN + ACK handshake)
- **Async Runtime**: Tokio for efficient I/O
- **Parsing**: Clap for robust CLI argument handling
- **Threading**: Spawns blocking threads to handle synchronous socket operations

## Limitations

- Requires network connectivity to target
- TCP connect scans (full handshake) - not as stealthy as SYN scans
- No UDP scanning support (current version)
- Ordinary user privileges (SYN scanning requires root/admin)

## Future Enhancements

- UDP port scanning
- SYN scanning (low-level packet crafting)
- Service banner grabbing
- Output formats (JSON, XML)
- Target ranges (CIDR notation)
- OS detection

## Disclaimer

This tool is for authorized network testing and security auditing only. Unauthorized network scanning may be illegal. Use responsibly and only on systems you own or have explicit permission to test.
