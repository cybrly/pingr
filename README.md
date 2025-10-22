# pingr

[![Crates.io](https://img.shields.io/crates/v/pingr.svg)](https://crates.io/crates/pingr)
[![Documentation](https://docs.rs/pingr/badge.svg)](https://docs.rs/pingr)
[![License](https://img.shields.io/crates/l/pingr.svg)](https://github.com/cybrly/pingr#license)

Feel the pulse of your network! A blazing fast, modern network scanner with beautiful terminal output and multiple export formats.

## ✨ Features

- 🚀 **Blazing Fast**: Async parallel scanning with up to 10,000 concurrent threads
- 🎨 **Beautiful Output**: Color-coded RTT times show network health at a glance
- 📊 **Multiple Export Formats**: JSON, CSV, nmap, and plain text
- 🧠 **Smart Defaults**: Auto-optimizes thread count based on network size
- 📈 **Detailed Statistics**: RTT measurements, packet loss, and response time analysis
- 🔍 **DNS Resolution**: Optional hostname lookups for discovered hosts
- ⚡ **Cross-Platform**: Works on Linux, macOS, Windows, and ARM devices

## Installation
```bash
cargo install pingr
```

## Quick Start
```bash
# Scan local network with auto-optimization
sudo pingr

# Scan with custom settings
sudo pingr -t 500 192.168.1.0/24

# Comprehensive scan with all features
sudo pingr -r --stats -c 3 -o results -f both 10.0.0.0/16
```

## Usage Examples

### Basic Network Discovery
```bash
# Simple scan with colored output
sudo pingr 192.168.1.0/24
```

### Enterprise Network Audit
```bash
# Full scan with hostname resolution and statistics
sudo pingr -t auto -c 3 -r --stats -v -o audit -f both 10.0.0.0/16
```

### Stealth Scan
```bash
# Slow, quiet scan to avoid detection
sudo pingr --rate 10 --timeout 2 -q 172.16.0.0/12
```

### Quick Host Discovery
```bash
# Fast discovery for automation scripts
sudo pingr -q -t 1000 192.168.0.0/22 > alive_hosts.txt
```

## Understanding RTT Colors

The tool color-codes response times for quick network health assessment:

- 🟢 **Green (0-10ms)**: Excellent - Local network, wired connections
- 🟡 **Yellow (11-50ms)**: Good - Normal Wi-Fi, acceptable latency
- 🟠 **Orange (51-100ms)**: Fair - Slower devices, potential congestion
- 🔴 **Red (100ms+)**: Poor - Network issues, investigate these hosts

## Command Line Options
```
pingr [OPTIONS] [CIDR]

Arguments:
  [CIDR]  Network to scan in CIDR notation [default: 192.168.1.0/24]

Options:
  -t, --threads <THREADS>      Concurrent threads (auto = automatic) [default: auto]
  -v, --verbose               Show unreachable hosts
  -o, --output <OUTPUT>       Output file path (without extension)
  -f, --format <FORMAT>       Output format [text, json, both]
  -c, --count <COUNT>         Ping attempts per host [default: 1]
  -r, --resolve               Resolve hostnames
  --timeout <TIMEOUT>         Ping timeout in seconds [default: 1]
  --stats                     Show RTT statistics
  --rate <RATE>              Rate limit (pings/sec, 0 = unlimited)
  --export <FORMAT>          Export format (csv, nmap)
  -q, --quiet                Minimal output
  --no-color                 Disable colored output
  -h, --help                 Print help
  -V, --version              Print version
```

## Performance Guide

| Network Size | Hosts    | Recommended Threads | Scan Time  |
|-------------|----------|-------------------|------------|
| /24         | 254      | 256               | ~2 sec     |
| /22         | 1,022    | 512               | ~5 sec     |
| /20         | 4,094    | 1,024             | ~10 sec    |
| /16         | 65,534   | 4,096             | ~30 sec    |
| /12         | 1,048,574| 8,192             | ~5 min     |

## Building from Source
```bash
git clone https://github.com/cybrly/pingr.git
cd pingr
cargo build --release
sudo ./target/release/pingr
```

## Cross-Compilation
```bash
# For Raspberry Pi
cross build --release --target aarch64-unknown-linux-musl

# For Ubuntu/Debian
cross build --release --target x86_64-unknown-linux-musl
```

## Author

**Chris Neuwirth**
[CNeuwirth@networksgroup.com](mailto:CNeuwirth@networksgroup.com)
[GitHub: @cybrly](https://github.com/cybrly)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
