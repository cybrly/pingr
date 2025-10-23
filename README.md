# pingr

[![Crates.io](https://img.shields.io/crates/v/pingr.svg)](https://crates.io/crates/pingr)
[![Documentation](https://docs.rs/pingr/badge.svg)](https://docs.rs/pingr)
[![License](https://img.shields.io/crates/l/pingr.svg)](https://github.com/cybrly/pingr#license)

A blazing fast, modern network scanner with beautiful terminal output and multiple export formats. Alternative to tools like `fping` and `nmap` host discovery.

## ✨ Features

- 🚀 **Blazing Fast**: Async parallel scanning with up to 10,000 concurrent threads
- 🎨 **Beautiful Output**: Color-coded RTT times show network health at a glance
- 📊 **Multiple Export Formats**: JSON, CSV, nmap, and plain text
- 🧠 **Smart Defaults**: Auto-optimizes threads, enables hostname resolution and adaptive timeout
- 📈 **Detailed Statistics**: RTT measurements, packet loss, and response time analysis
- 🔍 **DNS Resolution**: Automatic hostname lookups (disable with `-n`)
- 📁 **File Input**: Bulk scanning from target lists
- 🛡️ **Interrupt Handling**: Graceful Ctrl-C with automatic result saving
- 💻 **Script-Friendly**: Simple mode outputs clean IP lists for piping
- ⚡ **Cross-Platform**: Works on Linux, macOS, Windows, and ARM devices

## Installation

```bash
cargo install pingr
```

## Quick Start

```bash
# Show help
pingr

# Simple scan with automatic hostname resolution
sudo pingr 192.168.1.0/24

# Fast scan without hostname resolution
sudo pingr -n 192.168.1.0/24

# Clean IP list output for scripts
sudo pingr -s 192.168.1.0/24

# Scan multiple networks from file
sudo pingr -i targets.txt
```

## Usage

```
pingr <CIDR>... [OPTIONS]
pingr -i <FILE> [OPTIONS]

Arguments:
  <CIDR>         Network(s) in CIDR notation

Options:
  -i, --input <FILE>      Input file with targets
  -s, --simple            Simple mode - IP addresses only
  -n, --no-resolve        Skip hostname resolution
  -q, --quiet             Quiet mode (minimal output)
  -v, --verbose           Show unreachable hosts
  -t, --threads <N>       Concurrent threads (auto)
  -c, --count <N>         Ping attempts per host (1)
  -o, --output <FILE>     Save results to file
  -f, --format <FMT>      Output format (text/json/both)
  --timeout <SEC>         Ping timeout in seconds (1)
  --stats                 Show RTT statistics
  --no-adaptive           Disable adaptive timeout
  --no-color              Disable colored output
  --export <FMT>          Export format (csv/nmap)
  -h, --help              Show help message
```

## Examples

### Basic Scanning

```bash
# Simple scan with beautiful output
sudo pingr 192.168.1.0/24

# Fast scan without DNS resolution
sudo pingr -n 10.0.0.0/24

# Multiple networks
sudo pingr 192.168.1.0/24 10.0.0.0/24 172.16.0.0/24
```

### Script Integration

```bash
# Clean IP list for piping
sudo pingr -s 192.168.1.0/24 | xargs -I {} nmap -sV {}

# Use in bash scripts
for ip in $(sudo pingr -s 192.168.1.0/24); do
    echo "Checking $ip..."
    ssh admin@$ip uptime 2>/dev/null
done

# Save to file for later processing
sudo pingr -s 192.168.1.0/24 > live_hosts.txt
```

### Bulk Scanning

Create a `targets.txt` file:

```text
# Corporate networks
192.168.1.0/24
192.168.2.0/24
10.0.0.0/24

# Branch offices
10.10.10.0/24
10.10.20.0/24

# Single servers
10.0.0.10
192.168.1.1
```

Then scan:

```bash
# Scan all networks from file
sudo pingr -i targets.txt

# With full features
sudo pingr -i targets.txt -t 5000 --stats -o results -f both

# Simple mode for automation
sudo pingr -s -i targets.txt > all_live_hosts.txt
```

### Enterprise Network Audit

```bash
# Comprehensive scan with all features
sudo pingr \
    -i networks.txt \     # Read from file
    -t auto \             # Auto-optimize threads
    -c 3 \                # 3 pings per host
    --stats \             # Show RTT statistics
    -v \                  # Show all hosts
    -o audit_$(date +%Y%m%d) \  # Timestamped output
    -f both \             # JSON and text output
    --export csv          # Also export as CSV
```

### Interrupt Handling

```bash
# Start a large scan
sudo pingr -i large_networks.txt -t 5000

# Press Ctrl-C anytime to save partial results
# Results automatically saved to pingr_interrupted_TIMESTAMP.txt/json
```

## Understanding RTT Colors

The tool color-codes response times for quick network health assessment:

- 🟢 **Green (0-10ms)**: Excellent - Local network, wired connections
- 🟡 **Yellow (11-50ms)**: Good - Normal Wi-Fi, acceptable latency
- 🟠 **Orange (51-100ms)**: Fair - Slower devices, potential congestion
- 🔴 **Red (100ms+)**: Poor - Network issues, investigate these hosts

## Performance Guide

| Network Size | Hosts     | Recommended Threads | Scan Time |
| ------------ | --------- | ------------------- | --------- |
| /24          | 254       | 256                 | ~2 sec    |
| /22          | 1,022     | 512                 | ~5 sec    |
| /20          | 4,094     | 1,024               | ~10 sec   |
| /16          | 65,534    | 4,096               | ~30 sec   |
| /12          | 1,048,574 | 8,192               | ~5 min    |

## Target File Format

The input file supports:

- CIDR notation: `192.168.1.0/24`
- Single IPs: `10.0.0.1` (converted to /32)
- Comments: Lines starting with `#`
- Empty lines are ignored

## Building from Source

```bash
git clone https://github.com/cybrly/pingr.git
cd pingr
cargo build --release
sudo ./target/release/pingr
```

### Cross-Compilation

```bash
# Install cross
cargo install cross

# For Raspberry Pi
cross build --release --target aarch64-unknown-linux-musl

# For Ubuntu/Debian
cross build --release --target x86_64-unknown-linux-musl

# For Windows
cross build --release --target x86_64-pc-windows-gnu
```

## Platform Support

- ✅ Linux (x86_64, aarch64, armv7)
- ✅ macOS (Intel & Apple Silicon)
- ✅ Windows (with administrator privileges)
- ✅ Raspberry Pi (all models)
- ✅ Docker containers (with --cap-add=NET_RAW)

## Docker Usage

```dockerfile
FROM rust:latest
RUN cargo install pingr
ENTRYPOINT ["pingr"]
```

```bash
docker build -t pingr .
docker run --rm --cap-add=NET_RAW pingr 192.168.1.0/24
```

## Requirements

- **Privileges**: Requires root/sudo for ICMP raw sockets
- **Rust**: 1.70+ for building from source
- **Memory**: ~50MB for /16 network scan
- **Network**: ICMP echo requests must be allowed

## Changelog

### v0.3.0 (2024-01-XX)

- 🔄 **Breaking Changes**:
  - Hostname resolution now ON by default (use `-n` to disable)
  - Adaptive timeout now ON by default (use `--no-adaptive` to disable)
  - No more default 192.168.1.0/24 scan - shows help instead
- ✨ **New Features**:
  - Added `-s/--simple` mode for clean IP-only output
  - Help menu displayed when run without arguments
  - Improved script integration support
- 🐛 **Fixes**:
  - Better interrupt handling
  - Improved error messages

### v0.2.0 (2024-01-XX)

- 🎯 **File Input Support**: Read targets from text files with `-i` flag
- 🌐 **Multi-Network Scanning**: Scan multiple networks in one run
- 🛡️ **Interrupt Handling**: Graceful Ctrl-C with automatic result saving
- 📊 **Network Grouping**: Results organized by source network
- 🔧 **Enhanced Progress**: Better progress tracking for multiple networks
- 📈 **Improved Statistics**: Added RTT min/max/avg calculations

### v0.1.0 (2024-01-XX)

- Initial release
- Fast async scanning with customizable concurrency
- Colorful terminal output with RTT color-coding
- Multiple export formats (JSON, CSV, nmap)
- Basic RTT statistics and DNS resolution
- Auto-optimization for thread count

## Tips & Tricks

### Speed Optimization

```bash
# Maximum speed (no DNS, high threads)
sudo pingr -n -t 10000 10.0.0.0/16

# Balanced (auto threads, with DNS)
sudo pingr 10.0.0.0/16
```

### Network Monitoring

```bash
# Regular monitoring script
#!/bin/bash
while true; do
    sudo pingr -s 192.168.1.0/24 > /tmp/current_hosts.txt
    diff /tmp/previous_hosts.txt /tmp/current_hosts.txt
    mv /tmp/current_hosts.txt /tmp/previous_hosts.txt
    sleep 300
done
```

### Integration with Other Tools

```bash
# Find and scan web servers
sudo pingr -s 10.0.0.0/24 | xargs -P10 -I {} curl -s -o /dev/null -w "%{http_code} {}\n" http://{}:80 2>/dev/null

# SSH availability check
sudo pingr -s 192.168.1.0/24 | parallel -j10 "nc -z -w1 {} 22 && echo {} has SSH"

# Generate Ansible inventory
echo "[servers]" > inventory.ini
sudo pingr 10.0.0.0/24 | grep -E "\.1[0-9]{2}" >> inventory.ini
```

## Troubleshooting

### Permission Denied

```bash
# Linux: Set capabilities to avoid sudo
sudo setcap cap_net_raw+ep $(which pingr)

# macOS: Always requires sudo
# Windows: Run as Administrator
```

### No Results

- Check firewall rules allow ICMP
- Verify network connectivity
- Try increasing timeout: `--timeout 3`
- Some hosts may block ICMP

### Slow Performance

- Reduce thread count for congested networks
- Use `-n` to skip DNS resolution
- Check system ulimits: `ulimit -n`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

```bash
# Fork and clone
git clone https://github.com/yourusername/pingr.git
cd pingr

# Create feature branch
git checkout -b feature/amazing-feature

# Make changes and test
cargo test
cargo clippy
cargo fmt

# Commit and push
git commit -m "Add amazing feature"
git push origin feature/amazing-feature
```

## Author

**Chris Neuwirth**
[CNeuwirth@networksgroup.com](mailto:CNeuwirth@networksgroup.com)
[GitHub: @cybrly](https://github.com/cybrly)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [surge-ping](https://github.com/kolapapa/surge-ping) for ICMP functionality
- Uses [tokio](https://tokio.rs) for async runtime
- Terminal colors by [colored](https://github.com/mackwic/colored)
- Progress bars from [indicatif](https://github.com/console-rs/indicatif)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=cybrly/pingr&type=Date)](https://star-history.com/#cybrly/pingr&Date)

---

**Note**: `pingr` requires root/administrator privileges to send ICMP packets. This is a system requirement for raw socket access, not a limitation of the tool.

For more information, bug reports, or feature requests, please visit the [GitHub repository](https://github.com/cybrly/pingr).
