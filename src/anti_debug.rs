use std::time::{Duration, Instant};
use std::thread;

#[cfg(target_os = "windows")]
use windows::Win32::System::Debugging::{IsDebuggerPresent, CheckRemoteDebuggerPresent};

#[cfg(target_os = "linux")]
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
                IsDebuggerPresent().as_bool()
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Check for common debugger processes
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

            // Check for TracerPid in /proc/self/status
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