use std::{
    fs,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};
use sysinfo::{System, SystemExt, ProcessExt};
use winapi::um::{
    winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    processthreadsapi::OpenProcess,
    handleapi::CloseHandle,
    winuser::{GetAsyncKeyState, GetKeyState},
    winbase::GetComputerNameA,
    winreg::{HKEY_LOCAL_MACHINE, KEY_READ, RegOpenKeyExA, RegQueryValueExA},
};
use windows::Win32::System::{
    Registry::{HKEY_LOCAL_MACHINE, KEY_READ, RegOpenKeyExA, RegQueryValueExA},
    ProcessStatus::{K32EnumProcessModules, K32GetModuleInformation},
    ProcessThread::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    Threading::{GetCurrentProcess, GetCurrentProcessId},
};

#[derive(Debug)]
pub struct AntiVM {
    system: System,
}

impl AntiVM {
    pub fn new() -> Self {
        Self {
            system: System::new_all(),
        }
    }

    pub fn detect_vm(&self) -> bool {
        // Check for common VM processes
        let vm_processes = [
            "vmtoolsd.exe",
            "vmwaretray.exe",
            "vmwareuser.exe",
            "VBoxService.exe",
            "VBoxTray.exe",
            "qemu-ga.exe",
        ];

        for process in self.system.processes().values() {
            if vm_processes.contains(&process.name().to_lowercase().as_str()) {
                return true;
            }
        }

        // Check for VM-specific files
        let vm_files = [
            "C:\\Program Files\\VMware",
            "C:\\Program Files\\Oracle\\VirtualBox",
            "C:\\Program Files\\QEMU",
            "/usr/share/vmware",
            "/usr/share/virtualbox",
            "/usr/share/qemu",
        ];

        for file in vm_files.iter() {
            if Path::new(file).exists() {
                return true;
            }
        }

        // Check for VM-specific registry keys
        unsafe {
            let mut hkey = std::ptr::null_mut();
            let vm_registry_keys = [
                "SOFTWARE\\VMware, Inc.\\VMware Tools",
                "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
                "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
            ];

            for key in vm_registry_keys.iter() {
                if RegOpenKeyExA(
                    HKEY_LOCAL_MACHINE,
                    key.as_ptr() as *const i8,
                    0,
                    KEY_READ,
                    &mut hkey,
                ) == 0
                {
                    CloseHandle(hkey);
                    return true;
                }
            }
        }

        // Check for VM-specific hardware
        if let Ok(output) = Command::new("systeminfo").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let vm_indicators = [
                "VMware",
                "VirtualBox",
                "QEMU",
                "Microsoft Hv",
                "Hyper-V",
            ];

            for indicator in vm_indicators.iter() {
                if output_str.contains(indicator) {
                    return true;
                }
            }
        }

        // Check for VM-specific memory patterns
        unsafe {
            let process = GetCurrentProcess();
            let mut modules = [std::ptr::null_mut(); 1024];
            let mut needed = 0;

            if K32EnumProcessModules(
                process,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<*mut _>()) as u32,
                &mut needed,
            ) != 0
            {
                let module_count = needed as usize / std::mem::size_of::<*mut _>();
                for i in 0..module_count {
                    let mut module_info = std::mem::zeroed();
                    if K32GetModuleInformation(
                        process,
                        modules[i],
                        &mut module_info,
                        std::mem::size_of::<*mut _>() as u32,
                    ) != 0
                    {
                        // Check for VM-specific DLLs
                        let vm_dlls = [
                            "vmware.dll",
                            "vmhgfs.dll",
                            "vmGuestLib.dll",
                            "VBoxHook.dll",
                            "VBoxDDR0.r0",
                        ];

                        for dll in vm_dlls.iter() {
                            if module_info.szModule.contains(dll) {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        // Check for VM-specific timing patterns
        let start = Instant::now();
        for _ in 0..1000 {
            unsafe {
                GetAsyncKeyState(0);
            }
        }
        let duration = start.elapsed();

        // VMs often have more consistent timing patterns
        if duration.as_micros() < 1000 || duration.as_micros() > 5000 {
            return true;
        }

        // Check for VM-specific keyboard patterns
        unsafe {
            let mut vm_keyboard = false;
            for i in 0..256 {
                if GetKeyState(i) & 0x8000 != 0 {
                    vm_keyboard = true;
                    break;
                }
            }
            if vm_keyboard {
                return true;
            }
        }

        // Check for VM-specific computer name patterns
        unsafe {
            let mut computer_name = [0u8; 32];
            let mut size = computer_name.len() as u32;
            if GetComputerNameA(
                computer_name.as_mut_ptr() as *mut i8,
                &mut size,
            ) != 0
            {
                let name = String::from_utf8_lossy(&computer_name[..size as usize]);
                let vm_names = ["VIRTUAL", "VM", "VBOX", "QEMU"];
                for vm_name in vm_names.iter() {
                    if name.to_uppercase().contains(vm_name) {
                        return true;
                    }
                }
            }
        }

        false
    }

    pub fn detect_sandbox(&self) -> bool {
        // Check for sandbox-specific processes
        let sandbox_processes = [
            "wireshark.exe",
            "procmon.exe",
            "procmon64.exe",
            "tcpview.exe",
            "tcpview64.exe",
            "autoruns.exe",
            "autoruns64.exe",
            "filemon.exe",
            "filemon64.exe",
            "regmon.exe",
            "regmon64.exe",
            "processhacker.exe",
            "processhacker64.exe",
            "x64dbg.exe",
            "x32dbg.exe",
            "ollydbg.exe",
            "windbg.exe",
            "ida.exe",
            "ida64.exe",
            "ghidra.exe",
            "radare2.exe",
            "cutter.exe",
            "immunity debugger.exe",
            "immunity debugger64.exe",
            "x64dbg.exe",
            "x32dbg.exe",
            "ollydbg.exe",
            "windbg.exe",
            "ida.exe",
            "ida64.exe",
            "ghidra.exe",
            "radare2.exe",
            "cutter.exe",
            "immunity debugger.exe",
            "immunity debugger64.exe",
        ];

        for process in self.system.processes().values() {
            if sandbox_processes.contains(&process.name().to_lowercase().as_str()) {
                return true;
            }
        }

        // Check for sandbox-specific files
        let sandbox_files = [
            "C:\\Program Files\\Wireshark",
            "C:\\Program Files\\Sysinternals",
            "C:\\Program Files\\IDA",
            "C:\\Program Files\\x64dbg",
            "C:\\Program Files\\OllyDbg",
            "C:\\Program Files\\Immunity Inc",
            "C:\\Program Files\\Ghidra",
            "C:\\Program Files\\Radare2",
            "C:\\Program Files\\Cutter",
            "/usr/share/wireshark",
            "/usr/share/sysinternals",
            "/usr/share/ida",
            "/usr/share/x64dbg",
            "/usr/share/ollydbg",
            "/usr/share/immunity",
            "/usr/share/ghidra",
            "/usr/share/radare2",
            "/usr/share/cutter",
        ];

        for file in sandbox_files.iter() {
            if Path::new(file).exists() {
                return true;
            }
        }

        // Check for sandbox-specific registry keys
        unsafe {
            let mut hkey = std::ptr::null_mut();
            let sandbox_registry_keys = [
                "SOFTWARE\\Wireshark",
                "SOFTWARE\\Sysinternals",
                "SOFTWARE\\IDA",
                "SOFTWARE\\x64dbg",
                "SOFTWARE\\OllyDbg",
                "SOFTWARE\\Immunity Inc",
                "SOFTWARE\\Ghidra",
                "SOFTWARE\\Radare2",
                "SOFTWARE\\Cutter",
            ];

            for key in sandbox_registry_keys.iter() {
                if RegOpenKeyExA(
                    HKEY_LOCAL_MACHINE,
                    key.as_ptr() as *const i8,
                    0,
                    KEY_READ,
                    &mut hkey,
                ) == 0
                {
                    CloseHandle(hkey);
                    return true;
                }
            }
        }

        // Check for sandbox-specific DLLs
        unsafe {
            let process = GetCurrentProcess();
            let mut modules = [std::ptr::null_mut(); 1024];
            let mut needed = 0;

            if K32EnumProcessModules(
                process,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<*mut _>()) as u32,
                &mut needed,
            ) != 0
            {
                let module_count = needed as usize / std::mem::size_of::<*mut _>();
                for i in 0..module_count {
                    let mut module_info = std::mem::zeroed();
                    if K32GetModuleInformation(
                        process,
                        modules[i],
                        &mut module_info,
                        std::mem::size_of::<*mut _>() as u32,
                    ) != 0
                    {
                        // Check for sandbox-specific DLLs
                        let sandbox_dlls = [
                            "sbiedll.dll",  // Sandboxie
                            "dbghelp.dll",  // Debugging
                            "api_log.dll",  // API monitoring
                            "dir_watch.dll", // File monitoring
                            "api_hook.dll",  // API hooking
                        ];

                        for dll in sandbox_dlls.iter() {
                            if module_info.szModule.contains(dll) {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        // Check for sandbox-specific timing patterns
        let start = Instant::now();
        for _ in 0..1000 {
            unsafe {
                GetAsyncKeyState(0);
            }
        }
        let duration = start.elapsed();

        // Sandboxes often have more consistent timing patterns
        if duration.as_micros() < 1000 || duration.as_micros() > 5000 {
            return true;
        }

        // Check for sandbox-specific keyboard patterns
        unsafe {
            let mut sandbox_keyboard = false;
            for i in 0..256 {
                if GetKeyState(i) & 0x8000 != 0 {
                    sandbox_keyboard = true;
                    break;
                }
            }
            if sandbox_keyboard {
                return true;
            }
        }

        // Check for sandbox-specific computer name patterns
        unsafe {
            let mut computer_name = [0u8; 32];
            let mut size = computer_name.len() as u32;
            if GetComputerNameA(
                computer_name.as_mut_ptr() as *mut i8,
                &mut size,
            ) != 0
            {
                let name = String::from_utf8_lossy(&computer_name[..size as usize]);
                let sandbox_names = ["SANDBOX", "ANALYSIS", "MALWARE", "VIRUS"];
                for sandbox_name in sandbox_names.iter() {
                    if name.to_uppercase().contains(sandbox_name) {
                        return true;
                    }
                }
            }
        }

        false
    }

    pub fn detect_debugger(&self) -> bool {
        // Check for debugger processes
        let debugger_processes = [
            "x64dbg.exe",
            "x32dbg.exe",
            "ollydbg.exe",
            "windbg.exe",
            "ida.exe",
            "ida64.exe",
            "ghidra.exe",
            "radare2.exe",
            "cutter.exe",
            "immunity debugger.exe",
            "immunity debugger64.exe",
        ];

        for process in self.system.processes().values() {
            if debugger_processes.contains(&process.name().to_lowercase().as_str()) {
                return true;
            }
        }

        // Check for debugger DLLs
        unsafe {
            let process = GetCurrentProcess();
            let mut modules = [std::ptr::null_mut(); 1024];
            let mut needed = 0;

            if K32EnumProcessModules(
                process,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<*mut _>()) as u32,
                &mut needed,
            ) != 0
            {
                let module_count = needed as usize / std::mem::size_of::<*mut _>();
                for i in 0..module_count {
                    let mut module_info = std::mem::zeroed();
                    if K32GetModuleInformation(
                        process,
                        modules[i],
                        &mut module_info,
                        std::mem::size_of::<*mut _>() as u32,
                    ) != 0
                    {
                        // Check for debugger-specific DLLs
                        let debugger_dlls = [
                            "dbghelp.dll",
                            "api_log.dll",
                            "dir_watch.dll",
                            "api_hook.dll",
                        ];

                        for dll in debugger_dlls.iter() {
                            if module_info.szModule.contains(dll) {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        // Check for debugger-specific timing patterns
        let start = Instant::now();
        for _ in 0..1000 {
            unsafe {
                GetAsyncKeyState(0);
            }
        }
        let duration = start.elapsed();

        // Debuggers often have more consistent timing patterns
        if duration.as_micros() < 1000 || duration.as_micros() > 5000 {
            return true;
        }

        // Check for debugger-specific keyboard patterns
        unsafe {
            let mut debugger_keyboard = false;
            for i in 0..256 {
                if GetKeyState(i) & 0x8000 != 0 {
                    debugger_keyboard = true;
                    break;
                }
            }
            if debugger_keyboard {
                return true;
            }
        }

        // Check for debugger-specific computer name patterns
        unsafe {
            let mut computer_name = [0u8; 32];
            let mut size = computer_name.len() as u32;
            if GetComputerNameA(
                computer_name.as_mut_ptr() as *mut i8,
                &mut size,
            ) != 0
            {
                let name = String::from_utf8_lossy(&computer_name[..size as usize]);
                let debugger_names = ["DEBUG", "ANALYSIS", "REVERSE"];
                for debugger_name in debugger_names.iter() {
                    if name.to_uppercase().contains(debugger_name) {
                        return true;
                    }
                }
            }
        }

        false
    }

    pub fn detect_analysis(&self) -> bool {
        // Check for analysis tools
        let analysis_tools = [
            "wireshark.exe",
            "procmon.exe",
            "procmon64.exe",
            "tcpview.exe",
            "tcpview64.exe",
            "autoruns.exe",
            "autoruns64.exe",
            "filemon.exe",
            "filemon64.exe",
            "regmon.exe",
            "regmon64.exe",
            "processhacker.exe",
            "processhacker64.exe",
            "x64dbg.exe",
            "x32dbg.exe",
            "ollydbg.exe",
            "windbg.exe",
            "ida.exe",
            "ida64.exe",
            "ghidra.exe",
            "radare2.exe",
            "cutter.exe",
            "immunity debugger.exe",
            "immunity debugger64.exe",
        ];

        for process in self.system.processes().values() {
            if analysis_tools.contains(&process.name().to_lowercase().as_str()) {
                return true;
            }
        }

        // Check for analysis-specific files
        let analysis_files = [
            "C:\\Program Files\\Wireshark",
            "C:\\Program Files\\Sysinternals",
            "C:\\Program Files\\IDA",
            "C:\\Program Files\\x64dbg",
            "C:\\Program Files\\OllyDbg",
            "C:\\Program Files\\Immunity Inc",
            "C:\\Program Files\\Ghidra",
            "C:\\Program Files\\Radare2",
            "C:\\Program Files\\Cutter",
            "/usr/share/wireshark",
            "/usr/share/sysinternals",
            "/usr/share/ida",
            "/usr/share/x64dbg",
            "/usr/share/ollydbg",
            "/usr/share/immunity",
            "/usr/share/ghidra",
            "/usr/share/radare2",
            "/usr/share/cutter",
        ];

        for file in analysis_files.iter() {
            if Path::new(file).exists() {
                return true;
            }
        }

        // Check for analysis-specific registry keys
        unsafe {
            let mut hkey = std::ptr::null_mut();
            let analysis_registry_keys = [
                "SOFTWARE\\Wireshark",
                "SOFTWARE\\Sysinternals",
                "SOFTWARE\\IDA",
                "SOFTWARE\\x64dbg",
                "SOFTWARE\\OllyDbg",
                "SOFTWARE\\Immunity Inc",
                "SOFTWARE\\Ghidra",
                "SOFTWARE\\Radare2",
                "SOFTWARE\\Cutter",
            ];

            for key in analysis_registry_keys.iter() {
                if RegOpenKeyExA(
                    HKEY_LOCAL_MACHINE,
                    key.as_ptr() as *const i8,
                    0,
                    KEY_READ,
                    &mut hkey,
                ) == 0
                {
                    CloseHandle(hkey);
                    return true;
                }
            }
        }

        // Check for analysis-specific DLLs
        unsafe {
            let process = GetCurrentProcess();
            let mut modules = [std::ptr::null_mut(); 1024];
            let mut needed = 0;

            if K32EnumProcessModules(
                process,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<*mut _>()) as u32,
                &mut needed,
            ) != 0
            {
                let module_count = needed as usize / std::mem::size_of::<*mut _>();
                for i in 0..module_count {
                    let mut module_info = std::mem::zeroed();
                    if K32GetModuleInformation(
                        process,
                        modules[i],
                        &mut module_info,
                        std::mem::size_of::<*mut _>() as u32,
                    ) != 0
                    {
                        // Check for analysis-specific DLLs
                        let analysis_dlls = [
                            "sbiedll.dll",  // Sandboxie
                            "dbghelp.dll",  // Debugging
                            "api_log.dll",  // API monitoring
                            "dir_watch.dll", // File monitoring
                            "api_hook.dll",  // API hooking
                        ];

                        for dll in analysis_dlls.iter() {
                            if module_info.szModule.contains(dll) {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        // Check for analysis-specific timing patterns
        let start = Instant::now();
        for _ in 0..1000 {
            unsafe {
                GetAsyncKeyState(0);
            }
        }
        let duration = start.elapsed();

        // Analysis tools often have more consistent timing patterns
        if duration.as_micros() < 1000 || duration.as_micros() > 5000 {
            return true;
        }

        // Check for analysis-specific keyboard patterns
        unsafe {
            let mut analysis_keyboard = false;
            for i in 0..256 {
                if GetKeyState(i) & 0x8000 != 0 {
                    analysis_keyboard = true;
                    break;
                }
            }
            if analysis_keyboard {
                return true;
            }
        }

        // Check for analysis-specific computer name patterns
        unsafe {
            let mut computer_name = [0u8; 32];
            let mut size = computer_name.len() as u32;
            if GetComputerNameA(
                computer_name.as_mut_ptr() as *mut i8,
                &mut size,
            ) != 0
            {
                let name = String::from_utf8_lossy(&computer_name[..size as usize]);
                let analysis_names = ["ANALYSIS", "REVERSE", "MALWARE", "VIRUS"];
                for analysis_name in analysis_names.iter() {
                    if name.to_uppercase().contains(analysis_name) {
                        return true;
                    }
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_vm() {
        let anti_vm = AntiVM::new();
        assert!(!anti_vm.detect_vm());
    }

    #[test]
    fn test_anti_sandbox() {
        let anti_vm = AntiVM::new();
        assert!(!anti_vm.detect_sandbox());
    }

    #[test]
    fn test_anti_debugger() {
        let anti_vm = AntiVM::new();
        assert!(!anti_vm.detect_debugger());
    }

    #[test]
    fn test_anti_analysis() {
        let anti_vm = AntiVM::new();
        assert!(!anti_vm.detect_analysis());
    }
} 