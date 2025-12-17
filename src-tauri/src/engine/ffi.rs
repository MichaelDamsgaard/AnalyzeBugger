//! FFI bindings to C++ DebugEngine.dll

use std::ffi::{c_char, c_void, CString, CStr};
use std::path::Path;
use libloading::{Library, Symbol};

/// Handle to a debug session (opaque pointer from C++)
pub type SessionHandle = *mut c_void;

/// Send+Sync wrapper for SessionHandle
/// Safety: The C++ debug engine is designed to be called from a single thread
/// and we protect access via Mutex in the SessionManager
#[derive(Debug, Clone, Copy)]
pub struct SafeSessionHandle(pub SessionHandle);

unsafe impl Send for SafeSessionHandle {}
unsafe impl Sync for SafeSessionHandle {}

/// LongBool from C++ (4 bytes, 0 = false, non-zero = true)
pub type LongBool = i32;

/// Registers structure (matches C++ BIP_Registers)
#[repr(C, packed)]
#[derive(Debug, Clone, Default)]
pub struct BipRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rip: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub eflags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
}

/// Module information structure (matches C++ BIP_ModuleInfo)
#[repr(C, packed)]
pub struct BipModuleInfo {
    pub base_address: u64,
    pub size: u32,
    pub entry_point: u64,
    pub name_ptr: *const c_char,
    pub name_len: u32,
}

impl Default for BipModuleInfo {
    fn default() -> Self {
        Self {
            base_address: 0,
            size: 0,
            entry_point: 0,
            name_ptr: std::ptr::null(),
            name_len: 0,
        }
    }
}

impl BipModuleInfo {
    /// Get the module name as a Rust string
    pub fn get_name(&self) -> String {
        if self.name_ptr.is_null() || self.name_len == 0 {
            return String::new();
        }
        unsafe {
            let slice = std::slice::from_raw_parts(self.name_ptr as *const u8, self.name_len as usize);
            String::from_utf8_lossy(slice).to_string()
        }
    }
}

/// API trace entry structure (matches C++ BIP_TraceEntry)
#[repr(C, packed)]
pub struct BipTraceEntry {
    pub module_name_ptr: *const c_char,
    pub function_name_ptr: *const c_char,
    pub address: u64,
    pub invoke_count: u32,
    pub total_ticks: u64,
}

impl Default for BipTraceEntry {
    fn default() -> Self {
        Self {
            module_name_ptr: std::ptr::null(),
            function_name_ptr: std::ptr::null(),
            address: 0,
            invoke_count: 0,
            total_ticks: 0,
        }
    }
}

impl BipTraceEntry {
    /// Get module name as Rust string
    pub fn get_module_name(&self) -> String {
        if self.module_name_ptr.is_null() {
            return String::new();
        }
        unsafe {
            CStr::from_ptr(self.module_name_ptr)
                .to_string_lossy()
                .to_string()
        }
    }

    /// Get function name as Rust string
    pub fn get_function_name(&self) -> String {
        if self.function_name_ptr.is_null() {
            return String::new();
        }
        unsafe {
            CStr::from_ptr(self.function_name_ptr)
                .to_string_lossy()
                .to_string()
        }
    }
}

/// Session status structure (matches C++ BIP_SessionStatus)
#[repr(C, packed)]
#[derive(Debug, Clone, Default)]
pub struct BipSessionStatus {
    pub is_running: LongBool,
    pub is_paused: LongBool,
    pub is_stopped: LongBool,
    pub process_id: u32,
    pub thread_id: u32,
    pub module_count: i32,
    pub breakpoint_count: i32,
    pub current_ip: u64,
}

/// C++ Debug Engine DLL wrapper
pub struct DebugEngineDll {
    library: Library,
}

// Mark as Send + Sync for use in Arc
unsafe impl Send for DebugEngineDll {}
unsafe impl Sync for DebugEngineDll {}

impl DebugEngineDll {
    /// Load the Debug Engine DLL
    pub fn load(dll_path: &Path) -> Result<Self, String> {
        unsafe {
            let library = Library::new(dll_path)
                .map_err(|e| format!("Failed to load DLL: {}", e))?;
            Ok(Self { library })
        }
    }

    /// Get DLL version
    pub fn get_version(&self) -> Result<u32, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn() -> u32> =
                self.library.get(b"BIP_GetVersion")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func())
        }
    }

    /// Create a new debug session
    pub fn create_session(&self, target_path: &str) -> Result<SessionHandle, String> {
        let target = CString::new(target_path)
            .map_err(|_| "Invalid path".to_string())?;

        unsafe {
            let func: Symbol<unsafe extern "system" fn(*const c_char) -> SessionHandle> =
                self.library.get(b"BIP_CreateSession")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            let handle = func(target.as_ptr());
            if handle.is_null() {
                Err("Failed to create session".to_string())
            } else {
                Ok(handle)
            }
        }
    }

    /// Destroy a debug session
    pub fn destroy_session(&self, handle: SessionHandle) -> Result<bool, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle) -> LongBool> =
                self.library.get(b"BIP_DestroySession")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle) != 0)
        }
    }

    /// Get session status
    pub fn get_status(&self, handle: SessionHandle) -> Result<BipSessionStatus, String> {
        let mut status = BipSessionStatus::default();
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle, *mut BipSessionStatus) -> LongBool> =
                self.library.get(b"BIP_GetStatus")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            if func(handle, &mut status as *mut BipSessionStatus) != 0 {
                Ok(status)
            } else {
                Err("Failed to get status".to_string())
            }
        }
    }

    /// Start debugging
    pub fn start(&self, handle: SessionHandle) -> Result<bool, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle) -> LongBool> =
                self.library.get(b"BIP_Start")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle) != 0)
        }
    }

    /// Stop debugging
    pub fn stop(&self, handle: SessionHandle) -> Result<bool, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle) -> LongBool> =
                self.library.get(b"BIP_Stop")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle) != 0)
        }
    }

    /// Pause execution
    pub fn pause(&self, handle: SessionHandle) -> Result<bool, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle) -> LongBool> =
                self.library.get(b"BIP_Pause")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle) != 0)
        }
    }

    /// Continue execution
    pub fn continue_execution(&self, handle: SessionHandle) -> Result<bool, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle) -> LongBool> =
                self.library.get(b"BIP_Continue")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle) != 0)
        }
    }

    /// Single step into
    pub fn step_into(&self, handle: SessionHandle) -> Result<bool, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle) -> LongBool> =
                self.library.get(b"BIP_StepInto")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle) != 0)
        }
    }

    /// Single step over
    pub fn step_over(&self, handle: SessionHandle) -> Result<bool, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle) -> LongBool> =
                self.library.get(b"BIP_StepOver")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle) != 0)
        }
    }

    /// Set software breakpoint
    pub fn set_breakpoint(&self, handle: SessionHandle, address: u64, bp_type: i32) -> Result<i32, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle, u64, i32) -> i32> =
                self.library.get(b"BIP_SetBreakpoint")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle, address, bp_type))
        }
    }

    /// Remove breakpoint
    pub fn remove_breakpoint(&self, handle: SessionHandle, bp_id: i32) -> Result<bool, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle, i32) -> LongBool> =
                self.library.get(b"BIP_RemoveBreakpoint")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle, bp_id) != 0)
        }
    }

    /// Set hardware breakpoint
    pub fn set_hardware_breakpoint(&self, handle: SessionHandle, register: i32, address: u64, bp_type: i32) -> Result<bool, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle, i32, u64, i32) -> LongBool> =
                self.library.get(b"BIP_SetHardwareBreakpoint")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle, register, address, bp_type) != 0)
        }
    }

    /// Clear hardware breakpoint
    pub fn clear_hardware_breakpoint(&self, handle: SessionHandle, register: i32) -> Result<bool, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle, i32) -> LongBool> =
                self.library.get(b"BIP_ClearHardwareBreakpoint")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle, register) != 0)
        }
    }

    /// Read memory
    pub fn read_memory(&self, handle: SessionHandle, address: u64, size: u32, buffer: &mut [u8]) -> Result<bool, String> {
        if buffer.len() < size as usize {
            return Err("Buffer too small".to_string());
        }

        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle, u64, u32, *mut u8) -> LongBool> =
                self.library.get(b"BIP_ReadMemory")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle, address, size, buffer.as_mut_ptr()) != 0)
        }
    }

    /// Write memory
    pub fn write_memory(&self, handle: SessionHandle, address: u64, buffer: &[u8]) -> Result<bool, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle, u64, u32, *const u8) -> LongBool> =
                self.library.get(b"BIP_WriteMemory")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle, address, buffer.len() as u32, buffer.as_ptr()) != 0)
        }
    }

    /// Search for pattern in memory
    pub fn search_pattern(&self, handle: SessionHandle, pattern: &[u8]) -> Result<u64, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle, *const u8, u32) -> u64> =
                self.library.get(b"BIP_SearchPattern")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle, pattern.as_ptr(), pattern.len() as u32))
        }
    }

    /// Get registers
    pub fn get_registers(&self, handle: SessionHandle) -> Result<BipRegisters, String> {
        let mut regs = BipRegisters::default();
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle, *mut BipRegisters) -> LongBool> =
                self.library.get(b"BIP_GetRegisters")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            if func(handle, &mut regs as *mut BipRegisters) != 0 {
                Ok(regs)
            } else {
                Err("Failed to get registers".to_string())
            }
        }
    }

    /// Set registers
    pub fn set_registers(&self, handle: SessionHandle, regs: &BipRegisters) -> Result<bool, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle, *const BipRegisters) -> LongBool> =
                self.library.get(b"BIP_SetRegisters")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle, regs as *const BipRegisters) != 0)
        }
    }

    /// Get module count
    pub fn get_module_count(&self, handle: SessionHandle) -> Result<i32, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle) -> i32> =
                self.library.get(b"BIP_GetModuleCount")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle))
        }
    }

    /// Get module info
    pub fn get_module_info(&self, handle: SessionHandle, index: i32) -> Result<BipModuleInfo, String> {
        let mut info = BipModuleInfo::default();
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle, i32, *mut BipModuleInfo) -> LongBool> =
                self.library.get(b"BIP_GetModuleInfo")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            if func(handle, index, &mut info as *mut BipModuleInfo) != 0 {
                Ok(info)
            } else {
                Err("Failed to get module info".to_string())
            }
        }
    }

    /// Get export count for a module
    pub fn get_export_count(&self, handle: SessionHandle, module_index: i32) -> Result<i32, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle, i32) -> i32> =
                self.library.get(b"BIP_GetExportCount")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle, module_index))
        }
    }

    /// Get trace entry count
    pub fn get_trace_count(&self, handle: SessionHandle) -> Result<i32, String> {
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle) -> i32> =
                self.library.get(b"BIP_GetTraceCount")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            Ok(func(handle))
        }
    }

    /// Get trace entry
    pub fn get_trace_entry(&self, handle: SessionHandle, index: i32) -> Result<BipTraceEntry, String> {
        let mut entry = BipTraceEntry::default();
        unsafe {
            let func: Symbol<unsafe extern "system" fn(SessionHandle, i32, *mut BipTraceEntry) -> LongBool> =
                self.library.get(b"BIP_GetTraceEntry")
                    .map_err(|e| format!("Symbol not found: {}", e))?;
            if func(handle, index, &mut entry as *mut BipTraceEntry) != 0 {
                Ok(entry)
            } else {
                Err("Failed to get trace entry".to_string())
            }
        }
    }
}
