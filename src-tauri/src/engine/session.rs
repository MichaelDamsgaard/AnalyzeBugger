//! Debug session management with actual DLL integration

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

use super::ffi::{DebugEngineDll, BipSessionStatus, BipRegisters, BipModuleInfo, BipTraceEntry, SafeSessionHandle};

/// Manages debug sessions with DLL integration
pub struct SessionManager {
    dll: Option<Arc<DebugEngineDll>>,
    sessions: HashMap<String, DebugSession>,
    active_session: Option<String>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            dll: None,
            sessions: HashMap::new(),
            active_session: None,
        }
    }

    /// Load the debug engine DLL
    pub fn load_dll(&mut self, dll_path: &Path) -> Result<(), String> {
        match DebugEngineDll::load(dll_path) {
            Ok(dll) => {
                self.dll = Some(Arc::new(dll));
                Ok(())
            }
            Err(e) => Err(format!("Failed to load DLL: {}", e))
        }
    }

    /// Check if DLL is loaded
    pub fn is_dll_loaded(&self) -> bool {
        self.dll.is_some()
    }

    /// Get DLL version
    pub fn get_dll_version(&self) -> Option<String> {
        self.dll.as_ref().and_then(|dll| {
            dll.get_version().ok().map(|v| {
                format!("{}.{}.{}.{}",
                    (v >> 24) & 0xFF,
                    (v >> 16) & 0xFF,
                    (v >> 8) & 0xFF,
                    v & 0xFF)
            })
        })
    }

    /// Get overall status
    pub fn get_status(&self) -> SessionStatus {
        SessionStatus {
            active: self.active_session.is_some(),
            session_count: self.sessions.len(),
            active_session_id: self.active_session.clone(),
            dll_loaded: self.dll.is_some(),
            dll_version: self.get_dll_version(),
        }
    }

    /// Create a new debug session
    pub fn create_session(&mut self, target_path: &str) -> Result<String, String> {
        let dll = self.dll.as_ref().ok_or("DLL not loaded")?;

        // Create session in DLL
        let handle = dll.create_session(target_path)?;

        let session_id = Uuid::new_v4().to_string();

        let session = DebugSession {
            id: session_id.clone(),
            target_path: target_path.to_string(),
            state: SessionState::Created,
            process_id: None,
            thread_id: None,
            handle: SafeSessionHandle(handle),
            dll: Arc::clone(dll),
        };

        self.sessions.insert(session_id.clone(), session);
        self.active_session = Some(session_id.clone());

        Ok(session_id)
    }

    /// Get a session by ID
    pub fn get_session(&self, session_id: &str) -> Option<&DebugSession> {
        self.sessions.get(session_id)
    }

    /// Get a mutable session by ID
    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut DebugSession> {
        self.sessions.get_mut(session_id)
    }

    /// Get the active session
    pub fn get_active_session(&self) -> Option<&DebugSession> {
        self.active_session.as_ref().and_then(|id| self.sessions.get(id))
    }

    /// Get mutable active session
    pub fn get_active_session_mut(&mut self) -> Option<&mut DebugSession> {
        if let Some(id) = self.active_session.clone() {
            self.sessions.get_mut(&id)
        } else {
            None
        }
    }

    /// Remove a session
    pub fn remove_session(&mut self, session_id: &str) -> Result<bool, String> {
        if let Some(session) = self.sessions.remove(session_id) {
            // Destroy session in DLL
            let _ = session.dll.destroy_session(session.handle.0);

            if self.active_session.as_deref() == Some(session_id) {
                self.active_session = None;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Set active session
    pub fn set_active_session(&mut self, session_id: &str) -> bool {
        if self.sessions.contains_key(session_id) {
            self.active_session = Some(session_id.to_string());
            true
        } else {
            false
        }
    }
}

/// Debug session information with DLL handle
pub struct DebugSession {
    pub id: String,
    pub target_path: String,
    pub state: SessionState,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
    handle: SafeSessionHandle,
    dll: Arc<DebugEngineDll>,
}

impl DebugSession {
    /// Start the debug session
    pub fn start(&mut self) -> Result<(), String> {
        if self.dll.start(self.handle.0)? {
            self.state = SessionState::Running;
            self.update_status()?;
            Ok(())
        } else {
            Err("Failed to start session".to_string())
        }
    }

    /// Stop the debug session
    pub fn stop(&mut self) -> Result<(), String> {
        if self.dll.stop(self.handle.0)? {
            self.state = SessionState::Terminated;
            Ok(())
        } else {
            Err("Failed to stop session".to_string())
        }
    }

    /// Pause execution
    pub fn pause(&mut self) -> Result<(), String> {
        if self.dll.pause(self.handle.0)? {
            self.state = SessionState::Paused;
            self.update_status()?;
            Ok(())
        } else {
            Err("Failed to pause session".to_string())
        }
    }

    /// Continue execution
    pub fn continue_execution(&mut self) -> Result<(), String> {
        if self.dll.continue_execution(self.handle.0)? {
            self.state = SessionState::Running;
            Ok(())
        } else {
            Err("Failed to continue session".to_string())
        }
    }

    /// Step into
    pub fn step_into(&mut self) -> Result<(), String> {
        if self.dll.step_into(self.handle.0)? {
            self.state = SessionState::Stepping;
            Ok(())
        } else {
            Err("Failed to step into".to_string())
        }
    }

    /// Step over
    pub fn step_over(&mut self) -> Result<(), String> {
        if self.dll.step_over(self.handle.0)? {
            self.state = SessionState::Stepping;
            Ok(())
        } else {
            Err("Failed to step over".to_string())
        }
    }

    /// Set breakpoint
    pub fn set_breakpoint(&self, address: u64, bp_type: i32) -> Result<i32, String> {
        self.dll.set_breakpoint(self.handle.0, address, bp_type)
    }

    /// Remove breakpoint
    pub fn remove_breakpoint(&self, bp_id: i32) -> Result<bool, String> {
        self.dll.remove_breakpoint(self.handle.0, bp_id)
    }

    /// Set hardware breakpoint
    pub fn set_hardware_breakpoint(&self, register: i32, address: u64, bp_type: i32) -> Result<bool, String> {
        self.dll.set_hardware_breakpoint(self.handle.0, register, address, bp_type)
    }

    /// Clear hardware breakpoint
    pub fn clear_hardware_breakpoint(&self, register: i32) -> Result<bool, String> {
        self.dll.clear_hardware_breakpoint(self.handle.0, register)
    }

    /// Read memory
    pub fn read_memory(&self, address: u64, size: u32) -> Result<Vec<u8>, String> {
        let mut buffer = vec![0u8; size as usize];
        if self.dll.read_memory(self.handle.0, address, size, &mut buffer)? {
            Ok(buffer)
        } else {
            Err("Failed to read memory".to_string())
        }
    }

    /// Write memory
    pub fn write_memory(&self, address: u64, data: &[u8]) -> Result<bool, String> {
        self.dll.write_memory(self.handle.0, address, data)
    }

    /// Search pattern
    pub fn search_pattern(&self, pattern: &[u8]) -> Result<u64, String> {
        self.dll.search_pattern(self.handle.0, pattern)
    }

    /// Get registers
    pub fn get_registers(&self) -> Result<BipRegisters, String> {
        self.dll.get_registers(self.handle.0)
    }

    /// Set registers
    pub fn set_registers(&self, regs: &BipRegisters) -> Result<bool, String> {
        self.dll.set_registers(self.handle.0, regs)
    }

    /// Get module count
    pub fn get_module_count(&self) -> Result<i32, String> {
        self.dll.get_module_count(self.handle.0)
    }

    /// Get module info
    pub fn get_module_info(&self, index: i32) -> Result<BipModuleInfo, String> {
        self.dll.get_module_info(self.handle.0, index)
    }

    /// Get trace count
    pub fn get_trace_count(&self) -> Result<i32, String> {
        self.dll.get_trace_count(self.handle.0)
    }

    /// Get trace entry
    pub fn get_trace_entry(&self, index: i32) -> Result<BipTraceEntry, String> {
        self.dll.get_trace_entry(self.handle.0, index)
    }

    /// Get detailed status from DLL
    pub fn get_detailed_status(&self) -> Result<BipSessionStatus, String> {
        self.dll.get_status(self.handle.0)
    }

    /// Update local state from DLL status
    fn update_status(&mut self) -> Result<(), String> {
        let status = self.dll.get_status(self.handle.0)?;
        self.process_id = if status.process_id > 0 { Some(status.process_id) } else { None };
        self.thread_id = if status.thread_id > 0 { Some(status.thread_id) } else { None };

        if status.is_stopped != 0 {
            self.state = SessionState::Terminated;
        } else if status.is_paused != 0 {
            self.state = SessionState::Paused;
        } else if status.is_running != 0 {
            self.state = SessionState::Running;
        }

        Ok(())
    }

    /// Get current instruction pointer
    pub fn get_current_ip(&self) -> Result<u64, String> {
        let status = self.dll.get_status(self.handle.0)?;
        Ok(status.current_ip)
    }
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Created,
    Running,
    Paused,
    Stepping,
    Terminated,
}

/// Overall status response
#[derive(Debug, Serialize)]
pub struct SessionStatus {
    pub active: bool,
    pub session_count: usize,
    pub active_session_id: Option<String>,
    pub dll_loaded: bool,
    pub dll_version: Option<String>,
}

/// Detailed session info for API response
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub target_path: String,
    pub state: SessionState,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
    pub current_ip: Option<u64>,
    pub module_count: Option<i32>,
    pub breakpoint_count: Option<i32>,
}

impl From<&DebugSession> for SessionInfo {
    fn from(session: &DebugSession) -> Self {
        let (current_ip, module_count, breakpoint_count) =
            if let Ok(status) = session.get_detailed_status() {
                (
                    Some(status.current_ip),
                    Some(status.module_count),
                    Some(status.breakpoint_count),
                )
            } else {
                (None, None, None)
            };

        SessionInfo {
            id: session.id.clone(),
            target_path: session.target_path.clone(),
            state: session.state,
            process_id: session.process_id,
            thread_id: session.thread_id,
            current_ip,
            module_count,
            breakpoint_count,
        }
    }
}
