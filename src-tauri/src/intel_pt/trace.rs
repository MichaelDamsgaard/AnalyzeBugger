//! Intel PT Trace Session Management

use super::config::PtTraceConfig;
use super::types::*;
use super::winipt::WinIptDriver;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

fn generate_trace_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("pt-trace-{:016x}", timestamp)
}

#[derive(Debug)]
pub struct TraceSession {
    pub id: String,
    pub state: TraceState,
    pub config: PtTraceConfig,
    pub process_id: Option<u32>,
    pub core_id: Option<u32>,
    buffer: Vec<u8>,
    driver_handle: Option<u64>,
    start_time: Option<u64>,
    end_time: Option<u64>,
    overflow: bool,
}

impl TraceSession {
    pub fn new_process_trace(process_id: u32, config: PtTraceConfig) -> Self {
        Self {
            id: generate_trace_id(),
            state: TraceState::Idle,
            config,
            process_id: Some(process_id),
            core_id: None,
            buffer: Vec::new(),
            driver_handle: None,
            start_time: None,
            end_time: None,
            overflow: false,
        }
    }

    pub fn new_core_trace(core_id: u32, config: PtTraceConfig) -> Self {
        Self {
            id: generate_trace_id(),
            state: TraceState::Idle,
            config,
            process_id: None,
            core_id: Some(core_id),
            buffer: Vec::new(),
            driver_handle: None,
            start_time: None,
            end_time: None,
            overflow: false,
        }
    }

    pub fn allocate_buffer(&mut self) -> Result<(), String> {
        self.buffer = vec![0u8; self.config.buffer.size];
        Ok(())
    }

    pub fn get_buffer(&self) -> &[u8] { &self.buffer }
    pub fn get_buffer_mut(&mut self) -> &mut [u8] { &mut self.buffer }
    pub fn set_driver_handle(&mut self, handle: u64) { self.driver_handle = Some(handle); }
    pub fn get_driver_handle(&self) -> Option<u64> { self.driver_handle }
    pub fn mark_started(&mut self, tsc: u64) { self.state = TraceState::Tracing; self.start_time = Some(tsc); }
    pub fn mark_stopped(&mut self, tsc: u64) { self.state = TraceState::Stopped; self.end_time = Some(tsc); }
    pub fn has_overflow(&self) -> bool { self.overflow }

    pub fn get_trace_data(&self) -> TraceData {
        TraceData {
            trace_id: self.id.clone(),
            process_id: self.process_id,
            core_id: self.core_id,
            raw_data: self.buffer.clone(),
            buffer_size: self.buffer.len(),
            packet_count_estimate: self.buffer.len() / 4,
            overflow: self.overflow,
            start_tsc: self.start_time.unwrap_or(0),
            end_tsc: self.end_time,
            config: self.config.clone(),
        }
    }
}

pub struct TraceManager {
    sessions: HashMap<String, TraceSession>,
    driver: Arc<Mutex<WinIptDriver>>,
    driver_status: IptDriverStatus,
    max_concurrent: usize,
}

impl TraceManager {
    pub fn new() -> Self {
        let driver = WinIptDriver::new();
        let driver_status = IptDriverStatus {
            loaded: driver.is_available(),
            version: driver.get_version(),
            active_traces: 0,
            available_buffer: 0,
            last_error: None,
        };
        Self {
            sessions: HashMap::new(),
            driver: Arc::new(Mutex::new(driver)),
            driver_status,
            max_concurrent: 4,
        }
    }

    pub fn get_active_trace_count(&self) -> usize {
        self.sessions.values().filter(|s| s.state == TraceState::Tracing).count()
    }

    pub fn get_driver_status(&self) -> &IptDriverStatus { &self.driver_status }

    pub fn start_process_trace(&mut self, process_id: u32, config: PtTraceConfig) -> Result<String, String> {
        if self.get_active_trace_count() >= self.max_concurrent {
            return Err(format!("Max concurrent traces ({}) reached", self.max_concurrent));
        }

        let mut session = TraceSession::new_process_trace(process_id, config);
        session.state = TraceState::Configuring;
        session.allocate_buffer()?;

        // Clone config before mutable borrow of buffer
        let config_clone = session.config.clone();
        let buffer = session.get_buffer_mut();

        {
            let mut driver = self.driver.lock().map_err(|e| e.to_string())?;
            if !driver.is_available() {
                return Err("Intel PT driver not available".to_string());
            }
            let handle = driver.start_process_trace(process_id, buffer, &config_clone)?;
            session.set_driver_handle(handle);
        }

        let tsc = self.get_current_tsc();
        session.mark_started(tsc);
        let id = session.id.clone();
        self.sessions.insert(id.clone(), session);
        self.driver_status.active_traces = self.get_active_trace_count();
        Ok(id)
    }

    pub fn start_core_trace(&mut self, core_id: u32, config: PtTraceConfig) -> Result<String, String> {
        if self.get_active_trace_count() >= self.max_concurrent {
            return Err(format!("Max concurrent traces ({}) reached", self.max_concurrent));
        }

        let mut session = TraceSession::new_core_trace(core_id, config);
        session.state = TraceState::Configuring;
        session.allocate_buffer()?;

        // Clone config before mutable borrow of buffer
        let config_clone = session.config.clone();
        let buffer = session.get_buffer_mut();

        {
            let mut driver = self.driver.lock().map_err(|e| e.to_string())?;
            if !driver.is_available() {
                return Err("Intel PT driver not available".to_string());
            }
            let handle = driver.start_core_trace(core_id, buffer, &config_clone)?;
            session.set_driver_handle(handle);
        }

        let tsc = self.get_current_tsc();
        session.mark_started(tsc);
        let id = session.id.clone();
        self.sessions.insert(id.clone(), session);
        self.driver_status.active_traces = self.get_active_trace_count();
        Ok(id)
    }

    pub fn stop_trace(&mut self, trace_id: &str) -> Result<(), String> {
        // Get current TSC before borrowing session
        let tsc = self.get_current_tsc();

        let session = self.sessions.get_mut(trace_id)
            .ok_or_else(|| format!("Trace not found: {}", trace_id))?;

        if session.state != TraceState::Tracing && session.state != TraceState::Paused {
            return Err(format!("Cannot stop trace in state {:?}", session.state));
        }

        if let Some(handle) = session.get_driver_handle() {
            let mut driver = self.driver.lock().map_err(|e| e.to_string())?;
            driver.stop_trace(handle)?;
        }

        session.mark_stopped(tsc);
        self.driver_status.active_traces = self.get_active_trace_count();
        Ok(())
    }

    pub fn pause_trace(&mut self, trace_id: &str) -> Result<(), String> {
        let session = self.sessions.get_mut(trace_id)
            .ok_or_else(|| format!("Trace not found: {}", trace_id))?;

        if session.state != TraceState::Tracing {
            return Err(format!("Cannot pause trace in state {:?}", session.state));
        }

        if let Some(handle) = session.get_driver_handle() {
            let mut driver = self.driver.lock().map_err(|e| e.to_string())?;
            driver.pause_trace(handle)?;
        }
        session.state = TraceState::Paused;
        Ok(())
    }

    pub fn resume_trace(&mut self, trace_id: &str) -> Result<(), String> {
        let session = self.sessions.get_mut(trace_id)
            .ok_or_else(|| format!("Trace not found: {}", trace_id))?;

        if session.state != TraceState::Paused {
            return Err(format!("Cannot resume trace in state {:?}", session.state));
        }

        if let Some(handle) = session.get_driver_handle() {
            let mut driver = self.driver.lock().map_err(|e| e.to_string())?;
            driver.resume_trace(handle)?;
        }
        session.state = TraceState::Tracing;
        Ok(())
    }

    pub fn get_trace_data(&self, trace_id: &str) -> Result<TraceData, String> {
        let session = self.sessions.get(trace_id)
            .ok_or_else(|| format!("Trace not found: {}", trace_id))?;
        if session.state != TraceState::Stopped {
            return Err(format!("Trace must be stopped (current: {:?})", session.state));
        }
        Ok(session.get_trace_data())
    }

    pub fn get_raw_trace_data(&self, trace_id: &str) -> Result<Vec<u8>, String> {
        let session = self.sessions.get(trace_id)
            .ok_or_else(|| format!("Trace not found: {}", trace_id))?;
        Ok(session.get_buffer().to_vec())
    }

    pub fn list_sessions(&self) -> Vec<TraceSessionInfo> {
        self.sessions.values().map(|s| TraceSessionInfo {
            id: s.id.clone(),
            state: s.state,
            process_id: s.process_id,
            core_id: s.core_id,
            buffer_size: s.get_buffer().len(),
            overflow: s.has_overflow(),
        }).collect()
    }

    fn get_current_tsc(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        { unsafe { std::arch::x86_64::_rdtsc() } }
        #[cfg(not(target_arch = "x86_64"))]
        { 0 }
    }
}

impl Default for TraceManager {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone)]
pub struct TraceSessionInfo {
    pub id: String,
    pub state: TraceState,
    pub process_id: Option<u32>,
    pub core_id: Option<u32>,
    pub buffer_size: usize,
    pub overflow: bool,
}

#[derive(Debug, Clone)]
pub struct BufferStatus {
    pub total_size: usize,
    pub used_size: usize,
    pub overflow: bool,
    pub wrap_count: usize,
}
