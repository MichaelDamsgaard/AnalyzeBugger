//! Intel Processor Trace (PT) Module
//!
//! Provides comprehensive Intel PT support for AnalyzeBugger:
//! - Per-process and per-core tracing via Windows ipt.sys
//! - Full packet decoding via libipt
//! - Control flow reconstruction
//! - Timing analysis and anomaly detection
//! - Branch prediction analysis
//!
//! Architecture:
//! ```
//! ┌─────────────────┐
//! │  Tauri Commands │  High-level API exposed to frontend
//! └────────┬────────┘
//!          │
//! ┌────────▼────────┐
//! │   TraceManager  │  Manages multiple trace sessions
//! └────────┬────────┘
//!          │
//! ┌────────▼────────┐
//! │   WinIPT Layer  │  Windows ipt.sys driver interface
//! └────────┬────────┘
//!          │
//! ┌────────▼────────┐
//! │  Packet Decoder │  libipt-based packet decoding
//! └────────┬────────┘
//!          │
//! ┌────────▼────────┐
//! │    Analysis     │  Timing, CFG, anomaly detection
//! └─────────────────┘
//! ```

pub mod types;
pub mod config;
pub mod winipt;
pub mod decoder;
pub mod trace;
pub mod analysis;

pub use types::*;
pub use config::*;
pub use trace::TraceManager;
pub use analysis::*;

use std::sync::{Arc, Mutex};
use serde_json::json;

/// Global Intel PT manager
pub struct IntelPTManager {
    /// Trace manager for active traces
    trace_manager: Arc<Mutex<TraceManager>>,
    /// Whether Intel PT is available on this system
    available: bool,
    /// CPU capabilities
    capabilities: PtCapabilities,
}

impl IntelPTManager {
    /// Create a new Intel PT manager
    pub fn new() -> Self {
        let (available, capabilities) = Self::detect_capabilities();

        Self {
            trace_manager: Arc::new(Mutex::new(TraceManager::new())),
            available,
            capabilities,
        }
    }

    /// Detect Intel PT capabilities
    fn detect_capabilities() -> (bool, PtCapabilities) {
        // Check CPUID for Intel PT support
        // CPUID.07H.EBX[25] = 1 indicates Intel PT support

        #[cfg(target_arch = "x86_64")]
        {
            use std::arch::x86_64::__cpuid;

            unsafe {
                // Check for Intel PT support
                let cpuid_07 = __cpuid(0x07);
                let pt_supported = (cpuid_07.ebx >> 25) & 1 == 1;

                if !pt_supported {
                    return (false, PtCapabilities::default());
                }

                // Get detailed PT capabilities from CPUID.14H
                let cpuid_14_0 = __cpuid(0x14);
                let cpuid_14_1 = if cpuid_14_0.eax >= 1 {
                    __cpuid(0x14)
                } else {
                    std::arch::x86_64::CpuidResult { eax: 0, ebx: 0, ecx: 0, edx: 0 }
                };

                let caps = PtCapabilities {
                    supported: true,
                    // CR3 filtering
                    cr3_filtering: (cpuid_14_0.ebx & 1) != 0,
                    // PSB and Cycle-accurate Mode
                    psb_cyc: (cpuid_14_0.ebx >> 1) & 1 != 0,
                    // IP Filtering and TraceStop
                    ip_filtering: (cpuid_14_0.ebx >> 2) & 1 != 0,
                    // MTC timing packets
                    mtc: (cpuid_14_0.ebx >> 3) & 1 != 0,
                    // PTWRITE support
                    ptwrite: (cpuid_14_0.ebx >> 4) & 1 != 0,
                    // Power Event Trace
                    power_event: (cpuid_14_0.ebx >> 5) & 1 != 0,
                    // ToPA output
                    topa: (cpuid_14_0.ecx & 1) != 0,
                    // Single-range output
                    single_range: (cpuid_14_0.ecx >> 2) & 1 != 0,
                    // Trace Transport subsystem
                    trace_transport: (cpuid_14_0.ecx >> 3) & 1 != 0,
                    // IP payloads have LIP values
                    lip: (cpuid_14_0.ecx >> 31) & 1 != 0,
                    // Number of address ranges
                    num_addr_ranges: ((cpuid_14_1.eax >> 0) & 0x7) as u8,
                    // Supported MTC period encodings
                    mtc_period_bitmap: ((cpuid_14_1.eax >> 16) & 0xFFFF) as u16,
                    // Cycle threshold bitmap
                    cyc_threshold_bitmap: ((cpuid_14_1.ebx >> 0) & 0xFFFF) as u16,
                    // PSB frequency bitmap
                    psb_freq_bitmap: ((cpuid_14_1.ebx >> 16) & 0xFFFF) as u16,
                };

                (true, caps)
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            (false, PtCapabilities::default())
        }
    }

    /// Check if Intel PT is available
    pub fn is_available(&self) -> bool {
        self.available
    }

    /// Get capabilities
    pub fn get_capabilities(&self) -> &PtCapabilities {
        &self.capabilities
    }

    /// Get status as JSON
    pub fn get_status(&self) -> serde_json::Value {
        let manager = self.trace_manager.lock().unwrap();

        json!({
            "available": self.available,
            "capabilities": {
                "supported": self.capabilities.supported,
                "cr3_filtering": self.capabilities.cr3_filtering,
                "psb_cyc": self.capabilities.psb_cyc,
                "ip_filtering": self.capabilities.ip_filtering,
                "mtc": self.capabilities.mtc,
                "ptwrite": self.capabilities.ptwrite,
                "power_event": self.capabilities.power_event,
                "topa": self.capabilities.topa,
                "single_range": self.capabilities.single_range,
                "num_addr_ranges": self.capabilities.num_addr_ranges,
            },
            "active_traces": manager.get_active_trace_count(),
            "driver_status": manager.get_driver_status(),
        })
    }

    /// Start tracing a process
    pub fn start_process_trace(
        &self,
        process_id: u32,
        config: PtTraceConfig,
    ) -> Result<String, String> {
        if !self.available {
            return Err("Intel PT not available on this system".to_string());
        }

        let mut manager = self.trace_manager.lock().map_err(|e| e.to_string())?;
        manager.start_process_trace(process_id, config)
    }

    /// Start core-wide tracing
    pub fn start_core_trace(
        &self,
        core_id: u32,
        config: PtTraceConfig,
    ) -> Result<String, String> {
        if !self.available {
            return Err("Intel PT not available on this system".to_string());
        }

        let mut manager = self.trace_manager.lock().map_err(|e| e.to_string())?;
        manager.start_core_trace(core_id, config)
    }

    /// Stop a trace
    pub fn stop_trace(&self, trace_id: &str) -> Result<(), String> {
        let mut manager = self.trace_manager.lock().map_err(|e| e.to_string())?;
        manager.stop_trace(trace_id)
    }

    /// Get trace data
    pub fn get_trace_data(&self, trace_id: &str) -> Result<TraceData, String> {
        let manager = self.trace_manager.lock().map_err(|e| e.to_string())?;
        manager.get_trace_data(trace_id)
    }

    /// Decode trace packets
    pub fn decode_trace(&self, trace_id: &str) -> Result<DecodedTrace, String> {
        let manager = self.trace_manager.lock().map_err(|e| e.to_string())?;
        let raw_data = manager.get_raw_trace_data(trace_id)?;
        decoder::decode_trace(&raw_data)
    }

    /// Analyze trace for timing anomalies
    pub fn analyze_timing(&self, trace_id: &str) -> Result<TimingAnalysis, String> {
        let decoded = self.decode_trace(trace_id)?;
        Ok(analysis::analyze_timing(&decoded))
    }

    /// Reconstruct control flow graph from trace
    pub fn reconstruct_cfg(&self, trace_id: &str) -> Result<ControlFlowGraph, String> {
        let decoded = self.decode_trace(trace_id)?;
        Ok(analysis::reconstruct_cfg(&decoded))
    }

    /// Get trace manager reference
    pub fn get_trace_manager(&self) -> Arc<Mutex<TraceManager>> {
        Arc::clone(&self.trace_manager)
    }

    /// List all trace sessions
    pub fn list_sessions(&self) -> Result<Vec<trace::TraceSessionInfo>, String> {
        let manager = self.trace_manager.lock().map_err(|e| e.to_string())?;
        Ok(manager.list_sessions())
    }
}

impl Default for IntelPTManager {
    fn default() -> Self {
        Self::new()
    }
}
