//! Windows IPT Driver Interface
//!
//! Interface to the Windows inbox Intel PT driver (ipt.sys)
//! Based on reverse engineering of WinIPT by Alex Ionescu
//!
//! The ipt.sys driver provides:
//! - Per-process tracing (CR3 filtering)
//! - Per-core tracing
//! - ToPA and single-range output
//! - Timing packet configuration

use std::ffi::c_void;
use std::ptr;

use super::types::*;
use super::config::*;

/// IOCTL codes for ipt.sys driver
mod ioctl {
    pub const FILE_DEVICE_UNKNOWN: u32 = 0x22;
    pub const METHOD_BUFFERED: u32 = 0;
    pub const FILE_ANY_ACCESS: u32 = 0;

    pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
        (device_type << 16) | (access << 14) | (function << 2) | method
    }

    // IPT driver IOCTLs (based on WinIPT research)
    pub const IOCTL_IPT_GET_TRACE_VERSION: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_IPT_START_CORE_TRACE: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_IPT_STOP_CORE_TRACE: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_IPT_START_PROCESS_TRACE: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_IPT_STOP_PROCESS_TRACE: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_IPT_GET_TRACE_DATA: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_IPT_QUERY_CAPABILITIES: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_IPT_CONFIGURE_TRACE: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_IPT_PAUSE_TRACE: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_IPT_RESUME_TRACE: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_IPT_GET_TRACE_STATUS: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS);
}

/// IPT trace options (maps to driver structure)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IptTraceOptions {
    /// Option version
    pub version: u32,
    /// Timing options
    pub timing_options: u32,
    /// MTC frequency
    pub mtc_freq: u32,
    /// CYC threshold
    pub cyc_thresh: u32,
    /// PSB frequency
    pub psb_freq: u32,
    /// Branch options
    pub branch_options: u32,
    /// Reserved
    pub reserved: [u32; 4],
}

/// IPT trace buffer info
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IptTraceBuffer {
    /// Buffer base address
    pub base: *mut c_void,
    /// Buffer size
    pub size: usize,
    /// Current write position
    pub write_pos: usize,
    /// Whether overflow occurred
    pub overflow: u32,
}

/// Safe handle wrapper for thread safety
#[derive(Debug)]
struct SafeHandle(isize);

// Safety: The handle is just an opaque value that can be sent across threads.
// The actual synchronization happens via Mutex in TraceManager.
unsafe impl Send for SafeHandle {}
unsafe impl Sync for SafeHandle {}

impl SafeHandle {
    fn new(handle: isize) -> Self {
        Self(handle)
    }

    fn as_raw(&self) -> isize {
        self.0
    }
}

/// Windows IPT driver interface
pub struct WinIptDriver {
    /// Handle to the IPT device (wrapped for thread safety)
    device_handle: Option<SafeHandle>,
    /// Driver loaded status
    loaded: bool,
    /// Last error
    last_error: Option<String>,
    /// Driver version string
    version: Option<String>,
}

// Mark WinIptDriver as thread-safe (it uses interior mutability via Mutex in TraceManager)
unsafe impl Send for WinIptDriver {}
unsafe impl Sync for WinIptDriver {}

impl WinIptDriver {
    /// Create a new WinIPT driver interface
    pub fn new() -> Self {
        let mut driver = Self {
            device_handle: None,
            loaded: false,
            last_error: None,
            version: None,
        };

        driver.try_open();
        driver
    }

    /// Try to open the IPT device
    fn try_open(&mut self) {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use std::ffi::OsStr;

            // Constants for CreateFileW
            const GENERIC_READ: u32 = 0x80000000;
            const GENERIC_WRITE: u32 = 0x40000000;

            let device_path = OsStr::new("\\\\.\\IPT")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>();

            unsafe {
                let handle = windows_sys::Win32::Storage::FileSystem::CreateFileW(
                    device_path.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                        | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
                    ptr::null(),
                    windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING,
                    windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL,
                    0, // hTemplateFile - use 0 instead of null pointer
                );

                if handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                    self.device_handle = Some(SafeHandle::new(handle));
                    self.loaded = true;
                    self.version = Some("1.0".to_string());
                } else {
                    self.last_error = Some(format!(
                        "Failed to open IPT device: error {}",
                        windows_sys::Win32::Foundation::GetLastError()
                    ));
                }
            }
        }

        #[cfg(not(windows))]
        {
            self.last_error = Some("Intel PT driver interface only available on Windows".to_string());
        }
    }

    /// Check if driver is loaded
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Check if driver is available (alias for is_loaded for compatibility)
    pub fn is_available(&self) -> bool {
        self.loaded
    }

    /// Get driver version
    pub fn get_version(&self) -> Option<String> {
        self.version.clone()
    }

    /// Get last error
    pub fn get_last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Get driver status
    pub fn get_status(&self) -> IptDriverStatus {
        IptDriverStatus {
            loaded: self.loaded,
            version: self.version.clone(),
            active_traces: 0, // Would query from driver
            available_buffer: 0,
            last_error: self.last_error.clone(),
        }
    }

    /// Convert config to driver options
    fn config_to_options(&self, config: &PtTraceConfig) -> IptTraceOptions {
        let mut timing_options = 0u32;

        if config.timing.enable_tsc {
            timing_options |= 1 << 0;
        }
        if config.timing.enable_mtc {
            timing_options |= 1 << 1;
        }
        if config.timing.enable_cyc {
            timing_options |= 1 << 2;
        }

        let mut branch_options = 0u32;
        if config.branch_filtering.conditional {
            branch_options |= 1 << 0;
        }
        if config.branch_filtering.unconditional_direct {
            branch_options |= 1 << 1;
        }
        if config.branch_filtering.indirect {
            branch_options |= 1 << 2;
        }
        if config.branch_filtering.calls {
            branch_options |= 1 << 3;
        }
        if config.branch_filtering.returns {
            branch_options |= 1 << 4;
        }

        IptTraceOptions {
            version: 1,
            timing_options,
            mtc_freq: config.timing.mtc_frequency as u32,
            cyc_thresh: config.timing.cyc_threshold as u32,
            psb_freq: config.timing.psb_frequency.to_encoding() as u32,
            branch_options,
            reserved: [0; 4],
        }
    }

    /// Start per-process trace
    /// Returns a handle (as u64) that can be used to stop/pause/resume the trace
    pub fn start_process_trace(
        &mut self,
        process_id: u32,
        _buffer: &mut [u8],
        config: &PtTraceConfig,
    ) -> Result<u64, String> {
        if !self.loaded {
            return Err("IPT driver not loaded".to_string());
        }

        let _options = self.config_to_options(config);

        // In a real implementation, we would:
        // 1. Set up trace buffer via driver IOCTL
        // 2. Call DeviceIoControl with IOCTL_IPT_START_PROCESS_TRACE
        // 3. Return the trace handle from driver

        #[cfg(windows)]
        {
            // Placeholder - actual implementation would use DeviceIoControl
            // Generate a unique handle based on process ID and timestamp
            let handle = ((process_id as u64) << 32) | (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64 & 0xFFFFFFFF);
            Ok(handle)
        }

        #[cfg(not(windows))]
        {
            let _ = process_id;
            Err("Not implemented on this platform".to_string())
        }
    }

    /// Start per-core trace
    /// Returns a handle (as u64) that can be used to stop/pause/resume the trace
    pub fn start_core_trace(
        &mut self,
        core_id: u32,
        _buffer: &mut [u8],
        config: &PtTraceConfig,
    ) -> Result<u64, String> {
        if !self.loaded {
            return Err("IPT driver not loaded".to_string());
        }

        let _options = self.config_to_options(config);

        #[cfg(windows)]
        {
            // Placeholder - actual implementation would use DeviceIoControl
            let handle = ((core_id as u64 | 0x80000000) << 32) | (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64 & 0xFFFFFFFF);
            Ok(handle)
        }

        #[cfg(not(windows))]
        {
            let _ = core_id;
            Err("Not implemented on this platform".to_string())
        }
    }

    /// Stop a trace by handle
    pub fn stop_trace(&mut self, handle: u64) -> Result<(), String> {
        if !self.loaded {
            return Err("IPT driver not loaded".to_string());
        }

        // Determine trace type from handle encoding
        let is_core_trace = (handle >> 63) & 1 == 1;

        // Would call appropriate IOCTL based on trace type
        if is_core_trace {
            // IOCTL_IPT_STOP_CORE_TRACE
        } else {
            // IOCTL_IPT_STOP_PROCESS_TRACE
        }

        Ok(())
    }

    /// Pause a trace by handle
    pub fn pause_trace(&mut self, _handle: u64) -> Result<(), String> {
        if !self.loaded {
            return Err("IPT driver not loaded".to_string());
        }

        // Would call IOCTL_IPT_PAUSE_TRACE
        Ok(())
    }

    /// Resume a trace by handle
    pub fn resume_trace(&mut self, _handle: u64) -> Result<(), String> {
        if !self.loaded {
            return Err("IPT driver not loaded".to_string());
        }

        // Would call IOCTL_IPT_RESUME_TRACE
        Ok(())
    }

    /// Query driver capabilities
    pub fn query_capabilities(&self) -> Result<PtCapabilities, String> {
        if !self.loaded {
            return Err("IPT driver not loaded".to_string());
        }

        // Would call IOCTL_IPT_QUERY_CAPABILITIES
        // For now, return capabilities from CPUID
        Ok(PtCapabilities::default())
    }
}

impl Default for WinIptDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WinIptDriver {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if let Some(ref handle) = self.device_handle {
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(handle.as_raw());
                }
            }
        }
    }
}

// ============================================================================
// Alternative: Direct MSR Access (requires kernel driver)
// ============================================================================

/// Direct MSR access for advanced scenarios
/// Requires a kernel driver (like HyperDbg)
pub mod msr {
    /// Intel PT MSR addresses
    pub mod addresses {
        /// IA32_RTIT_OUTPUT_BASE - Base address of the output region
        pub const IA32_RTIT_OUTPUT_BASE: u32 = 0x560;
        /// IA32_RTIT_OUTPUT_MASK_PTRS - Output mask and pointers
        pub const IA32_RTIT_OUTPUT_MASK_PTRS: u32 = 0x561;
        /// IA32_RTIT_CTL - PT control register
        pub const IA32_RTIT_CTL: u32 = 0x570;
        /// IA32_RTIT_STATUS - PT status register
        pub const IA32_RTIT_STATUS: u32 = 0x571;
        /// IA32_RTIT_CR3_MATCH - CR3 match register for filtering
        pub const IA32_RTIT_CR3_MATCH: u32 = 0x572;
        /// IA32_RTIT_ADDR0_A - Address range 0 base
        pub const IA32_RTIT_ADDR0_A: u32 = 0x580;
        /// IA32_RTIT_ADDR0_B - Address range 0 limit
        pub const IA32_RTIT_ADDR0_B: u32 = 0x581;
        /// IA32_RTIT_ADDR1_A - Address range 1 base
        pub const IA32_RTIT_ADDR1_A: u32 = 0x582;
        /// IA32_RTIT_ADDR1_B - Address range 1 limit
        pub const IA32_RTIT_ADDR1_B: u32 = 0x583;
    }

    /// IA32_RTIT_CTL bit definitions
    pub mod ctl_bits {
        /// TraceEn - Enable tracing
        pub const TRACE_EN: u64 = 1 << 0;
        /// CYCEn - Enable CYC packets
        pub const CYC_EN: u64 = 1 << 1;
        /// OS - Trace CPL 0
        pub const OS: u64 = 1 << 2;
        /// User - Trace CPL > 0
        pub const USER: u64 = 1 << 3;
        /// PwrEvtEn - Enable power event packets
        pub const PWR_EVT_EN: u64 = 1 << 4;
        /// FUPonPTW - Generate FUP on PTWRITE
        pub const FUP_ON_PTW: u64 = 1 << 5;
        /// FabricEn - Enable Trace Transport
        pub const FABRIC_EN: u64 = 1 << 6;
        /// CR3Filter - Enable CR3 filtering
        pub const CR3_FILTER: u64 = 1 << 7;
        /// ToPA - Use ToPA output
        pub const TOPA: u64 = 1 << 8;
        /// MTCEn - Enable MTC packets
        pub const MTC_EN: u64 = 1 << 9;
        /// TSCEn - Enable TSC packets
        pub const TSC_EN: u64 = 1 << 10;
        /// DisRETC - Disable return compression
        pub const DIS_RETC: u64 = 1 << 11;
        /// PTWEn - Enable PTWRITE
        pub const PTW_EN: u64 = 1 << 12;
        /// BranchEn - Enable branch tracing
        pub const BRANCH_EN: u64 = 1 << 13;
        /// MTCFreq - MTC packet frequency (bits 14-17)
        pub const MTC_FREQ_SHIFT: u64 = 14;
        pub const MTC_FREQ_MASK: u64 = 0xF << 14;
        /// CycThresh - CYC packet threshold (bits 19-22)
        pub const CYC_THRESH_SHIFT: u64 = 19;
        pub const CYC_THRESH_MASK: u64 = 0xF << 19;
        /// PSBFreq - PSB packet frequency (bits 24-27)
        pub const PSB_FREQ_SHIFT: u64 = 24;
        pub const PSB_FREQ_MASK: u64 = 0xF << 24;
        /// Addr0Cfg - Address range 0 config (bits 32-35)
        pub const ADDR0_CFG_SHIFT: u64 = 32;
        /// Addr1Cfg - Address range 1 config (bits 36-39)
        pub const ADDR1_CFG_SHIFT: u64 = 36;
        /// InjectPsbPmiOnEnable - Inject PSB+PMI on enable (bit 56)
        pub const INJECT_PSB_PMI: u64 = 1 << 56;
    }

    /// IA32_RTIT_STATUS bit definitions
    pub mod status_bits {
        /// FilterEn - Filtering is active
        pub const FILTER_EN: u64 = 1 << 0;
        /// ContextEn - Tracing is context-enabled
        pub const CONTEXT_EN: u64 = 1 << 1;
        /// TriggerEn - Trigger is active
        pub const TRIGGER_EN: u64 = 1 << 2;
        /// Error - Operational error
        pub const ERROR: u64 = 1 << 4;
        /// Stopped - Tracing stopped
        pub const STOPPED: u64 = 1 << 5;
        /// PendPSB - PSB is pending
        pub const PEND_PSB: u64 = 1 << 6;
        /// PendTopaPMI - ToPA PMI is pending
        pub const PEND_TOPA_PMI: u64 = 1 << 7;
        /// PacketByteCnt - Bytes in current packet (bits 32-48)
        pub const PACKET_BYTE_CNT_SHIFT: u64 = 32;
        pub const PACKET_BYTE_CNT_MASK: u64 = 0x1FFFF << 32;
    }

    /// Build IA32_RTIT_CTL value from config
    pub fn build_rtit_ctl(config: &super::PtTraceConfig) -> u64 {
        let mut ctl: u64 = 0;

        // Basic enables
        ctl |= ctl_bits::TRACE_EN;
        ctl |= ctl_bits::BRANCH_EN;

        // Ring filtering
        match config.ring_filter {
            super::RingFilter::Ring0Only => ctl |= ctl_bits::OS,
            super::RingFilter::Ring3Only => ctl |= ctl_bits::USER,
            super::RingFilter::BothRings => ctl |= ctl_bits::OS | ctl_bits::USER,
        }

        // Timing
        if config.timing.enable_tsc {
            ctl |= ctl_bits::TSC_EN;
        }
        if config.timing.enable_mtc {
            ctl |= ctl_bits::MTC_EN;
            ctl |= (config.timing.mtc_frequency as u64) << ctl_bits::MTC_FREQ_SHIFT;
        }
        if config.timing.enable_cyc {
            ctl |= ctl_bits::CYC_EN;
            ctl |= (config.timing.cyc_threshold as u64) << ctl_bits::CYC_THRESH_SHIFT;
        }

        // PSB frequency
        ctl |= (config.timing.psb_frequency.to_encoding() as u64) << ctl_bits::PSB_FREQ_SHIFT;

        // Other options
        if config.ptwrite {
            ctl |= ctl_bits::PTW_EN;
        }
        if config.power_events {
            ctl |= ctl_bits::PWR_EVT_EN;
        }
        if config.disable_ret_compression {
            ctl |= ctl_bits::DIS_RETC;
        }

        // ToPA output
        ctl |= ctl_bits::TOPA;

        // CR3 filtering for process traces
        if matches!(config.mode, super::TraceMode::ProcessTrace) {
            ctl |= ctl_bits::CR3_FILTER;
        }

        ctl
    }
}
