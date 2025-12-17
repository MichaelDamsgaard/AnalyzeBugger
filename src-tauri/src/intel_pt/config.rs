//! Intel PT configuration options
//!
//! Comprehensive configuration for Intel PT tracing:
//! - Trace filtering (CR3, IP ranges)
//! - Timing packet configuration
//! - Buffer management
//! - Output mode selection

use serde::{Deserialize, Serialize};

/// Intel PT trace configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtTraceConfig {
    /// Trace mode
    pub mode: TraceMode,
    /// Enable timing packets (TSC, MTC, CYC)
    pub timing: TimingConfig,
    /// IP filtering ranges
    pub ip_filtering: IpFilterConfig,
    /// Buffer configuration
    pub buffer: BufferConfig,
    /// Branch filtering
    pub branch_filtering: BranchFilterConfig,
    /// Output configuration
    pub output: OutputConfig,
    /// Ring filtering (Ring 0, Ring 3, or both)
    pub ring_filter: RingFilter,
    /// Enable PTWRITE packet recording
    pub ptwrite: bool,
    /// Enable power event packets
    pub power_events: bool,
    /// Enable return compression
    pub return_compression: bool,
    /// Disable RET compression (for better accuracy)
    pub disable_ret_compression: bool,
}

impl Default for PtTraceConfig {
    fn default() -> Self {
        Self {
            mode: TraceMode::ProcessTrace,
            timing: TimingConfig::default(),
            ip_filtering: IpFilterConfig::default(),
            buffer: BufferConfig::default(),
            branch_filtering: BranchFilterConfig::default(),
            output: OutputConfig::default(),
            ring_filter: RingFilter::Ring3Only,
            ptwrite: true,
            power_events: false,
            return_compression: true,
            disable_ret_compression: false,
        }
    }
}

/// Trace mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceMode {
    /// Per-process tracing (uses CR3 filtering)
    ProcessTrace,
    /// Per-core tracing (all processes on core)
    CoreTrace,
    /// System-wide tracing
    SystemTrace,
}

/// Timing packet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingConfig {
    /// Enable TSC (Timestamp Counter) packets
    pub enable_tsc: bool,
    /// Enable MTC (Mini Time Counter) packets
    pub enable_mtc: bool,
    /// Enable CYC (Cycle Count) packets
    pub enable_cyc: bool,
    /// MTC frequency (period encoding, 0-15)
    /// Lower values = more frequent MTC packets
    pub mtc_frequency: u8,
    /// CYC threshold (0-15)
    /// Minimum cycles between CYC packets
    pub cyc_threshold: u8,
    /// PSB (Packet Stream Boundary) frequency
    /// PSB packets help resync decoder after buffer loss
    pub psb_frequency: PsbFrequency,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            enable_tsc: true,
            enable_mtc: true,
            enable_cyc: true,
            mtc_frequency: 3, // ~1ms at typical frequencies
            cyc_threshold: 1, // Record cycles frequently
            psb_frequency: PsbFrequency::Every4K,
        }
    }
}

/// PSB (Packet Stream Boundary) frequency
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PsbFrequency {
    /// PSB every 2K trace bytes
    Every2K,
    /// PSB every 4K trace bytes
    Every4K,
    /// PSB every 8K trace bytes
    Every8K,
    /// PSB every 16K trace bytes
    Every16K,
    /// PSB every 32K trace bytes
    Every32K,
    /// PSB every 64K trace bytes
    Every64K,
    /// PSB every 128K trace bytes
    Every128K,
    /// PSB every 256K trace bytes
    Every256K,
}

impl PsbFrequency {
    /// Convert to encoding value
    pub fn to_encoding(&self) -> u8 {
        match self {
            PsbFrequency::Every2K => 0,
            PsbFrequency::Every4K => 1,
            PsbFrequency::Every8K => 2,
            PsbFrequency::Every16K => 3,
            PsbFrequency::Every32K => 4,
            PsbFrequency::Every64K => 5,
            PsbFrequency::Every128K => 6,
            PsbFrequency::Every256K => 7,
        }
    }
}

/// IP filtering configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFilterConfig {
    /// Enable IP filtering
    pub enabled: bool,
    /// IP ranges to trace (up to 4 ranges typically)
    pub ranges: Vec<IpRange>,
    /// Filter mode
    pub mode: IpFilterMode,
}

impl Default for IpFilterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ranges: Vec::new(),
            mode: IpFilterMode::FilterIn,
        }
    }
}

/// An IP range for filtering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRange {
    /// Range start address (inclusive)
    pub start: u64,
    /// Range end address (inclusive)
    pub end: u64,
    /// Range name (for identification)
    pub name: String,
}

/// IP filter mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpFilterMode {
    /// Only trace IPs within specified ranges
    FilterIn,
    /// Trace everything except specified ranges
    FilterOut,
    /// Stop tracing when entering ranges
    StopOnEnter,
    /// Stop tracing when exiting ranges
    StopOnExit,
}

/// Buffer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferConfig {
    /// Buffer size in bytes
    pub size: usize,
    /// Enable circular buffer mode
    pub circular: bool,
    /// Number of ToPA (Table of Physical Addresses) entries
    pub topa_entries: usize,
    /// Interrupt threshold (% full before interrupt)
    pub interrupt_threshold: u8,
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            // 16MB buffer for rich trace data
            size: 16 * 1024 * 1024,
            circular: true,
            topa_entries: 512,
            interrupt_threshold: 90,
        }
    }
}

/// Branch filtering configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchFilterConfig {
    /// Trace conditional branches (Jcc)
    pub conditional: bool,
    /// Trace unconditional direct branches
    pub unconditional_direct: bool,
    /// Trace indirect branches
    pub indirect: bool,
    /// Trace calls
    pub calls: bool,
    /// Trace returns
    pub returns: bool,
    /// Trace far branches
    pub far_branches: bool,
    /// Trace interrupts
    pub interrupts: bool,
}

impl Default for BranchFilterConfig {
    fn default() -> Self {
        Self {
            conditional: true,
            unconditional_direct: true,
            indirect: true,
            calls: true,
            returns: true,
            far_branches: true,
            interrupts: true,
        }
    }
}

/// Output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output scheme
    pub scheme: OutputScheme,
    /// Maximum trace file size (0 = unlimited)
    pub max_file_size: usize,
    /// Compress output
    pub compress: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            scheme: OutputScheme::ToPA,
            max_file_size: 0,
            compress: false,
        }
    }
}

/// Output scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputScheme {
    /// Table of Physical Addresses (recommended)
    ToPA,
    /// Single contiguous region
    SingleRange,
    /// Trace Transport subsystem
    TraceTransport,
}

/// Ring privilege level filter
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RingFilter {
    /// Trace only Ring 0 (kernel)
    Ring0Only,
    /// Trace only Ring 3 (user)
    Ring3Only,
    /// Trace both Ring 0 and Ring 3
    BothRings,
}

/// Preset configurations for common use cases
impl PtTraceConfig {
    /// High-fidelity trace configuration
    /// Maximum detail, larger buffer, all timing
    pub fn high_fidelity() -> Self {
        Self {
            mode: TraceMode::ProcessTrace,
            timing: TimingConfig {
                enable_tsc: true,
                enable_mtc: true,
                enable_cyc: true,
                mtc_frequency: 1, // Very frequent
                cyc_threshold: 0, // Every cycle change
                psb_frequency: PsbFrequency::Every2K,
            },
            buffer: BufferConfig {
                size: 64 * 1024 * 1024, // 64MB
                circular: false, // Don't overwrite
                topa_entries: 1024,
                interrupt_threshold: 95,
            },
            branch_filtering: BranchFilterConfig::default(),
            ip_filtering: IpFilterConfig::default(),
            output: OutputConfig::default(),
            ring_filter: RingFilter::Ring3Only,
            ptwrite: true,
            power_events: true,
            return_compression: false, // Disable for accuracy
            disable_ret_compression: true,
        }
    }

    /// Low overhead configuration
    /// Minimal timing, smaller buffer
    pub fn low_overhead() -> Self {
        Self {
            mode: TraceMode::ProcessTrace,
            timing: TimingConfig {
                enable_tsc: true,
                enable_mtc: false,
                enable_cyc: false,
                mtc_frequency: 15, // Least frequent
                cyc_threshold: 15,
                psb_frequency: PsbFrequency::Every64K,
            },
            buffer: BufferConfig {
                size: 4 * 1024 * 1024, // 4MB
                circular: true,
                topa_entries: 128,
                interrupt_threshold: 80,
            },
            branch_filtering: BranchFilterConfig::default(),
            ip_filtering: IpFilterConfig::default(),
            output: OutputConfig::default(),
            ring_filter: RingFilter::Ring3Only,
            ptwrite: false,
            power_events: false,
            return_compression: true,
            disable_ret_compression: false,
        }
    }

    /// Timing analysis configuration
    /// Optimized for detecting timing anomalies
    pub fn timing_analysis() -> Self {
        Self {
            mode: TraceMode::ProcessTrace,
            timing: TimingConfig {
                enable_tsc: true,
                enable_mtc: true,
                enable_cyc: true,
                mtc_frequency: 0, // Most frequent MTC
                cyc_threshold: 0, // Capture every cycle
                psb_frequency: PsbFrequency::Every4K,
            },
            buffer: BufferConfig {
                size: 32 * 1024 * 1024, // 32MB
                circular: true,
                topa_entries: 512,
                interrupt_threshold: 90,
            },
            // Only trace branches for timing analysis
            branch_filtering: BranchFilterConfig {
                conditional: true,
                unconditional_direct: true,
                indirect: true,
                calls: true,
                returns: true,
                far_branches: false,
                interrupts: true,
            },
            ip_filtering: IpFilterConfig::default(),
            output: OutputConfig::default(),
            ring_filter: RingFilter::Ring3Only,
            ptwrite: true, // Capture PTWRITE for debugging
            power_events: true, // Useful for timing analysis
            return_compression: true,
            disable_ret_compression: false,
        }
    }

    /// Kernel tracing configuration (requires Ring 0 access)
    pub fn kernel_trace() -> Self {
        Self {
            mode: TraceMode::CoreTrace,
            timing: TimingConfig::default(),
            buffer: BufferConfig {
                size: 128 * 1024 * 1024, // 128MB for kernel
                circular: true,
                topa_entries: 2048,
                interrupt_threshold: 85,
            },
            branch_filtering: BranchFilterConfig::default(),
            ip_filtering: IpFilterConfig::default(),
            output: OutputConfig::default(),
            ring_filter: RingFilter::BothRings,
            ptwrite: true,
            power_events: true,
            return_compression: true,
            disable_ret_compression: false,
        }
    }

    /// Control flow analysis configuration
    /// Optimized for reconstructing control flow graphs
    pub fn control_flow_analysis() -> Self {
        Self {
            mode: TraceMode::ProcessTrace,
            timing: TimingConfig {
                enable_tsc: true,
                enable_mtc: false,
                enable_cyc: false,
                mtc_frequency: 8,
                cyc_threshold: 8,
                psb_frequency: PsbFrequency::Every8K,
            },
            buffer: BufferConfig {
                size: 32 * 1024 * 1024, // 32MB
                circular: true,
                topa_entries: 512,
                interrupt_threshold: 90,
            },
            branch_filtering: BranchFilterConfig {
                conditional: true,
                unconditional_direct: true,
                indirect: true,
                calls: true,
                returns: true,
                far_branches: false,
                interrupts: false,
            },
            ip_filtering: IpFilterConfig::default(),
            output: OutputConfig::default(),
            ring_filter: RingFilter::Ring3Only,
            ptwrite: false,
            power_events: false,
            return_compression: true,
            disable_ret_compression: false,
        }
    }

    /// Anti-debug detection configuration
    /// Optimized for detecting timing-based anti-debug techniques
    pub fn anti_debug_detection() -> Self {
        Self {
            mode: TraceMode::ProcessTrace,
            timing: TimingConfig {
                enable_tsc: true,
                enable_mtc: true,
                enable_cyc: true,
                mtc_frequency: 0, // Most frequent
                cyc_threshold: 0, // Capture every cycle
                psb_frequency: PsbFrequency::Every2K,
            },
            buffer: BufferConfig {
                size: 64 * 1024 * 1024, // 64MB
                circular: false, // Don't lose data
                topa_entries: 1024,
                interrupt_threshold: 95,
            },
            branch_filtering: BranchFilterConfig::default(),
            ip_filtering: IpFilterConfig::default(),
            output: OutputConfig::default(),
            ring_filter: RingFilter::Ring3Only,
            ptwrite: true,
            power_events: true,
            return_compression: false,
            disable_ret_compression: true,
        }
    }

    /// Code coverage configuration
    /// Optimized for tracking which code paths were executed
    pub fn code_coverage() -> Self {
        Self {
            mode: TraceMode::ProcessTrace,
            timing: TimingConfig {
                enable_tsc: false,
                enable_mtc: false,
                enable_cyc: false,
                mtc_frequency: 15,
                cyc_threshold: 15,
                psb_frequency: PsbFrequency::Every32K,
            },
            buffer: BufferConfig {
                size: 64 * 1024 * 1024, // 64MB
                circular: true,
                topa_entries: 512,
                interrupt_threshold: 80,
            },
            branch_filtering: BranchFilterConfig {
                conditional: true,
                unconditional_direct: false,
                indirect: true,
                calls: true,
                returns: false,
                far_branches: false,
                interrupts: false,
            },
            ip_filtering: IpFilterConfig::default(),
            output: OutputConfig::default(),
            ring_filter: RingFilter::Ring3Only,
            ptwrite: false,
            power_events: false,
            return_compression: true,
            disable_ret_compression: false,
        }
    }
}
