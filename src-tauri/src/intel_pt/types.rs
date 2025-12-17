//! Intel PT type definitions
//!
//! Comprehensive types for Intel Processor Trace:
//! - Packet types (TNT, TIP, FUP, PIP, etc.)
//! - Trace data structures
//! - Analysis results
//! - Configuration options

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Intel PT CPU capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PtCapabilities {
    /// Intel PT is supported
    pub supported: bool,
    /// CR3 filtering (per-process tracing)
    pub cr3_filtering: bool,
    /// PSB (Packet Stream Boundary) and Cycle-Accurate Mode
    pub psb_cyc: bool,
    /// IP filtering and TraceStop
    pub ip_filtering: bool,
    /// MTC (Mini Time Counter) packets
    pub mtc: bool,
    /// PTWRITE instruction support
    pub ptwrite: bool,
    /// Power Event Trace
    pub power_event: bool,
    /// ToPA (Table of Physical Addresses) output scheme
    pub topa: bool,
    /// Single-range output scheme
    pub single_range: bool,
    /// Trace Transport subsystem
    pub trace_transport: bool,
    /// IP payloads contain LIP (Linear IP) values
    pub lip: bool,
    /// Number of address ranges for filtering
    pub num_addr_ranges: u8,
    /// Bitmap of supported MTC period encodings
    pub mtc_period_bitmap: u16,
    /// Bitmap of supported cycle threshold values
    pub cyc_threshold_bitmap: u16,
    /// Bitmap of supported PSB frequencies
    pub psb_freq_bitmap: u16,
}

/// Intel PT packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtPacketType {
    /// Padding packet
    Pad,
    /// Packet Stream Boundary
    Psb,
    /// PSB End
    Psbend,
    /// Taken/Not-Taken (conditional branches)
    Tnt,
    /// Target IP (indirect branches, far transfers)
    Tip,
    /// Target IP - Packet Generation Enable
    TipPge,
    /// Target IP - Packet Generation Disable
    TipPgd,
    /// Flow Update Packet (asynchronous events)
    Fup,
    /// Paging Information Packet (CR3 changes)
    Pip,
    /// Mode packet (execution mode changes)
    Mode,
    /// Core Bus Ratio
    Cbr,
    /// Timestamp Counter
    Tsc,
    /// Mini Time Counter
    Mtc,
    /// Cycle Count
    Cyc,
    /// VMCS packet (VM entries/exits)
    Vmcs,
    /// Overflow (trace buffer overflow)
    Ovf,
    /// Execution Stop
    Exstop,
    /// Maintenance
    Mnt,
    /// PTWRITE
    Ptw,
    /// Power Entry
    Pwre,
    /// Power Exit
    Pwrx,
    /// Block Begin
    Bbp,
    /// Block Item
    Bip,
    /// Block End
    Bep,
    /// Unknown packet
    Unknown,
}

/// A single decoded PT packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtPacket {
    /// Packet type
    pub packet_type: PtPacketType,
    /// Raw packet bytes
    pub raw_bytes: Vec<u8>,
    /// Offset in trace buffer
    pub offset: u64,
    /// Payload (interpretation depends on packet type)
    pub payload: PtPacketPayload,
}

/// Packet payload data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PtPacketPayload {
    /// No payload
    None,
    /// TNT payload - bitmap of taken/not-taken decisions
    Tnt {
        /// Bit vector of branch outcomes (1=taken, 0=not-taken)
        bits: u64,
        /// Number of valid bits
        count: u8,
    },
    /// Target IP payload
    Tip {
        /// Target instruction pointer
        ip: u64,
        /// IP compression type
        compression: IpCompression,
    },
    /// Flow Update Packet payload
    Fup {
        /// Instruction pointer at event
        ip: u64,
        /// IP compression type
        compression: IpCompression,
    },
    /// Paging Information Packet
    Pip {
        /// CR3 value (page table base)
        cr3: u64,
        /// Non-root execution
        nr: bool,
    },
    /// Mode packet
    Mode {
        /// Execution mode
        exec_mode: ExecMode,
        /// Leaf value
        leaf: u8,
    },
    /// Timestamp Counter
    Tsc {
        /// TSC value
        tsc: u64,
    },
    /// Mini Time Counter
    Mtc {
        /// MTC value
        ctc: u8,
    },
    /// Cycle Count
    Cyc {
        /// Cycle count since last CYC
        cycles: u64,
    },
    /// Core Bus Ratio
    Cbr {
        /// Core:Bus ratio
        ratio: u8,
    },
    /// VMCS packet
    Vmcs {
        /// VMCS address
        vmcs: u64,
    },
    /// PTWRITE packet
    Ptw {
        /// Written value
        payload: u64,
        /// IP included
        ip: bool,
    },
    /// Power Entry
    Pwre {
        /// C-state
        state: u8,
        /// Hardware coordination
        hw: bool,
    },
    /// Power Exit
    Pwrx {
        /// Deepest C-state
        deepest: u8,
        /// Last C-state
        last: u8,
        /// Wake reason
        wake: u8,
    },
    /// Block Begin Packet
    Bbp {
        /// Block size
        size: u8,
        /// Block type
        block_type: u8,
    },
    /// Block Item Packet
    Bip {
        /// Item value
        value: u64,
    },
    /// Raw bytes for unknown packets
    Raw(Vec<u8>),
}

/// IP compression types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpCompression {
    /// Full 64-bit IP
    Full,
    /// Sign-extended from bit 47
    SignExt48,
    /// Upper 32 bits suppressed
    Upper32Suppressed,
    /// Lower 16 bits only
    Lower16,
    /// Lower 32 bits only
    Lower32,
    /// Update by adding signed 16-bit displacement
    Sext16,
}

/// Execution mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecMode {
    /// 16-bit mode
    Mode16,
    /// 32-bit mode (protected/compatibility)
    Mode32,
    /// 64-bit mode (long mode)
    Mode64,
}

/// Trace timing event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingEvent {
    /// Event offset in trace
    pub offset: u64,
    /// TSC value (if available)
    pub tsc: Option<u64>,
    /// MTC value (if available)
    pub mtc: Option<u8>,
    /// Cycle count since last timing packet
    pub cycles: Option<u64>,
    /// Calculated timestamp (nanoseconds from trace start)
    pub timestamp_ns: u64,
}

/// A branch event decoded from trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchEvent {
    /// Branch source address (approximate)
    pub source: u64,
    /// Branch target address
    pub target: u64,
    /// Whether branch was taken
    pub taken: bool,
    /// Branch type
    pub branch_type: BranchType,
    /// Timing information
    pub timing: Option<TimingEvent>,
    /// Execution mode at branch
    pub exec_mode: ExecMode,
}

/// Branch types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BranchType {
    /// Conditional branch (Jcc)
    Conditional,
    /// Unconditional direct jump
    DirectJump,
    /// Indirect jump (JMP reg/mem)
    IndirectJump,
    /// Direct call
    DirectCall,
    /// Indirect call (CALL reg/mem)
    IndirectCall,
    /// Return
    Return,
    /// Far call
    FarCall,
    /// Far return
    FarReturn,
    /// Interrupt
    Interrupt,
    /// System call
    Syscall,
    /// System return
    Sysret,
    /// Unknown
    Unknown,
}

/// Raw trace data from driver
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceData {
    /// Trace ID
    pub trace_id: String,
    /// Process ID (for process traces)
    pub process_id: Option<u32>,
    /// Core ID (for core traces)
    pub core_id: Option<u32>,
    /// Raw trace buffer
    pub raw_data: Vec<u8>,
    /// Trace buffer size
    pub buffer_size: usize,
    /// Number of packets (estimated)
    pub packet_count_estimate: usize,
    /// Whether overflow occurred
    pub overflow: bool,
    /// Start timestamp
    pub start_tsc: u64,
    /// End timestamp
    pub end_tsc: Option<u64>,
    /// Configuration used
    pub config: super::PtTraceConfig,
}

/// Fully decoded trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedTrace {
    /// Original trace ID
    pub trace_id: String,
    /// All decoded packets
    pub packets: Vec<PtPacket>,
    /// Branch events extracted from packets
    pub branches: Vec<BranchEvent>,
    /// Timing events
    pub timing_events: Vec<TimingEvent>,
    /// Mode changes
    pub mode_changes: Vec<(u64, ExecMode)>,
    /// CR3 changes (process context switches)
    pub cr3_changes: Vec<(u64, u64)>,
    /// VMCS changes (VM transitions)
    pub vmcs_changes: Vec<(u64, u64)>,
    /// PTWRITE values
    pub ptwrites: Vec<(u64, u64)>,
    /// Overflow positions
    pub overflow_positions: Vec<u64>,
    /// Decoder errors
    pub errors: Vec<String>,
    /// Statistics
    pub stats: TraceStats,
}

/// Trace statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceStats {
    /// Total packets decoded
    pub total_packets: usize,
    /// Packets by type
    pub packets_by_type: HashMap<String, usize>,
    /// Total branches
    pub total_branches: usize,
    /// Taken branches
    pub taken_branches: usize,
    /// Not-taken branches
    pub not_taken_branches: usize,
    /// Direct branches
    pub direct_branches: usize,
    /// Indirect branches
    pub indirect_branches: usize,
    /// Calls
    pub calls: usize,
    /// Returns
    pub returns: usize,
    /// Call/return balance (should be ~0 for complete traces)
    pub call_return_balance: i64,
    /// Time span (nanoseconds)
    pub time_span_ns: u64,
    /// Average branch rate (branches per microsecond)
    pub avg_branch_rate: f64,
}

/// Timing analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingAnalysis {
    /// Overall timing statistics
    pub stats: TimingStats,
    /// Detected timing anomalies
    pub anomalies: Vec<TimingAnomaly>,
    /// Timing histogram (cycle counts between branches)
    pub cycle_histogram: Vec<(u64, u64)>, // (cycle_count, frequency)
    /// Slowest code regions
    pub slow_regions: Vec<SlowRegion>,
    /// Fast code regions (potentially optimized or cache-hot)
    pub fast_regions: Vec<FastRegion>,
}

/// Timing statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimingStats {
    /// Total trace duration (nanoseconds)
    pub total_duration_ns: u64,
    /// Average cycles per branch
    pub avg_cycles_per_branch: f64,
    /// Median cycles per branch
    pub median_cycles_per_branch: u64,
    /// Min cycles between timing packets
    pub min_cycles: u64,
    /// Max cycles between timing packets
    pub max_cycles: u64,
    /// Standard deviation
    pub std_deviation: f64,
    /// TSC frequency (estimated, Hz)
    pub tsc_frequency_hz: u64,
}

/// A timing anomaly (suspicious timing behavior)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingAnomaly {
    /// Anomaly type
    pub anomaly_type: TimingAnomalyType,
    /// Address where anomaly occurred
    pub address: u64,
    /// Expected timing
    pub expected_cycles: u64,
    /// Observed timing
    pub observed_cycles: u64,
    /// Deviation factor
    pub deviation_factor: f64,
    /// Severity (0.0 - 1.0)
    pub severity: f64,
    /// Description
    pub description: String,
}

/// Types of timing anomalies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingAnomalyType {
    /// Unusually slow execution (possible anti-debug RDTSC check)
    UnusuallySlowExecution,
    /// Unusually fast execution (possible emulation or skip)
    UnusuallyFastExecution,
    /// Timing variance spike (inconsistent timing)
    HighVariance,
    /// Timing cliff (sudden timing change)
    TimingCliff,
    /// Suspiciously consistent timing (possible emulation)
    SuspiciouslyConsistent,
    /// RDTSC-based timing check pattern
    RdtscCheck,
    /// QueryPerformanceCounter-based check
    QpcCheck,
    /// GetTickCount-based check
    GetTickCountCheck,
    /// NtQueryPerformanceCounter-based check
    NtQueryPerfCounter,
}

/// A slow code region
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlowRegion {
    /// Start address
    pub start_address: u64,
    /// End address
    pub end_address: u64,
    /// Total cycles spent
    pub total_cycles: u64,
    /// Execution count
    pub exec_count: usize,
    /// Average cycles per execution
    pub avg_cycles: f64,
    /// Possible cause
    pub possible_cause: String,
}

/// A fast code region
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastRegion {
    /// Start address
    pub start_address: u64,
    /// End address
    pub end_address: u64,
    /// Average cycles
    pub avg_cycles: f64,
    /// Likely reason (cache-hot, optimized, etc.)
    pub likely_reason: String,
}

/// Control flow graph reconstructed from trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    /// Basic blocks
    pub blocks: Vec<BasicBlock>,
    /// Edges between blocks
    pub edges: Vec<CfgEdge>,
    /// Entry points
    pub entry_points: Vec<u64>,
    /// Exit points
    pub exit_points: Vec<u64>,
    /// Call sites
    pub call_sites: Vec<CallSite>,
    /// Functions identified
    pub functions: Vec<Function>,
}

/// A basic block in the CFG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Block ID
    pub id: u64,
    /// Start address
    pub start_address: u64,
    /// End address (last instruction)
    pub end_address: u64,
    /// Execution count
    pub exec_count: usize,
    /// Average time spent (cycles)
    pub avg_cycles: f64,
    /// Exit instruction type
    pub exit_type: BranchType,
}

/// An edge in the CFG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    /// Source block ID
    pub from_block: u64,
    /// Target block ID
    pub to_block: u64,
    /// Edge type
    pub edge_type: EdgeType,
    /// Execution count
    pub exec_count: usize,
    /// Branch taken probability (for conditional edges)
    pub taken_probability: Option<f64>,
}

/// Edge types in CFG
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeType {
    /// Fallthrough (not taken)
    FallThrough,
    /// Branch taken
    BranchTaken,
    /// Function call
    Call,
    /// Return
    Return,
    /// Exception/interrupt
    Exception,
}

/// A call site in the trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    /// Call address
    pub call_address: u64,
    /// Target function
    pub target_address: u64,
    /// Call count
    pub call_count: usize,
    /// Average time in function
    pub avg_time_in_function: f64,
    /// Return address
    pub return_address: u64,
}

/// A function identified from trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    /// Entry address
    pub entry_address: u64,
    /// All return addresses
    pub return_addresses: Vec<u64>,
    /// Blocks belonging to this function
    pub blocks: Vec<u64>,
    /// Call count
    pub call_count: usize,
    /// Average execution time
    pub avg_exec_time: f64,
    /// Called functions
    pub callees: Vec<u64>,
    /// Calling functions
    pub callers: Vec<u64>,
}

/// Trace session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceState {
    /// Not started
    Idle,
    /// Configuring
    Configuring,
    /// Actively tracing
    Tracing,
    /// Paused
    Paused,
    /// Stopped, data available
    Stopped,
    /// Error occurred
    Error,
}

/// Windows IPT driver status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IptDriverStatus {
    /// Driver is loaded
    pub loaded: bool,
    /// Driver version (if known)
    pub version: Option<String>,
    /// Number of active traces
    pub active_traces: usize,
    /// Available buffer size
    pub available_buffer: usize,
    /// Last error
    pub last_error: Option<String>,
}
