//! Intel PT Trace Analysis
//!
//! Advanced analysis: timing anomaly detection, CFG reconstruction, branch prediction

use super::types::*;
use std::collections::{HashMap, HashSet, BTreeMap};

pub fn analyze_timing(trace: &DecodedTrace) -> TimingAnalysis {
    let mut analyzer = TimingAnalyzer::new();
    analyzer.analyze(trace)
}

pub fn reconstruct_cfg(trace: &DecodedTrace) -> ControlFlowGraph {
    let mut builder = CfgBuilder::new();
    builder.build(trace)
}

struct TimingAnalyzer {
    cycle_samples: Vec<u64>,
    address_timing: HashMap<u64, Vec<u64>>,
    tsc_frequency: u64,
    anomaly_threshold: f64,
}

impl TimingAnalyzer {
    fn new() -> Self {
        Self {
            cycle_samples: Vec::new(),
            address_timing: HashMap::new(),
            tsc_frequency: 3_000_000_000,
            anomaly_threshold: 3.0,
        }
    }

    fn analyze(&mut self, trace: &DecodedTrace) -> TimingAnalysis {
        self.extract_cycle_data(trace);
        let stats = self.calculate_stats(trace);
        let anomalies = self.detect_anomalies(trace);
        let cycle_histogram = self.build_histogram();
        let slow_regions = self.find_slow_regions();
        let fast_regions = self.find_fast_regions();

        TimingAnalysis { stats, anomalies, cycle_histogram, slow_regions, fast_regions }
    }

    fn extract_cycle_data(&mut self, trace: &DecodedTrace) {
        let mut last_cycles = 0u64;
        for event in &trace.timing_events {
            if let Some(cycles) = event.cycles {
                if last_cycles > 0 {
                    self.cycle_samples.push(cycles.saturating_sub(last_cycles));
                }
                last_cycles = cycles;
            }
        }
        for branch in &trace.branches {
            if let Some(ref timing) = branch.timing {
                if let Some(cycles) = timing.cycles {
                    self.address_timing.entry(branch.source).or_default().push(cycles);
                }
            }
        }
    }

    fn calculate_stats(&self, trace: &DecodedTrace) -> TimingStats {
        if self.cycle_samples.is_empty() { return TimingStats::default(); }

        let sum: u64 = self.cycle_samples.iter().sum();
        let count = self.cycle_samples.len();
        let avg = sum as f64 / count as f64;

        let mut sorted = self.cycle_samples.clone();
        sorted.sort_unstable();
        let median = sorted[count / 2];
        let min = *sorted.first().unwrap_or(&0);
        let max = *sorted.last().unwrap_or(&0);

        let variance: f64 = self.cycle_samples.iter()
            .map(|&x| { let d = x as f64 - avg; d * d })
            .sum::<f64>() / count as f64;
        let std_dev = variance.sqrt();

        let total_duration_ns = (sum as f64 / self.tsc_frequency as f64 * 1e9) as u64;
        let avg_cycles_per_branch = if !trace.branches.is_empty() {
            sum as f64 / trace.branches.len() as f64
        } else { 0.0 };

        TimingStats {
            total_duration_ns,
            avg_cycles_per_branch,
            median_cycles_per_branch: median,
            min_cycles: min,
            max_cycles: max,
            std_deviation: std_dev,
            tsc_frequency_hz: self.tsc_frequency,
        }
    }

    fn detect_anomalies(&self, trace: &DecodedTrace) -> Vec<TimingAnomaly> {
        let mut anomalies = Vec::new();
        if self.cycle_samples.is_empty() { return anomalies; }

        let sum: u64 = self.cycle_samples.iter().sum();
        let count = self.cycle_samples.len();
        let avg = sum as f64 / count as f64;
        let variance: f64 = self.cycle_samples.iter()
            .map(|&x| { let d = x as f64 - avg; d * d })
            .sum::<f64>() / count as f64;
        let std_dev = variance.sqrt();

        for branch in &trace.branches {
            if let Some(ref timing) = branch.timing {
                if let Some(cycles) = timing.cycles {
                    let deviation = (cycles as f64 - avg).abs() / std_dev;
                    if deviation > self.anomaly_threshold {
                        let anomaly_type = if cycles as f64 > avg {
                            TimingAnomalyType::UnusuallySlowExecution
                        } else {
                            TimingAnomalyType::UnusuallyFastExecution
                        };
                        anomalies.push(TimingAnomaly {
                            anomaly_type,
                            address: branch.source,
                            expected_cycles: avg as u64,
                            observed_cycles: cycles,
                            deviation_factor: deviation,
                            severity: (deviation / 10.0).min(1.0),
                            description: format!("{:?} at 0x{:x}: {} vs {} ({:.1}σ)",
                                anomaly_type, branch.source, cycles, avg as u64, deviation),
                        });
                    }
                }
            }
        }

        // Detect RDTSC patterns
        for window in trace.timing_events.windows(2) {
            if let (Some(tsc1), Some(tsc2)) = (window[0].tsc, window[1].tsc) {
                let delta_offset = window[1].offset - window[0].offset;
                let tsc_delta = tsc2.saturating_sub(tsc1);
                if delta_offset < 100 && tsc_delta < 1000 {
                    for branch in &trace.branches {
                        if branch.branch_type == BranchType::Conditional {
                            if let Some(ref t) = branch.timing {
                                if t.offset > window[0].offset && t.offset < window[1].offset + 50 {
                                    anomalies.push(TimingAnomaly {
                                        anomaly_type: TimingAnomalyType::RdtscCheck,
                                        address: branch.source,
                                        expected_cycles: 0,
                                        observed_cycles: tsc_delta,
                                        deviation_factor: 0.0,
                                        severity: 0.8,
                                        description: format!("Potential RDTSC check at 0x{:x}", branch.source),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        anomalies
    }

    fn build_histogram(&self) -> Vec<(u64, u64)> {
        let mut buckets: BTreeMap<u64, u64> = BTreeMap::new();
        for &cycles in &self.cycle_samples {
            let bucket = if cycles == 0 { 0 } else { 1u64 << (63 - cycles.leading_zeros()) };
            *buckets.entry(bucket).or_default() += 1;
        }
        buckets.into_iter().collect()
    }

    fn find_slow_regions(&self) -> Vec<SlowRegion> {
        let mut regions = Vec::new();
        for (&addr, timings) in &self.address_timing {
            if timings.len() < 3 { continue; }
            let avg: f64 = timings.iter().sum::<u64>() as f64 / timings.len() as f64;
            if avg > 1000.0 {
                regions.push(SlowRegion {
                    start_address: addr,
                    end_address: addr + 16,
                    total_cycles: timings.iter().sum(),
                    exec_count: timings.len(),
                    avg_cycles: avg,
                    possible_cause: self.guess_slow_cause(avg as u64),
                });
            }
        }
        regions.sort_by(|a, b| b.total_cycles.cmp(&a.total_cycles));
        regions.truncate(20);
        regions
    }

    fn find_fast_regions(&self) -> Vec<FastRegion> {
        let mut regions = Vec::new();
        for (&addr, timings) in &self.address_timing {
            if timings.len() < 10 { continue; }
            let avg: f64 = timings.iter().sum::<u64>() as f64 / timings.len() as f64;
            if avg < 10.0 {
                regions.push(FastRegion {
                    start_address: addr,
                    end_address: addr + 16,
                    avg_cycles: avg,
                    likely_reason: if avg < 3.0 { "L1 cache hit".to_string() } else { "Cache-hot".to_string() },
                });
            }
        }
        regions.sort_by(|a, b| a.avg_cycles.partial_cmp(&b.avg_cycles).unwrap_or(std::cmp::Ordering::Equal));
        regions.truncate(20);
        regions
    }

    fn guess_slow_cause(&self, avg_cycles: u64) -> String {
        match avg_cycles {
            0..=100 => "Normal".to_string(),
            101..=500 => "Cache miss".to_string(),
            501..=2000 => "Memory/TLB miss".to_string(),
            2001..=10000 => "I/O or syscall".to_string(),
            _ => "Major stall (anti-debug?)".to_string(),
        }
    }
}

struct CfgBuilder {
    blocks: HashMap<u64, BasicBlock>,
    edges: Vec<CfgEdge>,
    functions: HashMap<u64, Function>,
    next_block_id: u64,
}

impl CfgBuilder {
    fn new() -> Self {
        Self { blocks: HashMap::new(), edges: Vec::new(), functions: HashMap::new(), next_block_id: 0 }
    }

    fn build(&mut self, trace: &DecodedTrace) -> ControlFlowGraph {
        self.identify_blocks(trace);
        self.build_edges(trace);
        self.identify_functions(trace);

        let blocks: Vec<BasicBlock> = self.blocks.values().cloned().collect();
        let entry_points: Vec<u64> = self.functions.keys().copied().collect();
        let exit_points: Vec<u64> = self.functions.values()
            .flat_map(|f| f.return_addresses.iter().copied()).collect();

        let call_sites: Vec<CallSite> = trace.branches.iter()
            .filter(|b| matches!(b.branch_type, BranchType::DirectCall | BranchType::IndirectCall))
            .map(|b| CallSite {
                call_address: b.source,
                target_address: b.target,
                call_count: 1,
                avg_time_in_function: 0.0,
                return_address: b.source + 5,
            }).collect();

        ControlFlowGraph {
            blocks,
            edges: self.edges.clone(),
            entry_points,
            exit_points,
            call_sites,
            functions: self.functions.values().cloned().collect(),
        }
    }

    fn identify_blocks(&mut self, trace: &DecodedTrace) {
        let mut block_starts: HashSet<u64> = HashSet::new();
        for branch in &trace.branches {
            if branch.target != 0 { block_starts.insert(branch.target); }
            if branch.source != 0 && branch.branch_type == BranchType::Conditional {
                block_starts.insert(branch.source + 2);
            }
        }
        for &start in &block_starts {
            self.blocks.insert(start, BasicBlock {
                id: self.next_block_id,
                start_address: start,
                end_address: start,
                exec_count: 0,
                avg_cycles: 0.0,
                exit_type: BranchType::Unknown,
            });
            self.next_block_id += 1;
        }
    }

    fn build_edges(&mut self, trace: &DecodedTrace) {
        let mut edge_counts: HashMap<(u64, u64), usize> = HashMap::new();
        for branch in &trace.branches {
            if branch.source == 0 || branch.target == 0 { continue; }
            let src = self.find_block_containing(branch.source);
            let tgt = self.find_block_containing(branch.target);
            if let (Some(s), Some(t)) = (src, tgt) {
                *edge_counts.entry((s, t)).or_default() += 1;
                if let Some(block) = self.blocks.get_mut(&s) {
                    if branch.source > block.end_address {
                        block.end_address = branch.source;
                        block.exit_type = branch.branch_type;
                    }
                    block.exec_count += 1;
                }
            }
        }
        for ((from, to), count) in edge_counts {
            let edge_type = match self.blocks.get(&from).map(|b| b.exit_type).unwrap_or(BranchType::Unknown) {
                BranchType::Conditional => EdgeType::BranchTaken,
                BranchType::DirectCall | BranchType::IndirectCall => EdgeType::Call,
                BranchType::Return => EdgeType::Return,
                BranchType::Interrupt => EdgeType::Exception,
                _ => EdgeType::BranchTaken,
            };
            self.edges.push(CfgEdge {
                from_block: self.blocks.get(&from).map(|b| b.id).unwrap_or(0),
                to_block: self.blocks.get(&to).map(|b| b.id).unwrap_or(0),
                edge_type,
                exec_count: count,
                taken_probability: None,
            });
        }
    }

    fn find_block_containing(&self, addr: u64) -> Option<u64> {
        self.blocks.keys().filter(|&&start| start <= addr).max().copied()
    }

    fn identify_functions(&mut self, trace: &DecodedTrace) {
        let mut call_targets: HashMap<u64, Vec<u64>> = HashMap::new();
        for branch in &trace.branches {
            if matches!(branch.branch_type, BranchType::DirectCall | BranchType::IndirectCall) {
                call_targets.entry(branch.target).or_default().push(branch.source);
            }
        }
        for (entry, callers) in &call_targets {
            if *entry == 0 { continue; }
            self.functions.insert(*entry, Function {
                entry_address: *entry,
                return_addresses: vec![],
                blocks: vec![],
                call_count: callers.len(),
                avg_exec_time: 0.0,
                callees: vec![],
                callers: callers.clone(),
            });
        }
    }
}

pub struct BranchPredictionAnalyzer {
    branch_history: HashMap<u64, Vec<bool>>,
}

impl BranchPredictionAnalyzer {
    pub fn new() -> Self { Self { branch_history: HashMap::new() } }

    pub fn analyze(&mut self, trace: &DecodedTrace) -> BranchPredictionStats {
        for branch in &trace.branches {
            if branch.branch_type == BranchType::Conditional {
                self.branch_history.entry(branch.source).or_default().push(branch.taken);
            }
        }

        let (static_taken, static_not_taken) = self.calculate_static_prediction();
        let bimodal = self.calculate_bimodal_prediction();
        let local = self.calculate_local_prediction();
        let hard = self.find_hard_to_predict();

        BranchPredictionStats {
            total_branches: trace.branches.iter().filter(|b| b.branch_type == BranchType::Conditional).count(),
            static_taken_accuracy: static_taken,
            static_not_taken_accuracy: static_not_taken,
            bimodal_accuracy: bimodal,
            local_history_accuracy: local,
            hard_to_predict_branches: hard,
        }
    }

    fn calculate_static_prediction(&self) -> (f64, f64) {
        let mut taken = 0usize;
        let mut total = 0usize;
        for outcomes in self.branch_history.values() {
            for &t in outcomes { total += 1; if t { taken += 1; } }
        }
        if total == 0 { return (0.0, 0.0); }
        (taken as f64 / total as f64, (total - taken) as f64 / total as f64)
    }

    fn calculate_bimodal_prediction(&self) -> f64 {
        let mut correct = 0usize;
        let mut total = 0usize;
        for outcomes in self.branch_history.values() {
            let mut counter: i8 = 1;
            for &taken in outcomes {
                total += 1;
                if (counter >= 0) == taken { correct += 1; }
                counter = if taken { (counter + 1).min(1) } else { (counter - 1).max(-2) };
            }
        }
        if total == 0 { 0.0 } else { correct as f64 / total as f64 }
    }

    fn calculate_local_prediction(&self) -> f64 {
        let mut correct = 0usize;
        let mut total = 0usize;
        for outcomes in self.branch_history.values() {
            let mut history: u8 = 0;
            let mut table: [i8; 16] = [0; 16];
            for &taken in outcomes {
                total += 1;
                let idx = (history & 0xF) as usize;
                if (table[idx] >= 0) == taken { correct += 1; }
                table[idx] = if taken { (table[idx] + 1).min(1) } else { (table[idx] - 1).max(-2) };
                history = (history << 1) | (taken as u8);
            }
        }
        if total == 0 { 0.0 } else { correct as f64 / total as f64 }
    }

    fn find_hard_to_predict(&self) -> Vec<HardBranch> {
        let mut hard = Vec::new();
        for (&addr, outcomes) in &self.branch_history {
            if outcomes.len() < 10 { continue; }
            let taken = outcomes.iter().filter(|&&t| t).count();
            let p = taken as f64 / outcomes.len() as f64;
            let entropy = if p > 0.0 && p < 1.0 { -p * p.log2() - (1.0 - p) * (1.0 - p).log2() } else { 0.0 };
            if entropy > 0.9 {
                hard.push(HardBranch { address: addr, taken_ratio: p, entropy, sample_count: outcomes.len() });
            }
        }
        hard.sort_by(|a, b| b.entropy.partial_cmp(&a.entropy).unwrap_or(std::cmp::Ordering::Equal));
        hard.truncate(20);
        hard
    }
}

impl Default for BranchPredictionAnalyzer { fn default() -> Self { Self::new() } }

#[derive(Debug, Clone)]
pub struct BranchPredictionStats {
    pub total_branches: usize,
    pub static_taken_accuracy: f64,
    pub static_not_taken_accuracy: f64,
    pub bimodal_accuracy: f64,
    pub local_history_accuracy: f64,
    pub hard_to_predict_branches: Vec<HardBranch>,
}

#[derive(Debug, Clone)]
pub struct HardBranch {
    pub address: u64,
    pub taken_ratio: f64,
    pub entropy: f64,
    pub sample_count: usize,
}

pub struct AntiDebugDetector;

impl AntiDebugDetector {
    pub fn new() -> Self { Self }

    pub fn analyze(&self, trace: &DecodedTrace) -> Vec<DetectedAntiDebug> {
        let mut detections = Vec::new();
        for window in trace.timing_events.windows(2) {
            if let (Some(tsc1), Some(tsc2)) = (window[0].tsc, window[1].tsc) {
                let delta = tsc2.saturating_sub(tsc1);
                if delta < 1000 {
                    for branch in &trace.branches {
                        if branch.branch_type == BranchType::Conditional {
                            if let Some(ref t) = branch.timing {
                                let diff = if t.offset > window[1].offset { t.offset - window[1].offset } else { window[1].offset - t.offset };
                                if diff < 100 {
                                    detections.push(DetectedAntiDebug {
                                        pattern_name: "RDTSC Delta Check".to_string(),
                                        address: branch.source,
                                        confidence: 0.8,
                                        measured_delta: delta,
                                        description: format!("Timing check at 0x{:x}: delta={}", branch.source, delta),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        detections
    }
}

impl Default for AntiDebugDetector { fn default() -> Self { Self::new() } }

#[derive(Debug, Clone)]
pub struct DetectedAntiDebug {
    pub pattern_name: String,
    pub address: u64,
    pub confidence: f64,
    pub measured_delta: u64,
    pub description: String,
}
