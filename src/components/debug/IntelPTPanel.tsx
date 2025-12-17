import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Cpu, Play, Square, RefreshCw, Activity, AlertTriangle,
  Clock, GitBranch, BarChart2, Settings, Trash2,
  ChevronDown, ChevronRight, Shield
} from "lucide-react";

interface PtStatus {
  available: boolean;
  capabilities: {
    supported: boolean;
    cr3_filtering: boolean;
    psb_cyc: boolean;
    ip_filtering: boolean;
    mtc: boolean;
    ptwrite: boolean;
    power_event: boolean;
    topa: boolean;
    single_range: boolean;
    num_addr_ranges: number;
  };
  active_traces: number;
  driver_status: {
    loaded: boolean;
    version: string | null;
    last_error: string | null;
  };
}

interface PtSession {
  id: string;
  state: string;
  process_id: number | null;
  core_id: number | null;
  buffer_size: number;
  overflow: boolean;
}

interface TimingAnomaly {
  type: string;
  address: string;
  expected: number;
  observed: number;
  deviation: number;
  severity: number;
  description: string;
}

interface SlowRegion {
  start: string;
  end: string;
  total_cycles: number;
  exec_count: number;
  avg_cycles: number;
  cause: string;
}

interface TraceStats {
  total_packets: number;
  total_branches: number;
  taken_branches: number;
  not_taken_branches: number;
  calls: number;
  returns: number;
  call_return_balance: number;
  packets_by_type: Record<string, number>;
  mode_changes: number;
  cr3_changes: number;
  overflows: number;
  errors: number;
}

interface TimingAnalysis {
  stats: {
    total_duration_ns: number;
    avg_cycles_per_branch: number;
    median_cycles_per_branch: number;
    min_cycles: number;
    max_cycles: number;
    std_deviation: number;
    tsc_frequency_hz: number;
  };
  anomalies: TimingAnomaly[];
  slow_regions: SlowRegion[];
  fast_regions: { start: string; avg_cycles: number; reason: string }[];
}

interface CfgBlock {
  id: number;
  start: string;
  end: string;
  exec_count: number;
  exit_type: string;
}

interface CfgEdge {
  from: number;
  to: number;
  type: string;
  count: number;
}

interface CfgData {
  blocks: CfgBlock[];
  edges: CfgEdge[];
  functions: { entry: string; call_count: number; callers: number }[];
  entry_points: string[];
  call_sites: number;
}

type PresetConfig = "default" | "high_fidelity" | "low_overhead" | "timing_analysis" | "control_flow" | "anti_debug" | "code_coverage";

export function IntelPTPanel() {
  const [status, setStatus] = useState<PtStatus | null>(null);
  const [sessions, setSessions] = useState<PtSession[]>([]);
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [traceStats, setTraceStats] = useState<TraceStats | null>(null);
  const [timingAnalysis, setTimingAnalysis] = useState<TimingAnalysis | null>(null);
  const [cfgData, setCfgData] = useState<CfgData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "timing" | "cfg" | "anomalies">("overview");
  const [preset, setPreset] = useState<PresetConfig>("default");
  const [processId, setProcessId] = useState("");
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(["capabilities", "sessions"]));

  // Fetch Intel PT status
  const fetchStatus = useCallback(async () => {
    try {
      const result = await invoke<string>("get_intel_pt_status");
      setStatus(JSON.parse(result));
    } catch (err) {
      console.error("Failed to fetch Intel PT status:", err);
    }
  }, []);

  // Fetch sessions
  const fetchSessions = useCallback(async () => {
    try {
      const result = await invoke<string>("list_pt_sessions");
      const data = JSON.parse(result);
      setSessions(data.sessions || []);
    } catch (err) {
      console.error("Failed to fetch sessions:", err);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    fetchSessions();
    const interval = setInterval(() => {
      fetchStatus();
      fetchSessions();
    }, 2000);
    return () => clearInterval(interval);
  }, [fetchStatus, fetchSessions]);

  // Start trace
  const startTrace = async () => {
    if (!processId) {
      setError("Please enter a process ID");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const result = await invoke<string>("start_pt_process_trace", {
        processId: parseInt(processId),
        preset,
      });
      const data = JSON.parse(result);
      setSelectedSession(data.trace_id);
      await fetchSessions();
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  // Stop trace
  const stopTrace = async (traceId: string) => {
    setLoading(true);
    try {
      await invoke<string>("stop_pt_trace", { traceId });
      await fetchSessions();
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  // Decode trace
  const decodeTrace = async (traceId: string) => {
    setLoading(true);
    try {
      const result = await invoke<string>("decode_pt_trace", { traceId });
      setTraceStats(JSON.parse(result));
      setActiveTab("overview");
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  // Analyze timing
  const analyzeTiming = async (traceId: string) => {
    setLoading(true);
    try {
      const result = await invoke<string>("analyze_pt_timing", { traceId });
      setTimingAnalysis(JSON.parse(result));
      setActiveTab("timing");
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  // Get CFG
  const getCfg = async (traceId: string) => {
    setLoading(true);
    try {
      const result = await invoke<string>("get_pt_cfg", { traceId });
      setCfgData(JSON.parse(result));
      setActiveTab("cfg");
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const newSet = new Set(prev);
      if (newSet.has(section)) {
        newSet.delete(section);
      } else {
        newSet.add(section);
      }
      return newSet;
    });
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  };

  const formatNs = (ns: number) => {
    if (ns < 1000) return `${ns} ns`;
    if (ns < 1000000) return `${(ns / 1000).toFixed(2)} us`;
    if (ns < 1000000000) return `${(ns / 1000000).toFixed(2)} ms`;
    return `${(ns / 1000000000).toFixed(2)} s`;
  };

  if (!status) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <RefreshCw className="w-4 h-4 animate-spin mr-2" />
        Loading Intel PT status...
      </div>
    );
  }

  if (!status.available) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <AlertTriangle className="w-8 h-8 mx-auto mb-2 text-accent-yellow" />
          <p className="text-sm font-medium">Intel PT Not Available</p>
          <p className="text-xs mt-1">
            {status.driver_status?.last_error || "Intel PT hardware not detected or driver not loaded"}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-10 bg-bg-secondary border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <Cpu className="w-4 h-4 text-accent-cyan" />
          <span className="text-sm font-medium">Intel PT Trace</span>
          <span className="text-xs px-1.5 py-0.5 rounded bg-accent-green/20 text-accent-green">
            Available
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-text-secondary">
            Active: {status.active_traces}
          </span>
          <button
            onClick={() => { fetchStatus(); fetchSessions(); }}
            className="p-1.5 rounded hover:bg-bg-hover"
            title="Refresh"
          >
            <RefreshCw className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="px-3 py-2 bg-accent-red/10 border-b border-accent-red/30 flex items-center justify-between">
          <span className="text-xs text-accent-red">{error}</span>
          <button onClick={() => setError(null)} className="text-accent-red hover:text-accent-red/80">
            <Trash2 className="w-3 h-3" />
          </button>
        </div>
      )}

      <div className="flex-1 overflow-auto">
        {/* Control Section */}
        <div className="p-3 border-b border-border">
          <div className="flex items-center gap-2 mb-2">
            <input
              type="text"
              value={processId}
              onChange={(e) => setProcessId(e.target.value)}
              placeholder="Process ID"
              className="w-24 px-2 py-1 text-xs bg-bg-primary border border-border rounded focus:outline-none focus:border-accent-blue"
            />
            <select
              value={preset}
              onChange={(e) => setPreset(e.target.value as PresetConfig)}
              className="px-2 py-1 text-xs bg-bg-primary border border-border rounded focus:outline-none focus:border-accent-blue"
            >
              <option value="default">Default</option>
              <option value="high_fidelity">High Fidelity</option>
              <option value="low_overhead">Low Overhead</option>
              <option value="timing_analysis">Timing Analysis</option>
              <option value="control_flow">Control Flow</option>
              <option value="anti_debug">Anti-Debug Detection</option>
              <option value="code_coverage">Code Coverage</option>
            </select>
            <button
              onClick={startTrace}
              disabled={loading || !processId}
              className="px-3 py-1 text-xs bg-accent-green/20 text-accent-green rounded hover:bg-accent-green/30 disabled:opacity-50 flex items-center gap-1"
            >
              <Play className="w-3 h-3" />
              Start Trace
            </button>
          </div>
        </div>

        {/* Capabilities Section */}
        <div className="border-b border-border">
          <button
            onClick={() => toggleSection("capabilities")}
            className="w-full px-3 py-2 flex items-center gap-2 hover:bg-bg-hover text-left"
          >
            {expandedSections.has("capabilities") ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
            <Settings className="w-3 h-3 text-accent-blue" />
            <span className="text-xs font-medium">Capabilities</span>
          </button>
          {expandedSections.has("capabilities") && (
            <div className="px-3 pb-2 grid grid-cols-3 gap-2 text-xs">
              <CapBadge name="CR3 Filter" enabled={status.capabilities.cr3_filtering} />
              <CapBadge name="PSB/CYC" enabled={status.capabilities.psb_cyc} />
              <CapBadge name="IP Filter" enabled={status.capabilities.ip_filtering} />
              <CapBadge name="MTC" enabled={status.capabilities.mtc} />
              <CapBadge name="PTWRITE" enabled={status.capabilities.ptwrite} />
              <CapBadge name="ToPA" enabled={status.capabilities.topa} />
              <CapBadge name="Power Events" enabled={status.capabilities.power_event} />
              <span className="text-text-secondary">
                Addr Ranges: {status.capabilities.num_addr_ranges}
              </span>
            </div>
          )}
        </div>

        {/* Sessions Section */}
        <div className="border-b border-border">
          <button
            onClick={() => toggleSection("sessions")}
            className="w-full px-3 py-2 flex items-center gap-2 hover:bg-bg-hover text-left"
          >
            {expandedSections.has("sessions") ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
            <Activity className="w-3 h-3 text-accent-cyan" />
            <span className="text-xs font-medium">Sessions ({sessions.length})</span>
          </button>
          {expandedSections.has("sessions") && (
            <div className="px-3 pb-2">
              {sessions.length === 0 ? (
                <p className="text-xs text-text-secondary">No active sessions</p>
              ) : (
                <div className="space-y-1">
                  {sessions.map((session) => (
                    <div
                      key={session.id}
                      className={`p-2 rounded border ${
                        selectedSession === session.id
                          ? "border-accent-blue bg-accent-blue/10"
                          : "border-border hover:border-border-hover"
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-mono truncate flex-1">{session.id}</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                          session.state === "Tracing" ? "bg-accent-green/20 text-accent-green" :
                          session.state === "Stopped" ? "bg-accent-blue/20 text-accent-blue" :
                          "bg-bg-tertiary text-text-secondary"
                        }`}>
                          {session.state}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-[10px] text-text-secondary">
                        {session.process_id && <span>PID: {session.process_id}</span>}
                        {session.core_id !== null && <span>Core: {session.core_id}</span>}
                        <span>{formatBytes(session.buffer_size)}</span>
                        {session.overflow && (
                          <span className="text-accent-red">Overflow!</span>
                        )}
                      </div>
                      <div className="flex items-center gap-1 mt-2">
                        {session.state === "Tracing" && (
                          <button
                            onClick={() => stopTrace(session.id)}
                            className="px-2 py-0.5 text-[10px] bg-accent-red/20 text-accent-red rounded hover:bg-accent-red/30"
                          >
                            <Square className="w-2 h-2 inline mr-1" />
                            Stop
                          </button>
                        )}
                        {session.state === "Stopped" && (
                          <>
                            <button
                              onClick={() => { setSelectedSession(session.id); decodeTrace(session.id); }}
                              className="px-2 py-0.5 text-[10px] bg-bg-tertiary rounded hover:bg-bg-hover"
                            >
                              <BarChart2 className="w-2 h-2 inline mr-1" />
                              Decode
                            </button>
                            <button
                              onClick={() => { setSelectedSession(session.id); analyzeTiming(session.id); }}
                              className="px-2 py-0.5 text-[10px] bg-bg-tertiary rounded hover:bg-bg-hover"
                            >
                              <Clock className="w-2 h-2 inline mr-1" />
                              Timing
                            </button>
                            <button
                              onClick={() => { setSelectedSession(session.id); getCfg(session.id); }}
                              className="px-2 py-0.5 text-[10px] bg-bg-tertiary rounded hover:bg-bg-hover"
                            >
                              <GitBranch className="w-2 h-2 inline mr-1" />
                              CFG
                            </button>
                          </>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Analysis Results */}
        {(traceStats || timingAnalysis || cfgData) && (
          <div className="border-b border-border">
            {/* Tab buttons */}
            <div className="flex items-center gap-1 px-3 py-1 bg-bg-secondary border-b border-border">
              <TabBtn active={activeTab === "overview"} onClick={() => setActiveTab("overview")}>
                Overview
              </TabBtn>
              <TabBtn active={activeTab === "timing"} onClick={() => setActiveTab("timing")}>
                Timing
              </TabBtn>
              <TabBtn active={activeTab === "cfg"} onClick={() => setActiveTab("cfg")}>
                CFG
              </TabBtn>
              <TabBtn active={activeTab === "anomalies"} onClick={() => setActiveTab("anomalies")}>
                Anomalies
              </TabBtn>
            </div>

            <div className="p-3">
              {activeTab === "overview" && traceStats && (
                <div className="space-y-2">
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <StatBox label="Total Packets" value={traceStats.total_packets.toLocaleString()} />
                    <StatBox label="Total Branches" value={traceStats.total_branches.toLocaleString()} />
                    <StatBox label="Taken" value={traceStats.taken_branches.toLocaleString()} color="green" />
                    <StatBox label="Not Taken" value={traceStats.not_taken_branches.toLocaleString()} color="red" />
                    <StatBox label="Calls" value={traceStats.calls.toLocaleString()} />
                    <StatBox label="Returns" value={traceStats.returns.toLocaleString()} />
                  </div>
                  <div className="text-xs text-text-secondary">
                    Call/Return Balance: {traceStats.call_return_balance}
                    {Math.abs(traceStats.call_return_balance) > 10 && (
                      <span className="text-accent-yellow ml-1">(imbalanced - possible incomplete trace)</span>
                    )}
                  </div>
                  {traceStats.overflows > 0 && (
                    <div className="text-xs text-accent-red flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" />
                      {traceStats.overflows} buffer overflow(s) detected
                    </div>
                  )}
                </div>
              )}

              {activeTab === "timing" && timingAnalysis && (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <StatBox label="Duration" value={formatNs(timingAnalysis.stats.total_duration_ns)} />
                    <StatBox label="Avg Cycles/Branch" value={timingAnalysis.stats.avg_cycles_per_branch.toFixed(1)} />
                    <StatBox label="Min Cycles" value={timingAnalysis.stats.min_cycles.toLocaleString()} />
                    <StatBox label="Max Cycles" value={timingAnalysis.stats.max_cycles.toLocaleString()} />
                  </div>

                  {timingAnalysis.slow_regions.length > 0 && (
                    <div>
                      <h4 className="text-xs font-medium mb-1 flex items-center gap-1">
                        <Clock className="w-3 h-3 text-accent-red" />
                        Slow Regions
                      </h4>
                      <div className="space-y-1 max-h-32 overflow-auto">
                        {timingAnalysis.slow_regions.map((region, i) => (
                          <div key={i} className="text-[10px] p-1.5 bg-bg-tertiary rounded flex justify-between">
                            <span className="font-mono text-accent-blue">{region.start}</span>
                            <span>{region.avg_cycles.toFixed(0)} cycles ({region.cause})</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activeTab === "cfg" && cfgData && (
                <div className="space-y-3">
                  <div className="grid grid-cols-3 gap-2 text-xs">
                    <StatBox label="Blocks" value={cfgData.blocks.length.toString()} />
                    <StatBox label="Edges" value={cfgData.edges.length.toString()} />
                    <StatBox label="Functions" value={cfgData.functions.length.toString()} />
                  </div>

                  <div>
                    <h4 className="text-xs font-medium mb-1">Entry Points</h4>
                    <div className="flex flex-wrap gap-1">
                      {cfgData.entry_points.slice(0, 10).map((ep, i) => (
                        <span key={i} className="text-[10px] font-mono px-1.5 py-0.5 bg-bg-tertiary rounded text-accent-cyan">
                          {ep}
                        </span>
                      ))}
                      {cfgData.entry_points.length > 10 && (
                        <span className="text-[10px] text-text-secondary">
                          +{cfgData.entry_points.length - 10} more
                        </span>
                      )}
                    </div>
                  </div>

                  <div>
                    <h4 className="text-xs font-medium mb-1">Hot Functions</h4>
                    <div className="space-y-1 max-h-32 overflow-auto">
                      {cfgData.functions
                        .sort((a, b) => b.call_count - a.call_count)
                        .slice(0, 10)
                        .map((fn, i) => (
                          <div key={i} className="text-[10px] p-1.5 bg-bg-tertiary rounded flex justify-between">
                            <span className="font-mono text-accent-blue">{fn.entry}</span>
                            <span>{fn.call_count} calls</span>
                          </div>
                        ))}
                    </div>
                  </div>
                </div>
              )}

              {activeTab === "anomalies" && timingAnalysis && (
                <div className="space-y-2">
                  {timingAnalysis.anomalies.length === 0 ? (
                    <div className="text-center py-4">
                      <Shield className="w-6 h-6 mx-auto mb-1 text-accent-green" />
                      <p className="text-xs text-text-secondary">No timing anomalies detected</p>
                    </div>
                  ) : (
                    <>
                      <div className="flex items-center gap-2 mb-2">
                        <AlertTriangle className="w-4 h-4 text-accent-yellow" />
                        <span className="text-xs font-medium">
                          {timingAnalysis.anomalies.length} Anomalies Detected
                        </span>
                      </div>
                      <div className="space-y-1 max-h-48 overflow-auto">
                        {timingAnalysis.anomalies.map((anomaly, i) => (
                          <div key={i} className="p-2 bg-bg-tertiary rounded border-l-2 border-accent-yellow">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-[10px] font-mono text-accent-blue">{anomaly.address}</span>
                              <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                                anomaly.severity > 0.7 ? "bg-accent-red/20 text-accent-red" :
                                anomaly.severity > 0.4 ? "bg-accent-yellow/20 text-accent-yellow" :
                                "bg-bg-tertiary text-text-secondary"
                              }`}>
                                {(anomaly.severity * 100).toFixed(0)}% severity
                              </span>
                            </div>
                            <p className="text-[10px] text-text-secondary">{anomaly.description}</p>
                            <div className="text-[10px] mt-1">
                              <span className="text-text-secondary">Expected: </span>
                              <span>{anomaly.expected}</span>
                              <span className="text-text-secondary"> Observed: </span>
                              <span className="text-accent-red">{anomaly.observed}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="h-6 bg-bg-secondary border-t border-border flex items-center px-3 text-[10px] text-text-secondary">
        <span>Intel PT v{status.driver_status?.version || "unknown"}</span>
        <span className="mx-2">|</span>
        <span>Driver: {status.driver_status?.loaded ? "Loaded" : "Not Loaded"}</span>
      </div>
    </div>
  );
}

function CapBadge({ name, enabled }: { name: string; enabled: boolean }) {
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded ${
      enabled ? "bg-accent-green/20 text-accent-green" : "bg-bg-tertiary text-text-secondary"
    }`}>
      {name}
    </span>
  );
}

function TabBtn({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`px-2 py-1 text-[10px] rounded ${
        active ? "bg-accent-blue/20 text-accent-blue" : "text-text-secondary hover:text-text-primary"
      }`}
    >
      {children}
    </button>
  );
}

function StatBox({ label, value, color }: { label: string; value: string; color?: "green" | "red" }) {
  const colorClass = color === "green" ? "text-accent-green" : color === "red" ? "text-accent-red" : "text-text-primary";
  return (
    <div className="p-2 bg-bg-tertiary rounded">
      <div className="text-[10px] text-text-secondary">{label}</div>
      <div className={`text-sm font-medium ${colorClass}`}>{value}</div>
    </div>
  );
}
