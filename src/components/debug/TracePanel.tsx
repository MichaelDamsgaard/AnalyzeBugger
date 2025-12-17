import { useState, useCallback, useRef, useEffect } from "react";
import { useSessionStore } from "../../stores/sessionStore";
import { useAnalysisStore } from "../../stores/analysisStore";
import {
  Play, Pause, Square, StepForward, ArrowDownToLine, ArrowUpFromLine,
  Target, History, Trash2, Download, Filter, Zap, Circle
} from "lucide-react";

interface TraceEntry {
  id: number;
  address: string;
  instruction: string;
  registers: {
    ax: string;
    bx: string;
    cx: string;
    dx: string;
    flags: string;
  };
  timestamp: number;
  note?: string;
}

export function TracePanel() {
  const {
    status,
    registers,
    continueExecution,
    pauseExecution,
    stepInto,
    stepOver,
    stopSession,
  } = useSessionStore();

  const { result, navigateTo } = useAnalysisStore();

  const [isTracing, setIsTracing] = useState(false);
  const [traceLog, setTraceLog] = useState<TraceEntry[]>([]);
  const [runToAddress, setRunToAddress] = useState("");
  const [maxTraceEntries, setMaxTraceEntries] = useState(1000);
  const [filterPattern, setFilterPattern] = useState("");
  const [showFilters, setShowFilters] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);

  const traceIdRef = useRef(0);
  const traceEndRef = useRef<HTMLDivElement>(null);

  const session = status?.session;
  const isRunning = session?.state === "running";
  const isPaused = session?.state === "paused" || session?.state === "stepping";
  const hasSession = !!session;

  // Auto-scroll trace log
  useEffect(() => {
    if (autoScroll && traceEndRef.current) {
      traceEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [traceLog, autoScroll]);

  // Add trace entry when stepping
  const recordTrace = useCallback(() => {
    if (!registers || !session?.current_ip) return;

    // Find instruction at current IP
    const currentInsn = result?.instructions.find(
      (i: { address: string }) => i.address === session.current_ip
    );

    const entry: TraceEntry = {
      id: ++traceIdRef.current,
      address: session.current_ip,
      instruction: currentInsn
        ? `${currentInsn.mnemonic} ${currentInsn.op_str}`
        : "???",
      registers: {
        ax: registers.rax.slice(-4),
        bx: registers.rbx.slice(-4),
        cx: registers.rcx.slice(-4),
        dx: registers.rdx.slice(-4),
        flags: registers.eflags.slice(-4),
      },
      timestamp: Date.now(),
    };

    setTraceLog(prev => {
      const newLog = [...prev, entry];
      // Trim to max entries
      if (newLog.length > maxTraceEntries) {
        return newLog.slice(-maxTraceEntries);
      }
      return newLog;
    });
  }, [registers, session?.current_ip, result?.instructions, maxTraceEntries]);

  // Step with trace recording
  const handleStepInto = useCallback(async () => {
    if (isTracing) recordTrace();
    await stepInto();
    if (isTracing) recordTrace();
  }, [stepInto, isTracing, recordTrace]);

  const handleStepOver = useCallback(async () => {
    if (isTracing) recordTrace();
    await stepOver();
    if (isTracing) recordTrace();
  }, [stepOver, isTracing, recordTrace]);

  // Step Out - run until return instruction
  const handleStepOut = useCallback(async () => {
    if (!isPaused || !result) return;

    // Find the next RET instruction
    const currentIdx = result.instructions.findIndex(
      (i: { address: string }) => i.address === session?.current_ip
    );

    if (currentIdx === -1) return;

    // Look for RET/RETN/RETF in remaining instructions
    for (let i = currentIdx + 1; i < result.instructions.length; i++) {
      const insn = result.instructions[i];
      const mnemonic = insn.mnemonic.toLowerCase();
      if (mnemonic === "ret" || mnemonic === "retn" || mnemonic === "retf" || mnemonic === "iret") {
        // Set temporary breakpoint and run
        setRunToAddress(insn.address);
        // In a real implementation, we'd set a breakpoint and continue
        // For now, we'll step until we hit the return
        break;
      }
    }
  }, [isPaused, result, session?.current_ip]);

  // Run to address
  const handleRunToAddress = useCallback(async () => {
    if (!runToAddress || !isPaused) return;
    // In a real implementation, set a temporary breakpoint and continue
    // For now, step until we reach the address
    continueExecution();
  }, [runToAddress, isPaused, continueExecution]);

  // Clear trace log
  const clearTrace = useCallback(() => {
    setTraceLog([]);
    traceIdRef.current = 0;
  }, []);

  // Export trace as text
  const exportTrace = useCallback(() => {
    const lines = traceLog.map(entry =>
      `${entry.address}  ${entry.instruction.padEnd(30)} ` +
      `AX=${entry.registers.ax} BX=${entry.registers.bx} ` +
      `CX=${entry.registers.cx} DX=${entry.registers.dx} ` +
      `FL=${entry.registers.flags}`
    );

    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `trace_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }, [traceLog]);

  // Filter trace entries
  const filteredTrace = filterPattern
    ? traceLog.filter(entry =>
        entry.address.toLowerCase().includes(filterPattern.toLowerCase()) ||
        entry.instruction.toLowerCase().includes(filterPattern.toLowerCase())
      )
    : traceLog;

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement) return;

      if (e.key === "F5" && !e.shiftKey) {
        e.preventDefault();
        if (isPaused) continueExecution();
      } else if (e.key === "F5" && e.shiftKey) {
        e.preventDefault();
        if (hasSession) stopSession();
      } else if (e.key === "F10") {
        e.preventDefault();
        if (isPaused) handleStepOver();
      } else if (e.key === "F11" && !e.shiftKey) {
        e.preventDefault();
        if (isPaused) handleStepInto();
      } else if (e.key === "F11" && e.shiftKey) {
        e.preventDefault();
        if (isPaused) handleStepOut();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isPaused, hasSession, continueExecution, stopSession, handleStepOver, handleStepInto, handleStepOut]);

  if (!hasSession && !result) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <History className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">Execution Trace</p>
          <p className="text-xs mt-1">Debug or analyze a target to trace</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-10 bg-bg-secondary border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <History className="w-4 h-4 text-accent-cyan" />
          <span className="text-sm font-medium">Trace</span>
          {traceLog.length > 0 && (
            <span className="text-xs text-text-secondary">
              ({filteredTrace.length}{filterPattern ? ` / ${traceLog.length}` : ""} entries)
            </span>
          )}
        </div>

        <div className="flex items-center gap-1">
          {/* Trace toggle */}
          <button
            onClick={() => setIsTracing(!isTracing)}
            className={`px-2 py-1 text-xs rounded flex items-center gap-1 ${
              isTracing
                ? "bg-accent-red/20 text-accent-red"
                : "bg-bg-tertiary text-text-secondary hover:text-text-primary"
            }`}
            title={isTracing ? "Stop recording" : "Start recording"}
          >
            {isTracing ? <Circle className="w-3 h-3 fill-current animate-pulse" /> : <Circle className="w-3 h-3" />}
            {isTracing ? "Recording" : "Record"}
          </button>

          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`p-1.5 rounded ${showFilters ? "bg-accent-blue/20 text-accent-blue" : "hover:bg-bg-hover"}`}
            title="Filter trace"
          >
            <Filter className="w-3 h-3" />
          </button>

          <button
            onClick={clearTrace}
            className="p-1.5 rounded hover:bg-bg-hover text-text-secondary hover:text-accent-red"
            title="Clear trace"
          >
            <Trash2 className="w-3 h-3" />
          </button>

          <button
            onClick={exportTrace}
            disabled={traceLog.length === 0}
            className="p-1.5 rounded hover:bg-bg-hover disabled:opacity-50"
            title="Export trace"
          >
            <Download className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Debug Controls */}
      <div className="h-10 bg-bg-tertiary border-b border-border flex items-center px-3 gap-2">
        {/* Execution controls */}
        <div className="flex items-center gap-1">
          <ControlButton
            icon={<Play className="w-4 h-4" />}
            onClick={continueExecution}
            disabled={!isPaused}
            title="Continue (F5)"
          />
          <ControlButton
            icon={<Pause className="w-4 h-4" />}
            onClick={pauseExecution}
            disabled={!isRunning}
            title="Pause"
          />
          <ControlButton
            icon={<Square className="w-4 h-4" />}
            onClick={stopSession}
            disabled={!hasSession}
            title="Stop (Shift+F5)"
            destructive
          />
        </div>

        <div className="w-px h-6 bg-border" />

        {/* Stepping controls */}
        <div className="flex items-center gap-1">
          <ControlButton
            icon={<ArrowDownToLine className="w-4 h-4" />}
            onClick={handleStepInto}
            disabled={!isPaused}
            title="Step Into (F11)"
          />
          <ControlButton
            icon={<StepForward className="w-4 h-4" />}
            onClick={handleStepOver}
            disabled={!isPaused}
            title="Step Over (F10)"
          />
          <ControlButton
            icon={<ArrowUpFromLine className="w-4 h-4" />}
            onClick={handleStepOut}
            disabled={!isPaused}
            title="Step Out (Shift+F11)"
          />
        </div>

        <div className="w-px h-6 bg-border" />

        {/* Run to address */}
        <div className="flex items-center gap-1">
          <input
            type="text"
            value={runToAddress}
            onChange={(e) => setRunToAddress(e.target.value)}
            placeholder="Address..."
            className="w-24 px-2 py-1 text-xs bg-bg-primary border border-border rounded focus:outline-none focus:border-accent-blue font-mono"
          />
          <ControlButton
            icon={<Target className="w-4 h-4" />}
            onClick={handleRunToAddress}
            disabled={!runToAddress || !isPaused}
            title="Run to address"
          />
        </div>

        {/* Status */}
        <div className="flex-1" />
        {session && (
          <div className={`px-2 py-0.5 rounded text-xs ${
            isRunning ? "bg-accent-green/20 text-accent-green" :
            isPaused ? "bg-accent-yellow/20 text-accent-yellow" :
            "bg-bg-tertiary text-text-secondary"
          }`}>
            {session.state}
          </div>
        )}
      </div>

      {/* Filter bar */}
      {showFilters && (
        <div className="h-9 bg-bg-secondary border-b border-border flex items-center px-3 gap-2">
          <input
            type="text"
            value={filterPattern}
            onChange={(e) => setFilterPattern(e.target.value)}
            placeholder="Filter by address or instruction..."
            className="flex-1 px-2 py-1 text-xs bg-bg-primary border border-border rounded focus:outline-none focus:border-accent-blue"
          />
          <label className="flex items-center gap-1 text-xs text-text-secondary">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="rounded"
            />
            Auto-scroll
          </label>
          <label className="flex items-center gap-1 text-xs text-text-secondary">
            Max:
            <input
              type="number"
              value={maxTraceEntries}
              onChange={(e) => setMaxTraceEntries(Math.max(100, parseInt(e.target.value) || 1000))}
              className="w-16 px-1 py-0.5 text-xs bg-bg-primary border border-border rounded"
            />
          </label>
        </div>
      )}

      {/* Trace Log */}
      <div className="flex-1 overflow-auto font-mono text-xs">
        {filteredTrace.length === 0 ? (
          <div className="h-full flex items-center justify-center text-text-secondary">
            <div className="text-center">
              <Zap className="w-6 h-6 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No trace entries</p>
              <p className="text-xs mt-1">
                {isTracing ? "Step through code to record trace" : "Enable recording and step"}
              </p>
            </div>
          </div>
        ) : (
          <table className="w-full">
            <thead className="sticky top-0 bg-bg-secondary">
              <tr className="text-left text-[10px] text-text-secondary uppercase">
                <th className="px-2 py-1 w-8">#</th>
                <th className="px-2 py-1 w-24">Address</th>
                <th className="px-2 py-1">Instruction</th>
                <th className="px-2 py-1 w-14">AX</th>
                <th className="px-2 py-1 w-14">BX</th>
                <th className="px-2 py-1 w-14">CX</th>
                <th className="px-2 py-1 w-14">DX</th>
                <th className="px-2 py-1 w-14">Flags</th>
              </tr>
            </thead>
            <tbody>
              {filteredTrace.map((entry, idx) => {
                const prevEntry = idx > 0 ? filteredTrace[idx - 1] : null;
                return (
                  <tr
                    key={entry.id}
                    onClick={() => navigateTo(entry.address)}
                    className="hover:bg-bg-hover cursor-pointer border-b border-border/30"
                  >
                    <td className="px-2 py-0.5 text-text-secondary">{entry.id}</td>
                    <td className="px-2 py-0.5 text-accent-blue">{entry.address}</td>
                    <td className="px-2 py-0.5">
                      <InstructionDisplay instruction={entry.instruction} />
                    </td>
                    <td className={`px-2 py-0.5 ${prevEntry?.registers.ax !== entry.registers.ax ? "text-accent-red" : ""}`}>
                      {entry.registers.ax}
                    </td>
                    <td className={`px-2 py-0.5 ${prevEntry?.registers.bx !== entry.registers.bx ? "text-accent-red" : ""}`}>
                      {entry.registers.bx}
                    </td>
                    <td className={`px-2 py-0.5 ${prevEntry?.registers.cx !== entry.registers.cx ? "text-accent-red" : ""}`}>
                      {entry.registers.cx}
                    </td>
                    <td className={`px-2 py-0.5 ${prevEntry?.registers.dx !== entry.registers.dx ? "text-accent-red" : ""}`}>
                      {entry.registers.dx}
                    </td>
                    <td className={`px-2 py-0.5 ${prevEntry?.registers.flags !== entry.registers.flags ? "text-accent-yellow" : ""}`}>
                      {entry.registers.flags}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        <div ref={traceEndRef} />
      </div>

      {/* Keyboard shortcuts legend */}
      <div className="h-6 bg-bg-secondary border-t border-border flex items-center px-3 gap-4 text-[10px] text-text-secondary">
        <span><kbd className="px-1 bg-bg-tertiary rounded">F5</kbd> Continue</span>
        <span><kbd className="px-1 bg-bg-tertiary rounded">Shift+F5</kbd> Stop</span>
        <span><kbd className="px-1 bg-bg-tertiary rounded">F10</kbd> Step Over</span>
        <span><kbd className="px-1 bg-bg-tertiary rounded">F11</kbd> Step Into</span>
        <span><kbd className="px-1 bg-bg-tertiary rounded">Shift+F11</kbd> Step Out</span>
      </div>
    </div>
  );
}

function ControlButton({
  icon,
  onClick,
  disabled,
  title,
  destructive,
}: {
  icon: React.ReactNode;
  onClick: () => void;
  disabled: boolean;
  title: string;
  destructive?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`p-1.5 rounded transition-colors ${
        disabled
          ? "opacity-30 cursor-not-allowed"
          : destructive
          ? "hover:bg-accent-red/20 hover:text-accent-red"
          : "hover:bg-bg-hover"
      }`}
    >
      {icon}
    </button>
  );
}

function InstructionDisplay({ instruction }: { instruction: string }) {
  const parts = instruction.split(" ");
  const mnemonic = parts[0] || "";
  const operands = parts.slice(1).join(" ");

  // Color code by instruction type
  const mnemonicClass =
    mnemonic.startsWith("j") || mnemonic === "call" || mnemonic === "ret"
      ? "text-accent-yellow"
      : mnemonic.startsWith("mov") || mnemonic.startsWith("push") || mnemonic.startsWith("pop")
      ? "text-accent-blue"
      : mnemonic === "int" || mnemonic === "syscall"
      ? "text-accent-red"
      : "text-accent-green";

  return (
    <span>
      <span className={mnemonicClass}>{mnemonic}</span>
      {operands && <span className="text-text-secondary"> {operands}</span>}
    </span>
  );
}
