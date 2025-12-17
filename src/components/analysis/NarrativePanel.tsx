import { useState, useEffect, useRef } from "react";
import {
  Play, Pause, RotateCcw, AlertTriangle, CheckCircle2,
  Circle, ChevronRight, Loader2, Zap, Shield, Bug
} from "lucide-react";

// Narrative entry types
type NarrativeType = "info" | "success" | "warning" | "error" | "analyzing" | "finding";

interface NarrativeEntry {
  id: number;
  type: NarrativeType;
  message: string;
  timestamp: Date;
  details?: string;
  mitreTechnique?: string;
  confidence?: number;
}

interface AnalysisState {
  isRunning: boolean;
  phase: string;
  progress: number;
}

export function NarrativePanel() {
  const [entries, setEntries] = useState<NarrativeEntry[]>([]);
  const [analysis, setAnalysis] = useState<AnalysisState>({
    isRunning: false,
    phase: "idle",
    progress: 0,
  });
  const [autoScroll] = useState(true);
  const entriesEndRef = useRef<HTMLDivElement>(null);
  const nextId = useRef(0);

  // Auto-scroll to bottom
  useEffect(() => {
    if (autoScroll) {
      entriesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [entries, autoScroll]);

  // Add a narrative entry
  const addEntry = (type: NarrativeType, message: string, extra?: Partial<NarrativeEntry>) => {
    setEntries(prev => [...prev, {
      id: nextId.current++,
      type,
      message,
      timestamp: new Date(),
      ...extra,
    }]);
  };

  // Simulate AI analysis (in production, this streams from bip-server)
  const startAnalysis = async () => {
    if (analysis.isRunning) return;

    setEntries([]);
    setAnalysis({ isRunning: true, phase: "initializing", progress: 0 });

    // Phase 1: File analysis
    addEntry("info", "Starting analysis of target binary...");
    await delay(300);

    addEntry("analyzing", "Parsing PE headers...");
    await delay(500);
    setAnalysis(s => ({ ...s, phase: "pe_analysis", progress: 10 }));

    addEntry("success", "PE32+ executable detected, 64-bit");
    await delay(200);

    addEntry("info", "Sections: .text, .data, .rdata, .rsrc, .reloc");
    await delay(300);

    // Phase 2: Entropy analysis
    addEntry("analyzing", "Calculating section entropy...");
    await delay(600);
    setAnalysis(s => ({ ...s, phase: "entropy", progress: 25 }));

    addEntry("warning", "High entropy detected in .text section: 7.21", {
      details: "Entropy > 7.0 typically indicates packing or encryption",
    });
    await delay(300);

    addEntry("finding", "Possible UPX packing detected", {
      mitreTechnique: "T1027.002",
      confidence: 0.85,
      details: "Software Packing - Defense Evasion",
    });
    await delay(500);

    // Phase 3: Import analysis
    setAnalysis(s => ({ ...s, phase: "imports", progress: 40 }));
    addEntry("analyzing", "Analyzing import table...");
    await delay(400);

    addEntry("info", "47 imported functions from 8 DLLs");
    await delay(200);

    addEntry("warning", "Suspicious imports detected:", {
      details: "VirtualAllocEx, WriteProcessMemory, CreateRemoteThread",
    });
    await delay(300);

    addEntry("finding", "Process Injection capability identified", {
      mitreTechnique: "T1055.001",
      confidence: 0.92,
      details: "DLL Injection via CreateRemoteThread",
    });
    await delay(500);

    // Phase 4: String analysis
    setAnalysis(s => ({ ...s, phase: "strings", progress: 55 }));
    addEntry("analyzing", "Extracting and decoding strings...");
    await delay(700);

    addEntry("success", "Found 234 readable strings");
    await delay(200);

    addEntry("warning", "Encrypted strings detected - attempting decode...");
    await delay(600);

    addEntry("success", "Decoded 47 XOR-encrypted strings (key: 0x5A)");
    await delay(300);

    addEntry("finding", "Potential C2 URLs found", {
      mitreTechnique: "T1071.001",
      confidence: 0.88,
      details: "hxxp://evil[.]com/gate.php, hxxp://backup[.]evil/c2",
    });
    await delay(500);

    // Phase 5: Behavioral patterns
    setAnalysis(s => ({ ...s, phase: "behavior", progress: 75 }));
    addEntry("analyzing", "Correlating behavioral patterns...");
    await delay(800);

    addEntry("finding", "Anti-debug technique detected", {
      mitreTechnique: "T1622",
      confidence: 0.95,
      details: "IsDebuggerPresent check at 0x401089",
    });
    await delay(400);

    addEntry("finding", "Registry persistence mechanism", {
      mitreTechnique: "T1547.001",
      confidence: 0.78,
      details: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    });
    await delay(500);

    // Phase 6: Verdict
    setAnalysis(s => ({ ...s, phase: "verdict", progress: 95 }));
    addEntry("analyzing", "Generating verdict...");
    await delay(600);

    addEntry("error", "VERDICT: Malicious - High Confidence (94%)", {
      details: "Classification: Trojan Dropper / Emotet variant",
    });
    await delay(300);

    addEntry("success", "Analysis complete - 6 MITRE techniques identified");
    setAnalysis({ isRunning: false, phase: "complete", progress: 100 });
  };

  const pauseAnalysis = () => {
    setAnalysis(s => ({ ...s, isRunning: false }));
    addEntry("info", "Analysis paused by user");
  };

  const resetAnalysis = () => {
    setEntries([]);
    setAnalysis({ isRunning: false, phase: "idle", progress: 0 });
  };

  return (
    <div className="h-full flex flex-col bg-bg-primary">
      {/* Header */}
      <div className="h-10 bg-bg-secondary border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-accent-purple" />
          <span className="text-sm font-medium">AI Analysis</span>
          {analysis.isRunning && (
            <span className="text-xs text-accent-purple animate-pulse">
              {analysis.phase}
            </span>
          )}
        </div>

        <div className="flex items-center gap-1">
          {!analysis.isRunning ? (
            <button
              onClick={startAnalysis}
              className="p-1.5 hover:bg-bg-hover rounded transition-colors"
              title="Start Analysis"
            >
              <Play className="w-4 h-4 text-accent-green" />
            </button>
          ) : (
            <button
              onClick={pauseAnalysis}
              className="p-1.5 hover:bg-bg-hover rounded transition-colors"
              title="Pause Analysis"
            >
              <Pause className="w-4 h-4 text-accent-yellow" />
            </button>
          )}
          <button
            onClick={resetAnalysis}
            className="p-1.5 hover:bg-bg-hover rounded transition-colors"
            title="Reset"
          >
            <RotateCcw className="w-4 h-4 text-text-secondary" />
          </button>
        </div>
      </div>

      {/* Progress bar */}
      {analysis.progress > 0 && (
        <div className="h-1 bg-bg-tertiary">
          <div
            className="h-full bg-accent-purple transition-all duration-300"
            style={{ width: `${analysis.progress}%` }}
          />
        </div>
      )}

      {/* Narrative entries */}
      <div className="flex-1 overflow-auto p-3 space-y-2">
        {entries.length === 0 && !analysis.isRunning && (
          <div className="h-full flex flex-col items-center justify-center text-text-secondary">
            <Shield className="w-10 h-10 mb-3 text-accent-purple/50" />
            <p className="text-sm">AI Analysis Ready</p>
            <p className="text-xs mt-1">Click play to start automatic analysis</p>
          </div>
        )}

        {entries.map((entry) => (
          <NarrativeEntryRow key={entry.id} entry={entry} />
        ))}

        {analysis.isRunning && analysis.phase !== "complete" && (
          <div className="flex items-center gap-2 text-text-secondary text-sm">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span>Analyzing...</span>
          </div>
        )}

        <div ref={entriesEndRef} />
      </div>

      {/* Footer stats */}
      {entries.length > 0 && (
        <div className="h-8 bg-bg-secondary border-t border-border flex items-center justify-between px-3 text-xs text-text-secondary">
          <span>
            {entries.filter(e => e.type === "finding").length} findings
          </span>
          <span>
            {entries.filter(e => e.mitreTechnique).length} MITRE techniques
          </span>
        </div>
      )}
    </div>
  );
}

function NarrativeEntryRow({ entry }: { entry: NarrativeEntry }) {
  const [expanded, setExpanded] = useState(false);

  const icon = {
    info: <Circle className="w-3 h-3 text-accent-blue" />,
    success: <CheckCircle2 className="w-3 h-3 text-accent-green" />,
    warning: <AlertTriangle className="w-3 h-3 text-accent-yellow" />,
    error: <AlertTriangle className="w-3 h-3 text-accent-red" />,
    analyzing: <Loader2 className="w-3 h-3 text-accent-purple animate-spin" />,
    finding: <Bug className="w-3 h-3 text-accent-orange" />,
  }[entry.type];

  const bgClass = {
    info: "",
    success: "",
    warning: "bg-accent-yellow/5",
    error: "bg-accent-red/10",
    analyzing: "",
    finding: "bg-accent-orange/10 border-l-2 border-accent-orange",
  }[entry.type];

  return (
    <div
      className={`rounded px-2 py-1.5 ${bgClass} ${entry.details ? "cursor-pointer" : ""}`}
      onClick={() => entry.details && setExpanded(!expanded)}
    >
      <div className="flex items-start gap-2">
        <div className="mt-0.5">{icon}</div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm text-text-primary">{entry.message}</span>
            {entry.mitreTechnique && (
              <span className="px-1.5 py-0.5 text-[10px] bg-accent-red/20 text-accent-red rounded font-medium">
                {entry.mitreTechnique}
              </span>
            )}
            {entry.confidence && (
              <span className="text-[10px] text-text-secondary">
                {Math.round(entry.confidence * 100)}%
              </span>
            )}
          </div>

          {expanded && entry.details && (
            <div className="mt-1 text-xs text-text-secondary pl-0 border-l-2 border-border ml-0 pl-2">
              {entry.details}
            </div>
          )}
        </div>

        {entry.details && (
          <ChevronRight
            className={`w-4 h-4 text-text-secondary transition-transform ${expanded ? "rotate-90" : ""}`}
          />
        )}
      </div>

      <div className="text-[10px] text-text-secondary mt-1 pl-5">
        {entry.timestamp.toLocaleTimeString()}
      </div>
    </div>
  );
}

// Helper
function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
