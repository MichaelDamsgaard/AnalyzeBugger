import { useState, useEffect, useCallback, ReactNode } from "react";
import { FloatingPane } from "./FloatingPane";
import { Plus, Layout, Trash2 } from "lucide-react";

export interface PaneConfig {
  id: string;
  title: string;
  content: ReactNode;
  position: { x: number; y: number };
  size: { width: number; height: number };
  glowColor: string;
  isMinimized: boolean;
}

interface PaneManagerProps {
  children?: ReactNode;
}

const MCP_API_URL = "http://localhost:19550";

export function PaneManager({ children }: PaneManagerProps) {
  const [panes, setPanes] = useState<PaneConfig[]>([]);
  const [showPaneList, setShowPaneList] = useState(false);

  // Fetch pane data from MCP API
  const fetchPaneData = useCallback(async (paneId: string) => {
    try {
      const response = await fetch(`${MCP_API_URL}/pane/${paneId}`);
      const result = await response.json();
      if (result.success) {
        return result.data;
      }
    } catch (e) {
      console.warn("Failed to fetch pane data:", e);
    }
    return null;
  }, []);

  // Poll for pane updates
  useEffect(() => {
    const interval = setInterval(async () => {
      for (const pane of panes) {
        const data = await fetchPaneData(pane.id);
        if (data) {
          // Update pane content if data changed
          setPanes((prev) =>
            prev.map((p) =>
              p.id === pane.id
                ? { ...p, content: <DataPane data={data.data} /> }
                : p
            )
          );
        }
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [panes, fetchPaneData]);

  const addPane = useCallback((config: Partial<PaneConfig>) => {
    const id = config.id || `pane-${Date.now()}`;
    const newPane: PaneConfig = {
      id,
      title: config.title || "Analysis",
      content: config.content || <div className="p-4 text-white/50">Loading...</div>,
      position: config.position || {
        x: 100 + panes.length * 30,
        y: 100 + panes.length * 30,
      },
      size: config.size || { width: 400, height: 300 },
      glowColor: config.glowColor || "cyan",
      isMinimized: false,
    };
    setPanes((prev) => [...prev, newPane]);
  }, [panes.length]);

  const removePane = useCallback((id: string) => {
    setPanes((prev) => prev.filter((p) => p.id !== id));
  }, []);

  const clearAllPanes = useCallback(() => {
    setPanes([]);
  }, []);

  // Preset pane configurations
  const presetPanes = [
    {
      id: "crypto-analysis",
      title: "Crypto Analysis",
      glowColor: "purple",
      content: <CryptoAnalysisPane />,
    },
    {
      id: "execution-trace",
      title: "Execution Trace",
      glowColor: "green",
      content: <ExecutionTracePane />,
    },
    {
      id: "memory-map",
      title: "Memory Map",
      glowColor: "cyan",
      content: <MemoryMapPane />,
    },
    {
      id: "data-flow",
      title: "Data Flow",
      glowColor: "yellow",
      content: <DataFlowPane />,
    },
  ];

  return (
    <div className="relative">
      {/* Main content */}
      {children}

      {/* Floating panes */}
      {panes.map((pane) => (
        <FloatingPane
          key={pane.id}
          id={pane.id}
          title={pane.title}
          initialPosition={pane.position}
          initialSize={pane.size}
          glowColor={pane.glowColor}
          isMinimized={pane.isMinimized}
          onClose={() => removePane(pane.id)}
        >
          {pane.content}
        </FloatingPane>
      ))}

      {/* Pane control button */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
        {showPaneList && (
          <div className="bg-black/90 backdrop-blur-md rounded-lg border border-cyan-500/30 shadow-[0_0_20px_rgba(0,255,255,0.2)] p-3 mb-2">
            <div className="text-xs text-cyan-400 font-bold mb-2 uppercase tracking-wider">
              Add Analysis Pane
            </div>
            <div className="space-y-1">
              {presetPanes.map((preset) => (
                <button
                  key={preset.id}
                  onClick={() => {
                    addPane(preset);
                    setShowPaneList(false);
                  }}
                  className="w-full text-left px-3 py-1.5 text-xs text-white/70 hover:bg-white/10 rounded transition-colors"
                >
                  {preset.title}
                </button>
              ))}
            </div>
            <div className="border-t border-white/10 mt-2 pt-2">
              <button
                onClick={() => {
                  clearAllPanes();
                  setShowPaneList(false);
                }}
                className="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-red-400 hover:bg-red-500/10 rounded transition-colors"
              >
                <Trash2 className="w-3 h-3" />
                Clear All Panes
              </button>
            </div>
          </div>
        )}

        <button
          onClick={() => setShowPaneList(!showPaneList)}
          className="w-12 h-12 bg-black/80 backdrop-blur-md rounded-full border border-cyan-500/50 shadow-[0_0_20px_rgba(0,255,255,0.3)] flex items-center justify-center hover:border-cyan-400 transition-all group"
          title="Add floating pane"
        >
          {showPaneList ? (
            <Layout className="w-5 h-5 text-cyan-400" />
          ) : (
            <Plus className="w-5 h-5 text-cyan-400 group-hover:rotate-90 transition-transform" />
          )}
        </button>
      </div>
    </div>
  );
}

// Data pane for displaying arbitrary JSON data
function DataPane({ data }: { data: unknown }) {
  return (
    <div className="p-3 font-mono text-xs overflow-auto h-full">
      <pre className="text-green-400 whitespace-pre-wrap">
        {JSON.stringify(data, null, 2)}
      </pre>
    </div>
  );
}

// Crypto analysis pane
function CryptoAnalysisPane() {
  const [analysis, setAnalysis] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  return (
    <div className="p-3 h-full overflow-auto">
      <div className="space-y-3">
        {!analysis ? (
          <div className="text-center text-white/50 text-xs py-8">
            <div className="mb-2">No crypto analysis loaded</div>
            <button
              onClick={() => setLoading(true)}
              className="px-3 py-1 bg-purple-500/20 border border-purple-500/30 rounded text-purple-400 hover:bg-purple-500/30 transition-colors"
            >
              Analyze Binary
            </button>
          </div>
        ) : (
          <div className="space-y-2">
            <div className="text-purple-400 font-bold text-sm">
              {analysis.cipher_type}
            </div>
            <div className="text-white/70 text-xs">
              {analysis.cipher_description}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// Execution trace pane
function ExecutionTracePane() {
  return (
    <div className="p-3 h-full overflow-auto font-mono text-xs">
      <div className="space-y-1">
        {Array.from({ length: 20 }).map((_, i) => (
          <div
            key={i}
            className="flex gap-4 text-green-400 opacity-70 hover:opacity-100 transition-opacity"
          >
            <span className="text-green-600">0x{(0x10100 + i * 3).toString(16)}</span>
            <span>mov eax, [ebx+{i * 4}]</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// Memory map pane with visual representation
function MemoryMapPane() {
  return (
    <div className="p-3 h-full overflow-auto">
      <div className="grid grid-cols-16 gap-px">
        {Array.from({ length: 256 }).map((_, i) => {
          const val = Math.floor(Math.random() * 256);
          const intensity = val / 255;
          return (
            <div
              key={i}
              className="w-3 h-3 rounded-sm transition-colors cursor-pointer hover:ring-1 hover:ring-cyan-400"
              style={{
                backgroundColor: `rgba(0, ${Math.floor(val * 0.8)}, ${val}, ${0.3 + intensity * 0.7})`,
              }}
              title={`0x${i.toString(16).padStart(2, "0")}: ${val.toString(16).padStart(2, "0")}`}
            />
          );
        })}
      </div>
      <div className="mt-3 flex justify-between text-[10px] text-white/40">
        <span>0x0000</span>
        <span>0x0100</span>
      </div>
    </div>
  );
}

// Data flow visualization
function DataFlowPane() {
  const [lines, setLines] = useState<string[]>([]);

  useEffect(() => {
    const chars = "0123456789ABCDEF";
    const interval = setInterval(() => {
      const newLine = Array.from({ length: 32 })
        .map(() => chars[Math.floor(Math.random() * chars.length)])
        .join(" ");
      setLines((prev) => [...prev.slice(-15), newLine]);
    }, 100);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="p-3 h-full overflow-hidden font-mono text-[10px]">
      <div className="space-y-1">
        {lines.map((line, i) => (
          <div
            key={i}
            className="text-yellow-400"
            style={{ opacity: 0.3 + (i / lines.length) * 0.7 }}
          >
            {line}
          </div>
        ))}
      </div>
    </div>
  );
}
