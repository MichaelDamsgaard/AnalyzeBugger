import { useState, useEffect } from "react";
import { useSessionStore } from "../../stores/sessionStore";
import { useAnalysisStore } from "../../stores/analysisStore";
import { Layers, ArrowUp, ArrowDown } from "lucide-react";

interface StackEntry {
  address: string;
  value: string;
  annotation?: string;
  isReturnAddress?: boolean;
  isFramePointer?: boolean;
  isStackPointer?: boolean;
}

export function StackPanel() {
  const { registers, status } = useSessionStore();
  const { result: analysisResult } = useAnalysisStore();
  const [stackData, setStackData] = useState<StackEntry[]>([]);
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);

  const isStatic = !registers && !!analysisResult;
  const is16Bit = analysisResult?.file_info.arch.includes("16");

  // Generate demo stack for static analysis
  useEffect(() => {
    if (isStatic && is16Bit) {
      // COM file initial stack - PSP at top, return address
      const demoStack: StackEntry[] = [
        { address: "FFFC", value: "0000", annotation: "Return to DOS (INT 20h)", isReturnAddress: true },
        { address: "FFFE", value: "0000", annotation: "PSP Segment", isStackPointer: true },
      ];
      setStackData(demoStack);
    }
  }, [isStatic, is16Bit]);

  // Fetch real stack data when debugging
  useEffect(() => {
    if (registers && status?.session?.state === "paused") {
      const rsp = BigInt(registers.rsp);
      // In a real implementation, we'd fetch memory at RSP
      // For now, generate placeholder
      const entries: StackEntry[] = [];
      for (let i = 0; i < 16; i++) {
        const addr = rsp + BigInt(i * 8);
        entries.push({
          address: `0x${addr.toString(16)}`,
          value: "????????????????",
          isStackPointer: i === 0,
        });
      }
      setStackData(entries);
    }
  }, [registers, status?.session?.state]);

  if (stackData.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <Layers className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No stack data</p>
          <p className="text-xs mt-1">Debug a target to view stack</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-8 bg-bg-secondary border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-accent-green" />
          <span className="text-sm font-medium">Stack</span>
          {isStatic && (
            <span className="text-xs text-accent-yellow">(Initial)</span>
          )}
        </div>
        <div className="flex items-center gap-1 text-xs text-text-secondary">
          <ArrowUp className="w-3 h-3" />
          <span>Higher</span>
        </div>
      </div>

      {/* Stack contents */}
      <div className="flex-1 overflow-auto font-mono text-xs">
        <table className="w-full">
          <thead className="sticky top-0 bg-bg-tertiary">
            <tr className="text-text-secondary text-[10px]">
              <th className="px-2 py-1 text-left w-20">Address</th>
              <th className="px-2 py-1 text-left w-24">Value</th>
              <th className="px-2 py-1 text-left">Annotation</th>
            </tr>
          </thead>
          <tbody>
            {stackData.map((entry, idx) => (
              <tr
                key={idx}
                onClick={() => setSelectedIdx(idx)}
                className={`cursor-pointer transition-colors ${
                  selectedIdx === idx ? "bg-accent-blue/20" :
                  entry.isStackPointer ? "bg-accent-green/10" :
                  entry.isReturnAddress ? "bg-accent-purple/10" :
                  "hover:bg-bg-hover"
                }`}
              >
                <td className="px-2 py-0.5 text-accent-blue">
                  {entry.address}
                </td>
                <td className={`px-2 py-0.5 ${
                  entry.isReturnAddress ? "text-accent-purple" :
                  entry.isFramePointer ? "text-accent-orange" :
                  "text-text-primary"
                }`}>
                  {entry.value}
                </td>
                <td className="px-2 py-0.5 text-text-secondary">
                  {entry.isStackPointer && (
                    <span className="text-accent-green mr-2">← SP</span>
                  )}
                  {entry.isFramePointer && (
                    <span className="text-accent-orange mr-2">← BP</span>
                  )}
                  {entry.annotation}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <div className="h-6 bg-bg-secondary border-t border-border flex items-center justify-between px-3 text-[10px] text-text-secondary">
        <span>{stackData.length} entries</span>
        <div className="flex items-center gap-1">
          <ArrowDown className="w-3 h-3" />
          <span>Stack grows down</span>
        </div>
      </div>
    </div>
  );
}
