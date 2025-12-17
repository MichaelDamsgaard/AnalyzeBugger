import { useState, useMemo } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import {
  Code2, Search, ChevronRight, ArrowRight,
  Bookmark, AlertTriangle
} from "lucide-react";

interface DetectedFunction {
  address: string;
  name: string;
  size: number;
  calls: string[];
  calledBy: string[];
  hasInterrupt: boolean;
  isEntryPoint: boolean;
}

export function FunctionsPanel() {
  const { result } = useAnalysisStore();
  const [filter, setFilter] = useState("");
  const [selectedFn, setSelectedFn] = useState<string | null>(null);

  // Auto-detect functions from disassembly
  const functions = useMemo<DetectedFunction[]>(() => {
    if (!result?.instructions) return [];

    const fns: DetectedFunction[] = [];
    const callTargets = new Map<string, string[]>(); // address -> callers
    const fnCalls = new Map<string, string[]>(); // fn address -> call targets

    // First pass: find CALL targets and potential function starts
    let currentFnStart: string | null = null;

    result.instructions.forEach((insn, idx) => {
      const mnemonic = insn.mnemonic.toLowerCase();

      // Function boundary heuristics
      // 1. Entry point (first instruction)
      if (idx === 0) {
        currentFnStart = insn.address;
        fns.push({
          address: insn.address,
          name: `entry_${insn.address}`,
          size: 0,
          calls: [],
          calledBy: [],
          hasInterrupt: false,
          isEntryPoint: true,
        });
      }

      // 2. After a RET, next instruction might be a new function
      if (idx > 0) {
        const prevMnemonic = result.instructions[idx - 1].mnemonic.toLowerCase();
        if ((prevMnemonic === "ret" || prevMnemonic === "retn" || prevMnemonic === "retf") &&
            mnemonic !== "nop" && !mnemonic.startsWith("j")) {
          // Potential new function
          if (!fns.find(f => f.address === insn.address)) {
            fns.push({
              address: insn.address,
              name: `sub_${insn.address.replace("0x", "")}`,
              size: 0,
              calls: [],
              calledBy: [],
              hasInterrupt: false,
              isEntryPoint: false,
            });
          }
        }
      }

      // Track CALL instructions
      if (mnemonic === "call") {
        const target = insn.op_str;
        if (target && target.startsWith("0x")) {
          // Record this call
          if (currentFnStart) {
            if (!fnCalls.has(currentFnStart)) {
              fnCalls.set(currentFnStart, []);
            }
            fnCalls.get(currentFnStart)!.push(target);
          }

          // Record who calls this target
          if (!callTargets.has(target)) {
            callTargets.set(target, []);
          }
          callTargets.get(target)!.push(insn.address);

          // Add target as a function if not already known
          if (!fns.find(f => f.address === target)) {
            fns.push({
              address: target,
              name: `sub_${target.replace("0x", "")}`,
              size: 0,
              calls: [],
              calledBy: [],
              hasInterrupt: false,
              isEntryPoint: false,
            });
          }
        }
      }

      // Track INT instructions (important for DOS)
      if (mnemonic === "int") {
        const fn = fns.find(f => f.address === currentFnStart);
        if (fn) fn.hasInterrupt = true;
      }
    });

    // Second pass: populate cross-references
    fns.forEach(fn => {
      fn.calls = fnCalls.get(fn.address) || [];
      fn.calledBy = callTargets.get(fn.address) || [];
    });

    // Sort by address
    return fns.sort((a, b) => {
      const addrA = parseInt(a.address, 16);
      const addrB = parseInt(b.address, 16);
      return addrA - addrB;
    });
  }, [result?.instructions]);

  const filteredFns = filter
    ? functions.filter(fn =>
        fn.name.toLowerCase().includes(filter.toLowerCase()) ||
        fn.address.toLowerCase().includes(filter.toLowerCase())
      )
    : functions;

  if (!result) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <Code2 className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No functions detected</p>
          <p className="text-xs mt-1">Analyze a file to detect functions</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-8 bg-bg-secondary border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <Code2 className="w-4 h-4 text-accent-purple" />
          <span className="text-sm font-medium">Functions</span>
          <span className="text-xs text-text-secondary">({functions.length})</span>
        </div>
      </div>

      {/* Search */}
      <div className="h-8 bg-bg-tertiary border-b border-border flex items-center px-2 gap-2">
        <Search className="w-3 h-3 text-text-secondary" />
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter functions..."
          className="flex-1 bg-transparent text-xs focus:outline-none"
        />
      </div>

      {/* Function list */}
      <div className="flex-1 overflow-auto font-mono text-xs">
        {filteredFns.map((fn) => (
          <div key={fn.address}>
            <button
              onClick={() => setSelectedFn(selectedFn === fn.address ? null : fn.address)}
              className={`w-full px-2 py-1 flex items-center gap-2 hover:bg-bg-hover transition-colors text-left ${
                selectedFn === fn.address ? "bg-accent-purple/10" : ""
              }`}
            >
              <ChevronRight
                className={`w-3 h-3 text-text-secondary transition-transform ${
                  selectedFn === fn.address ? "rotate-90" : ""
                }`}
              />

              {fn.isEntryPoint && (
                <span title="Entry Point">
                  <Bookmark className="w-3 h-3 text-accent-yellow" />
                </span>
              )}
              {fn.hasInterrupt && (
                <span title="Contains INT">
                  <AlertTriangle className="w-3 h-3 text-accent-orange" />
                </span>
              )}

              <span className="text-accent-blue">{fn.address}</span>
              <span className="text-text-primary flex-1">{fn.name}</span>

              {fn.calledBy.length > 0 && (
                <span className="text-accent-green text-[10px]">
                  ↑{fn.calledBy.length}
                </span>
              )}
              {fn.calls.length > 0 && (
                <span className="text-accent-purple text-[10px]">
                  ↓{fn.calls.length}
                </span>
              )}
            </button>

            {/* Expanded details */}
            {selectedFn === fn.address && (
              <div className="px-4 py-2 bg-bg-tertiary border-y border-border space-y-2">
                {fn.calls.length > 0 && (
                  <div>
                    <div className="text-[10px] text-text-secondary uppercase mb-1">
                      Calls ({fn.calls.length})
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {fn.calls.map((call, idx) => (
                        <span
                          key={idx}
                          className="px-1.5 py-0.5 bg-accent-purple/20 text-accent-purple rounded"
                        >
                          <ArrowRight className="w-2 h-2 inline mr-1" />
                          {call}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {fn.calledBy.length > 0 && (
                  <div>
                    <div className="text-[10px] text-text-secondary uppercase mb-1">
                      Called By ({fn.calledBy.length})
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {fn.calledBy.map((caller, idx) => (
                        <span
                          key={idx}
                          className="px-1.5 py-0.5 bg-accent-green/20 text-accent-green rounded"
                        >
                          {caller}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {fn.calls.length === 0 && fn.calledBy.length === 0 && (
                  <div className="text-text-secondary text-[10px]">
                    No cross-references found
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
