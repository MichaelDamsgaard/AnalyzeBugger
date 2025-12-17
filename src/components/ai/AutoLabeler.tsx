import { useState, useCallback, useMemo } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import {
  Tags, Sparkles, Check, CheckCheck, Tag,
  ChevronDown, ChevronRight, Play, Pause
} from "lucide-react";

interface FunctionLabel {
  address: string;
  originalName: string;
  suggestedName: string;
  confidence: number;
  category: string;
  reasoning: string;
  applied: boolean;
}

// Function categories used for labeling

export function AutoLabeler() {
  const { result, setLabel, labels } = useAnalysisStore();
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [progress, setProgress] = useState(0);
  const [functionLabels, setFunctionLabels] = useState<FunctionLabel[]>([]);
  const [expandedFn, setExpandedFn] = useState<Set<string>>(new Set());
  const [minConfidence, setMinConfidence] = useState(0.7);
  const [autoApply, setAutoApply] = useState(false);

  // Detect function boundaries
  const detectFunctions = useCallback((): string[] => {
    if (!result?.instructions) return [];

    const functions: string[] = [];
    const instructions = result.instructions;

    // First instruction is entry point
    if (instructions.length > 0) {
      functions.push(instructions[0].address);
    }

    // Find function boundaries (after RET, before non-NOP)
    for (let i = 1; i < instructions.length; i++) {
      const prev = instructions[i - 1];
      const curr = instructions[i];

      const prevMnemonic = prev.mnemonic.toLowerCase();
      const currMnemonic = curr.mnemonic.toLowerCase();

      // After RET instruction (and not followed by NOP)
      if (
        (prevMnemonic === "ret" || prevMnemonic === "retn" || prevMnemonic === "retf") &&
        currMnemonic !== "nop" &&
        currMnemonic !== "int" // Skip INT 3 padding
      ) {
        if (!functions.includes(curr.address)) {
          functions.push(curr.address);
        }
      }

      // After JMP instruction to far address (tail call optimization)
      if (prevMnemonic === "jmp" && !prev.op_str.toLowerCase().includes("short")) {
        if (!functions.includes(curr.address)) {
          functions.push(curr.address);
        }
      }
    }

    return functions;
  }, [result]);

  // Analyze a single function
  const analyzeFunction = useCallback(
    (startAddr: string, funcIndex: number, _totalFuncs: number): FunctionLabel => {
      if (!result?.instructions) {
        return {
          address: startAddr,
          originalName: `sub_${startAddr.replace("0x", "")}`,
          suggestedName: `sub_${startAddr.replace("0x", "")}`,
          confidence: 0,
          category: "Unknown",
          reasoning: "No instructions available",
          applied: false,
        };
      }

      const instructions = result.instructions;
      const startIdx = instructions.findIndex((i) => i.address === startAddr);
      if (startIdx === -1) {
        return {
          address: startAddr,
          originalName: `sub_${startAddr.replace("0x", "")}`,
          suggestedName: `sub_${startAddr.replace("0x", "")}`,
          confidence: 0,
          category: "Unknown",
          reasoning: "Address not found",
          applied: false,
        };
      }

      // Get function body (until RET or next function)
      let endIdx = startIdx;
      for (let i = startIdx; i < Math.min(startIdx + 100, instructions.length); i++) {
        endIdx = i;
        const m = instructions[i].mnemonic.toLowerCase();
        if (m === "ret" || m === "retn" || m === "retf") {
          break;
        }
      }

      const funcBody = instructions.slice(startIdx, endIdx + 1);
      const mnemonics = funcBody.map((i) => i.mnemonic.toLowerCase());
      const fullCode = funcBody.map((i) => `${i.mnemonic} ${i.op_str}`).join("\n").toLowerCase();

      let suggestedName = `sub_${startAddr.replace("0x", "")}`;
      let confidence = 0.3;
      let category = "Unknown";
      let reasoning = "Pattern not recognized";

      // Check if it's the entry point
      if (funcIndex === 0) {
        suggestedName = "entry_point";
        confidence = 1.0;
        category = "Entry";
        reasoning = "First function in binary - program entry point";
      }
      // DOS INT 21h patterns
      else if (fullCode.includes("int") && (fullCode.includes("21h") || fullCode.includes("0x21"))) {
        // Determine function based on AH value
        for (let i = 0; i < funcBody.length; i++) {
          if (funcBody[i].mnemonic.toLowerCase() === "mov" &&
              funcBody[i].op_str.toLowerCase().startsWith("ah,")) {
            const ahVal = funcBody[i].op_str.split(",")[1]?.trim().toLowerCase();

            if (ahVal === "9" || ahVal === "09h" || ahVal === "0x9") {
              suggestedName = "print_string";
              confidence = 0.95;
              category = "IO";
              reasoning = "Uses INT 21h/09h to print $-terminated string";
            } else if (ahVal === "4ch" || ahVal === "0x4c") {
              suggestedName = "exit_program";
              confidence = 0.98;
              category = "Control";
              reasoning = "Uses INT 21h/4Ch to terminate program";
            } else if (ahVal === "1" || ahVal === "01h" || ahVal === "0x1") {
              suggestedName = "read_char_echo";
              confidence = 0.9;
              category = "IO";
              reasoning = "Uses INT 21h/01h to read character with echo";
            } else if (ahVal === "2" || ahVal === "02h" || ahVal === "0x2") {
              suggestedName = "write_char";
              confidence = 0.9;
              category = "IO";
              reasoning = "Uses INT 21h/02h to write single character";
            } else if (ahVal === "3ch" || ahVal === "0x3c") {
              suggestedName = "create_file";
              confidence = 0.9;
              category = "File";
              reasoning = "Uses INT 21h/3Ch to create/truncate file";
            } else if (ahVal === "3dh" || ahVal === "0x3d") {
              suggestedName = "open_file";
              confidence = 0.9;
              category = "File";
              reasoning = "Uses INT 21h/3Dh to open file";
            } else if (ahVal === "3eh" || ahVal === "0x3e") {
              suggestedName = "close_file";
              confidence = 0.9;
              category = "File";
              reasoning = "Uses INT 21h/3Eh to close file handle";
            } else if (ahVal === "3fh" || ahVal === "0x3f") {
              suggestedName = "read_file";
              confidence = 0.9;
              category = "File";
              reasoning = "Uses INT 21h/3Fh to read from file";
            } else if (ahVal === "40h" || ahVal === "0x40") {
              suggestedName = "write_file";
              confidence = 0.9;
              category = "File";
              reasoning = "Uses INT 21h/40h to write to file";
            } else if (ahVal === "4bh" || ahVal === "0x4b") {
              suggestedName = "exec_program";
              confidence = 0.95;
              category = "Process";
              reasoning = "Uses INT 21h/4Bh to execute program";
            }
            break;
          }
        }

        // Generic DOS if no specific function matched
        if (category === "Unknown") {
          suggestedName = "dos_syscall";
          confidence = 0.6;
          category = "System";
          reasoning = "Contains DOS INT 21h system call";
        }
      }
      // Memory operations
      else if (mnemonics.includes("rep") || mnemonics.includes("repz") || mnemonics.includes("repnz")) {
        if (mnemonics.includes("movsb") || mnemonics.includes("movsw") || mnemonics.includes("movsd")) {
          suggestedName = "mem_copy";
          confidence = 0.85;
          category = "Memory";
          reasoning = "Uses REP MOVS to copy memory block";
        } else if (mnemonics.includes("stosb") || mnemonics.includes("stosw") || mnemonics.includes("stosd")) {
          suggestedName = "mem_fill";
          confidence = 0.85;
          category = "Memory";
          reasoning = "Uses REP STOS to fill memory block";
        } else if (mnemonics.includes("scasb") || mnemonics.includes("scasw")) {
          suggestedName = "string_scan";
          confidence = 0.8;
          category = "String";
          reasoning = "Uses REP SCAS to scan string for character";
        } else if (mnemonics.includes("cmpsb") || mnemonics.includes("cmpsw")) {
          suggestedName = "string_compare";
          confidence = 0.8;
          category = "String";
          reasoning = "Uses REP CMPS to compare strings";
        }
      }
      // XOR-heavy functions (crypto/obfuscation)
      else if (mnemonics.filter((m) => m === "xor").length >= 3) {
        const hasLoop = mnemonics.some((m) => m.startsWith("loop") || m === "jnz" || m === "jne");
        if (hasLoop) {
          suggestedName = "xor_crypt";
          confidence = 0.75;
          category = "Crypto";
          reasoning = "Contains XOR loop - likely encryption/decryption";
        } else {
          suggestedName = "xor_transform";
          confidence = 0.65;
          category = "Transform";
          reasoning = "Multiple XOR operations";
        }
      }
      // Simple wrapper/stub
      else if (funcBody.length <= 3) {
        if (mnemonics.includes("jmp")) {
          suggestedName = "jump_stub";
          confidence = 0.7;
          category = "Stub";
          reasoning = "Short function with JMP - likely a stub or thunk";
        } else if (mnemonics.includes("ret") || mnemonics.includes("retn")) {
          suggestedName = "null_sub";
          confidence = 0.8;
          category = "Stub";
          reasoning = "Empty function (just returns)";
        }
      }
      // Loop-based processing
      else if (mnemonics.some((m) => m.startsWith("loop"))) {
        suggestedName = "process_loop";
        confidence = 0.5;
        category = "Processing";
        reasoning = "Contains LOOP instruction for iteration";
      }
      // Call-heavy functions
      else if (mnemonics.filter((m) => m === "call").length >= 3) {
        suggestedName = "dispatch_func";
        confidence = 0.55;
        category = "Control";
        reasoning = "Multiple CALL instructions - likely a dispatcher";
      }

      // Check for existing label
      const existingLabel = labels.get(startAddr);
      if (existingLabel) {
        return {
          address: startAddr,
          originalName: existingLabel.name,
          suggestedName,
          confidence,
          category,
          reasoning,
          applied: true,
        };
      }

      return {
        address: startAddr,
        originalName: `sub_${startAddr.replace("0x", "")}`,
        suggestedName,
        confidence,
        category,
        reasoning,
        applied: false,
      };
    },
    [result, labels]
  );

  // Run full analysis
  const runAnalysis = useCallback(async () => {
    setIsAnalyzing(true);
    setIsPaused(false);
    setProgress(0);

    const functions = detectFunctions();
    const newLabels: FunctionLabel[] = [];

    for (let i = 0; i < functions.length; i++) {
      if (isPaused) {
        break;
      }

      const label = analyzeFunction(functions[i], i, functions.length);
      newLabels.push(label);

      // Apply automatically if enabled and confidence is high enough
      if (autoApply && label.confidence >= minConfidence && !label.applied) {
        setLabel(label.address, label.suggestedName, "function");
        label.applied = true;
      }

      setProgress(((i + 1) / functions.length) * 100);

      // Small delay for UI responsiveness
      if (i % 5 === 0) {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    }

    setFunctionLabels(newLabels);
    setIsAnalyzing(false);
  }, [detectFunctions, analyzeFunction, autoApply, minConfidence, setLabel, isPaused]);

  // Apply a single label
  const applyLabel = (fn: FunctionLabel) => {
    setLabel(fn.address, fn.suggestedName, "function");
    setFunctionLabels((prev) =>
      prev.map((f) => (f.address === fn.address ? { ...f, applied: true } : f))
    );
  };

  // Apply all high-confidence labels
  const applyAllHighConfidence = () => {
    functionLabels.forEach((fn) => {
      if (!fn.applied && fn.confidence >= minConfidence) {
        setLabel(fn.address, fn.suggestedName, "function");
      }
    });
    setFunctionLabels((prev) =>
      prev.map((f) =>
        !f.applied && f.confidence >= minConfidence ? { ...f, applied: true } : f
      )
    );
  };

  // Statistics
  const stats = useMemo(() => {
    const total = functionLabels.length;
    const applied = functionLabels.filter((f) => f.applied).length;
    const highConf = functionLabels.filter((f) => f.confidence >= 0.8).length;
    const medConf = functionLabels.filter((f) => f.confidence >= 0.5 && f.confidence < 0.8).length;
    const lowConf = functionLabels.filter((f) => f.confidence < 0.5).length;
    const categories = new Map<string, number>();
    functionLabels.forEach((f) => {
      categories.set(f.category, (categories.get(f.category) || 0) + 1);
    });
    return { total, applied, highConf, medConf, lowConf, categories };
  }, [functionLabels]);

  const toggleExpand = (addr: string) => {
    const newExpanded = new Set(expandedFn);
    if (newExpanded.has(addr)) {
      newExpanded.delete(addr);
    } else {
      newExpanded.add(addr);
    }
    setExpandedFn(newExpanded);
  };

  if (!result) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <Tags className="w-10 h-10 mx-auto mb-3 opacity-50" />
          <p className="text-sm">AI Auto-Labeler</p>
          <p className="text-xs mt-1">Analyze a file to auto-label functions</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-10 bg-gradient-to-r from-accent-cyan/20 to-accent-purple/20 border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <Tags className="w-5 h-5 text-accent-cyan" />
          <span className="text-sm font-medium">AI Auto-Labeler</span>
          <span className="px-1.5 py-0.5 text-[10px] bg-accent-cyan/20 text-accent-cyan rounded">
            Batch Analysis
          </span>
        </div>
        <div className="flex items-center gap-2">
          {isAnalyzing ? (
            <>
              <button
                onClick={() => setIsPaused(!isPaused)}
                className="p-1 hover:bg-bg-hover rounded"
                title={isPaused ? "Resume" : "Pause"}
              >
                {isPaused ? (
                  <Play className="w-4 h-4 text-accent-green" />
                ) : (
                  <Pause className="w-4 h-4 text-accent-yellow" />
                )}
              </button>
              <div className="w-24 h-1.5 bg-bg-tertiary rounded overflow-hidden">
                <div
                  className="h-full bg-accent-cyan transition-all"
                  style={{ width: `${progress}%` }}
                />
              </div>
              <span className="text-xs text-text-secondary">{Math.round(progress)}%</span>
            </>
          ) : (
            <button
              onClick={runAnalysis}
              className="flex items-center gap-1 px-3 py-1 text-xs bg-accent-cyan/20 text-accent-cyan rounded hover:bg-accent-cyan/30"
            >
              <Sparkles className="w-3 h-3" />
              Analyze All
            </button>
          )}
        </div>
      </div>

      {/* Settings bar */}
      <div className="h-8 bg-bg-tertiary border-b border-border flex items-center justify-between px-3 text-xs">
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1">
            <input
              type="checkbox"
              checked={autoApply}
              onChange={(e) => setAutoApply(e.target.checked)}
              className="w-3 h-3"
            />
            <span className="text-text-secondary">Auto-apply</span>
          </label>
          <label className="flex items-center gap-2">
            <span className="text-text-secondary">Min confidence:</span>
            <input
              type="range"
              min="0"
              max="100"
              value={minConfidence * 100}
              onChange={(e) => setMinConfidence(parseInt(e.target.value) / 100)}
              className="w-20 h-1"
            />
            <span>{Math.round(minConfidence * 100)}%</span>
          </label>
        </div>
        {functionLabels.length > 0 && (
          <button
            onClick={applyAllHighConfidence}
            className="flex items-center gap-1 px-2 py-0.5 text-accent-green hover:bg-accent-green/20 rounded"
          >
            <CheckCheck className="w-3 h-3" />
            Apply All ({functionLabels.filter((f) => !f.applied && f.confidence >= minConfidence).length})
          </button>
        )}
      </div>

      {/* Function list */}
      <div className="flex-1 overflow-auto">
        {functionLabels.length === 0 ? (
          <div className="h-full flex items-center justify-center text-text-secondary">
            <div className="text-center max-w-xs">
              <Sparkles className="w-8 h-8 mx-auto mb-3 opacity-50" />
              <p className="text-sm font-medium">No functions analyzed yet</p>
              <p className="text-xs mt-2">
                Click "Analyze All" to automatically detect and label all functions
                in the binary using AI-powered pattern recognition.
              </p>
            </div>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {functionLabels.map((fn) => (
              <div key={fn.address} className="bg-bg-primary">
                {/* Function row */}
                <button
                  onClick={() => toggleExpand(fn.address)}
                  className="w-full px-3 py-2 flex items-center gap-2 hover:bg-bg-hover transition-colors text-left"
                >
                  {expandedFn.has(fn.address) ? (
                    <ChevronDown className="w-4 h-4 text-text-secondary shrink-0" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-text-secondary shrink-0" />
                  )}

                  {/* Applied indicator */}
                  {fn.applied ? (
                    <Check className="w-4 h-4 text-accent-green shrink-0" />
                  ) : (
                    <Tag className="w-4 h-4 text-text-secondary shrink-0" />
                  )}

                  {/* Address */}
                  <span className="font-mono text-xs text-accent-blue w-16">
                    {fn.address}
                  </span>

                  {/* Suggested name */}
                  <span className={`text-sm font-medium ${fn.applied ? "text-accent-green" : "text-accent-purple"}`}>
                    {fn.suggestedName}
                  </span>

                  {/* Category */}
                  <span className="px-1.5 py-0.5 text-[10px] bg-bg-tertiary rounded">
                    {fn.category}
                  </span>

                  <span className="flex-1" />

                  {/* Confidence */}
                  <span
                    className={`px-1.5 py-0.5 text-[10px] rounded ${
                      fn.confidence >= 0.8
                        ? "bg-accent-green/20 text-accent-green"
                        : fn.confidence >= 0.5
                        ? "bg-accent-yellow/20 text-accent-yellow"
                        : "bg-bg-tertiary text-text-secondary"
                    }`}
                  >
                    {Math.round(fn.confidence * 100)}%
                  </span>

                  {/* Apply button */}
                  {!fn.applied && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        applyLabel(fn);
                      }}
                      className="px-2 py-0.5 text-[10px] bg-accent-cyan/20 text-accent-cyan rounded hover:bg-accent-cyan/30"
                    >
                      Apply
                    </button>
                  )}
                </button>

                {/* Expanded details */}
                {expandedFn.has(fn.address) && (
                  <div className="px-10 pb-3 text-xs">
                    <div className="p-2 bg-bg-tertiary rounded">
                      <span className="font-semibold">Reasoning:</span>{" "}
                      <span className="text-text-secondary">{fn.reasoning}</span>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Stats footer */}
      <div className="h-6 bg-bg-secondary border-t border-border flex items-center justify-between px-3 text-[10px] text-text-secondary shrink-0">
        <span>
          {stats.total} functions detected • {stats.applied} labeled
        </span>
        <div className="flex items-center gap-2">
          <span className="text-accent-green">{stats.highConf} high</span>
          <span className="text-accent-yellow">{stats.medConf} med</span>
          <span>{stats.lowConf} low</span>
        </div>
      </div>
    </div>
  );
}
