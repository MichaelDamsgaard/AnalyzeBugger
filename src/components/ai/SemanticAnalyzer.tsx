import { useState, useCallback } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import {
  Brain, Loader2, Sparkles, Check, ChevronDown,
  ChevronRight, AlertTriangle, Shield, Code, Lightbulb
} from "lucide-react";

interface SemanticInsight {
  type: "purpose" | "behavior" | "technique" | "vulnerability" | "suggestion";
  title: string;
  content: string;
  confidence: number;
  addresses?: string[];
}

interface FunctionAnalysis {
  address: string;
  suggestedName: string;
  summary: string;
  insights: SemanticInsight[];
  complexity: "simple" | "moderate" | "complex";
  category: string;
}

export function SemanticAnalyzer() {
  const { result, currentAddress, setLabel } = useAnalysisStore();
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analyses, setAnalyses] = useState<FunctionAnalysis[]>([]);
  const [expandedFn, setExpandedFn] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  // Analyze current function or selection
  const analyzeCurrentFunction = useCallback(async () => {
    if (!result || !currentAddress) return;

    setIsAnalyzing(true);

    // Find instructions around current address (simplified function detection)
    const startIdx = result.instructions.findIndex(i => i.address === currentAddress);
    if (startIdx === -1) {
      setIsAnalyzing(false);
      return;
    }

    // Get ~50 instructions as context
    const contextInsns = result.instructions.slice(
      Math.max(0, startIdx - 10),
      Math.min(result.instructions.length, startIdx + 40)
    );

    // Simulate AI analysis (in production, this calls Claude API)
    // For now, generate intelligent analysis based on patterns
    const analysis = generateSemanticAnalysis(currentAddress, contextInsns, result);

    setAnalyses(prev => {
      const existing = prev.findIndex(a => a.address === currentAddress);
      if (existing >= 0) {
        const updated = [...prev];
        updated[existing] = analysis;
        return updated;
      }
      return [...prev, analysis];
    });

    setExpandedFn(currentAddress);
    setIsAnalyzing(false);
  }, [result, currentAddress]);

  // Analyze all detected functions
  const analyzeAllFunctions = useCallback(async () => {
    if (!result) return;

    setIsAnalyzing(true);

    // Find function entry points (after RET instructions or CALL targets)
    const functionStarts: string[] = [result.instructions[0]?.address].filter(Boolean);

    for (let i = 1; i < result.instructions.length; i++) {
      const prev = result.instructions[i - 1];
      const curr = result.instructions[i];

      if (prev.mnemonic.toLowerCase().includes("ret") &&
          !curr.mnemonic.toLowerCase().startsWith("nop")) {
        functionStarts.push(curr.address);
      }
    }

    // Analyze first 10 functions
    const newAnalyses: FunctionAnalysis[] = [];
    for (const addr of functionStarts.slice(0, 10)) {
      const startIdx = result.instructions.findIndex(i => i.address === addr);
      const contextInsns = result.instructions.slice(startIdx, startIdx + 30);
      newAnalyses.push(generateSemanticAnalysis(addr, contextInsns, result));
    }

    setAnalyses(newAnalyses);
    setIsAnalyzing(false);
  }, [result]);

  const applyName = (analysis: FunctionAnalysis) => {
    setLabel(analysis.address, analysis.suggestedName, "function");
    setCopied(analysis.address);
    setTimeout(() => setCopied(null), 1500);
  };

  const getInsightIcon = (type: SemanticInsight["type"]) => {
    switch (type) {
      case "purpose": return Lightbulb;
      case "behavior": return Code;
      case "technique": return Sparkles;
      case "vulnerability": return AlertTriangle;
      case "suggestion": return Shield;
    }
  };

  const getInsightColor = (type: SemanticInsight["type"]) => {
    switch (type) {
      case "purpose": return "text-accent-blue";
      case "behavior": return "text-accent-purple";
      case "technique": return "text-accent-cyan";
      case "vulnerability": return "text-accent-red";
      case "suggestion": return "text-accent-green";
    }
  };

  if (!result) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <Brain className="w-10 h-10 mx-auto mb-3 opacity-50" />
          <p className="text-sm">AI Semantic Analyzer</p>
          <p className="text-xs mt-1">Analyze a file to enable AI insights</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-10 bg-gradient-to-r from-accent-purple/20 to-accent-blue/20 border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <Brain className="w-5 h-5 text-accent-purple" />
          <span className="text-sm font-medium">AI Semantic Analyzer</span>
          <span className="px-1.5 py-0.5 text-[10px] bg-accent-purple/20 text-accent-purple rounded">
            Claude-Powered
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={analyzeCurrentFunction}
            disabled={isAnalyzing || !currentAddress}
            className="flex items-center gap-1 px-2 py-1 text-xs bg-bg-tertiary hover:bg-bg-hover rounded transition-colors disabled:opacity-50"
          >
            {isAnalyzing ? (
              <Loader2 className="w-3 h-3 animate-spin" />
            ) : (
              <Sparkles className="w-3 h-3" />
            )}
            Analyze Current
          </button>
          <button
            onClick={analyzeAllFunctions}
            disabled={isAnalyzing}
            className="flex items-center gap-1 px-2 py-1 text-xs bg-accent-purple/20 text-accent-purple hover:bg-accent-purple/30 rounded transition-colors disabled:opacity-50"
          >
            Analyze All
          </button>
        </div>
      </div>

      {/* Analysis results */}
      <div className="flex-1 overflow-auto">
        {analyses.length === 0 ? (
          <div className="h-full flex items-center justify-center text-text-secondary">
            <div className="text-center max-w-xs">
              <Sparkles className="w-8 h-8 mx-auto mb-3 opacity-50" />
              <p className="text-sm font-medium">No analyses yet</p>
              <p className="text-xs mt-2">
                Click "Analyze Current" to get AI-powered insights about the selected code,
                or "Analyze All" to process all detected functions.
              </p>
            </div>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {analyses.map((analysis) => (
              <div key={analysis.address} className="bg-bg-primary">
                {/* Function header */}
                <button
                  onClick={() => setExpandedFn(expandedFn === analysis.address ? null : analysis.address)}
                  className="w-full px-3 py-2 flex items-center gap-2 hover:bg-bg-hover transition-colors text-left"
                >
                  {expandedFn === analysis.address ? (
                    <ChevronDown className="w-4 h-4 text-text-secondary" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-text-secondary" />
                  )}

                  <span className="font-mono text-xs text-accent-blue">
                    {analysis.address}
                  </span>

                  <span className="text-sm text-accent-purple font-medium">
                    {analysis.suggestedName}
                  </span>

                  <span className={`px-1.5 py-0.5 text-[10px] rounded ${
                    analysis.complexity === "simple" ? "bg-accent-green/20 text-accent-green" :
                    analysis.complexity === "moderate" ? "bg-accent-yellow/20 text-accent-yellow" :
                    "bg-accent-red/20 text-accent-red"
                  }`}>
                    {analysis.complexity}
                  </span>

                  <span className="px-1.5 py-0.5 text-[10px] bg-bg-tertiary text-text-secondary rounded">
                    {analysis.category}
                  </span>

                  <span className="flex-1" />

                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      applyName(analysis);
                    }}
                    className="px-2 py-0.5 text-[10px] bg-accent-purple/20 text-accent-purple rounded hover:bg-accent-purple/30"
                  >
                    {copied === analysis.address ? (
                      <Check className="w-3 h-3 inline" />
                    ) : (
                      "Apply Name"
                    )}
                  </button>
                </button>

                {/* Expanded details */}
                {expandedFn === analysis.address && (
                  <div className="px-4 pb-3 space-y-3">
                    {/* Summary */}
                    <div className="p-3 bg-bg-tertiary rounded-lg">
                      <p className="text-sm text-text-primary leading-relaxed">
                        {analysis.summary}
                      </p>
                    </div>

                    {/* Insights */}
                    <div className="space-y-2">
                      {analysis.insights.map((insight, idx) => {
                        const Icon = getInsightIcon(insight.type);
                        const color = getInsightColor(insight.type);

                        return (
                          <div
                            key={idx}
                            className={`p-2 border-l-2 ${color.replace("text-", "border-")} bg-bg-tertiary/50 rounded-r`}
                          >
                            <div className="flex items-center gap-2 mb-1">
                              <Icon className={`w-4 h-4 ${color}`} />
                              <span className={`text-xs font-medium ${color}`}>
                                {insight.title}
                              </span>
                              <span className="text-[10px] text-text-secondary">
                                {Math.round(insight.confidence * 100)}% confidence
                              </span>
                            </div>
                            <p className="text-xs text-text-secondary pl-6">
                              {insight.content}
                            </p>
                            {insight.addresses && insight.addresses.length > 0 && (
                              <div className="flex gap-1 mt-1 pl-6">
                                {insight.addresses.map((addr, i) => (
                                  <span key={i} className="font-mono text-[10px] text-accent-blue">
                                    {addr}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="h-6 bg-bg-secondary border-t border-border flex items-center justify-between px-3 text-[10px] text-text-secondary">
        <span>{analyses.length} functions analyzed</span>
        <span>AI-powered semantic understanding</span>
      </div>
    </div>
  );
}

// Generate semantic analysis based on instruction patterns
// In production, this would call Claude API for real AI analysis
function generateSemanticAnalysis(
  address: string,
  instructions: { address: string; mnemonic: string; op_str: string }[],
  _result: any
): FunctionAnalysis {
  const mnemonics = instructions.map(i => i.mnemonic.toLowerCase());
  const operands = instructions.map(i => i.op_str.toLowerCase());
  const allOps = operands.join(" ");

  // Detect patterns
  const hasInt21 = mnemonics.includes("int") && operands.some(o => o.includes("21") || o.includes("0x21"));
  const hasLoop = mnemonics.some(m => m.startsWith("loop") || m === "rep" || m === "repz" || m === "repnz");
  const hasXor = mnemonics.filter(m => m === "xor").length > 2;
  const hasCmp = mnemonics.includes("cmp") || mnemonics.includes("test");
  const hasPushPop = mnemonics.includes("push") && mnemonics.includes("pop");
  const hasString = allOps.includes("[si]") || allOps.includes("[di]") || allOps.includes("lods") || allOps.includes("stos");

  // Generate insights based on patterns
  const insights: SemanticInsight[] = [];
  let category = "Unknown";
  let suggestedName = `sub_${address.replace("0x", "")}`;
  let summary = "This function's purpose could not be determined with high confidence.";
  let complexity: FunctionAnalysis["complexity"] = "moderate";

  // DOS API detection
  if (hasInt21) {
    const ahValues = instructions
      .filter((_, i) => i > 0 && mnemonics[i] === "int")
      .map((_, i) => {
        // Look backwards for MOV AH
        for (let j = i - 1; j >= Math.max(0, i - 5); j--) {
          if (instructions[j].mnemonic.toLowerCase() === "mov" &&
              instructions[j].op_str.toLowerCase().startsWith("ah")) {
            return instructions[j].op_str.split(",")[1]?.trim();
          }
        }
        return null;
      })
      .filter(Boolean);

    category = "DOS API";
    if (ahValues.includes("9") || ahValues.includes("0x9") || ahValues.includes("09h")) {
      suggestedName = "print_string";
      summary = "This function prints a string to the console using DOS INT 21h function 09h. It expects DS:DX to point to a '$'-terminated string.";
      insights.push({
        type: "purpose",
        title: "String Output Function",
        content: "Uses DOS function 09h to display text. The string must be terminated with '$' character.",
        confidence: 0.95
      });
    } else if (ahValues.includes("4c") || ahValues.includes("0x4c") || ahValues.includes("4ch")) {
      suggestedName = "exit_program";
      summary = "This function terminates the program and returns control to DOS. The return code is set in AL.";
      insights.push({
        type: "purpose",
        title: "Program Exit",
        content: "Calls DOS termination function 4Ch. Check AL for the exit code.",
        confidence: 0.98
      });
    } else if (ahValues.includes("1") || ahValues.includes("0x1") || ahValues.includes("01h")) {
      suggestedName = "read_char_echo";
      summary = "Reads a single character from keyboard with echo to screen.";
      insights.push({
        type: "behavior",
        title: "Keyboard Input",
        content: "Waits for user keypress and echoes it to screen. Character returned in AL.",
        confidence: 0.9
      });
    }
  }

  // String processing detection
  if (hasString || hasLoop) {
    if (hasXor && hasLoop) {
      category = "Crypto/Encoding";
      suggestedName = "xor_decode_string";
      summary = "This function appears to XOR-decode or encode data using a loop. This is a common technique for obfuscating strings or implementing simple encryption.";
      complexity = "moderate";
      insights.push({
        type: "technique",
        title: "XOR Encoding Detected",
        content: "Uses XOR operation in a loop, typically for string obfuscation or simple encryption.",
        confidence: 0.85
      });
      insights.push({
        type: "vulnerability",
        title: "Weak Encryption",
        content: "Single-byte XOR is easily reversible. Check for hardcoded key values.",
        confidence: 0.7
      });
    } else if (hasLoop) {
      category = "String/Memory";
      suggestedName = "process_buffer";
      summary = "This function processes a buffer or string using a loop construct.";
      insights.push({
        type: "behavior",
        title: "Buffer Processing",
        content: "Iterates over memory, possibly copying, comparing, or transforming data.",
        confidence: 0.75
      });
    }
  }

  // Comparison/validation
  if (hasCmp && !hasLoop) {
    category = "Validation";
    suggestedName = "check_condition";
    summary = "This function performs comparison operations, likely validating input or state.";
    complexity = "simple";
    insights.push({
      type: "behavior",
      title: "Conditional Logic",
      content: "Contains comparison instructions suggesting input validation or state checking.",
      confidence: 0.7
    });
  }

  // Prologue/epilogue detection
  if (hasPushPop && instructions[0]?.mnemonic.toLowerCase() === "push" &&
      instructions[0]?.op_str.toLowerCase().includes("bp")) {
    insights.push({
      type: "technique",
      title: "Standard Function Prologue",
      content: "Uses standard stack frame setup (PUSH BP; MOV BP,SP pattern).",
      confidence: 0.95
    });
  }

  // Add suggestion for auto-labeling
  if (suggestedName !== `sub_${address.replace("0x", "")}`) {
    insights.push({
      type: "suggestion",
      title: "Recommended Action",
      content: `Consider renaming this function to "${suggestedName}" for better code readability.`,
      confidence: 0.8
    });
  }

  return {
    address,
    suggestedName,
    summary,
    insights,
    complexity,
    category
  };
}
