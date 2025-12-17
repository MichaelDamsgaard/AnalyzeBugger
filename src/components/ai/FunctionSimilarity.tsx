import { useState, useCallback, useMemo } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import {
  GitCompare, Search, Fingerprint, Loader2, ChevronDown, ChevronRight,
  Target, Copy, ExternalLink, Zap, Database, Code
} from "lucide-react";

interface FunctionSignature {
  address: string;
  name?: string;
  size: number;
  prologue: string;
  epilogue: string;
  callCount: number;
  stringRefs: number;
  cyclomatic: number; // simplified complexity
  pattern: string; // normalized pattern
}

interface SimilarityMatch {
  sourceAddress: string;
  sourceName?: string;
  matchType: "library" | "pattern" | "clone";
  matchName: string;
  confidence: number;
  evidence: string[];
  category?: string;
}

// Known function patterns/signatures
const KNOWN_PATTERNS: Array<{
  name: string;
  category: string;
  patterns: RegExp[];
  confidence: number;
}> = [
  // String functions
  {
    name: "strlen",
    category: "String",
    patterns: [
      /mov.*,.*\[.*\].*cmp.*byte.*,.*0.*jn?[ez]/i,
      /repne?\s+scasb/i,
    ],
    confidence: 0.85,
  },
  {
    name: "strcpy",
    category: "String",
    patterns: [
      /mov.*al,.*\[.*\].*mov.*\[.*\],.*al.*test.*al,.*al.*jn?[ez]/i,
      /rep\s+movsb/i,
    ],
    confidence: 0.8,
  },
  {
    name: "memcpy",
    category: "Memory",
    patterns: [
      /rep\s+movs[bdw]/i,
      /mov.*ecx.*shr.*ecx.*rep.*movsd.*and.*ecx.*rep.*movsb/i,
    ],
    confidence: 0.85,
  },
  {
    name: "memset",
    category: "Memory",
    patterns: [
      /rep\s+stos[bdw]/i,
      /mov.*al.*rep.*stosb/i,
    ],
    confidence: 0.85,
  },
  // Crypto patterns
  {
    name: "XOR_Cipher",
    category: "Crypto",
    patterns: [
      /xor.*\[.*\].*loop/i,
      /mov.*al.*xor.*al.*stosb.*loop/i,
    ],
    confidence: 0.75,
  },
  {
    name: "RC4_Init",
    category: "Crypto",
    patterns: [
      /mov.*byte.*\[.*\+.*\].*256.*loop/i,
    ],
    confidence: 0.7,
  },
  // Anti-analysis
  {
    name: "IsDebuggerPresent_Check",
    category: "Anti-Debug",
    patterns: [
      /mov.*eax.*fs:\[.*30h?\].*mov.*eax,.*\[eax\+.*\]/i,
      /call.*IsDebuggerPresent/i,
    ],
    confidence: 0.9,
  },
  {
    name: "TLS_Callback",
    category: "Anti-Debug",
    patterns: [
      /cmp.*dword.*\[.*\+.*8.*\],.*1/i, // DLL_PROCESS_ATTACH check
    ],
    confidence: 0.7,
  },
  // DOS patterns
  {
    name: "DOS_PrintString",
    category: "DOS API",
    patterns: [
      /mov.*ah,.*0?9h?.*int.*21h/i,
      /mov.*ah,.*09h?.*lea.*dx.*int.*21h/i,
    ],
    confidence: 0.95,
  },
  {
    name: "DOS_Exit",
    category: "DOS API",
    patterns: [
      /mov.*ah,.*4ch?.*int.*21h/i,
      /mov.*ax,.*4c00h?.*int.*21h/i,
    ],
    confidence: 0.95,
  },
  {
    name: "DOS_ReadFile",
    category: "DOS API",
    patterns: [
      /mov.*ah,.*3fh?.*int.*21h/i,
    ],
    confidence: 0.9,
  },
  {
    name: "DOS_WriteFile",
    category: "DOS API",
    patterns: [
      /mov.*ah,.*40h?.*int.*21h/i,
    ],
    confidence: 0.9,
  },
];

export function FunctionSimilarity() {
  const { result, navigateTo, setLabel } = useAnalysisStore();

  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [matches, setMatches] = useState<SimilarityMatch[]>([]);
  const [expandedMatch, setExpandedMatch] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>("all");

  // Extract function signatures from instructions
  const extractSignatures = useCallback((): FunctionSignature[] => {
    if (!result?.instructions) return [];

    const signatures: FunctionSignature[] = [];
    const instructions = result.instructions;

    // Find function boundaries (simplified - look for common prologues/epilogues)
    let currentFunc: { start: number; address: string } | null = null;

    for (let i = 0; i < instructions.length; i++) {
      const insn = instructions[i];
      const mnemonic = insn.mnemonic.toLowerCase();
      const ops = insn.op_str.toLowerCase();

      // Detect function start (push ebp/rbp, or label from analysis)
      const isPrologue =
        (mnemonic === "push" && (ops === "ebp" || ops === "rbp")) ||
        (mnemonic === "sub" && ops.includes("sp"));

      // Detect function end
      const isEpilogue =
        mnemonic === "ret" || mnemonic === "retn" || mnemonic === "retf" ||
        mnemonic === "iret";

      if (isPrologue && !currentFunc) {
        currentFunc = { start: i, address: insn.address };
      }

      if (isEpilogue && currentFunc) {
        const size = i - currentFunc.start + 1;
        if (size >= 3) { // Minimum function size
          const funcInsns = instructions.slice(currentFunc.start, i + 1);

          // Build pattern from instructions
          const pattern = funcInsns
            .map((fi: { mnemonic: string; op_str: string }) => `${fi.mnemonic} ${fi.op_str}`)
            .join("\n");

          // Count calls and string refs
          const callCount = funcInsns.filter(
            (fi: { mnemonic: string }) => fi.mnemonic.toLowerCase() === "call"
          ).length;

          const stringRefs = funcInsns.filter((fi: { op_str: string }) => {
            const stringMatch = result.strings.find(
              (s: { value: string }) => fi.op_str.includes(s.value?.substring(0, 10))
            );
            return !!stringMatch;
          }).length;

          // Simplified cyclomatic complexity (count branches)
          const branches = funcInsns.filter((fi: { mnemonic: string }) =>
            fi.mnemonic.toLowerCase().startsWith("j") ||
            fi.mnemonic.toLowerCase() === "loop"
          ).length;

          signatures.push({
            address: currentFunc.address,
            size,
            prologue: funcInsns.slice(0, Math.min(3, funcInsns.length))
              .map((fi: { mnemonic: string; op_str: string }) => `${fi.mnemonic} ${fi.op_str}`).join("; "),
            epilogue: funcInsns.slice(-Math.min(3, funcInsns.length))
              .map((fi: { mnemonic: string; op_str: string }) => `${fi.mnemonic} ${fi.op_str}`).join("; "),
            callCount,
            stringRefs,
            cyclomatic: branches + 1,
            pattern,
          });
        }
        currentFunc = null;
      }
    }

    return signatures;
  }, [result]);

  // Match signatures against known patterns
  const findMatches = useCallback(async () => {
    setIsAnalyzing(true);
    setMatches([]);

    // Simulate async analysis
    await new Promise(resolve => setTimeout(resolve, 500));

    const signatures = extractSignatures();
    const newMatches: SimilarityMatch[] = [];

    for (const sig of signatures) {
      // Check against known patterns
      for (const known of KNOWN_PATTERNS) {
        for (const pattern of known.patterns) {
          if (pattern.test(sig.pattern)) {
            newMatches.push({
              sourceAddress: sig.address,
              sourceName: sig.name,
              matchType: "library",
              matchName: known.name,
              confidence: known.confidence,
              evidence: [
                `Matches ${known.name} pattern`,
                `Function size: ${sig.size} instructions`,
                `Complexity: ${sig.cyclomatic}`,
              ],
              category: known.category,
            });
            break; // Only first match per known pattern
          }
        }
      }

      // Check for clones (similar functions within the binary)
      for (const otherSig of signatures) {
        if (otherSig.address === sig.address) continue;

        // Simple similarity: same size and similar complexity
        if (
          Math.abs(otherSig.size - sig.size) <= 2 &&
          Math.abs(otherSig.cyclomatic - sig.cyclomatic) <= 1 &&
          otherSig.callCount === sig.callCount
        ) {
          // Check if not already matched
          const alreadyMatched = newMatches.some(
            m => m.sourceAddress === sig.address && m.matchName === otherSig.address
          );

          if (!alreadyMatched && sig.address < otherSig.address) { // Avoid duplicates
            newMatches.push({
              sourceAddress: sig.address,
              matchType: "clone",
              matchName: `Clone of ${otherSig.address}`,
              confidence: 0.7,
              evidence: [
                `Similar size: ${sig.size} vs ${otherSig.size}`,
                `Same call count: ${sig.callCount}`,
                `Similar complexity: ${sig.cyclomatic} vs ${otherSig.cyclomatic}`,
              ],
              category: "Clone",
            });
          }
        }
      }
    }

    // Sort by confidence
    newMatches.sort((a, b) => b.confidence - a.confidence);

    setMatches(newMatches);
    setIsAnalyzing(false);
  }, [extractSignatures]);

  // Apply label to matched function
  const applyLabel = useCallback((address: string, name: string) => {
    setLabel(address, name, "function");
  }, [setLabel]);

  // Get unique categories
  const categories = useMemo(() => {
    const cats = new Set(matches.map(m => m.category || "Unknown"));
    return ["all", ...Array.from(cats)];
  }, [matches]);

  // Filter matches by category
  const filteredMatches = useMemo(() => {
    if (selectedCategory === "all") return matches;
    return matches.filter(m => m.category === selectedCategory);
  }, [matches, selectedCategory]);

  // Stats
  const stats = useMemo(() => ({
    total: matches.length,
    library: matches.filter(m => m.matchType === "library").length,
    clones: matches.filter(m => m.matchType === "clone").length,
    highConf: matches.filter(m => m.confidence >= 0.8).length,
  }), [matches]);

  if (!result) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <GitCompare className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">Function Similarity</p>
          <p className="text-xs mt-1">Analyze a file to find similar functions</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-10 bg-gradient-to-r from-accent-cyan/20 to-accent-blue/20 border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <GitCompare className="w-4 h-4 text-accent-cyan" />
          <span className="text-sm font-medium">Function Similarity</span>
          {matches.length > 0 && (
            <span className="text-xs text-text-secondary">
              ({stats.total} matches, {stats.highConf} high confidence)
            </span>
          )}
        </div>

        <button
          onClick={findMatches}
          disabled={isAnalyzing}
          className="flex items-center gap-1 px-3 py-1 text-xs bg-accent-cyan/20 text-accent-cyan rounded hover:bg-accent-cyan/30 disabled:opacity-50"
        >
          {isAnalyzing ? (
            <>
              <Loader2 className="w-3 h-3 animate-spin" />
              Analyzing...
            </>
          ) : (
            <>
              <Search className="w-3 h-3" />
              Find Matches
            </>
          )}
        </button>
      </div>

      {/* Category filter */}
      {matches.length > 0 && (
        <div className="h-9 bg-bg-secondary border-b border-border flex items-center px-3 gap-2 overflow-x-auto">
          {categories.map(cat => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-2 py-1 text-xs rounded whitespace-nowrap ${
                selectedCategory === cat
                  ? "bg-accent-cyan/20 text-accent-cyan"
                  : "text-text-secondary hover:text-text-primary hover:bg-bg-hover"
              }`}
            >
              {cat === "all" ? "All" : cat}
              {cat !== "all" && (
                <span className="ml-1 opacity-70">
                  ({matches.filter(m => m.category === cat).length})
                </span>
              )}
            </button>
          ))}
        </div>
      )}

      {/* Results */}
      <div className="flex-1 overflow-auto">
        {matches.length === 0 && !isAnalyzing ? (
          <div className="h-full flex items-center justify-center text-text-secondary">
            <div className="text-center max-w-md px-4">
              <Fingerprint className="w-8 h-8 mx-auto mb-3 opacity-50" />
              <p className="text-sm font-medium">AI Function Matching</p>
              <p className="text-xs mt-2">
                Click "Find Matches" to identify:
              </p>
              <ul className="text-xs mt-2 space-y-1 text-left">
                <li className="flex items-center gap-2">
                  <Database className="w-3 h-3 text-accent-blue" />
                  Library functions (strlen, memcpy, etc.)
                </li>
                <li className="flex items-center gap-2">
                  <Zap className="w-3 h-3 text-accent-yellow" />
                  Crypto routines (XOR, RC4, etc.)
                </li>
                <li className="flex items-center gap-2">
                  <Code className="w-3 h-3 text-accent-green" />
                  DOS API calls (print, exit, file I/O)
                </li>
                <li className="flex items-center gap-2">
                  <Copy className="w-3 h-3 text-accent-purple" />
                  Code clones within the binary
                </li>
              </ul>
            </div>
          </div>
        ) : isAnalyzing ? (
          <div className="h-full flex items-center justify-center text-text-secondary">
            <div className="text-center">
              <Loader2 className="w-8 h-8 mx-auto mb-3 animate-spin text-accent-cyan" />
              <p className="text-sm">Analyzing function patterns...</p>
              <p className="text-xs mt-1">Comparing against known signatures</p>
            </div>
          </div>
        ) : (
          <div className="p-2 space-y-2">
            {filteredMatches.map((match, idx) => (
              <div
                key={`${match.sourceAddress}-${idx}`}
                className="bg-bg-tertiary border border-border rounded overflow-hidden"
              >
                {/* Match header */}
                <button
                  onClick={() => setExpandedMatch(
                    expandedMatch === match.sourceAddress ? null : match.sourceAddress
                  )}
                  className="w-full p-2 flex items-center justify-between hover:bg-bg-hover"
                >
                  <div className="flex items-center gap-2">
                    {expandedMatch === match.sourceAddress ? (
                      <ChevronDown className="w-3 h-3 text-text-secondary" />
                    ) : (
                      <ChevronRight className="w-3 h-3 text-text-secondary" />
                    )}

                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        navigateTo(match.sourceAddress);
                      }}
                      className="font-mono text-xs text-accent-blue hover:underline"
                    >
                      {match.sourceAddress}
                    </button>

                    <span className="text-xs text-accent-cyan font-medium">
                      {match.matchName}
                    </span>

                    <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                      match.matchType === "library"
                        ? "bg-accent-blue/20 text-accent-blue"
                        : match.matchType === "clone"
                        ? "bg-accent-purple/20 text-accent-purple"
                        : "bg-accent-green/20 text-accent-green"
                    }`}>
                      {match.matchType}
                    </span>

                    {match.category && (
                      <span className="text-[10px] text-text-secondary">
                        [{match.category}]
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    <ConfidenceBadge confidence={match.confidence} />
                  </div>
                </button>

                {/* Expanded details */}
                {expandedMatch === match.sourceAddress && (
                  <div className="px-3 pb-3 border-t border-border bg-bg-secondary">
                    <div className="mt-2 space-y-2">
                      {/* Evidence */}
                      <div>
                        <div className="text-[10px] text-text-secondary uppercase mb-1">Evidence</div>
                        <ul className="text-xs space-y-0.5">
                          {match.evidence.map((ev, i) => (
                            <li key={i} className="flex items-center gap-1">
                              <span className="w-1 h-1 rounded-full bg-accent-cyan" />
                              {ev}
                            </li>
                          ))}
                        </ul>
                      </div>

                      {/* Actions */}
                      <div className="flex items-center gap-2 pt-2">
                        <button
                          onClick={() => applyLabel(match.sourceAddress, match.matchName)}
                          className="flex items-center gap-1 px-2 py-1 text-xs bg-accent-green/20 text-accent-green rounded hover:bg-accent-green/30"
                        >
                          <Target className="w-3 h-3" />
                          Apply Label
                        </button>
                        <button
                          onClick={() => navigateTo(match.sourceAddress)}
                          className="flex items-center gap-1 px-2 py-1 text-xs bg-bg-tertiary text-text-secondary rounded hover:bg-bg-hover"
                        >
                          <ExternalLink className="w-3 h-3" />
                          Go to Function
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Stats footer */}
      {matches.length > 0 && (
        <div className="h-8 bg-bg-secondary border-t border-border flex items-center justify-between px-3 text-xs text-text-secondary">
          <div className="flex items-center gap-4">
            <span>
              <Database className="w-3 h-3 inline mr-1" />
              Library: {stats.library}
            </span>
            <span>
              <Copy className="w-3 h-3 inline mr-1" />
              Clones: {stats.clones}
            </span>
          </div>
          <button
            onClick={() => {
              matches
                .filter(m => m.confidence >= 0.8)
                .forEach(m => applyLabel(m.sourceAddress, m.matchName));
            }}
            className="text-accent-green hover:underline"
          >
            Apply all high-confidence labels
          </button>
        </div>
      )}
    </div>
  );
}

function ConfidenceBadge({ confidence }: { confidence: number }) {
  const percent = Math.round(confidence * 100);
  const color =
    confidence >= 0.9 ? "text-accent-green bg-accent-green/20" :
    confidence >= 0.7 ? "text-accent-yellow bg-accent-yellow/20" :
    "text-accent-orange bg-accent-orange/20";

  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${color}`}>
      {percent}%
    </span>
  );
}
