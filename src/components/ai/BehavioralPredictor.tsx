import { useState, useCallback } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import {
  Brain, Play, AlertTriangle, Shield, Zap, Eye, Globe, Lock,
  FileText, HardDrive, Users, Terminal, RefreshCw, Loader2,
  ChevronDown, ChevronRight, Target
} from "lucide-react";

interface BehaviorCategory {
  id: string;
  name: string;
  icon: typeof Brain;
  color: string;
  indicators: BehaviorIndicator[];
  confidence: number;
  impact: "low" | "medium" | "high" | "critical";
}

interface BehaviorIndicator {
  type: string;
  description: string;
  evidence: string[];
  addresses?: string[];
}

interface PredictionResult {
  overallThreat: number; // 0-100
  classification: string;
  categories: BehaviorCategory[];
  executionFlow: string[];
  recommendations: string[];
}

// Behavior detection rules
const BEHAVIOR_RULES = {
  fileSystem: {
    patterns: [
      /CreateFile|OpenFile|ReadFile|WriteFile|DeleteFile/i,
      /fopen|fread|fwrite|fclose|remove|unlink/i,
      /mov.*ah,.*3[cdef]h?.*int.*21h/i, // DOS file operations
    ],
    indicators: ["File creation", "File modification", "File deletion"],
  },
  network: {
    patterns: [
      /socket|connect|send|recv|WSA/i,
      /InternetOpen|HttpOpen|URLDownload/i,
      /https?:\/\//i,
      /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    ],
    indicators: ["Network connection", "Data exfiltration", "C2 communication"],
  },
  registry: {
    patterns: [
      /RegCreateKey|RegSetValue|RegOpenKey|RegDeleteKey/i,
      /HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER/i,
      /\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i,
    ],
    indicators: ["Registry modification", "Persistence mechanism", "Configuration storage"],
  },
  process: {
    patterns: [
      /CreateProcess|ShellExecute|WinExec/i,
      /CreateRemoteThread|WriteProcessMemory|VirtualAllocEx/i,
      /NtCreateThread|RtlCreateUserThread/i,
      /mov.*ah,.*4bh?.*int.*21h/i, // DOS EXEC
    ],
    indicators: ["Process creation", "Code injection", "Process manipulation"],
  },
  crypto: {
    patterns: [
      /CryptEncrypt|CryptDecrypt|BCrypt/i,
      /AES|DES|RSA|RC4|MD5|SHA/i,
      /xor.*loop/i, // XOR loops
    ],
    indicators: ["Data encryption", "Hashing", "Key generation"],
  },
  antiAnalysis: {
    patterns: [
      /IsDebuggerPresent|CheckRemoteDebugger/i,
      /NtQueryInformationProcess|NtSetInformationThread/i,
      /GetTickCount|QueryPerformanceCounter.*Sleep/i,
      /VirtualMachine|VMware|VBox|Sandbox/i,
    ],
    indicators: ["Debugger detection", "VM detection", "Timing checks", "Environment fingerprinting"],
  },
  privilege: {
    patterns: [
      /AdjustTokenPrivileges|SeDebugPrivilege/i,
      /OpenProcessToken|LookupPrivilegeValue/i,
      /runas|admin|elevate/i,
    ],
    indicators: ["Privilege escalation", "Token manipulation"],
  },
};

export function BehavioralPredictor() {
  const { result, navigateTo } = useAnalysisStore();

  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [prediction, setPrediction] = useState<PredictionResult | null>(null);
  const [expandedCategory, setExpandedCategory] = useState<string | null>(null);

  // Analyze binary behavior
  const analyzeBehavior = useCallback(async () => {
    if (!result) return;

    setIsAnalyzing(true);
    setPrediction(null);

    // Simulate async analysis
    await new Promise(resolve => setTimeout(resolve, 800));

    const categories: BehaviorCategory[] = [];

    // Build searchable content from instructions and strings
    const codeContent = result.instructions
      .map((i: { mnemonic: string; op_str: string }) => `${i.mnemonic} ${i.op_str}`)
      .join("\n");

    const stringContent = result.strings
      .map((s: { value: string }) => s.value)
      .join("\n");

    const allContent = `${codeContent}\n${stringContent}`;

    // Check each behavior category
    const categoryConfigs: Array<{
      id: string;
      name: string;
      icon: typeof Brain;
      color: string;
      impact: "low" | "medium" | "high" | "critical";
      rules: typeof BEHAVIOR_RULES.fileSystem;
    }> = [
      { id: "filesystem", name: "File System Access", icon: HardDrive, color: "text-accent-blue", impact: "medium", rules: BEHAVIOR_RULES.fileSystem },
      { id: "network", name: "Network Communication", icon: Globe, color: "text-accent-red", impact: "high", rules: BEHAVIOR_RULES.network },
      { id: "registry", name: "Registry Modification", icon: FileText, color: "text-accent-yellow", impact: "medium", rules: BEHAVIOR_RULES.registry },
      { id: "process", name: "Process Manipulation", icon: Terminal, color: "text-accent-orange", impact: "critical", rules: BEHAVIOR_RULES.process },
      { id: "crypto", name: "Cryptographic Operations", icon: Lock, color: "text-accent-purple", impact: "medium", rules: BEHAVIOR_RULES.crypto },
      { id: "antianalysis", name: "Anti-Analysis Techniques", icon: Eye, color: "text-accent-red", impact: "critical", rules: BEHAVIOR_RULES.antiAnalysis },
      { id: "privilege", name: "Privilege Operations", icon: Users, color: "text-accent-orange", impact: "high", rules: BEHAVIOR_RULES.privilege },
    ];

    for (const config of categoryConfigs) {
      const indicators: BehaviorIndicator[] = [];
      let matchCount = 0;

      for (const pattern of config.rules.patterns) {
        const matches = allContent.match(pattern);
        if (matches) {
          matchCount++;

          // Find addresses where pattern appears
          const addresses: string[] = [];
          for (const insn of result.instructions) {
            const insnStr = `${insn.mnemonic} ${insn.op_str}`;
            if (pattern.test(insnStr)) {
              addresses.push(insn.address);
            }
          }

          indicators.push({
            type: config.rules.indicators[Math.min(matchCount - 1, config.rules.indicators.length - 1)],
            description: `Matched pattern: ${pattern.source.substring(0, 50)}...`,
            evidence: matches.slice(0, 3),
            addresses: addresses.slice(0, 5),
          });
        }
      }

      if (indicators.length > 0) {
        const confidence = Math.min(0.95, 0.5 + (matchCount * 0.15));
        categories.push({
          id: config.id,
          name: config.name,
          icon: config.icon,
          color: config.color,
          indicators,
          confidence,
          impact: config.impact,
        });
      }
    }

    // Calculate overall threat level
    let threatScore = 0;
    for (const cat of categories) {
      const impactWeight =
        cat.impact === "critical" ? 25 :
        cat.impact === "high" ? 15 :
        cat.impact === "medium" ? 8 : 3;
      threatScore += impactWeight * cat.confidence;
    }

    // Additional threat factors
    if (result.file_info.is_packed) threatScore += 15;
    if (result.mitre_techniques?.length > 3) threatScore += 10;
    if (result.iocs?.total > 5) threatScore += 10;

    threatScore = Math.min(100, threatScore);

    // Determine classification
    const classification =
      threatScore >= 80 ? "Highly Suspicious / Likely Malicious" :
      threatScore >= 60 ? "Suspicious - Requires Investigation" :
      threatScore >= 40 ? "Potentially Unwanted Behavior" :
      threatScore >= 20 ? "Low Risk - Standard Functionality" :
      "Benign - No Suspicious Behavior";

    // Predict execution flow
    const executionFlow: string[] = [];

    if (categories.some(c => c.id === "antianalysis")) {
      executionFlow.push("1. Check for debuggers and analysis tools");
    }
    if (categories.some(c => c.id === "privilege")) {
      executionFlow.push("2. Attempt to escalate privileges");
    }
    if (categories.some(c => c.id === "filesystem")) {
      executionFlow.push("3. Access file system (read/write operations)");
    }
    if (categories.some(c => c.id === "registry")) {
      executionFlow.push("4. Modify registry for persistence");
    }
    if (categories.some(c => c.id === "crypto")) {
      executionFlow.push("5. Encrypt/decrypt data");
    }
    if (categories.some(c => c.id === "network")) {
      executionFlow.push("6. Establish network communication");
    }
    if (categories.some(c => c.id === "process")) {
      executionFlow.push("7. Create processes or inject code");
    }

    if (executionFlow.length === 0) {
      executionFlow.push("Standard program execution flow detected");
    }

    // Generate recommendations
    const recommendations: string[] = [];

    if (threatScore >= 60) {
      recommendations.push("Execute only in isolated sandbox environment");
      recommendations.push("Capture network traffic during execution");
      recommendations.push("Monitor file system and registry changes");
    }
    if (categories.some(c => c.id === "network")) {
      recommendations.push("Block network access to identified IOCs");
    }
    if (categories.some(c => c.id === "crypto")) {
      recommendations.push("Analyze encryption routines for key extraction");
    }
    if (categories.some(c => c.id === "antianalysis")) {
      recommendations.push("Use hardware breakpoints to bypass anti-debug");
      recommendations.push("Patch anti-analysis checks before dynamic analysis");
    }
    if (result.file_info.is_packed) {
      recommendations.push("Unpack binary before further static analysis");
    }

    if (recommendations.length === 0) {
      recommendations.push("No special handling required");
    }

    setPrediction({
      overallThreat: threatScore,
      classification,
      categories,
      executionFlow,
      recommendations,
    });

    setIsAnalyzing(false);
  }, [result]);

  // Get threat color
  const getThreatColor = useCallback((score: number) => {
    if (score >= 80) return "text-accent-red";
    if (score >= 60) return "text-accent-orange";
    if (score >= 40) return "text-accent-yellow";
    return "text-accent-green";
  }, []);

  if (!result) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <Brain className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">Behavioral Predictor</p>
          <p className="text-xs mt-1">Analyze a file to predict behavior</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-10 bg-gradient-to-r from-accent-purple/20 to-accent-red/20 border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <Brain className="w-4 h-4 text-accent-purple" />
          <span className="text-sm font-medium">Behavioral Predictor</span>
        </div>

        <button
          onClick={analyzeBehavior}
          disabled={isAnalyzing}
          className="flex items-center gap-1 px-3 py-1 text-xs bg-accent-purple/20 text-accent-purple rounded hover:bg-accent-purple/30 disabled:opacity-50"
        >
          {isAnalyzing ? (
            <>
              <Loader2 className="w-3 h-3 animate-spin" />
              Analyzing...
            </>
          ) : (
            <>
              <Zap className="w-3 h-3" />
              Predict Behavior
            </>
          )}
        </button>
      </div>

      {/* Results */}
      <div className="flex-1 overflow-auto">
        {!prediction && !isAnalyzing ? (
          <div className="h-full flex items-center justify-center text-text-secondary">
            <div className="text-center max-w-md px-4">
              <Brain className="w-10 h-10 mx-auto mb-3 opacity-50" />
              <p className="text-sm font-medium">AI Behavioral Analysis</p>
              <p className="text-xs mt-2">
                Click "Predict Behavior" to analyze:
              </p>
              <ul className="text-xs mt-3 space-y-2 text-left">
                <li className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-accent-blue shrink-0" />
                  <span>Overall threat assessment and classification</span>
                </li>
                <li className="flex items-center gap-2">
                  <Target className="w-4 h-4 text-accent-red shrink-0" />
                  <span>Predicted execution flow and behavior</span>
                </li>
                <li className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-accent-yellow shrink-0" />
                  <span>Anti-analysis and evasion techniques</span>
                </li>
                <li className="flex items-center gap-2">
                  <RefreshCw className="w-4 h-4 text-accent-green shrink-0" />
                  <span>Analysis recommendations</span>
                </li>
              </ul>
            </div>
          </div>
        ) : isAnalyzing ? (
          <div className="h-full flex items-center justify-center text-text-secondary">
            <div className="text-center">
              <Loader2 className="w-10 h-10 mx-auto mb-3 animate-spin text-accent-purple" />
              <p className="text-sm">Analyzing behavioral patterns...</p>
              <p className="text-xs mt-1">Predicting execution flow</p>
            </div>
          </div>
        ) : prediction && (
          <div className="p-3 space-y-4">
            {/* Threat Score */}
            <div className="bg-bg-tertiary border border-border rounded p-4">
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm font-medium">Threat Assessment</span>
                <span className={`text-2xl font-bold ${getThreatColor(prediction.overallThreat)}`}>
                  {prediction.overallThreat}%
                </span>
              </div>

              {/* Threat bar */}
              <div className="h-2 bg-bg-primary rounded-full overflow-hidden mb-2">
                <div
                  className={`h-full transition-all duration-500 ${
                    prediction.overallThreat >= 80 ? "bg-accent-red" :
                    prediction.overallThreat >= 60 ? "bg-accent-orange" :
                    prediction.overallThreat >= 40 ? "bg-accent-yellow" :
                    "bg-accent-green"
                  }`}
                  style={{ width: `${prediction.overallThreat}%` }}
                />
              </div>

              <p className={`text-sm ${getThreatColor(prediction.overallThreat)}`}>
                {prediction.classification}
              </p>
            </div>

            {/* Behavior Categories */}
            {prediction.categories.length > 0 && (
              <div>
                <h3 className="text-xs text-text-secondary uppercase tracking-wider mb-2">
                  Detected Behaviors ({prediction.categories.length})
                </h3>
                <div className="space-y-2">
                  {prediction.categories.map(cat => {
                    const Icon = cat.icon;
                    return (
                      <div key={cat.id} className="bg-bg-tertiary border border-border rounded overflow-hidden">
                        <button
                          onClick={() => setExpandedCategory(
                            expandedCategory === cat.id ? null : cat.id
                          )}
                          className="w-full p-2 flex items-center justify-between hover:bg-bg-hover"
                        >
                          <div className="flex items-center gap-2">
                            {expandedCategory === cat.id ? (
                              <ChevronDown className="w-3 h-3 text-text-secondary" />
                            ) : (
                              <ChevronRight className="w-3 h-3 text-text-secondary" />
                            )}
                            <Icon className={`w-4 h-4 ${cat.color}`} />
                            <span className="text-sm">{cat.name}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                              cat.impact === "critical" ? "bg-accent-red/20 text-accent-red" :
                              cat.impact === "high" ? "bg-accent-orange/20 text-accent-orange" :
                              "bg-accent-yellow/20 text-accent-yellow"
                            }`}>
                              {cat.impact}
                            </span>
                          </div>
                          <span className="text-xs text-text-secondary">
                            {Math.round(cat.confidence * 100)}% conf
                          </span>
                        </button>

                        {expandedCategory === cat.id && (
                          <div className="px-3 pb-3 border-t border-border bg-bg-secondary">
                            <div className="mt-2 space-y-2">
                              {cat.indicators.map((ind, idx) => (
                                <div key={idx} className="text-xs">
                                  <div className="font-medium text-text-primary">{ind.type}</div>
                                  <div className="text-text-secondary mt-0.5">{ind.description}</div>
                                  {ind.addresses && ind.addresses.length > 0 && (
                                    <div className="flex flex-wrap gap-1 mt-1">
                                      {ind.addresses.map((addr, i) => (
                                        <button
                                          key={i}
                                          onClick={() => navigateTo(addr)}
                                          className="px-1.5 py-0.5 bg-accent-blue/20 text-accent-blue rounded text-[10px] font-mono hover:bg-accent-blue/30"
                                        >
                                          {addr}
                                        </button>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Predicted Execution Flow */}
            <div>
              <h3 className="text-xs text-text-secondary uppercase tracking-wider mb-2">
                Predicted Execution Flow
              </h3>
              <div className="bg-bg-tertiary border border-border rounded p-3">
                <ul className="text-xs space-y-1">
                  {prediction.executionFlow.map((step, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <Play className="w-3 h-3 text-accent-green shrink-0 mt-0.5" />
                      <span>{step}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Recommendations */}
            <div>
              <h3 className="text-xs text-text-secondary uppercase tracking-wider mb-2">
                Analysis Recommendations
              </h3>
              <div className="bg-bg-tertiary border border-border rounded p-3">
                <ul className="text-xs space-y-1">
                  {prediction.recommendations.map((rec, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <AlertTriangle className={`w-3 h-3 shrink-0 mt-0.5 ${
                        prediction.overallThreat >= 60 ? "text-accent-orange" : "text-accent-blue"
                      }`} />
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
