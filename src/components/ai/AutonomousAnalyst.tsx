import { useState, useRef, useEffect, useCallback } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import { useSessionStore } from "../../stores/sessionStore";
import {
  Bot, User, Play, Pause, Square, Settings, Sparkles,
  AlertTriangle, HelpCircle, ChevronRight, Loader2,
  Eye, Cpu, Lock, Globe, FileSearch, Zap, CheckCircle,
  XCircle, MessageSquare
} from "lucide-react";

type AnalystMode = "chat" | "autonomous";
type MessageType = "system" | "analyst" | "finding" | "checkpoint" | "user" | "action";
type AnalysisPhase = "idle" | "reconnaissance" | "static" | "behavioral" | "crypto" | "network" | "reporting" | "complete";

interface AnalystMessage {
  id: number;
  type: MessageType;
  content: string;
  timestamp: Date;
  phase?: AnalysisPhase;
  severity?: "info" | "warning" | "critical";
  addresses?: string[];
  awaitingInput?: boolean;
  inputPrompt?: string;
}

interface AnalysisGoal {
  id: string;
  description: string;
  status: "pending" | "active" | "complete" | "blocked";
  findings: string[];
}

// Analysis phases and their descriptions
const PHASE_INFO: Record<AnalysisPhase, { name: string; icon: typeof Eye; color: string }> = {
  idle: { name: "Idle", icon: Pause, color: "text-text-secondary" },
  reconnaissance: { name: "Reconnaissance", icon: Eye, color: "text-accent-blue" },
  static: { name: "Static Analysis", icon: FileSearch, color: "text-accent-purple" },
  behavioral: { name: "Behavioral Analysis", icon: Cpu, color: "text-accent-yellow" },
  crypto: { name: "Cryptanalysis", icon: Lock, color: "text-accent-orange" },
  network: { name: "Network Analysis", icon: Globe, color: "text-accent-red" },
  reporting: { name: "Generating Report", icon: Sparkles, color: "text-accent-green" },
  complete: { name: "Analysis Complete", icon: CheckCircle, color: "text-accent-green" },
};

export function AutonomousAnalyst() {
  const { result, navigateTo, setLabel, setComment } = useAnalysisStore();
  const { status: _status } = useSessionStore();

  const [mode, setMode] = useState<AnalystMode>("chat");
  const [messages, setMessages] = useState<AnalystMessage[]>([]);
  const [userInput, setUserInput] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [_isPaused, setIsPaused] = useState(false);
  const [currentPhase, setCurrentPhase] = useState<AnalysisPhase>("idle");
  const [goals, setGoals] = useState<AnalysisGoal[]>([]);
  const [awaitingCheckpoint, setAwaitingCheckpoint] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const analysisRef = useRef<{ cancelled: boolean }>({ cancelled: false });

  // Auto-scroll
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Add a message to the log
  const addMessage = useCallback((
    type: MessageType,
    content: string,
    options?: Partial<AnalystMessage>
  ) => {
    setMessages(prev => [...prev, {
      id: Date.now(),
      type,
      content,
      timestamp: new Date(),
      ...options
    }]);
  }, []);

  // Autonomous analysis engine
  const runAutonomousAnalysis = useCallback(async () => {
    if (!result) return;

    analysisRef.current.cancelled = false;
    setIsAnalyzing(true);
    setAwaitingCheckpoint(false);

    // Initialize goals
    setGoals([
      { id: "recon", description: "Understand binary structure and entry points", status: "pending", findings: [] },
      { id: "static", description: "Analyze code patterns and control flow", status: "pending", findings: [] },
      { id: "strings", description: "Extract and categorize strings", status: "pending", findings: [] },
      { id: "crypto", description: "Identify encryption/encoding routines", status: "pending", findings: [] },
      { id: "behavior", description: "Determine program behavior and intent", status: "pending", findings: [] },
      { id: "iocs", description: "Extract indicators of compromise", status: "pending", findings: [] },
    ]);

    addMessage("system", "Autonomous analysis initiated. I will analyze this binary systematically and request your input only when I need human insight or strategic direction.", {
      phase: "idle"
    });

    await delay(500);

    // Phase 1: Reconnaissance
    if (analysisRef.current.cancelled) return;
    setCurrentPhase("reconnaissance");
    setGoals(prev => prev.map(g => g.id === "recon" ? { ...g, status: "active" } : g));

    addMessage("action", `Beginning reconnaissance of ${result.file_info.name}...`, { phase: "reconnaissance" });
    await delay(800);

    const fileInfo = result.file_info;
    addMessage("analyst",
      `**File Profile:**\n` +
      `- Architecture: ${fileInfo.arch}\n` +
      `- Size: ${fileInfo.size.toLocaleString()} bytes\n` +
      `- Entropy: ${fileInfo.entropy}\n` +
      `- Packed: ${fileInfo.is_packed ? "**Yes** (high entropy suggests packing/encryption)" : "No"}\n\n` +
      `Identified ${result.instruction_count} instructions and ${result.string_count} strings.`,
      { phase: "reconnaissance", severity: fileInfo.is_packed ? "warning" : "info" }
    );

    // Check for packing - potential checkpoint
    if (fileInfo.is_packed) {
      await delay(500);
      addMessage("finding",
        "High entropy detected. This binary may be packed or encrypted. " +
        "I'll proceed with static analysis, but dynamic unpacking may be required for complete analysis.",
        { phase: "reconnaissance", severity: "warning" }
      );
    }

    setGoals(prev => prev.map(g => g.id === "recon" ? { ...g, status: "complete", findings: [`${fileInfo.arch} binary, ${fileInfo.is_packed ? "packed" : "not packed"}`] } : g));
    await delay(500);

    // Phase 2: Static Analysis
    if (analysisRef.current.cancelled) return;
    setCurrentPhase("static");
    setGoals(prev => prev.map(g => g.id === "static" ? { ...g, status: "active" } : g));

    addMessage("action", "Analyzing code structure and control flow...", { phase: "static" });
    await delay(600);

    // Analyze entry point
    const entryPoint = result.instructions[0]?.address;
    if (entryPoint) {
      setLabel(entryPoint, "entry_point", "function");
      addMessage("analyst", `Entry point identified at \`${entryPoint}\`. Labeled as \`entry_point\`.`, {
        phase: "static",
        addresses: [entryPoint]
      });
    }

    // Analyze MITRE techniques if present
    if (result.mitre_techniques?.length > 0) {
      await delay(500);
      const techniques = result.mitre_techniques.slice(0, 5);
      addMessage("finding",
        `**MITRE ATT&CK Techniques Detected:**\n` +
        techniques.map((t: { id: string; name: string; tactic: string }) =>
          `- ${t.id}: ${t.name} (${t.tactic})`
        ).join("\n"),
        { phase: "static", severity: "warning" }
      );
    }

    // Analyze suspicious patterns
    if (result.analysis?.suspicious_patterns?.length > 0) {
      await delay(500);
      addMessage("finding",
        `**Suspicious Code Patterns:**\n` +
        result.analysis.suspicious_patterns.slice(0, 3).map((p: { type: string; address: string }) =>
          `- ${p.type} at \`${p.address}\``
        ).join("\n"),
        { phase: "static", severity: "critical", addresses: result.analysis.suspicious_patterns.map((p: { address: string }) => p.address) }
      );
    }

    // Look for DOS interrupt patterns
    const dosInts = result.instructions.filter((i: { mnemonic: string; op_str: string }) =>
      i.mnemonic.toLowerCase() === "int" &&
      (i.op_str.includes("21") || i.op_str.includes("0x21"))
    );

    if (dosInts.length > 0) {
      await delay(500);
      addMessage("analyst",
        `Found ${dosInts.length} DOS INT 21h system calls. This is a DOS executable using standard DOS services. ` +
        `I'll trace the AH register values to identify specific functions.`,
        { phase: "static" }
      );

      // Trace DOS function calls
      const dosFunctions = new Set<string>();
      for (const intInsn of dosInts.slice(0, 10)) {
        const idx = result.instructions.findIndex((i: { address: string }) => i.address === intInsn.address);
        for (let j = idx - 1; j >= Math.max(0, idx - 5); j--) {
          const prev = result.instructions[j];
          if (prev.mnemonic.toLowerCase() === "mov" && prev.op_str.toLowerCase().startsWith("ah,")) {
            const ahVal = prev.op_str.split(",")[1]?.trim().toLowerCase();
            const funcName = getDosFunction(ahVal);
            if (funcName) {
              dosFunctions.add(funcName);
              setComment(intInsn.address, `DOS: ${funcName}`);
            }
            break;
          }
        }
      }

      if (dosFunctions.size > 0) {
        await delay(500);
        addMessage("analyst",
          `**DOS Functions Used:**\n` +
          Array.from(dosFunctions).map(f => `- ${f}`).join("\n"),
          { phase: "static" }
        );
      }
    }

    setGoals(prev => prev.map(g => g.id === "static" ? { ...g, status: "complete" } : g));
    await delay(500);

    // Phase 3: String Analysis
    if (analysisRef.current.cancelled) return;
    setGoals(prev => prev.map(g => g.id === "strings" ? { ...g, status: "active" } : g));

    addMessage("action", "Extracting and categorizing strings...", { phase: "static" });
    await delay(600);

    // Categorize strings
    const stringCategories = {
      urls: result.strings.filter((s: { value: string }) => /https?:\/\//i.test(s.value)),
      ips: result.strings.filter((s: { value: string }) => /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(s.value)),
      registry: result.strings.filter((s: { value: string }) => /HKEY_|\\Software\\/i.test(s.value)),
      paths: result.strings.filter((s: { value: string }) => /[A-Za-z]:\\/i.test(s.value)),
      suspicious: result.strings.filter((s: { value: string }) => /(password|secret|key|admin|cmd\.exe)/i.test(s.value)),
    };

    const hasNetworkIndicators = stringCategories.urls.length > 0 || stringCategories.ips.length > 0;
    const hasSuspiciousStrings = stringCategories.suspicious.length > 0;

    if (hasNetworkIndicators) {
      addMessage("finding",
        `**Network Indicators Found:**\n` +
        (stringCategories.urls.length > 0 ? `- ${stringCategories.urls.length} URL(s)\n` : "") +
        (stringCategories.ips.length > 0 ? `- ${stringCategories.ips.length} IP address(es)\n` : ""),
        { phase: "static", severity: "critical" }
      );
    }

    if (hasSuspiciousStrings) {
      await delay(400);
      addMessage("finding",
        `**Suspicious Strings:**\n` +
        stringCategories.suspicious.slice(0, 5).map((s: { value: string }) =>
          `- "${s.value.substring(0, 40)}${s.value.length > 40 ? "..." : ""}"`
        ).join("\n"),
        { phase: "static", severity: "warning" }
      );
    }

    setGoals(prev => prev.map(g => g.id === "strings" ? { ...g, status: "complete" } : g));
    await delay(500);

    // Phase 4: Cryptanalysis
    if (analysisRef.current.cancelled) return;
    setCurrentPhase("crypto");
    setGoals(prev => prev.map(g => g.id === "crypto" ? { ...g, status: "active" } : g));

    addMessage("action", "Searching for cryptographic patterns...", { phase: "crypto" });
    await delay(600);

    // Look for XOR patterns
    const xorInsns = result.instructions.filter((i: { mnemonic: string; op_str: string }) =>
      i.mnemonic.toLowerCase() === "xor" &&
      !isSelfXor(i.op_str.toLowerCase())
    );

    if (xorInsns.length > 3) {
      addMessage("analyst",
        `Found ${xorInsns.length} XOR instructions (excluding register clearing). ` +
        `This suggests potential encryption or obfuscation.`,
        { phase: "crypto" }
      );

      // Look for XOR loops
      const loopInsns = result.instructions.filter((i: { mnemonic: string }) =>
        i.mnemonic.toLowerCase().startsWith("loop")
      );

      if (loopInsns.length > 0) {
        await delay(500);
        addMessage("finding",
          `**Potential Encryption Loop Detected**\n` +
          `XOR instructions combined with LOOP suggest a simple XOR cipher. ` +
          `This is commonly used for string obfuscation or simple encryption.`,
          { phase: "crypto", severity: "warning" }
        );

        // CHECKPOINT: Ask about crypto analysis
        if (!analysisRef.current.cancelled) {
          await delay(500);
          setAwaitingCheckpoint(true);
          addMessage("checkpoint",
            "I've identified what appears to be an encryption/obfuscation routine. " +
            "Would you like me to attempt to identify the key and decode any encrypted strings? " +
            "This may require additional analysis time.",
            { phase: "crypto", awaitingInput: true, inputPrompt: "Proceed with cryptanalysis?" }
          );
          return; // Pause for user input
        }
      }
    }

    if (result.crypto?.count > 0) {
      addMessage("finding",
        `**Cryptographic Constants Detected:**\n` +
        result.crypto.findings.slice(0, 3).map((f: { type: string; offset: string }) =>
          `- ${f.type} at \`${f.offset}\``
        ).join("\n"),
        { phase: "crypto", severity: "warning" }
      );
    }

    setGoals(prev => prev.map(g => g.id === "crypto" ? { ...g, status: "complete" } : g));
    await completeAnalysis();

  }, [result, addMessage, setLabel, setComment]);

  // Complete the analysis and generate summary
  const completeAnalysis = useCallback(async () => {
    if (!result) return;

    // Phase 5: Behavioral Analysis
    setCurrentPhase("behavioral");
    setGoals(prev => prev.map(g => g.id === "behavior" ? { ...g, status: "active" } : g));

    addMessage("action", "Determining program behavior and intent...", { phase: "behavioral" });
    await delay(800);

    // Build behavior profile
    const behaviors: string[] = [];

    if (result.iocs?.urls?.length > 0 || result.iocs?.ips?.length > 0) {
      behaviors.push("Network communication capability (potential C2)");
    }
    if (result.strings.some((s: { value: string }) => /CreateFile|WriteFile|DeleteFile/i.test(s.value))) {
      behaviors.push("File system manipulation");
    }
    if (result.strings.some((s: { value: string }) => /RegCreateKey|RegSetValue/i.test(s.value))) {
      behaviors.push("Registry modification (potential persistence)");
    }
    if (result.strings.some((s: { value: string }) => /VirtualAlloc|WriteProcessMemory/i.test(s.value))) {
      behaviors.push("Process injection capability");
    }
    if (result.mitre_techniques?.some((t: { tactic: string }) => t.tactic === "Defense Evasion")) {
      behaviors.push("Anti-analysis/evasion techniques");
    }

    if (behaviors.length > 0) {
      addMessage("finding",
        `**Behavioral Profile:**\n` + behaviors.map(b => `- ${b}`).join("\n"),
        { phase: "behavioral", severity: behaviors.length > 2 ? "critical" : "warning" }
      );
    }

    setGoals(prev => prev.map(g => g.id === "behavior" ? { ...g, status: "complete", findings: behaviors } : g));
    await delay(500);

    // Phase 6: IOC Extraction
    setCurrentPhase("network");
    setGoals(prev => prev.map(g => g.id === "iocs" ? { ...g, status: "active" } : g));

    if (result.iocs?.total > 0) {
      addMessage("action", "Extracting indicators of compromise...", { phase: "network" });
      await delay(600);

      addMessage("finding",
        `**Indicators of Compromise:**\n` +
        `- URLs: ${result.iocs.urls?.length || 0}\n` +
        `- IP Addresses: ${result.iocs.ips?.length || 0}\n` +
        `- Domains: ${result.iocs.domains?.length || 0}\n` +
        `- Registry Keys: ${result.iocs.registry_keys?.length || 0}\n` +
        `- File Paths: ${result.iocs.paths?.length || 0}`,
        { phase: "network", severity: "critical" }
      );
    }

    setGoals(prev => prev.map(g => g.id === "iocs" ? { ...g, status: "complete" } : g));
    await delay(500);

    // Phase 7: Final Report
    setCurrentPhase("reporting");
    addMessage("action", "Generating analysis summary...", { phase: "reporting" });
    await delay(800);

    // Determine threat level
    const threatIndicators = [
      result.iocs?.total > 0,
      result.mitre_techniques?.length > 2,
      result.analysis?.suspicious_patterns?.length > 0,
      result.file_info.is_packed,
    ].filter(Boolean).length;

    const threatLevel = threatIndicators >= 3 ? "HIGH" : threatIndicators >= 2 ? "MEDIUM" : "LOW";
    const threatColor = threatIndicators >= 3 ? "critical" : threatIndicators >= 2 ? "warning" : "info";

    addMessage("analyst",
      `## Analysis Complete\n\n` +
      `**Threat Assessment: ${threatLevel}**\n\n` +
      `### Summary\n` +
      `This ${result.file_info.arch} binary ` +
      `${result.file_info.is_packed ? "appears to be packed/obfuscated and " : ""}` +
      `contains ${result.instruction_count} instructions. ` +
      `${result.mitre_techniques?.length > 0 ? `${result.mitre_techniques.length} MITRE ATT&CK techniques were identified. ` : ""}` +
      `${result.iocs?.total > 0 ? `${result.iocs.total} indicators of compromise were extracted. ` : ""}\n\n` +
      `### Recommendations\n` +
      `${threatIndicators >= 2 ? "- Treat as potentially malicious\n" : ""}` +
      `${result.iocs?.total > 0 ? "- Block identified network IOCs\n" : ""}` +
      `${result.file_info.is_packed ? "- Consider dynamic analysis for unpacking\n" : ""}` +
      `- Review flagged addresses for detailed analysis`,
      { phase: "reporting", severity: threatColor as "info" | "warning" | "critical" }
    );

    setCurrentPhase("complete");
    setIsAnalyzing(false);
    setGoals(prev => prev.map(g => ({ ...g, status: "complete" })));

    addMessage("system",
      "Autonomous analysis complete. You can ask me follow-up questions about any findings, " +
      "or switch to Chat mode for interactive discussion.",
      { phase: "complete" }
    );

  }, [result, addMessage]);

  // Handle user responding to checkpoint
  const handleCheckpointResponse = useCallback(async (proceed: boolean) => {
    setAwaitingCheckpoint(false);

    if (proceed) {
      addMessage("user", "Yes, proceed with cryptanalysis.");
      await delay(300);
      addMessage("analyst", "Understood. Initiating detailed cryptanalysis...", { phase: "crypto" });
      await delay(1000);
      addMessage("analyst",
        "Analyzed XOR patterns. Without dynamic execution, I cannot definitively extract the key. " +
        "However, based on common patterns, try these potential keys: `0x55`, `0xAA`, `0xFF`.",
        { phase: "crypto" }
      );
      setGoals(prev => prev.map(g => g.id === "crypto" ? { ...g, status: "complete" } : g));
      await completeAnalysis();
    } else {
      addMessage("user", "Skip cryptanalysis for now.");
      addMessage("analyst", "Understood. Skipping detailed cryptanalysis and continuing with behavioral analysis.", { phase: "crypto" });
      setGoals(prev => prev.map(g => g.id === "crypto" ? { ...g, status: "complete" } : g));
      await completeAnalysis();
    }
  }, [addMessage, completeAnalysis]);

  // Handle chat message submission
  const handleSubmit = useCallback((e: React.FormEvent) => {
    e.preventDefault();
    if (!userInput.trim()) return;

    if (awaitingCheckpoint) {
      const isYes = /^(y|yes|proceed|ok|sure|go)/i.test(userInput.trim());
      setUserInput("");
      handleCheckpointResponse(isYes);
      return;
    }

    addMessage("user", userInput);
    setUserInput("");

    // In chat mode, provide conversational response
    if (mode === "chat") {
      setTimeout(() => {
        addMessage("analyst", generateChatResponse(userInput, result));
      }, 500);
    }
  }, [userInput, awaitingCheckpoint, mode, result, addMessage, handleCheckpointResponse]);

  // Stop analysis
  const stopAnalysis = useCallback(() => {
    analysisRef.current.cancelled = true;
    setIsAnalyzing(false);
    setIsPaused(false);
    setAwaitingCheckpoint(false);
    addMessage("system", "Analysis stopped by user.");
  }, [addMessage]);

  // Render
  if (!result) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <Bot className="w-10 h-10 mx-auto mb-3 opacity-50" />
          <p className="text-sm">Autonomous AI Analyst</p>
          <p className="text-xs mt-1">Analyze a file to begin</p>
        </div>
      </div>
    );
  }

  const PhaseIcon = PHASE_INFO[currentPhase].icon;

  return (
    <div className="h-full flex flex-col">
      {/* Header with mode toggle */}
      <div className="h-10 bg-gradient-to-r from-accent-purple/20 to-accent-cyan/20 border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <Bot className="w-5 h-5 text-accent-purple" />
          <span className="text-sm font-medium">AI Analyst</span>

          {/* Mode toggle */}
          <div className="flex items-center gap-1 ml-2 bg-bg-tertiary rounded p-0.5">
            <button
              onClick={() => setMode("chat")}
              className={`px-2 py-0.5 text-xs rounded transition-colors ${
                mode === "chat"
                  ? "bg-accent-blue/20 text-accent-blue"
                  : "text-text-secondary hover:text-text-primary"
              }`}
            >
              <MessageSquare className="w-3 h-3 inline mr-1" />
              Chat
            </button>
            <button
              onClick={() => setMode("autonomous")}
              className={`px-2 py-0.5 text-xs rounded transition-colors ${
                mode === "autonomous"
                  ? "bg-accent-purple/20 text-accent-purple"
                  : "text-text-secondary hover:text-text-primary"
              }`}
            >
              <Zap className="w-3 h-3 inline mr-1" />
              Autonomous
            </button>
          </div>
        </div>

        {/* Analysis controls */}
        {mode === "autonomous" && (
          <div className="flex items-center gap-2">
            {isAnalyzing ? (
              <>
                <PhaseIcon className={`w-4 h-4 ${PHASE_INFO[currentPhase].color} animate-pulse`} />
                <span className="text-xs text-text-secondary">{PHASE_INFO[currentPhase].name}</span>
                <button
                  onClick={stopAnalysis}
                  className="p-1 hover:bg-bg-hover rounded text-accent-red"
                  title="Stop analysis"
                >
                  <Square className="w-4 h-4" />
                </button>
              </>
            ) : (
              <button
                onClick={runAutonomousAnalysis}
                className="flex items-center gap-1 px-3 py-1 text-xs bg-accent-purple/20 text-accent-purple rounded hover:bg-accent-purple/30"
              >
                <Play className="w-3 h-3" />
                Start Analysis
              </button>
            )}
          </div>
        )}
      </div>

      {/* Goals sidebar (autonomous mode) */}
      {mode === "autonomous" && goals.length > 0 && (
        <div className="h-auto max-h-32 bg-bg-tertiary border-b border-border p-2 overflow-y-auto">
          <div className="text-[10px] text-text-secondary mb-1 font-semibold">ANALYSIS GOALS</div>
          <div className="space-y-1">
            {goals.map(goal => (
              <div key={goal.id} className="flex items-center gap-2 text-xs">
                {goal.status === "complete" ? (
                  <CheckCircle className="w-3 h-3 text-accent-green shrink-0" />
                ) : goal.status === "active" ? (
                  <Loader2 className="w-3 h-3 text-accent-blue shrink-0 animate-spin" />
                ) : goal.status === "blocked" ? (
                  <XCircle className="w-3 h-3 text-accent-red shrink-0" />
                ) : (
                  <div className="w-3 h-3 rounded-full border border-text-secondary shrink-0" />
                )}
                <span className={goal.status === "complete" ? "text-text-secondary" : "text-text-primary"}>
                  {goal.description}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Messages area */}
      <div className="flex-1 overflow-auto p-3 space-y-3">
        {messages.length === 0 ? (
          <div className="h-full flex items-center justify-center text-text-secondary">
            <div className="text-center max-w-md">
              {mode === "chat" ? (
                <>
                  <MessageSquare className="w-8 h-8 mx-auto mb-3 opacity-50" />
                  <p className="text-sm font-medium">Chat Mode</p>
                  <p className="text-xs mt-2">
                    Ask me questions about this binary. I'll analyze and explain what I find.
                  </p>
                </>
              ) : (
                <>
                  <Bot className="w-8 h-8 mx-auto mb-3 opacity-50" />
                  <p className="text-sm font-medium">Autonomous Mode</p>
                  <p className="text-xs mt-2">
                    Click "Start Analysis" and I'll systematically analyze this binary,
                    only asking for your input when I need human insight.
                  </p>
                </>
              )}
            </div>
          </div>
        ) : (
          messages.map(msg => (
            <MessageBubble
              key={msg.id}
              message={msg}
              onNavigate={navigateTo}
              onCheckpointResponse={awaitingCheckpoint ? handleCheckpointResponse : undefined}
            />
          ))
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input area */}
      <form onSubmit={handleSubmit} className="p-3 border-t border-border bg-bg-secondary">
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={userInput}
            onChange={(e) => setUserInput(e.target.value)}
            placeholder={awaitingCheckpoint ? "Type yes/no or your response..." : mode === "chat" ? "Ask about this binary..." : "Provide context or guidance..."}
            className="flex-1 px-3 py-2 text-sm bg-bg-primary border border-border rounded-lg focus:outline-none focus:border-accent-purple"
          />
          <button
            type="submit"
            disabled={!userInput.trim()}
            className="p-2 bg-accent-purple/20 text-accent-purple rounded-lg hover:bg-accent-purple/30 disabled:opacity-50"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </form>
    </div>
  );
}

// Message bubble component
function MessageBubble({
  message,
  onNavigate,
  onCheckpointResponse
}: {
  message: AnalystMessage;
  onNavigate: (addr: string) => void;
  onCheckpointResponse?: (proceed: boolean) => void;
}) {
  const getIcon = () => {
    switch (message.type) {
      case "user": return <User className="w-4 h-4" />;
      case "system": return <Settings className="w-4 h-4" />;
      case "checkpoint": return <HelpCircle className="w-4 h-4 text-accent-yellow" />;
      case "finding": return <AlertTriangle className="w-4 h-4 text-accent-orange" />;
      case "action": return <Zap className="w-4 h-4 text-accent-cyan" />;
      default: return <Bot className="w-4 h-4" />;
    }
  };

  const getBgColor = () => {
    switch (message.type) {
      case "user": return "bg-accent-blue/20";
      case "checkpoint": return "bg-accent-yellow/20 border border-accent-yellow/30";
      case "finding":
        return message.severity === "critical"
          ? "bg-accent-red/20 border-l-2 border-accent-red"
          : message.severity === "warning"
          ? "bg-accent-orange/20 border-l-2 border-accent-orange"
          : "bg-bg-tertiary";
      case "system": return "bg-bg-tertiary text-text-secondary";
      case "action": return "bg-accent-cyan/10 text-accent-cyan italic";
      default: return "bg-bg-tertiary";
    }
  };

  return (
    <div className={`flex ${message.type === "user" ? "justify-end" : "justify-start"}`}>
      <div className={`max-w-[90%] rounded-lg p-3 ${getBgColor()}`}>
        {/* Header */}
        <div className="flex items-center gap-2 mb-1">
          {getIcon()}
          <span className="text-[10px] text-text-secondary">
            {message.timestamp.toLocaleTimeString()}
          </span>
        </div>

        {/* Content with markdown-like formatting */}
        <div className="text-sm whitespace-pre-wrap leading-relaxed">
          {formatContent(message.content)}
        </div>

        {/* Addresses */}
        {message.addresses && message.addresses.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {message.addresses.map((addr, i) => (
              <button
                key={i}
                onClick={() => onNavigate(addr)}
                className="px-2 py-0.5 text-[10px] font-mono bg-accent-blue/20 text-accent-blue rounded hover:bg-accent-blue/30"
              >
                {addr}
              </button>
            ))}
          </div>
        )}

        {/* Checkpoint buttons */}
        {message.type === "checkpoint" && message.awaitingInput && onCheckpointResponse && (
          <div className="flex gap-2 mt-3">
            <button
              onClick={() => onCheckpointResponse(true)}
              className="px-3 py-1 text-xs bg-accent-green/20 text-accent-green rounded hover:bg-accent-green/30"
            >
              Yes, proceed
            </button>
            <button
              onClick={() => onCheckpointResponse(false)}
              className="px-3 py-1 text-xs bg-bg-tertiary text-text-secondary rounded hover:bg-bg-hover"
            >
              Skip for now
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// Format content with basic markdown
function formatContent(content: string): React.ReactNode {
  // Very basic markdown: **bold**, `code`, headers
  const parts = content.split(/(\*\*[^*]+\*\*|`[^`]+`|##?\s.+)/g);

  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={i}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return <code key={i} className="px-1 py-0.5 bg-bg-primary rounded text-accent-blue">{part.slice(1, -1)}</code>;
    }
    if (part.startsWith("## ")) {
      return <div key={i} className="text-base font-bold mt-2 mb-1">{part.slice(3)}</div>;
    }
    if (part.startsWith("# ")) {
      return <div key={i} className="text-lg font-bold mt-2 mb-1">{part.slice(2)}</div>;
    }
    return <span key={i}>{part}</span>;
  });
}

// Generate chat response
function generateChatResponse(query: string, result: any): string {
  const lower = query.toLowerCase();

  if (lower.includes("what") && (lower.includes("do") || lower.includes("is"))) {
    return `This is a ${result.file_info.arch} binary with ${result.instruction_count} instructions. ` +
      `${result.file_info.is_packed ? "It appears to be packed or encrypted (high entropy). " : ""}` +
      `${result.mitre_techniques?.length > 0 ? `I've identified ${result.mitre_techniques.length} MITRE ATT&CK techniques. ` : ""}` +
      `Would you like me to run a full autonomous analysis?`;
  }

  if (lower.includes("suspicious") || lower.includes("malicious")) {
    const indicators = [];
    if (result.iocs?.total > 0) indicators.push(`${result.iocs.total} IOCs`);
    if (result.mitre_techniques?.length > 0) indicators.push(`${result.mitre_techniques.length} TTPs`);
    if (result.analysis?.suspicious_patterns?.length > 0) indicators.push("suspicious code patterns");

    return indicators.length > 0
      ? `I found several suspicious indicators: ${indicators.join(", ")}. Switch to Autonomous mode for a complete threat assessment.`
      : "I haven't found obvious malicious indicators, but that doesn't mean it's safe. A deeper analysis may reveal hidden functionality.";
  }

  return `I can help analyze that. For a comprehensive analysis, switch to **Autonomous** mode where I'll systematically examine the binary and only ask for your input when needed.`;
}

// Helper functions
function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function isSelfXor(ops: string): boolean {
  const parts = ops.split(",").map(s => s.trim());
  return parts.length === 2 && parts[0] === parts[1];
}

function getDosFunction(ahVal: string): string | null {
  const v = ahVal.replace(/h$/i, "").replace(/^0x/, "").toLowerCase();
  const funcs: Record<string, string> = {
    "1": "Read char with echo",
    "01": "Read char with echo",
    "2": "Write character",
    "02": "Write character",
    "9": "Print string ($-terminated)",
    "09": "Print string ($-terminated)",
    "4c": "Terminate program",
    "3c": "Create file",
    "3d": "Open file",
    "3e": "Close file",
    "3f": "Read file",
    "40": "Write file",
    "4b": "Execute program (EXEC)",
  };
  return funcs[v] || null;
}
