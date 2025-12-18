/**
 * Autonomous Analyst - Real Claude Integration
 *
 * Claude performs systematic binary analysis with minimal human intervention.
 * The human provides guidance and context; Claude does the actual analysis.
 */

import { useState, useRef, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useAnalysisStore } from "../../stores/analysisStore";
import { runAnalysisPhase, askClaude, type AnalysisPhase, type ClaudeResponse } from "../../services/claudeService";
import { ApiKeyForm } from "./ApiKeyForm";
import {
  Bot, User, Play, Square, Sparkles,
  AlertTriangle, ChevronRight, Loader2,
  Eye, Cpu, Lock, FileSearch, Zap, CheckCircle,
  XCircle, MessageSquare, RotateCcw
} from "lucide-react";

type AnalystMode = "chat" | "autonomous";
type MessageType = "system" | "analyst" | "finding" | "checkpoint" | "user" | "action" | "error";

interface AnalystMessage {
  id: number;
  type: MessageType;
  content: string;
  timestamp: Date;
  phase?: AnalysisPhase;
  severity?: "info" | "warning" | "critical";
  addresses?: string[];
  awaitingInput?: boolean;
}

interface AnalysisGoal {
  id: string;
  description: string;
  phase: AnalysisPhase;
  status: "pending" | "active" | "complete" | "failed";
  findings: string[];
}

// Analysis phases with their display info
const PHASE_INFO: Record<AnalysisPhase, { name: string; icon: typeof Eye; color: string }> = {
  reconnaissance: { name: "Reconnaissance", icon: Eye, color: "text-accent-blue" },
  static_analysis: { name: "Static Analysis", icon: FileSearch, color: "text-accent-purple" },
  string_analysis: { name: "String Analysis", icon: MessageSquare, color: "text-accent-cyan" },
  control_flow: { name: "Control Flow", icon: Zap, color: "text-accent-yellow" },
  behavioral: { name: "Behavioral Analysis", icon: Cpu, color: "text-accent-orange" },
  threat_assessment: { name: "Threat Assessment", icon: Lock, color: "text-accent-red" },
  complete: { name: "Complete", icon: CheckCircle, color: "text-accent-green" },
};

export function AutonomousAnalyst() {
  const { result, navigateTo, setLabel, setComment } = useAnalysisStore();

  const [mode, setMode] = useState<AnalystMode>("autonomous");
  const [messages, setMessages] = useState<AnalystMessage[]>([]);
  const [userInput, setUserInput] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentPhase, setCurrentPhase] = useState<AnalysisPhase>("reconnaissance");
  const [goals, setGoals] = useState<AnalysisGoal[]>([]);
  const [allFindings, setAllFindings] = useState<string>("");
  const [hasApiKey, setHasApiKey] = useState<boolean | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const analysisRef = useRef<{ cancelled: boolean }>({ cancelled: false });

  // Check if API key is configured on mount
  useEffect(() => {
    invoke<boolean>("has_api_key").then(setHasApiKey).catch(() => setHasApiKey(false));
  }, []);

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
      id: Date.now() + Math.random(),
      type,
      content,
      timestamp: new Date(),
      ...options
    }]);
  }, []);

  // Apply actions from Claude's response
  const applyActions = useCallback((response: ClaudeResponse) => {
    if (!response.actions) return;

    for (const action of response.actions) {
      switch (action.type) {
        case "navigate":
          if (action.address) navigateTo(action.address);
          break;
        case "label":
          if (action.address && action.name) {
            setLabel(action.address, action.name, "function");
          }
          break;
        case "comment":
          if (action.address && action.value) {
            setComment(action.address, action.value);
          }
          break;
      }
    }
  }, [navigateTo, setLabel, setComment]);

  // Run autonomous analysis with Claude
  const runAutonomousAnalysis = useCallback(async () => {
    if (!result) return;

    analysisRef.current.cancelled = false;
    setIsAnalyzing(true);
    setAllFindings("");

    // Initialize goals
    const analysisGoals: AnalysisGoal[] = [
      { id: "recon", description: "Identify binary type and structure", phase: "reconnaissance", status: "pending", findings: [] },
      { id: "static", description: "Analyze code patterns and functions", phase: "static_analysis", status: "pending", findings: [] },
      { id: "strings", description: "Extract and analyze strings", phase: "string_analysis", status: "pending", findings: [] },
      { id: "flow", description: "Trace control flow and logic", phase: "control_flow", status: "pending", findings: [] },
      { id: "behavior", description: "Determine program behavior", phase: "behavioral", status: "pending", findings: [] },
      { id: "threat", description: "Assess threat level", phase: "threat_assessment", status: "pending", findings: [] },
    ];
    setGoals(analysisGoals);

    addMessage("system", "Starting autonomous analysis. Claude will systematically examine this binary and report findings.", {
      phase: "reconnaissance"
    });

    let cumulativeFindings = "";
    const phases: AnalysisPhase[] = [
      "reconnaissance",
      "static_analysis",
      "string_analysis",
      "control_flow",
      "behavioral",
      "threat_assessment"
    ];

    for (let i = 0; i < phases.length; i++) {
      if (analysisRef.current.cancelled) {
        addMessage("system", "Analysis cancelled by user.");
        break;
      }

      const phase = phases[i];
      const goalId = analysisGoals[i].id;
      const phaseInfo = PHASE_INFO[phase];

      // Update current phase
      setCurrentPhase(phase);
      setGoals(prev => prev.map(g =>
        g.id === goalId ? { ...g, status: "active" } : g
      ));

      addMessage("action", `${phaseInfo.name}...`, { phase });

      try {
        // Call Claude for this phase
        const response = await runAnalysisPhase(phase, result, cumulativeFindings);

        if (analysisRef.current.cancelled) break;

        // Determine severity based on content
        let severity: "info" | "warning" | "critical" = "info";
        const lowerText = response.text.toLowerCase();
        if (lowerText.includes("critical") || lowerText.includes("malicious") || lowerText.includes("dangerous")) {
          severity = "critical";
        } else if (lowerText.includes("warning") || lowerText.includes("suspicious") || lowerText.includes("packed")) {
          severity = "warning";
        }

        addMessage("analyst", response.text, {
          phase,
          severity,
          addresses: response.highlights
        });

        // Apply any actions
        applyActions(response);

        // Accumulate findings
        cumulativeFindings += `\n\n## ${phaseInfo.name}\n${response.text}`;
        setAllFindings(cumulativeFindings);

        // Mark goal complete
        setGoals(prev => prev.map(g =>
          g.id === goalId ? { ...g, status: "complete", findings: [response.text.slice(0, 100)] } : g
        ));

      } catch (error) {
      console.error("[Autonomous] Error:", error);
        addMessage("error", `Error during ${phaseInfo.name}: ${error}`, { phase, severity: "critical" });
        setGoals(prev => prev.map(g =>
          g.id === goalId ? { ...g, status: "failed" } : g
        ));
      }

      // Small delay between phases for UX
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    if (!analysisRef.current.cancelled) {
      setCurrentPhase("complete");
      addMessage("system", "Autonomous analysis complete. You can ask follow-up questions in Chat mode or re-run the analysis.", {
        phase: "complete"
      });
    }

    setIsAnalyzing(false);
  }, [result, addMessage, applyActions]);

  // Handle chat message in chat mode
  const handleChatSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    console.log("[Autonomous] Submit called, input:", userInput);
    if (!userInput.trim() || !result) return;

    const query = userInput;
    setUserInput("");

    addMessage("user", query);
    setIsAnalyzing(true);

    try {
      // Include previous findings as context
      const contextualPrompt = allFindings
        ? `Previous analysis findings:\n${allFindings}\n\nFollow-up question: ${query}`
        : query;

      console.log("[Autonomous] Calling askClaude...");
      const response = await askClaude(contextualPrompt, result);
      console.log("[Autonomous] Got response:", response.text?.substring(0,100));

      addMessage("analyst", response.text, {
        addresses: response.highlights,
        severity: response.findings?.some(f => f.type === "critical") ? "critical"
          : response.findings?.some(f => f.type === "warning") ? "warning" : "info"
      });

      applyActions(response);
    } catch (error) {
      console.error("[Autonomous] Error:", error);
      addMessage("error", `Error: ${error}`);
    } finally {
      setIsAnalyzing(false);
    }
  }, [userInput, result, allFindings, addMessage, applyActions]);

  // Stop analysis
  const stopAnalysis = useCallback(() => {
    analysisRef.current.cancelled = true;
    setIsAnalyzing(false);
    addMessage("system", "Analysis stopped.");
  }, [addMessage]);

  // Reset and start fresh
  const resetAnalysis = useCallback(() => {
    setMessages([]);
    setGoals([]);
    setAllFindings("");
    setCurrentPhase("reconnaissance");
  }, []);

  // Show API key form if no key is configured
  if (hasApiKey === false) {
    return <ApiKeyForm onKeySet={() => setHasApiKey(true)} />;
  }

  // Render empty state
  if (!result) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <Bot className="w-10 h-10 mx-auto mb-3 opacity-50" />
          <p className="text-sm font-medium">Claude Autonomous Analyst</p>
          <p className="text-xs mt-1">Load a binary to begin analysis</p>
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
          <span className="text-sm font-medium">Claude Analyst</span>
          <span className="px-1.5 py-0.5 text-[10px] bg-accent-green/20 text-accent-green rounded">
            Live API
          </span>

          {/* Mode toggle */}
          <div className="flex items-center gap-1 ml-2 bg-bg-tertiary rounded p-0.5">
            <button
              onClick={() => setMode("autonomous")}
              className={`px-2 py-0.5 text-xs rounded transition-colors ${
                mode === "autonomous"
                  ? "bg-accent-purple/20 text-accent-purple"
                  : "text-text-secondary hover:text-text-primary"
              }`}
            >
              <Zap className="w-3 h-3 inline mr-1" />
              Auto
            </button>
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
          </div>
        </div>

        {/* Controls */}
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
          ) : mode === "autonomous" ? (
            <>
              {messages.length > 0 && (
                <button
                  onClick={resetAnalysis}
                  className="p-1 hover:bg-bg-hover rounded text-text-secondary"
                  title="Reset"
                >
                  <RotateCcw className="w-4 h-4" />
                </button>
              )}
              <button
                onClick={runAutonomousAnalysis}
                className="flex items-center gap-1 px-3 py-1 text-xs bg-accent-purple/20 text-accent-purple rounded hover:bg-accent-purple/30"
              >
                <Play className="w-3 h-3" />
                {messages.length > 0 ? "Re-analyze" : "Start Analysis"}
              </button>
            </>
          ) : null}
        </div>
      </div>

      {/* Progress goals (autonomous mode) */}
      {mode === "autonomous" && goals.length > 0 && (
        <div className="bg-bg-tertiary border-b border-border p-2 overflow-y-auto max-h-28">
          <div className="text-[10px] text-text-secondary mb-1 font-semibold">ANALYSIS PROGRESS</div>
          <div className="grid grid-cols-2 gap-1">
            {goals.map(goal => (
              <div key={goal.id} className="flex items-center gap-2 text-xs">
                {goal.status === "complete" ? (
                  <CheckCircle className="w-3 h-3 text-accent-green shrink-0" />
                ) : goal.status === "active" ? (
                  <Loader2 className="w-3 h-3 text-accent-blue shrink-0 animate-spin" />
                ) : goal.status === "failed" ? (
                  <XCircle className="w-3 h-3 text-accent-red shrink-0" />
                ) : (
                  <div className="w-3 h-3 rounded-full border border-text-secondary shrink-0" />
                )}
                <span className={`truncate ${goal.status === "complete" ? "text-text-secondary" : "text-text-primary"}`}>
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
              {mode === "autonomous" ? (
                <>
                  <Bot className="w-8 h-8 mx-auto mb-3 opacity-50" />
                  <p className="text-sm font-medium">Autonomous Analysis</p>
                  <p className="text-xs mt-2">
                    Click "Start Analysis" and Claude will systematically examine this binary,
                    identifying functions, behaviors, and potential threats.
                  </p>
                </>
              ) : (
                <>
                  <MessageSquare className="w-8 h-8 mx-auto mb-3 opacity-50" />
                  <p className="text-sm font-medium">Chat Mode</p>
                  <p className="text-xs mt-2">
                    Ask questions about this binary. Claude has full context from the disassembly,
                    strings, and any previous analysis.
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
            />
          ))
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input area (chat mode) */}
      {mode === "chat" && (
        <form onSubmit={handleChatSubmit} className="p-3 border-t border-border bg-bg-secondary">
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={userInput}
              onChange={(e) => setUserInput(e.target.value)}
              placeholder="Ask about this binary..."
              disabled={isAnalyzing}
              className="flex-1 px-3 py-2 text-sm bg-bg-primary border border-border rounded-lg focus:outline-none focus:border-accent-purple disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={!userInput.trim() || isAnalyzing}
              className="p-2 bg-accent-purple/20 text-accent-purple rounded-lg hover:bg-accent-purple/30 disabled:opacity-50"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

// Message bubble component
function MessageBubble({
  message,
  onNavigate
}: {
  message: AnalystMessage;
  onNavigate: (addr: string) => void;
}) {
  const getIcon = () => {
    switch (message.type) {
      case "user": return <User className="w-4 h-4" />;
      case "system": return <Sparkles className="w-4 h-4 text-accent-cyan" />;
      case "finding": return <AlertTriangle className="w-4 h-4 text-accent-orange" />;
      case "action": return <Zap className="w-4 h-4 text-accent-cyan" />;
      case "error": return <XCircle className="w-4 h-4 text-accent-red" />;
      default: return <Bot className="w-4 h-4 text-accent-purple" />;
    }
  };

  const getBgColor = () => {
    switch (message.type) {
      case "user": return "bg-accent-blue/20";
      case "error": return "bg-accent-red/20 border border-accent-red/30";
      case "system": return "bg-bg-tertiary text-text-secondary italic";
      case "action": return "bg-accent-cyan/10 text-accent-cyan italic text-xs";
      default:
        return message.severity === "critical"
          ? "bg-accent-red/10 border-l-2 border-accent-red"
          : message.severity === "warning"
          ? "bg-accent-yellow/10 border-l-2 border-accent-yellow"
          : "bg-bg-tertiary";
    }
  };

  // Skip rendering action messages in a minimal way
  if (message.type === "action") {
    return (
      <div className="flex items-center gap-2 text-xs text-accent-cyan py-1">
        <Loader2 className="w-3 h-3 animate-spin" />
        {message.content}
      </div>
    );
  }

  return (
    <div className={`flex ${message.type === "user" ? "justify-end" : "justify-start"}`}>
      <div className={`max-w-[95%] rounded-lg p-3 ${getBgColor()}`}>
        {/* Header */}
        <div className="flex items-center gap-2 mb-1">
          {getIcon()}
          <span className="text-[10px] text-text-secondary">
            {message.timestamp.toLocaleTimeString()}
          </span>
          {message.phase && message.type !== "system" && (
            <span className={`text-[10px] px-1.5 py-0.5 rounded ${PHASE_INFO[message.phase].color} bg-bg-secondary`}>
              {PHASE_INFO[message.phase].name}
            </span>
          )}
        </div>

        {/* Content with markdown-like formatting */}
        <div className="text-sm whitespace-pre-wrap leading-relaxed">
          {formatContent(message.content)}
        </div>

        {/* Addresses */}
        {message.addresses && message.addresses.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            <span className="text-[10px] text-text-secondary">Addresses:</span>
            {message.addresses.slice(0, 8).map((addr, i) => (
              <button
                key={i}
                onClick={() => onNavigate(addr)}
                className="px-1.5 py-0.5 text-[10px] font-mono bg-accent-purple/20 text-accent-purple rounded hover:bg-accent-purple/30"
              >
                {addr}
              </button>
            ))}
            {message.addresses.length > 8 && (
              <span className="text-[10px] text-text-secondary">+{message.addresses.length - 8} more</span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// Format content with basic markdown
function formatContent(content: string): React.ReactNode {
  const parts = content.split(/(\*\*[^*]+\*\*|`[^`]+`|##?\s.+)/g);

  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={i}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return <code key={i} className="px-1 py-0.5 bg-bg-primary rounded text-accent-cyan text-[11px]">{part.slice(1, -1)}</code>;
    }
    if (part.startsWith("## ")) {
      return <div key={i} className="text-sm font-bold mt-2 mb-1 text-accent-blue">{part.slice(3)}</div>;
    }
    if (part.startsWith("# ")) {
      return <div key={i} className="text-base font-bold mt-2 mb-1">{part.slice(2)}</div>;
    }
    return <span key={i}>{part}</span>;
  });
}
