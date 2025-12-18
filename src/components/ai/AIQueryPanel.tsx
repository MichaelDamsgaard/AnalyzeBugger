/**
 * AI Query Panel - Real Claude Integration
 *
 * This panel provides direct access to Claude for binary analysis.
 * Claude IS the analyzer - this is not a simulation.
 */

import { useState, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useAnalysisStore } from "../../stores/analysisStore";
import { askClaude, type ClaudeResponse, type ClaudeAction } from "../../services/claudeService";
import { ApiKeyForm } from "./ApiKeyForm";
import {
  MessageSquare, Send, Loader2, Sparkles,
  Copy, Check, Trash2, AlertTriangle, AlertCircle, Info
} from "lucide-react";

interface QueryMessage {
  id: number;
  type: "user" | "assistant";
  content: string;
  timestamp: Date;
  codeBlocks?: { address: string; code: string }[];
  highlights?: string[];
  actions?: ClaudeAction[];
  findings?: ClaudeResponse["findings"];
  isError?: boolean;
}

// Example queries to help users get started
const EXAMPLE_QUERIES = [
  "What does this binary do?",
  "Find the main function and explain it",
  "Are there any suspicious patterns?",
  "What's the password/key?",
  "Explain the code at the entry point",
  "What MITRE techniques are present?",
  "Generate a YARA rule",
  "What system calls does it make?",
];

export function AIQueryPanel() {
  const { result, currentAddress, navigateTo, setLabel, setComment } = useAnalysisStore();
  const [messages, setMessages] = useState<QueryMessage[]>([]);
  const [input, setInput] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const [copied, setCopied] = useState<number | null>(null);
  const [hasApiKey, setHasApiKey] = useState<boolean | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Check if API key is configured on mount
  useEffect(() => {
    invoke<boolean>("has_api_key").then(setHasApiKey).catch(() => setHasApiKey(false));
  }, []);

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Show API key form if no key is configured
  if (hasApiKey === false) {
    return <ApiKeyForm onKeySet={() => setHasApiKey(true)} />;
  }

  // Apply actions from Claude's response
  const applyActions = (actions: ClaudeAction[]) => {
    for (const action of actions) {
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
  };

  const processQuery = async (query: string) => {
    console.log("[AIQueryPanel] processQuery called with:", query);
    console.log("[AIQueryPanel] result exists:", !!result);
    console.log("[AIQueryPanel] isProcessing:", isProcessing);

    if (!query.trim() || !result) {
      console.log("[AIQueryPanel] Early return - empty query or no result");
      return;
    }

    // Add user message
    const userMsg: QueryMessage = {
      id: Date.now(),
      type: "user",
      content: query,
      timestamp: new Date()
    };
    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setIsProcessing(true);

    try {
      // Call REAL Claude API via Tauri backend
      console.log("[AIQueryPanel] Calling askClaude...");
      const response = await askClaude(query, result, currentAddress || undefined);
      console.log("[AIQueryPanel] Response received:", response);

      const assistantMsg: QueryMessage = {
        id: Date.now() + 1,
        type: "assistant",
        content: response.text,
        timestamp: new Date(),
        highlights: response.highlights,
        actions: response.actions,
        findings: response.findings,
        isError: false
      };
      setMessages(prev => [...prev, assistantMsg]);

      // Apply any actions Claude suggested
      if (response.actions && response.actions.length > 0) {
        applyActions(response.actions);
      }
    } catch (error) {
      const errorMsg: QueryMessage = {
        id: Date.now() + 1,
        type: "assistant",
        content: `Error: ${error}`,
        timestamp: new Date(),
        isError: true
      };
      setMessages(prev => [...prev, errorMsg]);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    processQuery(input);
  };

  const copyToClipboard = (text: string, id: number) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 1500);
  };

  const clearHistory = () => {
    setMessages([]);
  };

  if (!result) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <MessageSquare className="w-10 h-10 mx-auto mb-3 opacity-50" />
          <p className="text-sm font-medium">Claude Analysis Interface</p>
          <p className="text-xs mt-1">Load a binary to begin analysis</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-10 bg-gradient-to-r from-accent-blue/20 to-accent-cyan/20 border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <MessageSquare className="w-5 h-5 text-accent-blue" />
          <span className="text-sm font-medium">Ask Claude</span>
          <span className="px-1.5 py-0.5 text-[10px] bg-accent-green/20 text-accent-green rounded">
            Live API
          </span>
        </div>
        {messages.length > 0 && (
          <button
            onClick={clearHistory}
            className="flex items-center gap-1 px-2 py-0.5 text-[10px] text-text-secondary hover:text-accent-red transition-colors"
          >
            <Trash2 className="w-3 h-3" />
            Clear
          </button>
        )}
      </div>

      {/* Context indicator */}
      <div className="px-3 py-1.5 bg-bg-tertiary border-b border-border text-[10px] text-text-secondary">
        <span className="text-accent-purple">{result.file_info.name}</span>
        <span className="mx-2">|</span>
        <span>{result.file_info.arch}</span>
        <span className="mx-2">|</span>
        <span>{result.instruction_count} instructions</span>
        {currentAddress && (
          <>
            <span className="mx-2">|</span>
            <span className="text-accent-blue">Focus: {currentAddress}</span>
          </>
        )}
      </div>

      {/* Messages area */}
      <div className="flex-1 overflow-auto p-3 space-y-3">
        {messages.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-text-secondary">
            <Sparkles className="w-8 h-8 mb-3 opacity-50 text-accent-purple" />
            <p className="text-sm font-medium mb-2">Claude Binary Analyst</p>
            <p className="text-xs text-center max-w-xs mb-4">
              I'm connected and ready to analyze. Ask me anything about this binary.
            </p>
            <div className="grid grid-cols-2 gap-2 max-w-md">
              {EXAMPLE_QUERIES.slice(0, 6).map((query, idx) => (
                <button
                  key={idx}
                  onClick={() => processQuery(query)}
                  className="px-3 py-2 text-xs text-left bg-bg-tertiary hover:bg-bg-hover rounded-lg transition-colors"
                >
                  {query}
                </button>
              ))}
            </div>
          </div>
        ) : (
          messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex ${msg.type === "user" ? "justify-end" : "justify-start"}`}
            >
              <div
                className={`max-w-[90%] rounded-lg p-3 ${
                  msg.type === "user"
                    ? "bg-accent-blue/20 text-text-primary"
                    : msg.isError
                    ? "bg-accent-red/20 border border-accent-red/30"
                    : "bg-bg-tertiary"
                }`}
              >
                {/* Findings badges */}
                {msg.findings && msg.findings.length > 0 && (
                  <div className="flex flex-wrap gap-1 mb-2">
                    {msg.findings.map((finding, idx) => (
                      <div
                        key={idx}
                        className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10px] ${
                          finding.type === "critical"
                            ? "bg-accent-red/20 text-accent-red"
                            : finding.type === "warning"
                            ? "bg-accent-yellow/20 text-accent-yellow"
                            : "bg-accent-blue/20 text-accent-blue"
                        }`}
                      >
                        {finding.type === "critical" ? (
                          <AlertCircle className="w-3 h-3" />
                        ) : finding.type === "warning" ? (
                          <AlertTriangle className="w-3 h-3" />
                        ) : (
                          <Info className="w-3 h-3" />
                        )}
                        {finding.title}
                      </div>
                    ))}
                  </div>
                )}

                {/* Message content */}
                <div className="text-sm whitespace-pre-wrap leading-relaxed">
                  {formatMarkdown(msg.content)}
                </div>

                {/* Code blocks */}
                {msg.codeBlocks && msg.codeBlocks.length > 0 && (
                  <div className="mt-2 space-y-2">
                    {msg.codeBlocks.map((block, idx) => (
                      <div key={idx} className="bg-bg-primary rounded p-2">
                        <div className="flex items-center justify-between mb-1">
                          <button
                            onClick={() => navigateTo(block.address)}
                            className="text-[10px] font-mono text-accent-blue hover:underline"
                          >
                            {block.address}
                          </button>
                          <button
                            onClick={() => copyToClipboard(block.code, msg.id * 100 + idx)}
                            className="p-0.5"
                          >
                            {copied === msg.id * 100 + idx ? (
                              <Check className="w-3 h-3 text-accent-green" />
                            ) : (
                              <Copy className="w-3 h-3 text-text-secondary" />
                            )}
                          </button>
                        </div>
                        <pre className="text-[11px] font-mono text-text-secondary overflow-x-auto">
                          {block.code}
                        </pre>
                      </div>
                    ))}
                  </div>
                )}

                {/* Highlighted addresses - clickable */}
                {msg.highlights && msg.highlights.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    <span className="text-[10px] text-text-secondary mr-1">Jump to:</span>
                    {msg.highlights.slice(0, 10).map((addr, idx) => (
                      <button
                        key={idx}
                        onClick={() => navigateTo(addr)}
                        className="px-1.5 py-0.5 text-[10px] font-mono bg-accent-purple/20 text-accent-purple rounded hover:bg-accent-purple/30"
                      >
                        {addr}
                      </button>
                    ))}
                    {msg.highlights.length > 10 && (
                      <span className="text-[10px] text-text-secondary">
                        +{msg.highlights.length - 10} more
                      </span>
                    )}
                  </div>
                )}

                {/* Actions applied */}
                {msg.actions && msg.actions.length > 0 && (
                  <div className="mt-2 text-[10px] text-accent-green">
                    Applied {msg.actions.length} action(s)
                  </div>
                )}

                {/* Timestamp */}
                <div className="mt-1 text-[10px] text-text-secondary">
                  {msg.timestamp.toLocaleTimeString()}
                </div>
              </div>
            </div>
          ))
        )}

        {/* Processing indicator */}
        {isProcessing && (
          <div className="flex justify-start">
            <div className="bg-bg-tertiary rounded-lg p-3 flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin text-accent-purple" />
              <span className="text-sm text-text-secondary">Claude is analyzing...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input area */}
      <form onSubmit={handleSubmit} className="p-3 border-t border-border bg-bg-secondary">
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask Claude about this binary..."
            disabled={isProcessing}
            className="flex-1 px-3 py-2 text-sm bg-bg-primary border border-border rounded-lg focus:outline-none focus:border-accent-purple disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={isProcessing || !input.trim()}
            className="p-2 bg-accent-purple/20 text-accent-purple rounded-lg hover:bg-accent-purple/30 disabled:opacity-50 transition-colors"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </form>
    </div>
  );
}

// Simple markdown formatting
function formatMarkdown(text: string): React.ReactNode {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`|```[\s\S]*?```)/g);

  return parts.map((part, i) => {
    if (part.startsWith("```") && part.endsWith("```")) {
      const code = part.slice(3, -3).replace(/^[a-z]+\n/, "");
      return (
        <pre key={i} className="my-2 p-2 bg-bg-primary rounded text-[11px] font-mono overflow-x-auto">
          {code}
        </pre>
      );
    }
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={i}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code key={i} className="px-1 py-0.5 bg-bg-primary rounded text-accent-cyan text-[11px]">
          {part.slice(1, -1)}
        </code>
      );
    }
    return <span key={i}>{part}</span>;
  });
}
