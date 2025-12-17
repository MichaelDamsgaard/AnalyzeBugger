import { useState, useRef, useEffect } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import {
  MessageSquare, Send, Loader2, Sparkles,
  Copy, Check, Trash2
} from "lucide-react";

interface QueryMessage {
  id: number;
  type: "user" | "assistant";
  content: string;
  timestamp: Date;
  codeBlocks?: { address: string; code: string }[];
  highlights?: string[];
}

// Example queries to help users
const EXAMPLE_QUERIES = [
  "What does this binary do?",
  "Find the main function",
  "Are there any suspicious API calls?",
  "Show me all string references",
  "What encryption is used?",
  "Find functions that access the network",
  "Explain the function at 0x0100",
  "What MITRE techniques are present?",
  "Generate a YARA rule for this sample",
  "Summarize the malware behavior",
];

export function AIQueryPanel() {
  const { result, navigateTo } = useAnalysisStore();
  const [messages, setMessages] = useState<QueryMessage[]>([]);
  const [input, setInput] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const [copied, setCopied] = useState<number | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const processQuery = async (query: string) => {
    if (!query.trim() || !result) return;

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

    // Generate AI response based on query and analysis data
    // In production, this would call Claude API with full context
    const response = await generateAIResponse(query, result);

    const assistantMsg: QueryMessage = {
      id: Date.now() + 1,
      type: "assistant",
      content: response.text,
      timestamp: new Date(),
      codeBlocks: response.codeBlocks,
      highlights: response.highlights
    };
    setMessages(prev => [...prev, assistantMsg]);
    setIsProcessing(false);
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
          <p className="text-sm">AI Query Assistant</p>
          <p className="text-xs mt-1">Analyze a file to ask questions</p>
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
          <span className="px-1.5 py-0.5 text-[10px] bg-accent-blue/20 text-accent-blue rounded">
            Natural Language
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

      {/* Messages area */}
      <div className="flex-1 overflow-auto p-3 space-y-3">
        {messages.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-text-secondary">
            <Sparkles className="w-8 h-8 mb-3 opacity-50" />
            <p className="text-sm font-medium mb-4">Ask anything about this binary</p>
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
                className={`max-w-[85%] rounded-lg p-3 ${
                  msg.type === "user"
                    ? "bg-accent-blue/20 text-text-primary"
                    : "bg-bg-tertiary"
                }`}
              >
                {/* Message content */}
                <div className="text-sm whitespace-pre-wrap leading-relaxed">
                  {msg.content}
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

                {/* Highlighted addresses */}
                {msg.highlights && msg.highlights.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {msg.highlights.map((addr, idx) => (
                      <button
                        key={idx}
                        onClick={() => navigateTo(addr)}
                        className="px-1.5 py-0.5 text-[10px] font-mono bg-accent-purple/20 text-accent-purple rounded hover:bg-accent-purple/30"
                      >
                        {addr}
                      </button>
                    ))}
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
              <Loader2 className="w-4 h-4 animate-spin text-accent-blue" />
              <span className="text-sm text-text-secondary">Analyzing...</span>
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
            placeholder="Ask about this binary..."
            disabled={isProcessing}
            className="flex-1 px-3 py-2 text-sm bg-bg-primary border border-border rounded-lg focus:outline-none focus:border-accent-blue disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={isProcessing || !input.trim()}
            className="p-2 bg-accent-blue/20 text-accent-blue rounded-lg hover:bg-accent-blue/30 disabled:opacity-50 transition-colors"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </form>
    </div>
  );
}

// Generate AI response based on query
// In production, this calls Claude API with full binary context
async function generateAIResponse(
  query: string,
  result: any
): Promise<{ text: string; codeBlocks?: { address: string; code: string }[]; highlights?: string[] }> {
  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 500));

  const lowerQuery = query.toLowerCase();

  // Pattern matching for common queries
  if (lowerQuery.includes("what does") && lowerQuery.includes("do")) {
    const arch = result.file_info.arch;
    const isPacked = result.file_info.is_packed;
    const hasNet = result.iocs?.urls?.length > 0 || result.iocs?.ips?.length > 0;
    const hasCrypto = result.crypto?.count > 0;

    let behavior = `This is a ${arch} binary`;
    if (isPacked) behavior += " that appears to be packed or obfuscated (high entropy detected)";
    if (hasNet) behavior += ". It contains network indicators suggesting C2 communication capability";
    if (hasCrypto) behavior += ". Cryptographic patterns were detected which may indicate encryption or encoding routines";

    behavior += `.\n\nKey findings:\n`;
    behavior += `- ${result.instruction_count} instructions analyzed\n`;
    behavior += `- ${result.string_count} strings extracted\n`;
    behavior += `- ${result.mitre_techniques?.length || 0} MITRE ATT&CK techniques identified\n`;
    behavior += `- ${result.iocs?.total || 0} IOCs extracted`;

    return { text: behavior };
  }

  if (lowerQuery.includes("main") || lowerQuery.includes("entry")) {
    const entryPoint = result.instructions[0]?.address;
    const entryCode = result.instructions.slice(0, 10).map((i: { address: string; mnemonic: string; op_str: string }) =>
      `${i.address}: ${i.mnemonic} ${i.op_str}`
    ).join("\n");

    return {
      text: `The entry point is at ${entryPoint}. Here's the code at program start:`,
      codeBlocks: [{ address: entryPoint, code: entryCode }],
      highlights: [entryPoint]
    };
  }

  if (lowerQuery.includes("suspicious") || lowerQuery.includes("malicious")) {
    const suspicious = [];
    if (result.analysis?.suspicious_patterns?.length > 0) {
      suspicious.push(...result.analysis.suspicious_patterns.map((p: { type: string; address: string; pattern: string }) =>
        `- ${p.type} at ${p.address}: ${p.pattern}`
      ));
    }
    if (result.mitre_techniques?.length > 0) {
      suspicious.push("\nMITRE ATT&CK techniques detected:");
      suspicious.push(...result.mitre_techniques.map((t: { id: string; name: string; tactic: string; evidence: string }) =>
        `- ${t.id}: ${t.name} (${t.tactic}) - ${t.evidence}`
      ));
    }

    if (suspicious.length === 0) {
      return { text: "No obviously suspicious patterns detected in static analysis. This doesn't mean the binary is safe - further dynamic analysis is recommended." };
    }

    return {
      text: "Suspicious indicators found:\n\n" + suspicious.join("\n"),
      highlights: result.analysis?.suspicious_patterns?.map((p: { address: string }) => p.address) || []
    };
  }

  if (lowerQuery.includes("string")) {
    const strings = result.strings.slice(0, 15);
    const formatted = strings.map((s: { offset: string; value: string }) => `${s.offset}: "${s.value}"`).join("\n");
    return {
      text: `Found ${result.string_count} strings. Here are the most notable ones:\n\n${formatted}`,
      highlights: strings.map((s: { offset: string }) => s.offset)
    };
  }

  if (lowerQuery.includes("encrypt") || lowerQuery.includes("crypto")) {
    if (result.crypto?.count > 0) {
      const findings = result.crypto.findings.map((f: { type: string; offset: string; confidence: number; pattern: string }) =>
        `- ${f.type} detected at ${f.offset} (${Math.round(f.confidence * 100)}% confidence): ${f.pattern}`
      ).join("\n");
      return {
        text: `Cryptographic patterns detected:\n\n${findings}`,
        highlights: result.crypto.findings.map((f: { offset: string }) => f.offset)
      };
    }
    return { text: "No standard cryptographic patterns detected. The binary may use custom or obfuscated encryption." };
  }

  if (lowerQuery.includes("mitre") || lowerQuery.includes("technique") || lowerQuery.includes("ttp")) {
    if (result.mitre_techniques?.length > 0) {
      const techniques = result.mitre_techniques.map((t: { id: string; name: string; tactic: string; evidence: string; confidence: number }) =>
        `**${t.id}** - ${t.name}\n  Tactic: ${t.tactic}\n  Evidence: ${t.evidence}\n  Confidence: ${Math.round(t.confidence * 100)}%`
      ).join("\n\n");
      return { text: `MITRE ATT&CK Techniques Identified:\n\n${techniques}` };
    }
    return { text: "No MITRE ATT&CK techniques were identified with high confidence." };
  }

  if (lowerQuery.includes("yara")) {
    const name = result.file_info.name.replace(/[^a-zA-Z0-9]/g, "_");
    const strings = result.strings.slice(0, 5).map((s: { value: string }, i: number) =>
      `    $s${i} = "${s.value.replace(/"/g, '\\"')}"`
    ).join("\n");

    const rule = `rule ${name}_detection {
  meta:
    description = "Auto-generated YARA rule for ${result.file_info.name}"
    author = "AnalyzeBugger AI"
    date = "${new Date().toISOString().split('T')[0]}"

  strings:
${strings}

  condition:
    2 of them
}`;

    return {
      text: "Generated YARA rule based on extracted strings:",
      codeBlocks: [{ address: "YARA", code: rule }]
    };
  }

  if (lowerQuery.includes("network") || lowerQuery.includes("c2") || lowerQuery.includes("communication")) {
    const urls = result.iocs?.urls || [];
    const ips = result.iocs?.ips || [];
    const domains = result.iocs?.domains || [];

    if (urls.length + ips.length + domains.length === 0) {
      return { text: "No network indicators found in static analysis. The binary may resolve addresses dynamically or use encoded/encrypted network strings." };
    }

    let response = "Network indicators found:\n\n";
    if (urls.length > 0) response += "URLs:\n" + urls.map((u: { defanged?: string; value: string }) => `- ${u.defanged || u.value}`).join("\n") + "\n\n";
    if (ips.length > 0) response += "IP Addresses:\n" + ips.map((i: { defanged?: string; value: string }) => `- ${i.defanged || i.value}`).join("\n") + "\n\n";
    if (domains.length > 0) response += "Domains:\n" + domains.map((d: { defanged?: string; value: string }) => `- ${d.defanged || d.value}`).join("\n");

    return { text: response };
  }

  if (lowerQuery.includes("explain") && lowerQuery.includes("0x")) {
    const addrMatch = lowerQuery.match(/0x[0-9a-fA-F]+/);
    if (addrMatch) {
      const addr = addrMatch[0].toLowerCase();
      const idx = result.instructions.findIndex((i: { address: string }) => i.address.toLowerCase() === addr);
      if (idx >= 0) {
        const context = result.instructions.slice(idx, idx + 10);
        const code = context.map((i: { address: string; mnemonic: string; op_str: string }) => `${i.address}: ${i.mnemonic} ${i.op_str}`).join("\n");
        return {
          text: `Code at ${addr}:`,
          codeBlocks: [{ address: addr, code }],
          highlights: [addr]
        };
      }
    }
    return { text: "Could not find the specified address in the disassembly." };
  }

  // Default response
  return {
    text: `I analyzed your query about "${query}". Based on the ${result.file_info.arch} binary:\n\n` +
          `This file contains ${result.instruction_count} instructions and ${result.string_count} strings. ` +
          `The entropy is ${result.file_info.entropy} which suggests ${parseFloat(result.file_info.entropy) > 7 ? "possible packing/encryption" : "normal code/data distribution"}.\n\n` +
          `Try asking more specific questions like:\n` +
          `- "What MITRE techniques are present?"\n` +
          `- "Show suspicious API calls"\n` +
          `- "Generate a YARA rule"\n` +
          `- "Explain the function at 0x0100"`
  };
}
