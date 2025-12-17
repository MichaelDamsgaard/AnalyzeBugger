import { useState, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Send, Bot, User, Loader2, Sparkles } from "lucide-react";
import { useSessionStore } from "../../stores/sessionStore";

interface Message {
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
}

export function ChatPanel() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const { status, registers, disassembly } = useSessionStore();

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage = input.trim();
    setInput("");
    setMessages((prev) => [
      ...prev,
      { role: "user", content: userMessage, timestamp: new Date() },
    ]);

    setIsLoading(true);

    try {
      // Build context from current debugging state
      const context = buildContext();

      const response = await invoke<string>("ask_claude", {
        prompt: userMessage,
        context: JSON.stringify(context),
      });

      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: response, timestamp: new Date() },
      ]);
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: `Error: ${e}`,
          timestamp: new Date(),
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const buildContext = () => {
    return {
      session: status?.session || null,
      registers: registers || null,
      disassembly: disassembly.slice(0, 10) || [], // First 10 instructions
    };
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  // Quick action buttons
  const quickActions = [
    { label: "Analyze function", prompt: "What does this function do? Explain the disassembly." },
    { label: "Is it malicious?", prompt: "Based on the current context, could this be malicious code? Explain your reasoning." },
    { label: "Suggest names", prompt: "Suggest meaningful names for the registers based on how they're being used." },
  ];

  return (
    <div className="h-full flex flex-col bg-bg-primary">
      {/* Messages */}
      <div className="flex-1 overflow-auto p-3 space-y-3">
        {messages.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-text-secondary">
            <Sparkles className="w-8 h-8 mb-3 text-accent-purple" />
            <p className="text-sm">Claude AI Assistant</p>
            <p className="text-xs mt-1">Ask questions about the code you're analyzing</p>

            {/* Quick Actions */}
            <div className="mt-4 flex flex-wrap gap-2 justify-center max-w-sm">
              {quickActions.map((action) => (
                <button
                  key={action.label}
                  onClick={() => setInput(action.prompt)}
                  className="px-3 py-1.5 text-xs bg-bg-tertiary border border-border rounded hover:border-accent-purple transition-colors"
                >
                  {action.label}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, idx) => (
          <div
            key={idx}
            className={`flex gap-3 ${
              msg.role === "user" ? "justify-end" : "justify-start"
            }`}
          >
            {msg.role === "assistant" && (
              <div className="w-7 h-7 rounded-full bg-accent-purple/20 flex items-center justify-center flex-shrink-0">
                <Bot className="w-4 h-4 text-accent-purple" />
              </div>
            )}

            <div
              className={`max-w-[80%] rounded-lg px-3 py-2 text-sm ${
                msg.role === "user"
                  ? "bg-accent-blue/20 text-text-primary"
                  : "bg-bg-tertiary text-text-primary"
              }`}
            >
              <pre className="whitespace-pre-wrap font-sans">{msg.content}</pre>
              <div className="text-xs text-text-secondary mt-1">
                {msg.timestamp.toLocaleTimeString()}
              </div>
            </div>

            {msg.role === "user" && (
              <div className="w-7 h-7 rounded-full bg-accent-blue/20 flex items-center justify-center flex-shrink-0">
                <User className="w-4 h-4 text-accent-blue" />
              </div>
            )}
          </div>
        ))}

        {isLoading && (
          <div className="flex gap-3">
            <div className="w-7 h-7 rounded-full bg-accent-purple/20 flex items-center justify-center">
              <Loader2 className="w-4 h-4 text-accent-purple animate-spin" />
            </div>
            <div className="bg-bg-tertiary rounded-lg px-3 py-2 text-sm text-text-secondary">
              Thinking...
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="p-3 border-t border-border">
        <div className="flex gap-2">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask Claude about this code..."
            rows={2}
            className="flex-1 px-3 py-2 text-sm bg-bg-tertiary border border-border rounded resize-none focus:border-accent-purple focus:outline-none"
          />
          <button
            onClick={handleSend}
            disabled={!input.trim() || isLoading}
            className="px-3 py-2 bg-accent-purple text-bg-primary rounded hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed transition-opacity"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
