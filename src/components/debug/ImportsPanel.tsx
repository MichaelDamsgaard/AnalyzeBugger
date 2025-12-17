import { useState, useMemo } from "react";
import { useAnalysisStore, ImportFunction } from "../../stores/analysisStore";
import {
  Package, ChevronRight, ChevronDown, Search, Copy, Check,
  AlertTriangle, Shield
} from "lucide-react";

// Suspicious API categories for highlighting
const SUSPICIOUS_APIS: Record<string, { color: string; reason: string }> = {
  // Process injection
  "VirtualAlloc": { color: "text-accent-red", reason: "Memory allocation (injection)" },
  "VirtualAllocEx": { color: "text-accent-red", reason: "Remote memory allocation" },
  "WriteProcessMemory": { color: "text-accent-red", reason: "Process memory write" },
  "CreateRemoteThread": { color: "text-accent-red", reason: "Remote thread creation" },
  "NtWriteVirtualMemory": { color: "text-accent-red", reason: "NT memory write" },
  // Anti-debug
  "IsDebuggerPresent": { color: "text-accent-yellow", reason: "Anti-debug check" },
  "CheckRemoteDebuggerPresent": { color: "text-accent-yellow", reason: "Anti-debug check" },
  "NtQueryInformationProcess": { color: "text-accent-yellow", reason: "Process info (anti-debug)" },
  // Crypto
  "CryptEncrypt": { color: "text-accent-purple", reason: "Encryption API" },
  "CryptDecrypt": { color: "text-accent-purple", reason: "Decryption API" },
  "CryptGenKey": { color: "text-accent-purple", reason: "Key generation" },
  // Network
  "InternetOpen": { color: "text-accent-blue", reason: "Network initialization" },
  "InternetConnect": { color: "text-accent-blue", reason: "Network connection" },
  "HttpSendRequest": { color: "text-accent-blue", reason: "HTTP request" },
  "URLDownloadToFile": { color: "text-accent-blue", reason: "File download" },
  // Registry
  "RegCreateKey": { color: "text-accent-orange", reason: "Registry modification" },
  "RegSetValue": { color: "text-accent-orange", reason: "Registry modification" },
  // File operations
  "CreateFile": { color: "text-text-secondary", reason: "File operation" },
  "DeleteFile": { color: "text-accent-orange", reason: "File deletion" },
  // Process
  "CreateProcess": { color: "text-accent-yellow", reason: "Process creation" },
  "ShellExecute": { color: "text-accent-yellow", reason: "Shell execution" },
  "WinExec": { color: "text-accent-yellow", reason: "Process execution" },
};

export function ImportsPanel() {
  const { result, navigateTo } = useAnalysisStore();
  const [expandedDlls, setExpandedDlls] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState("");
  const [copiedAddr, setCopiedAddr] = useState<string | null>(null);
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState(false);

  const imports = result?.imports || [];

  // Filter and compute stats
  const { filteredImports, totalFunctions, suspiciousCount } = useMemo(() => {
    let total = 0;
    let suspicious = 0;

    const filtered = imports.map(entry => {
      const matchingFns = entry.functions.filter(fn => {
        const matchesFilter = !filter ||
          fn.name.toLowerCase().includes(filter.toLowerCase()) ||
          entry.dll.toLowerCase().includes(filter.toLowerCase());

        const isSuspicious = Object.keys(SUSPICIOUS_APIS).some(api =>
          fn.name.toLowerCase().includes(api.toLowerCase())
        );

        if (isSuspicious) suspicious++;
        total++;

        if (showSuspiciousOnly && !isSuspicious) return false;
        return matchesFilter;
      });

      return { ...entry, functions: matchingFns };
    }).filter(entry => entry.functions.length > 0);

    return { filteredImports: filtered, totalFunctions: total, suspiciousCount: suspicious };
  }, [imports, filter, showSuspiciousOnly]);

  const toggleDll = (dll: string) => {
    setExpandedDlls(prev => {
      const next = new Set(prev);
      if (next.has(dll)) {
        next.delete(dll);
      } else {
        next.add(dll);
      }
      return next;
    });
  };

  const expandAll = () => {
    setExpandedDlls(new Set(imports.map(e => e.dll)));
  };

  const collapseAll = () => {
    setExpandedDlls(new Set());
  };

  const copyAddress = (addr: string) => {
    navigator.clipboard.writeText(addr);
    setCopiedAddr(addr);
    setTimeout(() => setCopiedAddr(null), 1500);
  };

  if (!result) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <Package className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No imports</p>
          <p className="text-xs mt-1">Analyze a PE file to view imports</p>
        </div>
      </div>
    );
  }

  if (imports.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <Package className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No imports found</p>
          <p className="text-xs mt-1">This may be a non-PE file or statically linked</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-8 bg-bg-secondary border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <Package className="w-4 h-4 text-accent-blue" />
          <span className="text-sm font-medium">Imports (IAT)</span>
          <span className="text-xs text-text-secondary">
            {imports.length} DLLs, {totalFunctions} functions
          </span>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={expandAll}
            className="px-1.5 py-0.5 text-[10px] text-text-secondary hover:text-text-primary"
          >
            Expand
          </button>
          <button
            onClick={collapseAll}
            className="px-1.5 py-0.5 text-[10px] text-text-secondary hover:text-text-primary"
          >
            Collapse
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="h-8 bg-bg-tertiary border-b border-border flex items-center px-2 gap-2">
        <Search className="w-3 h-3 text-text-secondary" />
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter imports..."
          className="flex-1 bg-transparent text-xs focus:outline-none"
        />
        <button
          onClick={() => setShowSuspiciousOnly(!showSuspiciousOnly)}
          className={`flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded ${
            showSuspiciousOnly
              ? "bg-accent-red/20 text-accent-red"
              : "text-text-secondary hover:text-text-primary"
          }`}
        >
          <AlertTriangle className="w-3 h-3" />
          {suspiciousCount}
        </button>
      </div>

      {/* Import list */}
      <div className="flex-1 overflow-auto">
        {filteredImports.map((entry) => (
          <div key={entry.dll} className="border-b border-border/50">
            {/* DLL header */}
            <button
              onClick={() => toggleDll(entry.dll)}
              className="w-full px-2 py-1.5 flex items-center gap-2 hover:bg-bg-hover transition-colors text-left"
            >
              {expandedDlls.has(entry.dll) ? (
                <ChevronDown className="w-3 h-3 text-text-secondary" />
              ) : (
                <ChevronRight className="w-3 h-3 text-text-secondary" />
              )}
              <Package className="w-3 h-3 text-accent-blue" />
              <span className="text-xs font-medium text-text-primary flex-1">
                {entry.dll}
              </span>
              <span className="text-[10px] text-text-secondary">
                {entry.functions.length} functions
              </span>
              <span className="text-[10px] text-text-secondary font-mono">
                {entry.iat_rva}
              </span>
            </button>

            {/* Functions */}
            {expandedDlls.has(entry.dll) && (
              <div className="bg-bg-tertiary/50">
                {entry.functions.map((fn, idx) => (
                  <FunctionRow
                    key={idx}
                    fn={fn}
                    copied={copiedAddr === fn.iat_address}
                    onCopy={() => copyAddress(fn.iat_address)}
                    onNavigate={() => navigateTo(fn.iat_address)}
                  />
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Footer */}
      <div className="h-6 bg-bg-secondary border-t border-border flex items-center justify-between px-3 text-[10px] text-text-secondary">
        <span>
          {showSuspiciousOnly ? `${suspiciousCount} suspicious` : `${totalFunctions} total`} imports
        </span>
        <span>Click address to navigate</span>
      </div>
    </div>
  );
}

function FunctionRow({
  fn,
  copied,
  onCopy,
  onNavigate,
}: {
  fn: ImportFunction;
  copied: boolean;
  onCopy: () => void;
  onNavigate: () => void;
}) {
  // Check if this is a suspicious API
  const suspiciousInfo = Object.entries(SUSPICIOUS_APIS).find(([api]) =>
    fn.name.toLowerCase().includes(api.toLowerCase())
  );

  return (
    <div className="px-4 py-1 flex items-center gap-2 hover:bg-bg-hover text-xs border-t border-border/30">
      {/* Warning icon for suspicious */}
      {suspiciousInfo ? (
        <Shield className={`w-3 h-3 ${suspiciousInfo[1].color} flex-shrink-0`} />
      ) : (
        <div className="w-3" />
      )}

      {/* Function name */}
      <span
        className={`flex-1 font-mono truncate ${
          suspiciousInfo ? suspiciousInfo[1].color : "text-text-primary"
        }`}
        title={suspiciousInfo ? suspiciousInfo[1].reason : undefined}
      >
        {fn.name}
      </span>

      {/* Ordinal/hint */}
      {fn.ordinal !== null && (
        <span className="text-[10px] text-text-secondary">
          #{fn.ordinal}
        </span>
      )}
      {fn.hint !== null && (
        <span className="text-[10px] text-text-secondary">
          h:{fn.hint}
        </span>
      )}

      {/* IAT address */}
      <button
        onClick={onNavigate}
        className="font-mono text-accent-blue hover:underline"
      >
        {fn.iat_address}
      </button>

      {/* Copy button */}
      <button
        onClick={(e) => { e.stopPropagation(); onCopy(); }}
        className="p-0.5 hover:bg-bg-hover rounded"
      >
        {copied ? (
          <Check className="w-3 h-3 text-accent-green" />
        ) : (
          <Copy className="w-3 h-3 text-text-secondary" />
        )}
      </button>
    </div>
  );
}
