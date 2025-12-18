import { useState, useMemo } from "react";
import {
  BarChart3, Lock, FileCode, AlertTriangle, ChevronDown,
  ChevronRight, Cpu, Layers, Binary
} from "lucide-react";
import { useAnalysisStore } from "../../stores/analysisStore";

// Section entropy data
interface SectionEntropy {
  name: string;
  entropy: number;
  size: number;
  characteristics: string[];
}

// Crypto detection
interface CryptoDetection {
  algorithm: string;
  address: string;
  confidence: number;
  context: string;
}

// Packer/compiler detection
interface PackerInfo {
  name: string;
  version?: string;
  confidence: number;
}

interface AnalysisData {
  fileInfo: {
    name: string;
    size: number;
    type: string;
    arch: string;
    subsystem: string;
    timestamp: string;
  };
  entropy: {
    overall: number;
    sections: SectionEntropy[];
  };
  crypto: CryptoDetection[];
  packer: PackerInfo | null;
  compiler: {
    name: string;
    version?: string;
    linker?: string;
  } | null;
  imports: {
    total: number;
    suspicious: number;
    categories: Record<string, number>;
  };
  strings: {
    total: number;
    interesting: number;
    encrypted: number;
  };
}

// No demo data - show empty state when no file loaded

export function AnalysisSidebar() {
  const { result: analysisResult } = useAnalysisStore();
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(["fileInfo", "entropy"])
  );

  // Use real analysis data when available, otherwise demo data
  const data = useMemo<AnalysisData | null>(() => {
    if (analysisResult) {
      const entropy = parseFloat(analysisResult.file_info.entropy);

      // Convert backend crypto findings to display format
      const cryptoDetections: CryptoDetection[] = analysisResult.crypto?.findings?.map(f => ({
        algorithm: f.type,
        address: f.offset,
        confidence: f.confidence,
        context: f.pattern,
      })) || [];

      // Build import categories from instruction analysis
      const analysis = analysisResult.analysis || {};
      const importCategories: Record<string, number> = {};
      if (analysis.calls > 0) importCategories["Calls"] = analysis.calls;
      if (analysis.jumps > 0) importCategories["Jumps"] = analysis.jumps;
      if (analysis.interrupts > 0) importCategories["Interrupts"] = analysis.interrupts;
      if (analysis.syscalls > 0) importCategories["Syscalls"] = analysis.syscalls;

      return {
        fileInfo: {
          name: analysisResult.file_info.name,
          size: analysisResult.file_info.size,
          type: analysisResult.file_info.arch,
          arch: analysisResult.file_info.arch.includes("64") ? "x64" : analysisResult.file_info.arch.includes("32") ? "x86" : "x86-16",
          subsystem: analysisResult.file_info.arch.includes("DOS") ? "DOS" : "Windows",
          timestamp: new Date().toISOString().split("T")[0],
        },
        entropy: {
          overall: entropy,
          sections: [
            { name: ".code", entropy: entropy, size: analysisResult.file_info.size, characteristics: ["CODE", "EXECUTE", "READ"] },
          ],
        },
        crypto: cryptoDetections,
        packer: analysisResult.file_info.is_packed ? { name: "High Entropy", confidence: 0.7 } : null,
        compiler: null,
        imports: {
          total: analysis.total_instructions || analysisResult.instruction_count,
          suspicious: (analysis.suspicious_patterns?.length || 0) + analysis.self_xors,
          categories: importCategories,
        },
        strings: {
          total: analysisResult.string_count,
          interesting: analysisResult.iocs?.total || 0,
          encrypted: 0,
        },
      };
    }
    return null;
  }, [analysisResult]);

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev);
      if (next.has(section)) {
        next.delete(section);
      } else {
        next.add(section);
      }
      return next;
    });
  };

  // Show empty state when no file is loaded
  if (!data) {
    return (
      <div className="h-full flex items-center justify-center bg-bg-primary opacity-50">
        <div className="text-center p-6">
          <FileCode className="w-12 h-12 mx-auto mb-3 text-text-secondary opacity-30" />
          <p className="text-sm text-text-secondary">No file loaded</p>
          <p className="text-xs text-text-secondary mt-1">Load a binary to see analysis</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto bg-bg-primary">
      {/* File Info */}
      <CollapsibleSection
        title="File Info"
        icon={FileCode}
        expanded={expandedSections.has("fileInfo")}
        onToggle={() => toggleSection("fileInfo")}
      >
        <div className="space-y-1 text-xs">
          <InfoRow label="Name" value={data.fileInfo.name} />
          <InfoRow label="Size" value={formatSize(data.fileInfo.size)} />
          <InfoRow label="Type" value={data.fileInfo.type} />
          <InfoRow label="Arch" value={data.fileInfo.arch} />
          <InfoRow label="Subsystem" value={data.fileInfo.subsystem} />
          <InfoRow label="Timestamp" value={data.fileInfo.timestamp} />
        </div>
      </CollapsibleSection>

      {/* Packer/Compiler */}
      <CollapsibleSection
        title="Identification"
        icon={Cpu}
        expanded={expandedSections.has("identification")}
        onToggle={() => toggleSection("identification")}
        badge={data.packer ? "Packed" : undefined}
        badgeColor="text-accent-yellow"
      >
        <div className="space-y-2 text-xs">
          {data.packer && (
            <div className="p-2 bg-accent-yellow/10 border border-accent-yellow/30 rounded">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-accent-yellow" />
                <span className="font-medium text-accent-yellow">Packer Detected</span>
              </div>
              <div className="mt-1 pl-6 text-text-secondary">
                {data.packer.name} {data.packer.version && `v${data.packer.version}`}
                <span className="ml-2">({Math.round(data.packer.confidence * 100)}%)</span>
              </div>
            </div>
          )}
          {data.compiler && (
            <div>
              <div className="text-text-secondary">Compiler:</div>
              <div className="text-text-primary">
                {data.compiler.name} {data.compiler.version && `(${data.compiler.version})`}
              </div>
              {data.compiler.linker && (
                <div className="text-text-secondary">Linker: {data.compiler.linker}</div>
              )}
            </div>
          )}
        </div>
      </CollapsibleSection>

      {/* Entropy */}
      <CollapsibleSection
        title="Entropy Analysis"
        icon={BarChart3}
        expanded={expandedSections.has("entropy")}
        onToggle={() => toggleSection("entropy")}
        badge={data.entropy.overall > 7 ? "High" : undefined}
        badgeColor={data.entropy.overall > 7 ? "text-accent-red" : "text-accent-green"}
      >
        <div className="space-y-3 text-xs">
          {/* Overall entropy */}
          <div>
            <div className="flex justify-between mb-1">
              <span className="text-text-secondary">Overall:</span>
              <span className={`font-medium ${getEntropyColor(data.entropy.overall)}`}>
                {data.entropy.overall.toFixed(2)}
              </span>
            </div>
            <EntropyBar value={data.entropy.overall} />
          </div>

          {/* Per-section */}
          <div className="space-y-2">
            {data.entropy.sections.map(section => (
              <div key={section.name}>
                <div className="flex justify-between mb-0.5">
                  <span className="text-text-primary font-mono">{section.name}</span>
                  <span className={getEntropyColor(section.entropy)}>
                    {section.entropy.toFixed(2)}
                  </span>
                </div>
                <EntropyBar value={section.entropy} />
                <div className="text-[10px] text-text-secondary mt-0.5">
                  {formatSize(section.size)} · {section.characteristics.join(", ")}
                </div>
              </div>
            ))}
          </div>
        </div>
      </CollapsibleSection>

      {/* Crypto Detection */}
      <CollapsibleSection
        title="Crypto Detection"
        icon={Lock}
        expanded={expandedSections.has("crypto")}
        onToggle={() => toggleSection("crypto")}
        badge={data.crypto.length > 0 ? `${data.crypto.length}` : undefined}
        badgeColor="text-accent-purple"
      >
        <div className="space-y-2">
          {data.crypto.length === 0 ? (
            <div className="text-xs text-text-secondary">No cryptographic algorithms detected</div>
          ) : (
            data.crypto.map((crypto, idx) => (
              <div key={idx} className="p-2 bg-bg-tertiary rounded text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-accent-purple">{crypto.algorithm}</span>
                  <span className="text-text-secondary">
                    {Math.round(crypto.confidence * 100)}%
                  </span>
                </div>
                <div className="text-accent-blue font-mono mt-1">{crypto.address}</div>
                <div className="text-text-secondary mt-1">{crypto.context}</div>
              </div>
            ))
          )}
        </div>
      </CollapsibleSection>

      {/* Imports Summary */}
      <CollapsibleSection
        title="Imports"
        icon={Layers}
        expanded={expandedSections.has("imports")}
        onToggle={() => toggleSection("imports")}
        badge={data.imports.suspicious > 0 ? `${data.imports.suspicious} suspicious` : undefined}
        badgeColor="text-accent-orange"
      >
        <div className="space-y-2 text-xs">
          <div className="flex justify-between">
            <span className="text-text-secondary">Total Functions:</span>
            <span className="text-text-primary">{data.imports.total}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-text-secondary">Suspicious:</span>
            <span className="text-accent-orange">{data.imports.suspicious}</span>
          </div>

          {/* Category breakdown */}
          <div className="mt-2 space-y-1">
            {Object.entries(data.imports.categories).map(([cat, count]) => (
              <div key={cat} className="flex items-center gap-2">
                <div className="flex-1 h-2 bg-bg-tertiary rounded overflow-hidden">
                  <div
                    className="h-full bg-accent-blue/50"
                    style={{ width: `${(count / data.imports.total) * 100}%` }}
                  />
                </div>
                <span className="text-text-secondary w-16">{cat}</span>
                <span className="text-text-primary w-6 text-right">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </CollapsibleSection>

      {/* Strings Summary */}
      <CollapsibleSection
        title="Strings"
        icon={Binary}
        expanded={expandedSections.has("strings")}
        onToggle={() => toggleSection("strings")}
      >
        <div className="space-y-1 text-xs">
          <InfoRow label="Total" value={data.strings.total.toString()} />
          <InfoRow label="Interesting" value={data.strings.interesting.toString()} valueColor="text-accent-blue" />
          <InfoRow label="Encrypted" value={data.strings.encrypted.toString()} valueColor="text-accent-yellow" />
        </div>
      </CollapsibleSection>
    </div>
  );
}

// Collapsible section component
function CollapsibleSection({
  title,
  icon: Icon,
  expanded,
  onToggle,
  badge,
  badgeColor,
  children,
}: {
  title: string;
  icon: typeof BarChart3;
  expanded: boolean;
  onToggle: () => void;
  badge?: string;
  badgeColor?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="border-b border-border">
      <button
        onClick={onToggle}
        className="w-full px-3 py-2 flex items-center gap-2 hover:bg-bg-hover transition-colors"
      >
        {expanded ? (
          <ChevronDown className="w-4 h-4 text-text-secondary" />
        ) : (
          <ChevronRight className="w-4 h-4 text-text-secondary" />
        )}
        <Icon className="w-4 h-4 text-text-secondary" />
        <span className="flex-1 text-sm text-text-primary text-left">{title}</span>
        {badge && (
          <span className={`text-xs ${badgeColor || "text-text-secondary"}`}>{badge}</span>
        )}
      </button>
      {expanded && <div className="px-3 pb-3">{children}</div>}
    </div>
  );
}

// Info row component
function InfoRow({
  label,
  value,
  valueColor,
}: {
  label: string;
  value: string;
  valueColor?: string;
}) {
  return (
    <div className="flex justify-between">
      <span className="text-text-secondary">{label}:</span>
      <span className={valueColor || "text-text-primary"}>{value}</span>
    </div>
  );
}

// Entropy bar component
function EntropyBar({ value }: { value: number }) {
  const percentage = (value / 8) * 100;
  const color = value > 7 ? "bg-accent-red" : value > 6 ? "bg-accent-yellow" : "bg-accent-green";

  return (
    <div className="h-1.5 bg-bg-tertiary rounded overflow-hidden">
      <div
        className={`h-full ${color} transition-all`}
        style={{ width: `${percentage}%` }}
      />
    </div>
  );
}

// Get entropy color based on value
function getEntropyColor(entropy: number): string {
  if (entropy > 7) return "text-accent-red";
  if (entropy > 6) return "text-accent-yellow";
  return "text-accent-green";
}

// Format file size
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
