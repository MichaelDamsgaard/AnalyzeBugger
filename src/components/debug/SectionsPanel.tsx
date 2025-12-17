import { useState } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import {
  Layers, AlertTriangle, Code,
  FileText, Cpu
} from "lucide-react";

// Section characteristic analysis
function analyzeSectionFlags(flags: string[]): { icon: typeof Code; color: string; warning?: string } {
  const hasCode = flags.includes("CODE") || flags.includes("EXECUTE");
  const hasWrite = flags.includes("WRITE");

  // Executable + Writable is suspicious (self-modifying code, unpacker)
  if (hasCode && hasWrite) {
    return {
      icon: AlertTriangle,
      color: "text-accent-red",
      warning: "Executable & Writable - possible packer/self-modifying code"
    };
  }

  if (hasCode) {
    return { icon: Code, color: "text-accent-purple" };
  }

  if (flags.includes("UNINITIALIZED")) {
    return { icon: Cpu, color: "text-accent-yellow" };
  }

  return { icon: FileText, color: "text-accent-blue" };
}

export function SectionsPanel() {
  const { result, navigateTo } = useAnalysisStore();
  const [selectedSection, setSelectedSection] = useState<string | null>(null);

  const sections = result?.sections || [];

  if (!result) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <Layers className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No sections</p>
          <p className="text-xs mt-1">Analyze a PE file to view sections</p>
        </div>
      </div>
    );
  }

  if (sections.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <Layers className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No sections found</p>
          <p className="text-xs mt-1">This may be a non-PE file</p>
        </div>
      </div>
    );
  }

  // Calculate total size
  const totalSize = sections.reduce((sum, s) => sum + s.raw_size, 0);

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-8 bg-bg-secondary border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-accent-cyan" />
          <span className="text-sm font-medium">Sections</span>
          <span className="text-xs text-text-secondary">
            {sections.length} sections
          </span>
        </div>
      </div>

      {/* Section visualization bar */}
      <div className="h-6 bg-bg-tertiary border-b border-border flex items-center px-2">
        <div className="flex-1 h-3 bg-bg-primary rounded overflow-hidden flex">
          {sections.map((section, idx) => {
            const width = totalSize > 0 ? (section.raw_size / totalSize) * 100 : 0;
            const analysis = analyzeSectionFlags(section.flags);
            return (
              <div
                key={idx}
                className={`h-full ${
                  analysis.color.replace("text-", "bg-")
                } opacity-60 hover:opacity-100 transition-opacity cursor-pointer`}
                style={{ width: `${Math.max(width, 1)}%` }}
                title={`${section.name}: ${formatSize(section.raw_size)}`}
                onClick={() => setSelectedSection(section.name)}
              />
            );
          })}
        </div>
      </div>

      {/* Section list */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-bg-tertiary">
            <tr className="text-text-secondary text-[10px]">
              <th className="px-2 py-1 text-left">Name</th>
              <th className="px-2 py-1 text-left">Virtual Addr</th>
              <th className="px-2 py-1 text-right">Virtual Size</th>
              <th className="px-2 py-1 text-right">Raw Size</th>
              <th className="px-2 py-1 text-left">Flags</th>
            </tr>
          </thead>
          <tbody>
            {sections.map((section, idx) => {
              const analysis = analyzeSectionFlags(section.flags);
              const Icon = analysis.icon;
              const isSelected = selectedSection === section.name;

              return (
                <tr
                  key={idx}
                  onClick={() => setSelectedSection(isSelected ? null : section.name)}
                  className={`cursor-pointer transition-colors ${
                    isSelected ? "bg-accent-blue/10" : "hover:bg-bg-hover"
                  }`}
                >
                  <td className="px-2 py-1.5">
                    <div className="flex items-center gap-2">
                      <Icon className={`w-3 h-3 ${analysis.color}`} />
                      <span className="font-mono font-medium">{section.name}</span>
                      {analysis.warning && (
                        <span title={analysis.warning}>
                          <AlertTriangle className="w-3 h-3 text-accent-red" />
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-2 py-1.5 font-mono text-accent-blue">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        navigateTo(section.virtual_address);
                      }}
                      className="hover:underline"
                    >
                      {section.virtual_address}
                    </button>
                  </td>
                  <td className="px-2 py-1.5 text-right font-mono text-text-secondary">
                    {formatSize(section.virtual_size)}
                  </td>
                  <td className="px-2 py-1.5 text-right font-mono text-text-secondary">
                    {formatSize(section.raw_size)}
                  </td>
                  <td className="px-2 py-1.5">
                    <div className="flex flex-wrap gap-1">
                      {section.flags.map((flag, flagIdx) => (
                        <span
                          key={flagIdx}
                          className={`px-1 py-0.5 text-[9px] rounded ${
                            flag === "EXECUTE" ? "bg-accent-red/20 text-accent-red" :
                            flag === "WRITE" ? "bg-accent-orange/20 text-accent-orange" :
                            flag === "CODE" ? "bg-accent-purple/20 text-accent-purple" :
                            "bg-bg-tertiary text-text-secondary"
                          }`}
                        >
                          {flag}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Selected section details */}
      {selectedSection && (
        <div className="h-24 bg-bg-tertiary border-t border-border p-2 overflow-auto">
          {(() => {
            const section = sections.find(s => s.name === selectedSection);
            if (!section) return null;
            const analysis = analyzeSectionFlags(section.flags);

            return (
              <div className="text-xs space-y-1">
                <div className="flex items-center gap-2 font-medium">
                  <span className={analysis.color}>{section.name}</span>
                  {analysis.warning && (
                    <span className="text-accent-red text-[10px]">
                      {analysis.warning}
                    </span>
                  )}
                </div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-text-secondary">
                  <div>Virtual Address: <span className="text-accent-blue font-mono">{section.virtual_address}</span></div>
                  <div>Raw Pointer: <span className="text-text-primary font-mono">{section.raw_pointer}</span></div>
                  <div>Virtual Size: <span className="text-text-primary">{section.virtual_size.toLocaleString()} bytes</span></div>
                  <div>Raw Size: <span className="text-text-primary">{section.raw_size.toLocaleString()} bytes</span></div>
                  <div>Characteristics: <span className="text-text-primary font-mono">{section.characteristics}</span></div>
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* Footer */}
      <div className="h-6 bg-bg-secondary border-t border-border flex items-center justify-between px-3 text-[10px] text-text-secondary">
        <span>Total: {formatSize(totalSize)}</span>
        <span>Click section to view details</span>
      </div>
    </div>
  );
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
