import { useState, useMemo } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import {
  PackageOpen, Search, Copy, Check
} from "lucide-react";

export function ExportsPanel() {
  const { result, navigateTo } = useAnalysisStore();
  const [filter, setFilter] = useState("");
  const [copiedAddr, setCopiedAddr] = useState<string | null>(null);
  const [selectedExport, setSelectedExport] = useState<number | null>(null);

  const exports = result?.exports;

  const filteredExports = useMemo(() => {
    if (!exports?.functions) return [];
    if (!filter) return exports.functions;

    const lowerFilter = filter.toLowerCase();
    return exports.functions.filter(fn =>
      fn.name?.toLowerCase().includes(lowerFilter) ||
      fn.ordinal.toString().includes(lowerFilter) ||
      fn.rva.toLowerCase().includes(lowerFilter)
    );
  }, [exports?.functions, filter]);

  const copyAddress = (addr: string) => {
    navigator.clipboard.writeText(addr);
    setCopiedAddr(addr);
    setTimeout(() => setCopiedAddr(null), 1500);
  };

  if (!result) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <PackageOpen className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No exports</p>
          <p className="text-xs mt-1">Analyze a PE file to view exports</p>
        </div>
      </div>
    );
  }

  if (!exports || exports.count === 0) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <PackageOpen className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No exports found</p>
          <p className="text-xs mt-1">This binary doesn't export any functions</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-8 bg-bg-secondary border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <PackageOpen className="w-4 h-4 text-accent-green" />
          <span className="text-sm font-medium">Exports (EAT)</span>
          <span className="text-xs text-text-secondary">
            {exports.count} functions
          </span>
        </div>
        {exports.dll_name && (
          <span className="text-xs text-text-secondary font-mono">
            {exports.dll_name}
          </span>
        )}
      </div>

      {/* Filter bar */}
      <div className="h-8 bg-bg-tertiary border-b border-border flex items-center px-2 gap-2">
        <Search className="w-3 h-3 text-text-secondary" />
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter exports..."
          className="flex-1 bg-transparent text-xs focus:outline-none"
        />
        <span className="text-[10px] text-text-secondary">
          {filteredExports.length} shown
        </span>
      </div>

      {/* Export list */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-bg-tertiary">
            <tr className="text-text-secondary text-[10px]">
              <th className="px-2 py-1 text-left w-16">Ordinal</th>
              <th className="px-2 py-1 text-left">Name</th>
              <th className="px-2 py-1 text-left w-24">RVA</th>
              <th className="px-2 py-1 w-8"></th>
            </tr>
          </thead>
          <tbody>
            {filteredExports.map((fn, idx) => (
              <tr
                key={idx}
                onClick={() => setSelectedExport(selectedExport === idx ? null : idx)}
                className={`cursor-pointer transition-colors ${
                  selectedExport === idx ? "bg-accent-green/10" : "hover:bg-bg-hover"
                }`}
              >
                <td className="px-2 py-1.5 font-mono text-accent-yellow">
                  #{fn.ordinal}
                </td>
                <td className="px-2 py-1.5">
                  <div className="flex items-center gap-2">
                    {fn.name ? (
                      <span className="font-mono text-text-primary">{fn.name}</span>
                    ) : (
                      <span className="text-text-secondary italic">
                        (ordinal only)
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-2 py-1.5">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      navigateTo(fn.rva);
                    }}
                    className="font-mono text-accent-blue hover:underline"
                  >
                    {fn.rva}
                  </button>
                </td>
                <td className="px-2 py-1.5">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      copyAddress(fn.rva);
                    }}
                    className="p-0.5 hover:bg-bg-hover rounded"
                  >
                    {copiedAddr === fn.rva ? (
                      <Check className="w-3 h-3 text-accent-green" />
                    ) : (
                      <Copy className="w-3 h-3 text-text-secondary" />
                    )}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <div className="h-6 bg-bg-secondary border-t border-border flex items-center justify-between px-3 text-[10px] text-text-secondary">
        <span>{exports.count} exports total</span>
        <span>Click RVA to navigate</span>
      </div>
    </div>
  );
}
