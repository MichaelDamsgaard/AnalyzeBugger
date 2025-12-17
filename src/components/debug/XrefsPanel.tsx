import { useMemo } from "react";
import { useAnalysisStore, XRef } from "../../stores/analysisStore";
import {
  ArrowDownToLine, ArrowUpFromLine, Phone, GitBranch,
  Database, FileText, ChevronRight
} from "lucide-react";

const XREF_TYPE_CONFIG: Record<XRef["type"], { icon: typeof Phone; color: string; label: string }> = {
  call: { icon: Phone, color: "text-accent-purple", label: "Call" },
  jump: { icon: GitBranch, color: "text-accent-yellow", label: "Jump" },
  data: { icon: Database, color: "text-accent-blue", label: "Data" },
  string: { icon: FileText, color: "text-accent-green", label: "String" },
};

export function XrefsPanel() {
  const { currentAddress, getXrefsTo, getXrefsFrom, navigateTo, labels } = useAnalysisStore();

  const xrefsTo = useMemo(() => {
    if (!currentAddress) return [];
    return getXrefsTo(currentAddress);
  }, [currentAddress, getXrefsTo]);

  const xrefsFrom = useMemo(() => {
    if (!currentAddress) return [];
    return getXrefsFrom(currentAddress);
  }, [currentAddress, getXrefsFrom]);

  // Get label for an address if it exists
  const getLabel = (addr: string) => labels.get(addr)?.name;

  if (!currentAddress) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <GitBranch className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No address selected</p>
          <p className="text-xs mt-1">Click an instruction to view xrefs</p>
        </div>
      </div>
    );
  }

  const totalXrefs = xrefsTo.length + xrefsFrom.length;

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-8 bg-bg-secondary border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <GitBranch className="w-4 h-4 text-accent-cyan" />
          <span className="text-sm font-medium">Cross References</span>
        </div>
        <span className="text-xs text-text-secondary font-mono">{currentAddress}</span>
      </div>

      {totalXrefs === 0 ? (
        <div className="flex-1 flex items-center justify-center text-text-secondary">
          <div className="text-center">
            <GitBranch className="w-6 h-6 mx-auto mb-2 opacity-50" />
            <p className="text-xs">No cross-references</p>
          </div>
        </div>
      ) : (
        <div className="flex-1 overflow-auto">
          {/* References TO this address (who calls/jumps here) */}
          {xrefsTo.length > 0 && (
            <div className="border-b border-border">
              <div className="h-7 bg-bg-tertiary flex items-center gap-2 px-3 sticky top-0">
                <ArrowDownToLine className="w-3 h-3 text-accent-green" />
                <span className="text-xs font-medium">Xrefs To ({xrefsTo.length})</span>
                <span className="text-[10px] text-text-secondary">References TO this address</span>
              </div>
              <div className="divide-y divide-border/50">
                {xrefsTo.map((xref, idx) => (
                  <XrefRow
                    key={idx}
                    xref={xref}
                    direction="to"
                    label={getLabel(xref.from)}
                    onClick={() => navigateTo(xref.from)}
                  />
                ))}
              </div>
            </div>
          )}

          {/* References FROM this address (what does this call/jump to) */}
          {xrefsFrom.length > 0 && (
            <div>
              <div className="h-7 bg-bg-tertiary flex items-center gap-2 px-3 sticky top-0">
                <ArrowUpFromLine className="w-3 h-3 text-accent-purple" />
                <span className="text-xs font-medium">Xrefs From ({xrefsFrom.length})</span>
                <span className="text-[10px] text-text-secondary">References FROM this address</span>
              </div>
              <div className="divide-y divide-border/50">
                {xrefsFrom.map((xref, idx) => (
                  <XrefRow
                    key={idx}
                    xref={xref}
                    direction="from"
                    label={getLabel(xref.to)}
                    onClick={() => navigateTo(xref.to)}
                  />
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Footer with summary */}
      <div className="h-6 bg-bg-secondary border-t border-border flex items-center justify-between px-3 text-[10px] text-text-secondary">
        <span>
          {xrefsTo.length} incoming, {xrefsFrom.length} outgoing
        </span>
        <span>Click to navigate</span>
      </div>
    </div>
  );
}

function XrefRow({
  xref,
  direction,
  label,
  onClick,
}: {
  xref: XRef;
  direction: "to" | "from";
  label?: string;
  onClick: () => void;
}) {
  const config = XREF_TYPE_CONFIG[xref.type];
  const Icon = config.icon;
  const address = direction === "to" ? xref.from : xref.to;

  return (
    <button
      onClick={onClick}
      className="w-full px-3 py-1.5 flex items-center gap-2 hover:bg-bg-hover transition-colors text-left"
    >
      <Icon className={`w-3 h-3 ${config.color} flex-shrink-0`} />

      <span className="text-xs font-mono text-accent-blue">
        {address}
      </span>

      {label && (
        <span className="text-xs text-accent-purple truncate">
          {label}
        </span>
      )}

      <span className="flex-1" />

      <span className={`text-[10px] px-1.5 py-0.5 rounded ${config.color} bg-current/10`}>
        {xref.mnemonic || config.label}
      </span>

      <ChevronRight className="w-3 h-3 text-text-secondary" />
    </button>
  );
}
