import { useState, useMemo } from "react";
import {
  Network, Globe, FileText, Key, Hash, Copy, Check,
  Download, ChevronRight, Mail
} from "lucide-react";
import { useAnalysisStore, IocEntry } from "../../stores/analysisStore";

// IOC types
type IocType = "ip" | "domain" | "url" | "hash" | "file" | "registry" | "email" | "other";

interface IoC {
  id: number;
  type: IocType;
  value: string;
  confidence: number;
  context: string;
  mitreTechniques: string[];
  defanged: string; // Safe display version
  tags: string[];
}

const IOC_TYPE_CONFIG: Record<IocType, { icon: typeof Network; color: string; label: string }> = {
  ip: { icon: Network, color: "text-blue-400", label: "IP Address" },
  domain: { icon: Globe, color: "text-green-400", label: "Domain" },
  url: { icon: Globe, color: "text-purple-400", label: "URL" },
  hash: { icon: Hash, color: "text-orange-400", label: "Hash" },
  file: { icon: FileText, color: "text-yellow-400", label: "File Path" },
  registry: { icon: Key, color: "text-cyan-400", label: "Registry" },
  email: { icon: Mail, color: "text-pink-400", label: "Email" },
  other: { icon: FileText, color: "text-gray-400", label: "Other" },
};

export function IocPanel() {
  const { result } = useAnalysisStore();

  // Convert backend IOCs to display format
  const iocs = useMemo<IoC[]>(() => {
    if (!result?.iocs) return [];

    const allIocs: IoC[] = [];
    let id = 1;

    // Helper to convert IOC entry
    const addIoc = (entry: IocEntry, type: IocType, tags: string[]) => {
      allIocs.push({
        id: id++,
        type,
        value: entry.value,
        defanged: entry.defanged || entry.value,
        confidence: 0.8, // Default confidence from string extraction
        context: `Found at offset ${entry.offset}`,
        mitreTechniques: type === "url" ? ["T1071.001"] :
                         type === "ip" ? ["T1071"] :
                         type === "registry" ? ["T1547.001"] : [],
        tags,
      });
    };

    // Process each IOC category
    result.iocs.urls?.forEach(e => addIoc(e, "url", ["network", "c2"]));
    result.iocs.ips?.forEach(e => addIoc(e, "ip", ["network"]));
    result.iocs.domains?.forEach(e => addIoc(e, "domain", ["network"]));
    result.iocs.paths?.forEach(e => addIoc(e, "file", ["filesystem"]));
    result.iocs.registry_keys?.forEach(e => addIoc(e, "registry", ["persistence"]));
    result.iocs.emails?.forEach(e => addIoc(e, "email", ["contact"]));

    return allIocs;
  }, [result?.iocs]);

  const [filter, setFilter] = useState<IocType | "all">("all");
  const [copiedId, setCopiedId] = useState<number | null>(null);
  const [selectedIocs, setSelectedIocs] = useState<Set<number>>(new Set());

  // Filter IOCs
  const filteredIocs = filter === "all"
    ? iocs
    : iocs.filter(ioc => ioc.type === filter);

  // Count by type
  const countByType = iocs.reduce((acc, ioc) => {
    acc[ioc.type] = (acc[ioc.type] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  // Copy to clipboard
  const copyToClipboard = async (ioc: IoC) => {
    await navigator.clipboard.writeText(ioc.value);
    setCopiedId(ioc.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Toggle selection
  const toggleSelection = (id: number) => {
    setSelectedIocs(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  // Export selected
  const exportSelected = (format: "stix" | "csv" | "json") => {
    const toExport = selectedIocs.size > 0
      ? iocs.filter(ioc => selectedIocs.has(ioc.id))
      : iocs;

    // In production, this would actually export
    console.log(`Exporting ${toExport.length} IOCs as ${format}`);
  };

  return (
    <div className="h-full flex flex-col bg-bg-primary">
      {/* Header */}
      <div className="h-10 bg-bg-secondary border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-accent-blue" />
          <span className="text-sm font-medium">Indicators of Compromise</span>
          <span className="text-xs text-text-secondary">
            {filteredIocs.length} found
          </span>
        </div>
      </div>

      {/* Filter tabs */}
      <div className="h-9 bg-bg-tertiary border-b border-border flex items-center px-2 gap-1 overflow-x-auto">
        <FilterButton
          active={filter === "all"}
          onClick={() => setFilter("all")}
          count={iocs.length}
        >
          All
        </FilterButton>
        {(Object.keys(IOC_TYPE_CONFIG) as IocType[]).map(type => {
          const count = countByType[type] || 0;
          if (count === 0) return null;
          const config = IOC_TYPE_CONFIG[type];
          return (
            <FilterButton
              key={type}
              active={filter === type}
              onClick={() => setFilter(type)}
              count={count}
              icon={config.icon}
              color={config.color}
            >
              {config.label}
            </FilterButton>
          );
        })}
      </div>

      {/* IOC list */}
      <div className="flex-1 overflow-auto">
        {filteredIocs.length === 0 ? (
          <div className="h-full flex items-center justify-center text-text-secondary">
            <div className="text-center">
              <Network className="w-10 h-10 mx-auto mb-3 opacity-50" />
              <p className="text-sm">No IOCs found</p>
            </div>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {filteredIocs.map(ioc => (
              <IocRow
                key={ioc.id}
                ioc={ioc}
                selected={selectedIocs.has(ioc.id)}
                copied={copiedId === ioc.id}
                onToggleSelect={() => toggleSelection(ioc.id)}
                onCopy={() => copyToClipboard(ioc)}
              />
            ))}
          </div>
        )}
      </div>

      {/* Footer - Export options */}
      <div className="h-10 bg-bg-secondary border-t border-border flex items-center justify-between px-3">
        <div className="text-xs text-text-secondary">
          {selectedIocs.size > 0 ? (
            <span>{selectedIocs.size} selected</span>
          ) : (
            <span>Click to select IOCs for export</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => exportSelected("stix")}
            className="flex items-center gap-1 px-2 py-1 text-xs bg-bg-tertiary hover:bg-bg-hover rounded transition-colors"
          >
            <Download className="w-3 h-3" />
            STIX
          </button>
          <button
            onClick={() => exportSelected("csv")}
            className="flex items-center gap-1 px-2 py-1 text-xs bg-bg-tertiary hover:bg-bg-hover rounded transition-colors"
          >
            <Download className="w-3 h-3" />
            CSV
          </button>
          <button
            onClick={() => exportSelected("json")}
            className="flex items-center gap-1 px-2 py-1 text-xs bg-bg-tertiary hover:bg-bg-hover rounded transition-colors"
          >
            <Download className="w-3 h-3" />
            JSON
          </button>
        </div>
      </div>
    </div>
  );
}

function FilterButton({
  active,
  onClick,
  count,
  icon: Icon,
  color,
  children,
}: {
  active: boolean;
  onClick: () => void;
  count: number;
  icon?: typeof Network;
  color?: string;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1 px-2 py-1 text-xs rounded transition-colors whitespace-nowrap ${
        active
          ? "bg-bg-hover text-text-primary"
          : "text-text-secondary hover:text-text-primary hover:bg-bg-hover"
      }`}
    >
      {Icon && <Icon className={`w-3 h-3 ${color || ""}`} />}
      {children}
      <span className="text-text-secondary">({count})</span>
    </button>
  );
}

function IocRow({
  ioc,
  selected,
  copied,
  onToggleSelect,
  onCopy,
}: {
  ioc: IoC;
  selected: boolean;
  copied: boolean;
  onToggleSelect: () => void;
  onCopy: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const config = IOC_TYPE_CONFIG[ioc.type];
  const Icon = config.icon;

  return (
    <div className={`${selected ? "bg-accent-blue/10" : ""}`}>
      <div className="px-3 py-2 flex items-center gap-3">
        {/* Selection checkbox */}
        <input
          type="checkbox"
          checked={selected}
          onChange={onToggleSelect}
          className="w-4 h-4 rounded border-border bg-bg-tertiary"
        />

        {/* Type icon */}
        <Icon className={`w-4 h-4 ${config.color} flex-shrink-0`} />

        {/* Value */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <code className="text-sm text-text-primary font-mono truncate">
              {ioc.defanged}
            </code>
            {ioc.mitreTechniques.length > 0 && (
              <span className="px-1 py-0.5 text-[10px] bg-accent-red/20 text-accent-red rounded">
                {ioc.mitreTechniques[0]}
              </span>
            )}
          </div>

          {/* Tags */}
          <div className="flex items-center gap-1 mt-1">
            {ioc.tags.map(tag => (
              <span
                key={tag}
                className="px-1.5 py-0.5 text-[10px] bg-bg-tertiary text-text-secondary rounded"
              >
                {tag}
              </span>
            ))}
            <span className="text-[10px] text-text-secondary">
              {Math.round(ioc.confidence * 100)}% confidence
            </span>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-1">
          <button
            onClick={onCopy}
            className="p-1.5 hover:bg-bg-hover rounded transition-colors"
            title="Copy to clipboard"
          >
            {copied ? (
              <Check className="w-4 h-4 text-accent-green" />
            ) : (
              <Copy className="w-4 h-4 text-text-secondary" />
            )}
          </button>
          <button
            onClick={() => setExpanded(!expanded)}
            className="p-1.5 hover:bg-bg-hover rounded transition-colors"
          >
            <ChevronRight
              className={`w-4 h-4 text-text-secondary transition-transform ${
                expanded ? "rotate-90" : ""
              }`}
            />
          </button>
        </div>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="px-3 pb-3 pl-10 space-y-2 text-xs">
          <div>
            <span className="text-text-secondary">Context: </span>
            <span className="text-text-primary">{ioc.context}</span>
          </div>
          <div>
            <span className="text-text-secondary">Original: </span>
            <code className="text-accent-blue">{ioc.value}</code>
          </div>
          {ioc.mitreTechniques.length > 0 && (
            <div className="flex items-center gap-1">
              <span className="text-text-secondary">MITRE: </span>
              {ioc.mitreTechniques.map(t => (
                <a
                  key={t}
                  href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-accent-red hover:underline"
                >
                  {t}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
