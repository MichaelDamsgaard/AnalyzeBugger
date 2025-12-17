import { useState, useMemo } from "react";
import {
  Shield, ChevronDown, ChevronRight, ExternalLink,
  AlertTriangle, CheckCircle2, Circle
} from "lucide-react";
import { useAnalysisStore, MitreTechnique } from "../../stores/analysisStore";

// Map tactic names to IDs
const TACTIC_MAP: Record<string, { id: string; color: string }> = {
  "Reconnaissance": { id: "TA0043", color: "text-slate-400" },
  "Resource Development": { id: "TA0042", color: "text-slate-400" },
  "Initial Access": { id: "TA0001", color: "text-blue-400" },
  "Execution": { id: "TA0002", color: "text-purple-400" },
  "Persistence": { id: "TA0003", color: "text-orange-400" },
  "Privilege Escalation": { id: "TA0004", color: "text-red-400" },
  "Defense Evasion": { id: "TA0005", color: "text-yellow-400" },
  "Credential Access": { id: "TA0006", color: "text-pink-400" },
  "Discovery": { id: "TA0007", color: "text-cyan-400" },
  "Lateral Movement": { id: "TA0008", color: "text-indigo-400" },
  "Collection": { id: "TA0009", color: "text-emerald-400" },
  "Command and Control": { id: "TA0011", color: "text-rose-400" },
  "Exfiltration": { id: "TA0010", color: "text-amber-400" },
  "Impact": { id: "TA0040", color: "text-red-500" },
};

// MITRE ATT&CK Tactic definitions
const TACTICS = [
  { id: "TA0043", name: "Reconnaissance", color: "text-slate-400" },
  { id: "TA0042", name: "Resource Development", color: "text-slate-400" },
  { id: "TA0001", name: "Initial Access", color: "text-blue-400" },
  { id: "TA0002", name: "Execution", color: "text-purple-400" },
  { id: "TA0003", name: "Persistence", color: "text-orange-400" },
  { id: "TA0004", name: "Privilege Escalation", color: "text-red-400" },
  { id: "TA0005", name: "Defense Evasion", color: "text-yellow-400" },
  { id: "TA0006", name: "Credential Access", color: "text-pink-400" },
  { id: "TA0007", name: "Discovery", color: "text-cyan-400" },
  { id: "TA0008", name: "Lateral Movement", color: "text-indigo-400" },
  { id: "TA0009", name: "Collection", color: "text-emerald-400" },
  { id: "TA0011", name: "Command and Control", color: "text-rose-400" },
  { id: "TA0010", name: "Exfiltration", color: "text-amber-400" },
  { id: "TA0040", name: "Impact", color: "text-red-500" },
];

interface MitreDetection {
  techniqueId: string;
  techniqueName: string;
  tacticId: string;
  tacticName: string;
  confidence: number;
  evidence: string[];
  location?: string;
  severity: "low" | "medium" | "high" | "critical";
}

export function MitrePanel() {
  const { result } = useAnalysisStore();

  // Convert backend mitre_techniques to our display format
  const detections = useMemo<MitreDetection[]>(() => {
    if (!result?.mitre_techniques) return [];

    return result.mitre_techniques.map((tech: MitreTechnique) => {
      const tacticInfo = TACTIC_MAP[tech.tactic] || { id: "TA0000", color: "text-gray-400" };
      const severity: "low" | "medium" | "high" | "critical" =
        tech.confidence >= 0.9 ? "high" :
        tech.confidence >= 0.7 ? "medium" : "low";

      return {
        techniqueId: tech.id,
        techniqueName: tech.name,
        tacticId: tacticInfo.id,
        tacticName: tech.tactic,
        confidence: tech.confidence,
        evidence: [tech.evidence],
        severity,
      };
    });
  }, [result?.mitre_techniques]);
  const [expandedTechnique, setExpandedTechnique] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<"list" | "matrix">("list");

  // Group detections by tactic
  const byTactic = detections.reduce((acc, det) => {
    if (!acc[det.tacticId]) {
      acc[det.tacticId] = [];
    }
    acc[det.tacticId].push(det);
    return acc;
  }, {} as Record<string, MitreDetection[]>);

  // Calculate coverage stats
  const tacticsCovered = new Set(detections.map(d => d.tacticId)).size;
  const avgConfidence = detections.length > 0
    ? detections.reduce((sum, d) => sum + d.confidence, 0) / detections.length
    : 0;

  return (
    <div className="h-full flex flex-col bg-bg-primary">
      {/* Header */}
      <div className="h-10 bg-bg-secondary border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-accent-red" />
          <span className="text-sm font-medium">MITRE ATT&CK</span>
          <span className="text-xs text-text-secondary">
            {detections.length} techniques
          </span>
        </div>

        <div className="flex items-center gap-1">
          <button
            onClick={() => setViewMode("list")}
            className={`px-2 py-1 text-xs rounded transition-colors ${
              viewMode === "list"
                ? "bg-bg-tertiary text-text-primary"
                : "text-text-secondary hover:text-text-primary"
            }`}
          >
            List
          </button>
          <button
            onClick={() => setViewMode("matrix")}
            className={`px-2 py-1 text-xs rounded transition-colors ${
              viewMode === "matrix"
                ? "bg-bg-tertiary text-text-primary"
                : "text-text-secondary hover:text-text-primary"
            }`}
          >
            Matrix
          </button>
        </div>
      </div>

      {/* Stats bar */}
      <div className="h-8 bg-bg-tertiary border-b border-border flex items-center justify-around text-xs">
        <div className="flex items-center gap-1">
          <span className="text-text-secondary">Tactics:</span>
          <span className="text-text-primary font-medium">{tacticsCovered}/14</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="text-text-secondary">Avg Confidence:</span>
          <span className="text-text-primary font-medium">
            {Math.round(avgConfidence * 100)}%
          </span>
        </div>
        <div className="flex items-center gap-1">
          <span className="text-text-secondary">Critical:</span>
          <span className="text-accent-red font-medium">
            {detections.filter(d => d.severity === "critical").length}
          </span>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto">
        {viewMode === "list" ? (
          <div className="p-2 space-y-1">
            {TACTICS.filter(t => byTactic[t.id]).map(tactic => (
              <TacticGroup
                key={tactic.id}
                tactic={tactic}
                detections={byTactic[tactic.id]}
                expandedTechnique={expandedTechnique}
                onToggle={setExpandedTechnique}
              />
            ))}
          </div>
        ) : (
          <MitreMatrix detections={detections} />
        )}
      </div>

      {/* Footer - Export */}
      <div className="h-8 bg-bg-secondary border-t border-border flex items-center justify-end px-3 gap-2">
        <button className="text-xs text-text-secondary hover:text-accent-blue transition-colors">
          Export STIX
        </button>
        <button className="text-xs text-text-secondary hover:text-accent-blue transition-colors">
          Export JSON
        </button>
      </div>
    </div>
  );
}

function TacticGroup({
  tactic,
  detections,
  expandedTechnique,
  onToggle,
}: {
  tactic: typeof TACTICS[0];
  detections: MitreDetection[];
  expandedTechnique: string | null;
  onToggle: (id: string | null) => void;
}) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="border border-border rounded overflow-hidden">
      {/* Tactic header */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="w-full h-8 bg-bg-secondary flex items-center justify-between px-2 hover:bg-bg-hover transition-colors"
      >
        <div className="flex items-center gap-2">
          {collapsed ? (
            <ChevronRight className="w-4 h-4 text-text-secondary" />
          ) : (
            <ChevronDown className="w-4 h-4 text-text-secondary" />
          )}
          <span className={`text-sm font-medium ${tactic.color}`}>
            {tactic.name}
          </span>
          <span className="text-xs text-text-secondary">
            ({detections.length})
          </span>
        </div>
        <span className="text-xs text-text-secondary">{tactic.id}</span>
      </button>

      {/* Techniques */}
      {!collapsed && (
        <div className="divide-y divide-border">
          {detections.map(det => (
            <TechniqueRow
              key={det.techniqueId}
              detection={det}
              expanded={expandedTechnique === det.techniqueId}
              onToggle={() => onToggle(
                expandedTechnique === det.techniqueId ? null : det.techniqueId
              )}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function TechniqueRow({
  detection,
  expanded,
  onToggle,
}: {
  detection: MitreDetection;
  expanded: boolean;
  onToggle: () => void;
}) {
  const severityColor = {
    low: "bg-blue-500/20 text-blue-400",
    medium: "bg-yellow-500/20 text-yellow-400",
    high: "bg-orange-500/20 text-orange-400",
    critical: "bg-red-500/20 text-red-400",
  }[detection.severity];

  const confidenceIcon = detection.confidence >= 0.8 ? (
    <CheckCircle2 className="w-3 h-3 text-accent-green" />
  ) : detection.confidence >= 0.6 ? (
    <AlertTriangle className="w-3 h-3 text-accent-yellow" />
  ) : (
    <Circle className="w-3 h-3 text-text-secondary" />
  );

  return (
    <div className="bg-bg-primary">
      <button
        onClick={onToggle}
        className="w-full px-3 py-2 flex items-center gap-3 hover:bg-bg-hover transition-colors text-left"
      >
        {/* Confidence indicator */}
        <div className="flex items-center gap-1" title={`${Math.round(detection.confidence * 100)}% confidence`}>
          {confidenceIcon}
        </div>

        {/* Technique ID */}
        <span className="text-xs text-accent-red font-mono w-24">
          {detection.techniqueId}
        </span>

        {/* Technique name */}
        <span className="flex-1 text-sm text-text-primary truncate">
          {detection.techniqueName}
        </span>

        {/* Severity badge */}
        <span className={`px-1.5 py-0.5 text-[10px] rounded ${severityColor}`}>
          {detection.severity}
        </span>

        {/* Expand indicator */}
        {expanded ? (
          <ChevronDown className="w-4 h-4 text-text-secondary" />
        ) : (
          <ChevronRight className="w-4 h-4 text-text-secondary" />
        )}
      </button>

      {/* Expanded details */}
      {expanded && (
        <div className="px-3 pb-3 pt-1 bg-bg-tertiary/50 space-y-2">
          {/* Evidence */}
          <div>
            <div className="text-xs text-text-secondary mb-1">Evidence:</div>
            <ul className="space-y-1">
              {detection.evidence.map((ev, idx) => (
                <li key={idx} className="text-xs text-text-primary pl-3 flex items-center gap-2">
                  <span className="w-1 h-1 rounded-full bg-accent-purple" />
                  {ev}
                </li>
              ))}
            </ul>
          </div>

          {/* Location */}
          {detection.location && (
            <div className="text-xs">
              <span className="text-text-secondary">Location: </span>
              <span className="text-accent-blue font-mono">{detection.location}</span>
            </div>
          )}

          {/* External link */}
          <a
            href={`https://attack.mitre.org/techniques/${detection.techniqueId.replace(".", "/")}/`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-accent-blue hover:underline"
          >
            View on MITRE ATT&CK
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      )}
    </div>
  );
}

function MitreMatrix({ detections }: { detections: MitreDetection[] }) {
  return (
    <div className="p-3">
      <div className="grid grid-cols-7 gap-1 text-[10px]">
        {TACTICS.slice(0, 7).map(tactic => (
          <div key={tactic.id} className="text-center">
            <div className={`font-medium ${tactic.color} mb-1 truncate`}>
              {tactic.name.split(" ")[0]}
            </div>
            <div className="space-y-0.5">
              {detections
                .filter(d => d.tacticId === tactic.id)
                .map(d => (
                  <div
                    key={d.techniqueId}
                    className="px-1 py-0.5 bg-accent-red/30 rounded text-accent-red truncate"
                    title={`${d.techniqueId}: ${d.techniqueName}`}
                  >
                    {d.techniqueId}
                  </div>
                ))}
            </div>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-7 gap-1 text-[10px] mt-2">
        {TACTICS.slice(7).map(tactic => (
          <div key={tactic.id} className="text-center">
            <div className={`font-medium ${tactic.color} mb-1 truncate`}>
              {tactic.name.split(" ")[0]}
            </div>
            <div className="space-y-0.5">
              {detections
                .filter(d => d.tacticId === tactic.id)
                .map(d => (
                  <div
                    key={d.techniqueId}
                    className="px-1 py-0.5 bg-accent-red/30 rounded text-accent-red truncate"
                    title={`${d.techniqueId}: ${d.techniqueName}`}
                  >
                    {d.techniqueId}
                  </div>
                ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
