import { Shield, Zap } from "lucide-react";
import { useAnalysisStore } from "../../stores/analysisStore";

/**
 * NarrativePanel - Shows real-time AI analysis narrative
 *
 * This panel displays analysis findings as they are discovered.
 * All data must come from actual analysis - no simulated/fake data.
 */
export function NarrativePanel() {
  const { result } = useAnalysisStore();

  // No file loaded - show empty state
  if (!result) {
    return (
      <div className="h-full flex flex-col bg-bg-primary">
        {/* Header */}
        <div className="h-10 bg-bg-secondary border-b border-border flex items-center px-3">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-accent-purple opacity-50" />
            <span className="text-sm font-medium text-text-secondary">AI Analysis</span>
          </div>
        </div>

        {/* Empty state */}
        <div className="flex-1 flex flex-col items-center justify-center text-text-secondary opacity-50">
          <Shield className="w-12 h-12 mb-3 opacity-30" />
          <p className="text-sm">No file loaded</p>
          <p className="text-xs mt-1">Load a binary to enable AI analysis</p>
        </div>
      </div>
    );
  }

  // File loaded - show analysis summary from real data
  const hasMitre = result.mitre_techniques && result.mitre_techniques.length > 0;
  const hasIocs = result.iocs && result.iocs.total > 0;
  const hasSuspicious = result.analysis?.suspicious_patterns && result.analysis.suspicious_patterns.length > 0;
  const hasCrypto = result.crypto && result.crypto.count > 0;
  const isPacked = result.file_info.is_packed;

  return (
    <div className="h-full flex flex-col bg-bg-primary">
      {/* Header */}
      <div className="h-10 bg-bg-secondary border-b border-border flex items-center px-3">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-accent-purple" />
          <span className="text-sm font-medium">AI Analysis</span>
          <span className="text-xs text-accent-green">Ready</span>
        </div>
      </div>

      {/* Analysis summary from real data */}
      <div className="flex-1 overflow-auto p-3 space-y-3">
        {/* File info */}
        <div className="p-2 bg-bg-tertiary rounded text-xs">
          <div className="text-text-secondary mb-1">Analyzed File</div>
          <div className="text-text-primary font-medium">{result.file_info.name}</div>
          <div className="text-text-secondary mt-1">
            {result.file_info.arch} · {result.file_info.size} bytes · Entropy: {result.file_info.entropy}
          </div>
        </div>

        {/* Packing detection */}
        {isPacked && (
          <div className="p-2 bg-accent-yellow/10 border border-accent-yellow/30 rounded text-xs">
            <div className="text-accent-yellow font-medium">High Entropy Detected</div>
            <div className="text-text-secondary mt-1">
              Binary may be packed or encrypted (entropy {">"} 7.0)
            </div>
          </div>
        )}

        {/* MITRE techniques */}
        {hasMitre && (
          <div className="p-2 bg-accent-red/10 border border-accent-red/30 rounded text-xs">
            <div className="text-accent-red font-medium">
              {result.mitre_techniques!.length} MITRE Techniques Detected
            </div>
            <div className="mt-1 space-y-1">
              {result.mitre_techniques!.slice(0, 3).map((t, i) => (
                <div key={i} className="text-text-secondary">
                  {t.id}: {t.name}
                </div>
              ))}
              {result.mitre_techniques!.length > 3 && (
                <div className="text-text-secondary">
                  +{result.mitre_techniques!.length - 3} more...
                </div>
              )}
            </div>
          </div>
        )}

        {/* IOCs */}
        {hasIocs && (
          <div className="p-2 bg-accent-orange/10 border border-accent-orange/30 rounded text-xs">
            <div className="text-accent-orange font-medium">
              {result.iocs!.total} Indicators of Compromise
            </div>
            <div className="text-text-secondary mt-1">
              {result.iocs!.urls?.length || 0} URLs, {result.iocs!.ips?.length || 0} IPs, {result.iocs!.registry_keys?.length || 0} Registry keys
            </div>
          </div>
        )}

        {/* Suspicious patterns */}
        {hasSuspicious && (
          <div className="p-2 bg-accent-purple/10 border border-accent-purple/30 rounded text-xs">
            <div className="text-accent-purple font-medium">
              {result.analysis!.suspicious_patterns!.length} Suspicious Patterns
            </div>
          </div>
        )}

        {/* Crypto */}
        {hasCrypto && (
          <div className="p-2 bg-accent-cyan/10 border border-accent-cyan/30 rounded text-xs">
            <div className="text-accent-cyan font-medium">
              {result.crypto!.count} Cryptographic Patterns
            </div>
          </div>
        )}

        {/* No findings */}
        {!hasMitre && !hasIocs && !hasSuspicious && !hasCrypto && !isPacked && (
          <div className="p-2 bg-accent-green/10 border border-accent-green/30 rounded text-xs">
            <div className="text-accent-green font-medium">No Suspicious Patterns</div>
            <div className="text-text-secondary mt-1">
              Static analysis did not detect obvious threats
            </div>
          </div>
        )}

        {/* Instruction stats */}
        <div className="p-2 bg-bg-tertiary rounded text-xs">
          <div className="text-text-secondary mb-1">Instruction Analysis</div>
          <div className="grid grid-cols-2 gap-1 text-text-primary">
            <div>Instructions: {result.instruction_count}</div>
            <div>Strings: {result.string_count}</div>
            {result.analysis && (
              <>
                <div>Calls: {result.analysis.calls}</div>
                <div>Jumps: {result.analysis.jumps}</div>
                <div>Interrupts: {result.analysis.interrupts}</div>
                <div>Self-XORs: {result.analysis.self_xors}</div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
