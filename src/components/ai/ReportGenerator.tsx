import { useState } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import {
  FileText, Download, Copy, Check, Loader2,
  FileJson, FileCode, Shield
} from "lucide-react";

type ReportFormat = "markdown" | "json" | "stix" | "yara";

export function ReportGenerator() {
  const { result } = useAnalysisStore();
  const [format, setFormat] = useState<ReportFormat>("markdown");
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedReport, setGeneratedReport] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const generateReport = async () => {
    if (!result) return;

    setIsGenerating(true);
    await new Promise(resolve => setTimeout(resolve, 300));

    let report = "";

    switch (format) {
      case "markdown":
        report = generateMarkdownReport(result);
        break;
      case "json":
        report = generateJsonReport(result);
        break;
      case "stix":
        report = generateStixReport(result);
        break;
      case "yara":
        report = generateYaraRule(result);
        break;
    }

    setGeneratedReport(report);
    setIsGenerating(false);
  };

  const copyReport = () => {
    if (generatedReport) {
      navigator.clipboard.writeText(generatedReport);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  const downloadReport = () => {
    if (!generatedReport || !result) return;

    const ext = format === "markdown" ? "md" :
                format === "json" ? "json" :
                format === "stix" ? "json" :
                "yar";

    const blob = new Blob([generatedReport], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${result.file_info.name}_report.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!result) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <FileText className="w-10 h-10 mx-auto mb-3 opacity-50" />
          <p className="text-sm">Report Generator</p>
          <p className="text-xs mt-1">Analyze a file to generate reports</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-10 bg-gradient-to-r from-accent-green/20 to-accent-cyan/20 border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <FileText className="w-5 h-5 text-accent-green" />
          <span className="text-sm font-medium">Report Generator</span>
          <span className="px-1.5 py-0.5 text-[10px] bg-accent-green/20 text-accent-green rounded">
            Auto-Doc
          </span>
        </div>
      </div>

      {/* Format selection */}
      <div className="h-12 bg-bg-tertiary border-b border-border flex items-center px-3 gap-2">
        <span className="text-xs text-text-secondary">Format:</span>
        <div className="flex gap-1">
          {[
            { id: "markdown", label: "Markdown", icon: FileText },
            { id: "json", label: "JSON", icon: FileJson },
            { id: "stix", label: "STIX 2.1", icon: Shield },
            { id: "yara", label: "YARA", icon: FileCode },
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => { setFormat(id as ReportFormat); setGeneratedReport(null); }}
              className={`flex items-center gap-1 px-2 py-1 text-xs rounded transition-colors ${
                format === id
                  ? "bg-accent-green/20 text-accent-green"
                  : "text-text-secondary hover:text-text-primary hover:bg-bg-hover"
              }`}
            >
              <Icon className="w-3 h-3" />
              {label}
            </button>
          ))}
        </div>
        <span className="flex-1" />
        <button
          onClick={generateReport}
          disabled={isGenerating}
          className="flex items-center gap-1 px-3 py-1 text-xs bg-accent-green/20 text-accent-green rounded hover:bg-accent-green/30 disabled:opacity-50"
        >
          {isGenerating ? (
            <Loader2 className="w-3 h-3 animate-spin" />
          ) : (
            <FileText className="w-3 h-3" />
          )}
          Generate
        </button>
      </div>

      {/* Report content */}
      <div className="flex-1 overflow-auto p-3">
        {!generatedReport ? (
          <div className="h-full flex items-center justify-center text-text-secondary">
            <div className="text-center max-w-xs">
              <FileText className="w-8 h-8 mx-auto mb-3 opacity-50" />
              <p className="text-sm">Select format and click Generate</p>
              <p className="text-xs mt-2">
                {format === "markdown" && "Full analysis report in Markdown format"}
                {format === "json" && "Structured JSON for automation/integration"}
                {format === "stix" && "STIX 2.1 threat intelligence format"}
                {format === "yara" && "YARA detection rule based on findings"}
              </p>
            </div>
          </div>
        ) : (
          <pre className="text-xs font-mono text-text-primary whitespace-pre-wrap bg-bg-tertiary p-4 rounded-lg overflow-auto">
            {generatedReport}
          </pre>
        )}
      </div>

      {/* Footer with actions */}
      {generatedReport && (
        <div className="h-10 bg-bg-secondary border-t border-border flex items-center justify-between px-3">
          <span className="text-[10px] text-text-secondary">
            {generatedReport.length.toLocaleString()} characters
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={copyReport}
              className="flex items-center gap-1 px-2 py-1 text-xs text-text-secondary hover:text-text-primary"
            >
              {copied ? (
                <Check className="w-3 h-3 text-accent-green" />
              ) : (
                <Copy className="w-3 h-3" />
              )}
              Copy
            </button>
            <button
              onClick={downloadReport}
              className="flex items-center gap-1 px-2 py-1 text-xs bg-accent-green/20 text-accent-green rounded hover:bg-accent-green/30"
            >
              <Download className="w-3 h-3" />
              Download
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function generateMarkdownReport(result: any): string {
  const date = new Date().toISOString().split("T")[0];

  return `# Malware Analysis Report

**Generated by:** AnalyzeBugger AI
**Date:** ${date}
**Analyst:** Automated Analysis

---

## Executive Summary

This report presents the automated static analysis of \`${result.file_info.name}\`.

| Property | Value |
|----------|-------|
| File Name | ${result.file_info.name} |
| Size | ${result.file_info.size.toLocaleString()} bytes |
| Architecture | ${result.file_info.arch} |
| Entropy | ${result.file_info.entropy} |
| Packed | ${result.file_info.is_packed ? "Yes (High Entropy)" : "No"} |

---

## Threat Assessment

${result.mitre_techniques?.length > 0 ? `
### MITRE ATT&CK Techniques

| ID | Name | Tactic | Confidence |
|----|------|--------|------------|
${result.mitre_techniques.map((t: { id: string; name: string; tactic: string; confidence: number }) =>
  `| ${t.id} | ${t.name} | ${t.tactic} | ${Math.round(t.confidence * 100)}% |`
).join("\n")}
` : "No MITRE ATT&CK techniques identified with high confidence."}

${result.analysis?.suspicious_patterns?.length > 0 ? `
### Suspicious Patterns

${result.analysis.suspicious_patterns.map((p: { type: string; address: string; pattern: string; severity: string }) =>
  `- **${p.type}** at \`${p.address}\`: ${p.pattern} (${p.severity})`
).join("\n")}
` : ""}

---

## Indicators of Compromise (IOCs)

${result.iocs?.urls?.length > 0 ? `
### URLs
${result.iocs.urls.map((u: { defanged?: string; value: string }) => `- \`${u.defanged || u.value}\``).join("\n")}
` : ""}

${result.iocs?.ips?.length > 0 ? `
### IP Addresses
${result.iocs.ips.map((i: { defanged?: string; value: string }) => `- \`${i.defanged || i.value}\``).join("\n")}
` : ""}

${result.iocs?.domains?.length > 0 ? `
### Domains
${result.iocs.domains.map((d: { defanged?: string; value: string }) => `- \`${d.defanged || d.value}\``).join("\n")}
` : ""}

${result.iocs?.registry_keys?.length > 0 ? `
### Registry Keys
${result.iocs.registry_keys.map((r: { value: string }) => `- \`${r.value}\``).join("\n")}
` : ""}

${result.iocs?.paths?.length > 0 ? `
### File Paths
${result.iocs.paths.map((p: { value: string }) => `- \`${p.value}\``).join("\n")}
` : ""}

---

## Cryptographic Analysis

${result.crypto?.count > 0 ? `
Cryptographic patterns detected:

${result.crypto.findings.map((f: { type: string; offset: string; pattern: string; confidence: number }) =>
  `- **${f.type}** at \`${f.offset}\` - ${f.pattern} (${Math.round(f.confidence * 100)}% confidence)`
).join("\n")}
` : "No standard cryptographic patterns detected."}

---

## Static Analysis Details

- **Total Instructions:** ${result.instruction_count.toLocaleString()}
- **Extracted Strings:** ${result.string_count.toLocaleString()}
- **Call Instructions:** ${result.analysis?.calls || 0}
- **Jump Instructions:** ${result.analysis?.jumps || 0}
- **Interrupt Calls:** ${result.analysis?.interrupts || 0}

${result.analysis?.interrupt_details?.length > 0 ? `
### Interrupt Details
${result.analysis.interrupt_details.map((i: { address: string; interrupt: string; description: string }) =>
  `- \`${i.address}\`: INT ${i.interrupt} - ${i.description}`
).join("\n")}
` : ""}

---

## Notable Strings

${result.strings.slice(0, 20).map((s: { offset: string; value: string }) =>
  `- \`${s.offset}\`: "${s.value.substring(0, 60)}${s.value.length > 60 ? "..." : ""}"`
).join("\n")}

---

## Recommendations

1. ${result.file_info.is_packed ? "The binary appears packed. Consider unpacking before deeper analysis." : "Proceed with dynamic analysis to observe runtime behavior."}
2. ${result.iocs?.total > 0 ? "Block identified IOCs at network perimeter." : "No network IOCs found; monitor for dynamic resolution."}
3. ${result.mitre_techniques?.length > 0 ? "Review identified TTPs against your threat model." : "Conduct behavioral analysis to identify TTPs."}

---

*Report generated by AnalyzeBugger AI - Automated Malware Analysis Platform*
`;
}

function generateJsonReport(result: any): string {
  const report = {
    metadata: {
      tool: "AnalyzeBugger AI",
      version: "1.0.0",
      generated: new Date().toISOString(),
      type: "static_analysis"
    },
    file: {
      name: result.file_info.name,
      size: result.file_info.size,
      architecture: result.file_info.arch,
      entropy: parseFloat(result.file_info.entropy),
      is_packed: result.file_info.is_packed
    },
    threat_assessment: {
      mitre_techniques: result.mitre_techniques || [],
      suspicious_patterns: result.analysis?.suspicious_patterns || [],
      risk_level: result.mitre_techniques?.length > 3 ? "high" :
                  result.mitre_techniques?.length > 0 ? "medium" : "low"
    },
    iocs: {
      urls: result.iocs?.urls || [],
      ips: result.iocs?.ips || [],
      domains: result.iocs?.domains || [],
      registry_keys: result.iocs?.registry_keys || [],
      file_paths: result.iocs?.paths || [],
      total: result.iocs?.total || 0
    },
    crypto: result.crypto || { findings: [], count: 0 },
    statistics: {
      instruction_count: result.instruction_count,
      string_count: result.string_count,
      calls: result.analysis?.calls || 0,
      jumps: result.analysis?.jumps || 0,
      interrupts: result.analysis?.interrupts || 0
    }
  };

  return JSON.stringify(report, null, 2);
}

function generateStixReport(result: any): string {
  const id = `indicator--${crypto.randomUUID ? crypto.randomUUID() : Date.now()}`;
  const now = new Date().toISOString();

  const stix = {
    type: "bundle",
    id: `bundle--${Date.now()}`,
    objects: [
      {
        type: "indicator",
        spec_version: "2.1",
        id: id,
        created: now,
        modified: now,
        name: `${result.file_info.name} Analysis`,
        description: `Static analysis of ${result.file_info.arch} binary`,
        indicator_types: ["malicious-activity"],
        pattern: `[file:name = '${result.file_info.name}']`,
        pattern_type: "stix",
        valid_from: now,
        labels: result.mitre_techniques?.map((t: { id: string }) => t.id) || []
      },
      ...(result.iocs?.urls?.map((u: { value: string }, i: number) => ({
        type: "indicator",
        spec_version: "2.1",
        id: `indicator--url-${i}-${Date.now()}`,
        created: now,
        modified: now,
        name: `URL IOC ${i + 1}`,
        pattern: `[url:value = '${u.value}']`,
        pattern_type: "stix",
        valid_from: now
      })) || []),
      ...(result.iocs?.ips?.map((ip: { value: string }, i: number) => ({
        type: "indicator",
        spec_version: "2.1",
        id: `indicator--ip-${i}-${Date.now()}`,
        created: now,
        modified: now,
        name: `IP IOC ${i + 1}`,
        pattern: `[ipv4-addr:value = '${ip.value}']`,
        pattern_type: "stix",
        valid_from: now
      })) || [])
    ]
  };

  return JSON.stringify(stix, null, 2);
}

function generateYaraRule(result: any): string {
  const name = result.file_info.name.replace(/[^a-zA-Z0-9]/g, "_");
  const date = new Date().toISOString().split("T")[0];

  // Select best strings for detection
  const goodStrings = result.strings
    .filter((s: { value: string }) => s.value.length >= 6 && s.value.length <= 100)
    .filter((s: { value: string }) => !/^[0-9.]+$/.test(s.value)) // No pure numbers
    .slice(0, 10);

  const stringDefs = goodStrings.map((s: { value: string }, i: number) =>
    `        $s${i} = "${s.value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`
  ).join("\n");

  // Add byte patterns from suspicious code
  const bytePatterns: string[] = [];
  if (result.analysis?.suspicious_patterns) {
    result.analysis.suspicious_patterns.slice(0, 3).forEach((p: { pattern: string; type: string }, i: number) => {
      bytePatterns.push(`        $b${i} = { ${p.pattern.substring(0, 30)} } // ${p.type}`);
    });
  }

  return `/*
    YARA Rule Generated by AnalyzeBugger AI
    Date: ${date}
    Target: ${result.file_info.name}
*/

rule ${name}_detection {
    meta:
        description = "Detects ${result.file_info.name}"
        author = "AnalyzeBugger AI"
        date = "${date}"
        arch = "${result.file_info.arch}"
        hash = "TODO: Add file hash"
${result.mitre_techniques?.length > 0 ? `        mitre = "${result.mitre_techniques.map((t: { id: string }) => t.id).join(", ")}"` : ""}

    strings:
${stringDefs}
${bytePatterns.length > 0 ? "\n" + bytePatterns.join("\n") : ""}

    condition:
        uint16(0) == 0x5A4D and // MZ header (if PE)
        ${goodStrings.length > 2 ? "3" : "2"} of ($s*) ${bytePatterns.length > 0 ? "or any of ($b*)" : ""}
}

rule ${name}_strings {
    meta:
        description = "String-based detection for ${result.file_info.name}"
        author = "AnalyzeBugger AI"
        date = "${date}"

    strings:
${stringDefs}

    condition:
        ${Math.min(3, goodStrings.length)} of them
}`;
}
