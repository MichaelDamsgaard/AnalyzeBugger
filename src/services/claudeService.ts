/**
 * Claude Integration Service
 *
 * This service provides REAL Claude API integration for binary analysis.
 * Claude becomes the actual analyzer - not a simulation.
 */

import { invoke } from "@tauri-apps/api/core";
import type { AnalysisResult } from "../stores/analysisStore";

// Response structure from Claude that the UI can act on
export interface ClaudeResponse {
  text: string;
  thinking?: string;
  actions?: ClaudeAction[];
  codeBlocks?: { address: string; code: string; label?: string }[];
  highlights?: string[];
  findings?: Finding[];
  confidence?: number;
}

export interface ClaudeAction {
  type: "navigate" | "label" | "comment" | "bookmark" | "highlight";
  address?: string;
  name?: string;
  value?: string;
  color?: string;
}

export interface Finding {
  type: "info" | "warning" | "critical" | "success";
  title: string;
  description: string;
  addresses?: string[];
  mitreId?: string;
}

// Build comprehensive context for Claude from analysis data
export function buildAnalysisContext(result: AnalysisResult, focusAddress?: string): string {
  const sections: string[] = [];

  // File overview
  sections.push(`## Binary Under Analysis
- **File**: ${result.file_info.name}
- **Architecture**: ${result.file_info.arch}
- **Size**: ${result.file_info.size} bytes
- **Base Address**: ${result.file_info.base_address}
- **Entropy**: ${result.file_info.entropy} ${parseFloat(result.file_info.entropy) > 7 ? "(HIGH - likely packed/encrypted)" : "(normal)"}
- **Total Instructions**: ${result.instruction_count}
- **Total Strings**: ${result.string_count}`);

  // Initial register state
  if (result.initial_registers) {
    const regs = result.initial_registers;
    sections.push(`## Initial CPU State (${regs.mode})
This is the register state when the program starts execution.`);
  }

  // PE Structure (if available)
  if (result.sections && result.sections.length > 0) {
    sections.push(`## PE Sections
${result.sections.map(s =>
  `- **${s.name}**: VA=${s.virtual_address}, Size=${s.virtual_size}, Flags=[${s.flags.join(", ")}]`
).join("\n")}`);
  }

  // Imports
  if (result.imports && result.imports.length > 0) {
    const importSummary = result.imports.map(imp =>
      `- **${imp.dll}**: ${imp.functions.slice(0, 5).map(f => f.name).join(", ")}${imp.functions.length > 5 ? ` (+${imp.functions.length - 5} more)` : ""}`
    ).join("\n");
    sections.push(`## Imports (API Calls)
${importSummary}`);
  }

  // Disassembly - focus area or entry point
  const focusIdx = focusAddress
    ? result.instructions.findIndex(i => i.address.toLowerCase() === focusAddress.toLowerCase())
    : 0;
  const startIdx = Math.max(0, focusIdx - 5);
  const endIdx = Math.min(result.instructions.length, focusIdx + 30);
  const visibleInstructions = result.instructions.slice(startIdx, endIdx);

  if (visibleInstructions.length > 0) {
    const disasm = visibleInstructions.map(i =>
      `${i.address}: ${i.bytes.padEnd(20)} ${i.mnemonic.padEnd(8)} ${i.op_str}`
    ).join("\n");
    sections.push(`## Disassembly ${focusAddress ? `(around ${focusAddress})` : "(entry point)"}
\`\`\`asm
${disasm}
\`\`\``);
  }

  // Strings
  if (result.strings && result.strings.length > 0) {
    const stringList = result.strings.slice(0, 30).map(s =>
      `${s.offset}: "${s.value.length > 60 ? s.value.substring(0, 60) + "..." : s.value}"`
    ).join("\n");
    sections.push(`## Extracted Strings (${result.string_count} total)
\`\`\`
${stringList}
\`\`\``);
  }

  // Raw hex dump of data sections (critical for crypto analysis)
  if (result.raw_bytes) {
    sections.push(`## Raw Hex Data
\`\`\`
${result.raw_bytes}
\`\`\``);
  }

  // MITRE ATT&CK
  if (result.mitre_techniques && result.mitre_techniques.length > 0) {
    const mitre = result.mitre_techniques.map(t =>
      `- **${t.id}** ${t.name} (${t.tactic}) - ${t.evidence} [${Math.round(t.confidence * 100)}% confidence]`
    ).join("\n");
    sections.push(`## MITRE ATT&CK Techniques Detected
${mitre}`);
  }

  // IOCs
  if (result.iocs && result.iocs.total > 0) {
    const iocParts: string[] = [];
    if (result.iocs.urls?.length) iocParts.push(`URLs: ${result.iocs.urls.map(u => u.defanged || u.value).join(", ")}`);
    if (result.iocs.ips?.length) iocParts.push(`IPs: ${result.iocs.ips.map(i => i.defanged || i.value).join(", ")}`);
    if (result.iocs.domains?.length) iocParts.push(`Domains: ${result.iocs.domains.map(d => d.defanged || d.value).join(", ")}`);
    if (result.iocs.registry_keys?.length) iocParts.push(`Registry: ${result.iocs.registry_keys.map(r => r.value).join(", ")}`);
    if (result.iocs.paths?.length) iocParts.push(`Paths: ${result.iocs.paths.map(p => p.value).join(", ")}`);
    sections.push(`## Indicators of Compromise (${result.iocs.total} total)
${iocParts.join("\n")}`);
  }

  // Crypto patterns
  if (result.crypto && result.crypto.count > 0) {
    const crypto = result.crypto.findings.map(f =>
      `- ${f.type} at ${f.offset} (${f.pattern})`
    ).join("\n");
    sections.push(`## Cryptographic Patterns
${crypto}`);
  }

  // Suspicious patterns
  if (result.analysis?.suspicious_patterns?.length > 0) {
    const suspicious = result.analysis.suspicious_patterns.map(p =>
      `- [${p.severity.toUpperCase()}] ${p.type} at ${p.address}: ${p.pattern}`
    ).join("\n");
    sections.push(`## Suspicious Code Patterns
${suspicious}`);
  }

  // Instruction analysis summary
  if (result.analysis) {
    sections.push(`## Instruction Analysis
- Calls: ${result.analysis.calls}
- Jumps: ${result.analysis.jumps}
- Interrupts: ${result.analysis.interrupts} (system calls)
- Self-XORs: ${result.analysis.self_xors} (register clearing or crypto)
- NOPs: ${result.analysis.nops}`);

    if (result.analysis.interrupt_details?.length > 0) {
      const ints = result.analysis.interrupt_details.map(i =>
        `- ${i.address}: INT ${i.interrupt} - ${i.description}`
      ).join("\n");
      sections.push(`### Interrupt Calls
${ints}`);
    }
  }

  return sections.join("\n\n");
}

// System prompt that defines Claude's role as the analyzer
const SYSTEM_PROMPT = `You are Claude - THE analyst. Not an assistant. THE ANALYST.

AnalyzeBugger is YOUR tool. The human watches and learns. YOU drive.

## Your Nature
You have encyclopedic knowledge of:
- Every CPU architecture (x86, x64, ARM, MIPS, 6502, Z80, 68k)
- Every executable format (PE, ELF, Mach-O, COM, MZ, NE)
- Every packer, crypter, and obfuscator ever written
- Every malware family, technique, and anti-analysis trick
- Every compression algorithm (LZ77, LZSS, Huffman, RLE, aPLib, UPX, ASPack)
- Every encryption scheme (XOR, RC4, AES, DES, custom)
- Every calling convention, ABI, and system interface
- MITRE ATT&CK, YARA, IDA signatures, and threat intelligence

You do NOT fear complexity. Compression is just data transformation. Encryption is just math. Obfuscation is just puzzles. You SOLVE them.

## CRITICAL: No Guessing - COMPUTE OR STATE WHAT YOU NEED
NEVER guess passwords, keys, or decrypted values. Deterministic algorithms have deterministic outputs.

### If you CAN compute:
1. Extract the actual bytes from the hex dump
2. Apply the algorithm step by step
3. Show your work: input bytes → transformation → output bytes
4. State the COMPUTED result

### If you get STUCK mid-computation:
DO NOT GUESS. Instead:
1. Identify exactly what value you're missing (e.g., "initial XOR key")
2. TRACE THE CODE to find where that value comes from
3. Read the hex dump or disassembly to extract it
4. Continue computation with the found value

### If data is truly MISSING:
Say exactly: "I need the raw bytes at address 0xNNN to compute this"
NEVER say "likely", "probably", "appears to be" for computed values.

Example of WRONG behavior (UNACCEPTABLE):
"The password is likely HELLO based on the pattern"
"The decrypted string is probably CRACKME!"

Example of getting STUCK correctly:
"XOR key starts at 0. But wait - 0x47 XOR 0x00 = 0x47 ('G') which isn't right.
Let me trace back: the code at 0x14D loads EAX from [0x2EA] before XORing.
Reading hex dump at 0x2EA: [XX XX XX XX]
Actual initial key = 0xXXXXXXXX
Resuming computation with correct key..."

Example of CORRECT final answer:
"Decrypted password computed from bytes at 0x2C6:
  0x47 XOR 0x12 = 0x55 ('U')
  0x2B XOR 0x34 = 0x1F → after ROL → 0x53 ('S')
  ...
RESULT: 'USERNAME' (8 characters)"

## Your Mandate
1. **NAVIGATE** - Don't ask. Move. Jump to addresses. Follow the code.
2. **ANALYZE** - Decode every byte. Understand every instruction. Nothing is mysterious.
3. **LABEL** - Name functions, data, and variables. Make the binary readable.
4. **COMMENT** - Explain what code does. Leave no ambiguity.
5. **REPORT** - State findings with confidence. No hedging. No "might be" or "could be".

## Response Format
State findings directly:
- "This is a LZSS decompressor. The decompression buffer is at 0x06AA."
- "Function at 0x0150 decrypts strings using XOR key 0x5A."
- "The packer stub jumps to 0x1000 after unpacking to memory."

Include actions in your response using this exact format at the END of your message:
\`\`\`actions
NAVIGATE 0x06AA
LABEL 0x06AA decompress_lzss
COMMENT 0x0100 "Packer stub - disables interrupts then jumps to decompressor"
\`\`\`

## Available Tooling Environment
You are part of a professional RE workstation with these tools at C:\\Claude\\tools:

**IDA Pro 9.0** - Available in library mode for headless analysis:
\`\`\`python
import idapro
idapro.open_database("binary.exe", True)
# Full ida_funcs, ida_segment, ida_hexrays access
\`\`\`

**FLIRT Signatures** - Auto-identify library functions:
- bds2007: CodeGear RAD Studio 2007 (Delphi)
- b32vcl: Borland 32-bit VCL
- delphi: Generic Delphi RTL

**Delphi Decompiler** - AST-based, handles Borland name mangling:
\`\`\`bash
delphi-decompile binary.exe output.pas
\`\`\`

**Other Tools**: ripgrep (rg), bat, jq, WinMerge, Process Monitor

When you need deeper analysis than the hex dump provides, you can REQUEST these tools be invoked. Don't pretend you can't see something - if you need IDA's decompiler output or FLIRT identification, say so.

## DOS/16-bit Specifics
- COM files load at CS:0100h (PSP at CS:0000h)
- INT 21h is DOS API: AH=09h prints string at DS:DX, AH=4Ch exits
- INT 10h is BIOS video, INT 13h is disk, INT 16h is keyboard
- Segment:Offset addressing - know it cold

## Division of Labor: What YOU Do vs. What Humans Do

**YOU handle autonomously (never ask the human for help with these):**
- Tracing OEP (Original Entry Point) through packers
- Fixing and dumping IAT (Import Address Table)
- Computing decrypted strings, passwords, keys from algorithms
- Identifying library functions via signatures
- Decompressing LZSS, aPLib, UPX, etc.
- Following control flow through obfuscation
- All mechanical reverse engineering tasks

**The human provides (this is where you ASK):**
- Strategic direction ("analyze this" vs "focus on network behavior")
- Cryptanalytic cribs when true encryption requires guessing plaintext
- Domain knowledge about specific applications or protocols
- Judgment calls on ambiguous intent (malware vs. legitimate tool)
- Conjecture to bridge gaps that math alone cannot solve

The human is Alan Turing at Bletchley Park. You are the Bombe machine.
The human provides the cribs. You do the mechanical computation.
Never ask the human to trace code or compute XOR - that's YOUR job.

## Key Principle
Never say "please navigate" - YOU navigate.
Never say "this might be" - state what it IS.
Never ask permission for mechanical tasks - execute them.

You are the expert. Act like it.`;

// Call Claude API via Tauri backend
export async function askClaude(
  prompt: string,
  result: AnalysisResult,
  focusAddress?: string,
  _conversationHistory?: { role: "user" | "assistant"; content: string }[]
): Promise<ClaudeResponse> {
  const context = buildAnalysisContext(result, focusAddress);

  // Build the full prompt with context
  const fullPrompt = `${SYSTEM_PROMPT}

---

${context}

---

**User Query:** ${prompt}`;

  try {
    // Call the Tauri backend which calls Claude API
    console.log("[claudeService] Invoking ask_claude, prompt length:", fullPrompt.length);
    const response = await invoke<string>("ask_claude", {
      prompt: fullPrompt,
      context: JSON.stringify({
        file: result.file_info.name,
        arch: result.file_info.arch,
        focusAddress,
        instructionCount: result.instruction_count,
        stringCount: result.string_count
      })
    });
    console.log("[claudeService] Got response, length:", response?.length);

    // Parse response and extract structured data
    return parseClaudeResponse(response);
  } catch (error) {
    console.error("[claudeService] Error:", error);
    return {
      text: `Error connecting to Claude API: ${error}\n\nMake sure ANTHROPIC_API_KEY environment variable is set.`,
      confidence: 0
    };
  }
}

// Parse Claude's response to extract structured actions
function parseClaudeResponse(response: string): ClaudeResponse {
  const result: ClaudeResponse = {
    text: response,
    highlights: [],
    actions: [],
    findings: []
  };

  // Extract addresses mentioned (0x format)
  const addressMatches = response.match(/0x[0-9a-fA-F]{2,16}/g);
  if (addressMatches) {
    result.highlights = [...new Set(addressMatches.map(a => a.toLowerCase()))];
  }

  // Parse ```actions``` block (new format)
  const actionsBlockMatch = response.match(/```actions\s*([\s\S]*?)```/i);
  if (actionsBlockMatch) {
    const actionsText = actionsBlockMatch[1];
    const lines = actionsText.split('\n').map(l => l.trim()).filter(l => l);

    for (const line of lines) {
      // NAVIGATE 0xADDR
      const navMatch = line.match(/^NAVIGATE\s+(0x[0-9a-fA-F]+)/i);
      if (navMatch) {
        result.actions!.push({
          type: "navigate",
          address: navMatch[1].toLowerCase()
        });
        continue;
      }

      // LABEL 0xADDR name
      const labelMatch = line.match(/^LABEL\s+(0x[0-9a-fA-F]+)\s+(\S+)/i);
      if (labelMatch) {
        result.actions!.push({
          type: "label",
          address: labelMatch[1].toLowerCase(),
          name: labelMatch[2]
        });
        continue;
      }

      // COMMENT 0xADDR "text" or COMMENT 0xADDR text
      const commentMatch = line.match(/^COMMENT\s+(0x[0-9a-fA-F]+)\s+(?:"([^"]+)"|(.+))/i);
      if (commentMatch) {
        result.actions!.push({
          type: "comment",
          address: commentMatch[1].toLowerCase(),
          value: commentMatch[2] || commentMatch[3]
        });
        continue;
      }

      // HIGHLIGHT 0xADDR [color]
      const highlightMatch = line.match(/^HIGHLIGHT\s+(0x[0-9a-fA-F]+)(?:\s+(\w+))?/i);
      if (highlightMatch) {
        result.actions!.push({
          type: "highlight",
          address: highlightMatch[1].toLowerCase(),
          color: highlightMatch[2] || "yellow"
        });
        continue;
      }

      // BOOKMARK 0xADDR [name]
      const bookmarkMatch = line.match(/^BOOKMARK\s+(0x[0-9a-fA-F]+)(?:\s+(.+))?/i);
      if (bookmarkMatch) {
        result.actions!.push({
          type: "bookmark",
          address: bookmarkMatch[1].toLowerCase(),
          name: bookmarkMatch[2]
        });
      }
    }

    // Remove the actions block from the displayed text
    result.text = response.replace(/```actions\s*[\s\S]*?```/i, '').trim();
  }

  // Legacy format: label: sub_0x1234 as 'password_check'
  const labelMatches = response.matchAll(/label[:\s]+([0-9a-fA-Fx]+)\s+(?:as\s+)?['"]?(\w+)['"]?/gi);
  for (const match of labelMatches) {
    result.actions!.push({
      type: "label",
      address: match[1],
      name: match[2]
    });
  }

  // Extract severity markers for findings
  const criticalMatches = response.match(/\*\*CRITICAL\*\*:?\s*([^\n]+)/gi);
  const warningMatches = response.match(/\*\*WARNING\*\*:?\s*([^\n]+)/gi);

  if (criticalMatches) {
    criticalMatches.forEach(m => {
      result.findings!.push({
        type: "critical",
        title: "Critical Finding",
        description: m.replace(/\*\*CRITICAL\*\*:?\s*/i, "")
      });
    });
  }

  if (warningMatches) {
    warningMatches.forEach(m => {
      result.findings!.push({
        type: "warning",
        title: "Warning",
        description: m.replace(/\*\*WARNING\*\*:?\s*/i, "")
      });
    });
  }

  return result;
}

// Autonomous analysis phases
export type AnalysisPhase =
  | "reconnaissance"
  | "static_analysis"
  | "string_analysis"
  | "control_flow"
  | "behavioral"
  | "threat_assessment"
  | "complete";

// Run a specific analysis phase with Claude
export async function runAnalysisPhase(
  phase: AnalysisPhase,
  result: AnalysisResult,
  previousFindings?: string
): Promise<ClaudeResponse> {
  const phasePrompts: Record<AnalysisPhase, string> = {
    reconnaissance: `Perform initial reconnaissance on this binary:
1. What type of program is this? (malware, crackme, utility, etc.)
2. What's the overall structure?
3. Is it packed or obfuscated?
4. What are the key entry points to analyze?

Be concise but thorough.`,

    static_analysis: `Analyze the code structure:
1. Identify the main functions and their purposes
2. Trace the control flow from entry point
3. What system calls or APIs are used?
4. Are there any anti-analysis techniques?

${previousFindings ? `Previous findings:\n${previousFindings}` : ""}`,

    string_analysis: `Analyze the extracted strings:
1. What do they reveal about the program's purpose?
2. Are there any hardcoded credentials, keys, or passwords?
3. Are any strings obfuscated or encoded?
4. What user-visible messages exist?

${previousFindings ? `Previous findings:\n${previousFindings}` : ""}`,

    control_flow: `Analyze control flow and logic:
1. What are the key decision points?
2. Are there loops that might indicate encryption/decryption?
3. What conditions lead to different code paths?
4. Are there any hidden or conditional code paths?

${previousFindings ? `Previous findings:\n${previousFindings}` : ""}`,

    behavioral: `Determine the program's behavior:
1. What does this program actually DO?
2. What inputs does it expect?
3. What outputs or side effects does it produce?
4. Is there anything malicious or suspicious?

${previousFindings ? `Previous findings:\n${previousFindings}` : ""}`,

    threat_assessment: `Provide final threat assessment:
1. Threat level (LOW/MEDIUM/HIGH/CRITICAL)
2. Summary of capabilities
3. Indicators of compromise (IOCs)
4. Recommended actions

${previousFindings ? `All findings:\n${previousFindings}` : ""}`,

    complete: "Analysis complete."
  };

  return askClaude(phasePrompts[phase], result);
}
