import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";

export interface FileInfo {
  name: string;
  size: number;
  arch: string;
  base_address: string;
  entropy: string;
  is_packed: boolean;
}

export interface StaticInstruction {
  address: string;
  bytes: string;
  mnemonic: string;
  op_str: string;
}

export interface ExtractedString {
  offset: string;
  value: string;
  length: number;
}

export interface InterruptDetail {
  address: string;
  interrupt: string;
  description: string;
}

export interface SuspiciousPattern {
  address: string;
  type: string;
  pattern: string;
  severity: string;
}

export interface InstructionAnalysis {
  total_instructions: number;
  calls: number;
  jumps: number;
  interrupts: number;
  syscalls: number;
  pushes: number;
  pops: number;
  nops: number;
  self_xors: number;
  interrupt_details: InterruptDetail[];
  suspicious_patterns: SuspiciousPattern[];
}

export interface IocEntry {
  value: string;
  offset: string;
  defanged?: string;
  type?: string;
}

export interface ExtractedIocs {
  urls: IocEntry[];
  ips: IocEntry[];
  paths: IocEntry[];
  registry_keys: IocEntry[];
  emails: IocEntry[];
  domains: IocEntry[];
  total: number;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  confidence: number;
  evidence: string;
}

export interface CryptoFinding {
  type: string;
  pattern: string;
  offset: string;
  confidence: number;
}

export interface CryptoAnalysis {
  findings: CryptoFinding[];
  count: number;
}

export interface InitialRegisters {
  mode: string;
  [key: string]: string | object;
}

// PE Section
export interface PESection {
  name: string;
  virtual_address: string;
  virtual_size: number;
  raw_size: number;
  raw_pointer: string;
  characteristics: string;
  flags: string[];
}

// PE Import
export interface ImportFunction {
  name: string;
  ordinal: number | null;
  hint: number | null;
  iat_address: string;
}

export interface ImportEntry {
  dll: string;
  function_count: number;
  iat_rva: string;
  functions: ImportFunction[];
}

// PE Export
export interface ExportFunction {
  ordinal: number;
  name: string | null;
  rva: string;
}

export interface ExportData {
  dll_name: string | null;
  functions: ExportFunction[];
  count: number;
}

export interface AnalysisResult {
  file_info: FileInfo;
  instructions: StaticInstruction[];
  instruction_count: number;
  strings: ExtractedString[];
  string_count: number;
  analysis: InstructionAnalysis;
  iocs: ExtractedIocs;
  mitre_techniques: MitreTechnique[];
  crypto: CryptoAnalysis;
  initial_registers: InitialRegisters;
  sections: PESection[];
  imports: ImportEntry[];
  exports: ExportData;
}

// Cross-reference types
export interface XRef {
  from: string;       // Source address
  to: string;         // Target address
  type: "call" | "jump" | "data" | "string";
  mnemonic?: string;  // The instruction mnemonic
}

// User annotation types
export interface AddressComment {
  address: string;
  comment: string;
  type: "inline" | "pre" | "post";
}

export interface AddressLabel {
  address: string;
  name: string;
  type: "function" | "label" | "data";
}

export interface Bookmark {
  address: string;
  name: string;
  color?: string;
}

interface AnalysisState {
  // State
  filePath: string | null;
  result: AnalysisResult | null;
  isAnalyzing: boolean;
  error: string | null;

  // Navigation state
  currentAddress: string | null;
  addressHistory: string[];
  historyIndex: number;

  // Cross-references (computed)
  xrefsTo: Map<string, XRef[]>;    // Address -> refs TO this address
  xrefsFrom: Map<string, XRef[]>;  // Address -> refs FROM this address

  // User annotations
  comments: Map<string, AddressComment>;
  labels: Map<string, AddressLabel>;
  bookmarks: Bookmark[];

  // Actions
  analyzeFile: (path: string) => Promise<void>;
  clearAnalysis: () => void;

  // Navigation actions
  navigateTo: (address: string) => void;
  navigateBack: () => void;
  navigateForward: () => void;

  // Annotation actions
  setComment: (address: string, comment: string, type?: "inline" | "pre" | "post") => void;
  setLabel: (address: string, name: string, type?: "function" | "label" | "data") => void;
  addBookmark: (address: string, name: string, color?: string) => void;
  removeBookmark: (address: string) => void;

  // Xref getter
  getXrefsTo: (address: string) => XRef[];
  getXrefsFrom: (address: string) => XRef[];
}

// Helper to compute xrefs from instructions
function computeXrefs(instructions: StaticInstruction[]): {
  xrefsTo: Map<string, XRef[]>;
  xrefsFrom: Map<string, XRef[]>;
} {
  const xrefsTo = new Map<string, XRef[]>();
  const xrefsFrom = new Map<string, XRef[]>();

  for (const insn of instructions) {
    const mnemonic = insn.mnemonic.toLowerCase();
    let xrefType: XRef["type"] | null = null;

    // Determine xref type
    if (mnemonic === "call") {
      xrefType = "call";
    } else if (mnemonic.startsWith("j") || mnemonic === "loop" || mnemonic === "loope" || mnemonic === "loopne") {
      xrefType = "jump";
    } else if (mnemonic === "lea" || mnemonic === "mov") {
      // Check if operand looks like an address reference
      if (insn.op_str.includes("[") || /^0x[0-9a-fA-F]+$/.test(insn.op_str.split(",").pop()?.trim() || "")) {
        xrefType = "data";
      }
    }

    if (xrefType) {
      // Extract target address from operand
      const opParts = insn.op_str.split(",");
      const targetPart = opParts[opParts.length - 1].trim();
      const addrMatch = targetPart.match(/0x([0-9a-fA-F]+)/);

      if (addrMatch) {
        const targetAddr = "0x" + addrMatch[1].toLowerCase();
        const xref: XRef = {
          from: insn.address,
          to: targetAddr,
          type: xrefType,
          mnemonic: insn.mnemonic,
        };

        // Add to xrefsTo (target address)
        if (!xrefsTo.has(targetAddr)) {
          xrefsTo.set(targetAddr, []);
        }
        xrefsTo.get(targetAddr)!.push(xref);

        // Add to xrefsFrom (source address)
        if (!xrefsFrom.has(insn.address)) {
          xrefsFrom.set(insn.address, []);
        }
        xrefsFrom.get(insn.address)!.push(xref);
      }
    }
  }

  return { xrefsTo, xrefsFrom };
}

export const useAnalysisStore = create<AnalysisState>((set, get) => ({
  // Initial state
  filePath: null,
  result: null,
  isAnalyzing: false,
  error: null,

  // Navigation state
  currentAddress: null,
  addressHistory: [],
  historyIndex: -1,

  // Cross-references
  xrefsTo: new Map(),
  xrefsFrom: new Map(),

  // User annotations
  comments: new Map(),
  labels: new Map(),
  bookmarks: [],

  // Analyze a file statically
  analyzeFile: async (path: string) => {
    set({ isAnalyzing: true, error: null, filePath: path });
    try {
      const resultStr = await invoke<string>("analyze_file", { path });
      const result = JSON.parse(resultStr) as AnalysisResult;

      // Compute cross-references
      const { xrefsTo, xrefsFrom } = computeXrefs(result.instructions);

      // Set initial address to entry point
      const entryAddr = result.instructions[0]?.address || null;

      set({
        result,
        isAnalyzing: false,
        xrefsTo,
        xrefsFrom,
        currentAddress: entryAddr,
        addressHistory: entryAddr ? [entryAddr] : [],
        historyIndex: entryAddr ? 0 : -1,
        // Clear annotations for new file
        comments: new Map(),
        labels: new Map(),
        bookmarks: [],
      });
    } catch (e) {
      set({ error: String(e), isAnalyzing: false });
    }
  },

  // Clear analysis
  clearAnalysis: () => {
    set({
      filePath: null,
      result: null,
      error: null,
      currentAddress: null,
      addressHistory: [],
      historyIndex: -1,
      xrefsTo: new Map(),
      xrefsFrom: new Map(),
      comments: new Map(),
      labels: new Map(),
      bookmarks: [],
    });
  },

  // Navigation actions
  navigateTo: (address: string) => {
    const { addressHistory, historyIndex } = get();
    // Truncate forward history and add new address
    const newHistory = [...addressHistory.slice(0, historyIndex + 1), address];
    set({
      currentAddress: address,
      addressHistory: newHistory,
      historyIndex: newHistory.length - 1,
    });
  },

  navigateBack: () => {
    const { addressHistory, historyIndex } = get();
    if (historyIndex > 0) {
      set({
        currentAddress: addressHistory[historyIndex - 1],
        historyIndex: historyIndex - 1,
      });
    }
  },

  navigateForward: () => {
    const { addressHistory, historyIndex } = get();
    if (historyIndex < addressHistory.length - 1) {
      set({
        currentAddress: addressHistory[historyIndex + 1],
        historyIndex: historyIndex + 1,
      });
    }
  },

  // Annotation actions
  setComment: (address: string, comment: string, type: "inline" | "pre" | "post" = "inline") => {
    const { comments } = get();
    const newComments = new Map(comments);
    if (comment.trim()) {
      newComments.set(address, { address, comment, type });
    } else {
      newComments.delete(address);
    }
    set({ comments: newComments });
  },

  setLabel: (address: string, name: string, type: "function" | "label" | "data" = "label") => {
    const { labels } = get();
    const newLabels = new Map(labels);
    if (name.trim()) {
      newLabels.set(address, { address, name, type });
    } else {
      newLabels.delete(address);
    }
    set({ labels: newLabels });
  },

  addBookmark: (address: string, name: string, color?: string) => {
    const { bookmarks } = get();
    // Don't add duplicate
    if (!bookmarks.find(b => b.address === address)) {
      set({ bookmarks: [...bookmarks, { address, name, color }] });
    }
  },

  removeBookmark: (address: string) => {
    const { bookmarks } = get();
    set({ bookmarks: bookmarks.filter(b => b.address !== address) });
  },

  // Xref getters
  getXrefsTo: (address: string) => {
    return get().xrefsTo.get(address) || [];
  },

  getXrefsFrom: (address: string) => {
    return get().xrefsFrom.get(address) || [];
  },
}));
