import { useState, useCallback, useMemo } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import {
  Wrench, Undo2, Trash2, Download,
  Code, Binary, AlertTriangle, Check, X, Plus, History
} from "lucide-react";

interface Patch {
  id: number;
  address: string;
  original: string; // hex bytes
  patched: string;  // hex bytes
  type: "bytes" | "instruction";
  instruction?: string; // original instruction if patching instruction
  newInstruction?: string; // new instruction text
  applied: boolean;
  timestamp: number;
  comment?: string;
}

type EditorMode = "hex" | "assemble";

// x86/x86-64 instruction encoding (simplified)
const SIMPLE_INSTRUCTIONS: Record<string, (ops: string) => string | null> = {
  nop: () => "90",
  ret: () => "C3",
  retn: () => "C3",
  int3: () => "CC",
  hlt: () => "F4",
  nope: () => "90", // alias
  // Short jumps (will need more complex handling for real implementation)
  "jmp short": (ops) => {
    const offset = parseInt(ops, 16);
    if (isNaN(offset) || offset < -128 || offset > 127) return null;
    return "EB" + (offset < 0 ? (256 + offset).toString(16) : offset.toString(16)).padStart(2, "0");
  },
};

// Common NOPs of different lengths
const NOP_SEQUENCES: Record<number, string> = {
  1: "90",
  2: "6690",
  3: "0F1F00",
  4: "0F1F4000",
  5: "0F1F440000",
  6: "660F1F440000",
  7: "0F1F8000000000",
  8: "0F1F840000000000",
  9: "660F1F840000000000",
};

export function PatchEditor() {
  const { result, navigateTo } = useAnalysisStore();

  const [mode, setMode] = useState<EditorMode>("hex");
  const [patches, setPatches] = useState<Patch[]>([]);
  const [undoStack, setUndoStack] = useState<Patch[]>([]);

  const [editAddress, setEditAddress] = useState("");
  const [hexInput, setHexInput] = useState("");
  const [asmInput, setAsmInput] = useState("");
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Patch ID counter
  const patchIdRef = { current: patches.length > 0 ? Math.max(...patches.map(p => p.id)) + 1 : 1 };

  // Get instruction at address
  const getInstructionAt = useCallback((address: string) => {
    if (!result) return null;
    return result.instructions.find(
      (i: { address: string; mnemonic: string; op_str: string; bytes: string }) =>
        i.address.toLowerCase() === address.toLowerCase()
    );
  }, [result]);

  // Validate hex string
  const isValidHex = (hex: string): boolean => {
    const clean = hex.replace(/\s/g, "");
    return /^[0-9a-fA-F]*$/.test(clean) && clean.length % 2 === 0;
  };

  // Assemble instruction (simplified)
  const assembleInstruction = useCallback((instruction: string): { bytes: string | null; error: string | null } => {
    const clean = instruction.toLowerCase().trim();

    // NOP with count: "nop 5" -> 5-byte NOP
    const nopMatch = clean.match(/^nops?\s+(\d+)$/);
    if (nopMatch) {
      const count = parseInt(nopMatch[1], 10);
      if (count >= 1 && count <= 9 && NOP_SEQUENCES[count]) {
        return { bytes: NOP_SEQUENCES[count], error: null };
      }
      if (count > 9) {
        // Multiple NOPs
        let result = "";
        let remaining = count;
        while (remaining > 0) {
          const nopLen = Math.min(remaining, 9);
          result += NOP_SEQUENCES[nopLen];
          remaining -= nopLen;
        }
        return { bytes: result, error: null };
      }
    }

    // Simple instructions
    for (const [pattern, encoder] of Object.entries(SIMPLE_INSTRUCTIONS)) {
      if (clean === pattern || clean.startsWith(pattern + " ")) {
        const ops = clean.slice(pattern.length).trim();
        const bytes = encoder(ops);
        if (bytes) {
          return { bytes: bytes.toUpperCase(), error: null };
        }
      }
    }

    // Raw hex: "db 90 90 90" or "db 0x90, 0x90"
    const dbMatch = clean.match(/^db\s+(.+)$/);
    if (dbMatch) {
      const bytes = dbMatch[1]
        .split(/[,\s]+/)
        .map(b => {
          const v = b.replace(/^0x/, "");
          return v.padStart(2, "0");
        })
        .join("");
      if (isValidHex(bytes)) {
        return { bytes: bytes.toUpperCase(), error: null };
      }
    }

    return { bytes: null, error: `Cannot assemble: "${instruction}". Use simple instructions (nop, ret, int3) or "db XX XX" for raw bytes.` };
  }, []);

  // Create patch from hex
  const createHexPatch = useCallback(() => {
    setError(null);

    if (!editAddress || !hexInput) {
      setError("Address and hex bytes required");
      return;
    }

    if (!isValidHex(hexInput)) {
      setError("Invalid hex string");
      return;
    }

    const cleanHex = hexInput.replace(/\s/g, "").toUpperCase();
    const insn = getInstructionAt(editAddress);

    const patch: Patch = {
      id: patchIdRef.current++,
      address: editAddress,
      original: insn?.bytes?.replace(/\s/g, "").toUpperCase() || "??",
      patched: cleanHex,
      type: "bytes",
      instruction: insn ? `${insn.mnemonic} ${insn.op_str}` : undefined,
      applied: false,
      timestamp: Date.now(),
      comment: comment || undefined,
    };

    setPatches(prev => [...prev, patch]);
    setHexInput("");
    setComment("");
  }, [editAddress, hexInput, comment, getInstructionAt]);

  // Create patch from assembly
  const createAsmPatch = useCallback(() => {
    setError(null);

    if (!editAddress || !asmInput) {
      setError("Address and instruction required");
      return;
    }

    const { bytes, error: asmError } = assembleInstruction(asmInput);

    if (asmError || !bytes) {
      setError(asmError || "Assembly failed");
      return;
    }

    const insn = getInstructionAt(editAddress);

    const patch: Patch = {
      id: patchIdRef.current++,
      address: editAddress,
      original: insn?.bytes?.replace(/\s/g, "").toUpperCase() || "??",
      patched: bytes,
      type: "instruction",
      instruction: insn ? `${insn.mnemonic} ${insn.op_str}` : undefined,
      newInstruction: asmInput,
      applied: false,
      timestamp: Date.now(),
      comment: comment || undefined,
    };

    setPatches(prev => [...prev, patch]);
    setAsmInput("");
    setComment("");
  }, [editAddress, asmInput, comment, assembleInstruction, getInstructionAt]);

  // Toggle patch applied state
  const togglePatch = useCallback((id: number) => {
    setPatches(prev => prev.map(p =>
      p.id === id ? { ...p, applied: !p.applied } : p
    ));
  }, []);

  // Remove patch
  const removePatch = useCallback((id: number) => {
    const patch = patches.find(p => p.id === id);
    if (patch) {
      setUndoStack(prev => [...prev, patch]);
    }
    setPatches(prev => prev.filter(p => p.id !== id));
  }, [patches]);

  // Undo last removal
  const undoRemove = useCallback(() => {
    if (undoStack.length === 0) return;
    const patch = undoStack[undoStack.length - 1];
    setUndoStack(prev => prev.slice(0, -1));
    setPatches(prev => [...prev, patch]);
  }, [undoStack]);

  // Export patches as JSON
  const exportPatches = useCallback(() => {
    const data = {
      file: result?.file_info.name || "unknown",
      patches: patches.map(p => ({
        address: p.address,
        original: p.original,
        patched: p.patched,
        type: p.type,
        instruction: p.instruction,
        newInstruction: p.newInstruction,
        applied: p.applied,
        comment: p.comment,
      })),
      exported: new Date().toISOString(),
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `patches_${result?.file_info.name || "binary"}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [patches, result]);

  // Stats
  const stats = useMemo(() => ({
    total: patches.length,
    applied: patches.filter(p => p.applied).length,
    bytes: patches.reduce((acc, p) => acc + p.patched.length / 2, 0),
  }), [patches]);

  if (!result) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <Wrench className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">Patch Editor</p>
          <p className="text-xs mt-1">Analyze a file to create patches</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-10 bg-bg-secondary border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <Wrench className="w-4 h-4 text-accent-orange" />
          <span className="text-sm font-medium">Patch Editor</span>
          {patches.length > 0 && (
            <span className="text-xs text-text-secondary">
              ({stats.applied}/{stats.total} applied, {stats.bytes} bytes)
            </span>
          )}
        </div>

        <div className="flex items-center gap-1">
          <button
            onClick={undoRemove}
            disabled={undoStack.length === 0}
            className="p-1.5 rounded hover:bg-bg-hover disabled:opacity-30"
            title="Undo remove"
          >
            <Undo2 className="w-3 h-3" />
          </button>
          <button
            onClick={exportPatches}
            disabled={patches.length === 0}
            className="p-1.5 rounded hover:bg-bg-hover disabled:opacity-30"
            title="Export patches"
          >
            <Download className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Mode tabs + Input */}
      <div className="bg-bg-tertiary border-b border-border p-3 space-y-3">
        {/* Mode toggle */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setMode("hex")}
            className={`flex items-center gap-1 px-3 py-1 text-xs rounded ${
              mode === "hex"
                ? "bg-accent-blue/20 text-accent-blue"
                : "bg-bg-secondary text-text-secondary hover:text-text-primary"
            }`}
          >
            <Binary className="w-3 h-3" />
            Hex Bytes
          </button>
          <button
            onClick={() => setMode("assemble")}
            className={`flex items-center gap-1 px-3 py-1 text-xs rounded ${
              mode === "assemble"
                ? "bg-accent-purple/20 text-accent-purple"
                : "bg-bg-secondary text-text-secondary hover:text-text-primary"
            }`}
          >
            <Code className="w-3 h-3" />
            Assemble
          </button>
        </div>

        {/* Address input */}
        <div className="flex items-center gap-2">
          <label className="text-xs text-text-secondary w-16">Address:</label>
          <input
            type="text"
            value={editAddress}
            onChange={(e) => setEditAddress(e.target.value)}
            placeholder="0x00401000"
            className="flex-1 px-2 py-1 text-xs bg-bg-primary border border-border rounded font-mono focus:outline-none focus:border-accent-blue"
          />
        </div>

        {/* Mode-specific input */}
        {mode === "hex" ? (
          <div className="flex items-center gap-2">
            <label className="text-xs text-text-secondary w-16">Bytes:</label>
            <input
              type="text"
              value={hexInput}
              onChange={(e) => setHexInput(e.target.value)}
              placeholder="90 90 90 (hex bytes)"
              className="flex-1 px-2 py-1 text-xs bg-bg-primary border border-border rounded font-mono focus:outline-none focus:border-accent-blue"
            />
            <button
              onClick={createHexPatch}
              className="px-3 py-1 text-xs bg-accent-blue text-white rounded hover:opacity-90 flex items-center gap-1"
            >
              <Plus className="w-3 h-3" />
              Add
            </button>
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <label className="text-xs text-text-secondary w-16">Asm:</label>
            <input
              type="text"
              value={asmInput}
              onChange={(e) => setAsmInput(e.target.value)}
              placeholder="nop / ret / db 90 90 90"
              className="flex-1 px-2 py-1 text-xs bg-bg-primary border border-border rounded font-mono focus:outline-none focus:border-accent-purple"
            />
            <button
              onClick={createAsmPatch}
              className="px-3 py-1 text-xs bg-accent-purple text-white rounded hover:opacity-90 flex items-center gap-1"
            >
              <Plus className="w-3 h-3" />
              Assemble
            </button>
          </div>
        )}

        {/* Comment */}
        <div className="flex items-center gap-2">
          <label className="text-xs text-text-secondary w-16">Comment:</label>
          <input
            type="text"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            placeholder="Optional description"
            className="flex-1 px-2 py-1 text-xs bg-bg-primary border border-border rounded focus:outline-none focus:border-accent-blue"
          />
        </div>

        {/* Error display */}
        {error && (
          <div className="flex items-center gap-2 px-2 py-1 bg-accent-red/20 text-accent-red rounded text-xs">
            <AlertTriangle className="w-3 h-3" />
            {error}
          </div>
        )}

        {/* Quick help */}
        <div className="text-[10px] text-text-secondary">
          {mode === "hex" ? (
            <span>Enter hex bytes separated by spaces: 90 90 90 or 909090</span>
          ) : (
            <span>Supported: nop, ret, int3, hlt, nop N, db XX XX XX</span>
          )}
        </div>
      </div>

      {/* Patches list */}
      <div className="flex-1 overflow-auto">
        {patches.length === 0 ? (
          <div className="h-full flex items-center justify-center text-text-secondary">
            <div className="text-center">
              <History className="w-6 h-6 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No patches yet</p>
              <p className="text-xs mt-1">Add patches using the form above</p>
            </div>
          </div>
        ) : (
          <div className="p-2 space-y-2">
            {patches.map(patch => (
              <div
                key={patch.id}
                className={`p-2 rounded border ${
                  patch.applied
                    ? "bg-accent-green/10 border-accent-green/30"
                    : "bg-bg-tertiary border-border"
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    {/* Address and type */}
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => navigateTo(patch.address)}
                        className="font-mono text-xs text-accent-blue hover:underline"
                      >
                        {patch.address}
                      </button>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                        patch.type === "instruction"
                          ? "bg-accent-purple/20 text-accent-purple"
                          : "bg-accent-blue/20 text-accent-blue"
                      }`}>
                        {patch.type}
                      </span>
                    </div>

                    {/* Original -> Patched */}
                    <div className="mt-1 font-mono text-xs">
                      <span className="text-text-secondary">{patch.original}</span>
                      <span className="mx-2 text-text-secondary">→</span>
                      <span className="text-accent-orange">{patch.patched}</span>
                    </div>

                    {/* Instruction info */}
                    {patch.instruction && (
                      <div className="mt-1 text-xs text-text-secondary">
                        <span className="line-through">{patch.instruction}</span>
                        {patch.newInstruction && (
                          <>
                            <span className="mx-2">→</span>
                            <span className="text-accent-green">{patch.newInstruction}</span>
                          </>
                        )}
                      </div>
                    )}

                    {/* Comment */}
                    {patch.comment && (
                      <div className="mt-1 text-xs text-text-secondary italic">
                        {patch.comment}
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => togglePatch(patch.id)}
                      className={`p-1 rounded ${
                        patch.applied
                          ? "bg-accent-green/20 text-accent-green"
                          : "hover:bg-bg-hover text-text-secondary"
                      }`}
                      title={patch.applied ? "Unapply patch" : "Apply patch"}
                    >
                      {patch.applied ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                    </button>
                    <button
                      onClick={() => removePatch(patch.id)}
                      className="p-1 rounded hover:bg-accent-red/20 hover:text-accent-red text-text-secondary"
                      title="Remove patch"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Footer with apply all */}
      {patches.length > 0 && (
        <div className="h-10 bg-bg-secondary border-t border-border flex items-center justify-between px-3">
          <div className="text-xs text-text-secondary">
            {stats.applied} of {stats.total} patches applied
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPatches(prev => prev.map(p => ({ ...p, applied: true })))}
              className="px-2 py-1 text-xs bg-accent-green/20 text-accent-green rounded hover:bg-accent-green/30"
            >
              Apply All
            </button>
            <button
              onClick={() => setPatches(prev => prev.map(p => ({ ...p, applied: false })))}
              className="px-2 py-1 text-xs bg-bg-tertiary text-text-secondary rounded hover:bg-bg-hover"
            >
              Unapply All
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
