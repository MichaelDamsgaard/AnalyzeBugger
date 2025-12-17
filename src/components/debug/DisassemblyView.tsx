import { useState, useRef, useEffect, useCallback } from "react";
import { useSessionStore } from "../../stores/sessionStore";
import { useAnalysisStore } from "../../stores/analysisStore";
import {
  ChevronRight, FileSearch, ChevronLeft, ArrowRight,
  Bookmark, MessageSquare, Tag
} from "lucide-react";

export function DisassemblyView() {
  const { disassembly, status } = useSessionStore();
  const {
    result: analysisResult,
    currentAddress,
    navigateTo,
    navigateBack,
    navigateForward,
    addressHistory,
    historyIndex,
    labels,
    comments,
    bookmarks,
    getXrefsTo,
  } = useAnalysisStore();

  const [goToAddress, setGoToAddress] = useState("");
  const [hoveredAddress, setHoveredAddress] = useState<string | null>(null);
  const tableRef = useRef<HTMLDivElement>(null);
  const currentRowRef = useRef<HTMLTableRowElement>(null);

  const currentIp = status?.session?.current_ip;

  // Use static analysis instructions if available, otherwise debug disassembly
  const instructions = analysisResult?.instructions || disassembly;
  const isStaticAnalysis = !!analysisResult;

  // Scroll to current address when it changes
  useEffect(() => {
    if (currentRowRef.current && tableRef.current) {
      currentRowRef.current.scrollIntoView({
        behavior: "smooth",
        block: "center",
      });
    }
  }, [currentAddress]);

  // Handle address navigation
  const handleGoTo = useCallback(() => {
    const addr = goToAddress.trim().toLowerCase();
    if (!addr) return;

    const normalizedAddr = addr.startsWith("0x") ? addr : `0x${addr}`;
    navigateTo(normalizedAddr);
    setGoToAddress("");
  }, [goToAddress, navigateTo]);

  // Parse jump/call targets for click navigation
  const parseTarget = useCallback((opStr: string): string | null => {
    // Match hex address patterns
    const match = opStr.match(/\b(0x[0-9a-fA-F]+)\b/);
    if (match) return match[1].toLowerCase();

    // Match short hex (like "0100")
    const shortMatch = opStr.match(/^([0-9a-fA-F]{4,})$/);
    if (shortMatch) return `0x${shortMatch[1].toLowerCase()}`;

    return null;
  }, []);

  if (instructions.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <FileSearch className="w-10 h-10 mx-auto mb-3 opacity-50" />
          <p>No disassembly to display</p>
          <p className="text-xs mt-1">Open a file and click Analyze or Debug</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Navigation Bar */}
      <div className="h-8 bg-bg-secondary border-b border-border flex items-center px-2 gap-2 shrink-0">
        {/* Back/Forward */}
        <button
          onClick={navigateBack}
          disabled={historyIndex <= 0}
          className="p-1 hover:bg-bg-hover rounded disabled:opacity-30 disabled:cursor-not-allowed"
          title="Go back"
        >
          <ChevronLeft className="w-4 h-4" />
        </button>
        <button
          onClick={navigateForward}
          disabled={historyIndex >= addressHistory.length - 1}
          className="p-1 hover:bg-bg-hover rounded disabled:opacity-30 disabled:cursor-not-allowed"
          title="Go forward"
        >
          <ChevronRight className="w-4 h-4" />
        </button>

        {/* Separator */}
        <div className="w-px h-4 bg-border" />

        {/* Go to Address */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleGoTo();
          }}
          className="flex items-center gap-1"
        >
          <input
            type="text"
            value={goToAddress}
            onChange={(e) => setGoToAddress(e.target.value)}
            placeholder="Go to address..."
            className="w-28 px-2 py-0.5 text-xs bg-bg-primary border border-border rounded focus:outline-none focus:border-accent-blue"
          />
          <button
            type="submit"
            className="p-1 hover:bg-bg-hover rounded"
            title="Go to address"
          >
            <ArrowRight className="w-3 h-3" />
          </button>
        </form>

        {/* Current Address Display */}
        <div className="flex-1" />
        {currentAddress && (
          <div className="flex items-center gap-2 text-xs text-text-secondary">
            <span className="text-accent-blue font-mono">{currentAddress}</span>
            {labels.get(currentAddress) && (
              <span className="px-1.5 py-0.5 bg-accent-purple/20 text-accent-purple rounded text-[10px]">
                {labels.get(currentAddress)!.name}
              </span>
            )}
          </div>
        )}
      </div>

      {/* Disassembly Table */}
      <div ref={tableRef} className="flex-1 overflow-auto font-mono text-sm">
        <table className="w-full">
          <thead className="sticky top-0 bg-bg-secondary z-10">
            <tr className="text-text-secondary text-xs">
              <th className="w-6 px-1 py-1 text-left"></th>
              <th className="w-6 px-1 py-1 text-left"></th>
              <th className="w-24 px-2 py-1 text-left">Address</th>
              <th className="w-8 px-1 py-1 text-center text-[10px]">Xrefs</th>
              <th className="w-32 px-2 py-1 text-left">Bytes</th>
              <th className="w-20 px-2 py-1 text-left">Mnemonic</th>
              <th className="px-2 py-1 text-left">Operands</th>
              <th className="w-48 px-2 py-1 text-left text-text-secondary">Comment</th>
            </tr>
          </thead>
          <tbody>
            {instructions.map((insn, idx) => {
              const isCurrent = !isStaticAnalysis && insn.address === currentIp;
              const isSelected = insn.address === currentAddress;
              const label = labels.get(insn.address);
              const comment = comments.get(insn.address);
              const bookmark = bookmarks.find((b) => b.address === insn.address);
              const xrefs = getXrefsTo(insn.address);
              const jumpTarget = parseTarget(insn.op_str);
              const isJumpOrCall =
                insn.mnemonic.toLowerCase().startsWith("j") ||
                insn.mnemonic.toLowerCase() === "call";

              return (
                <>
                  {/* Label row (if function or label exists) */}
                  {label && (
                    <tr key={`label-${idx}`} className="bg-bg-tertiary">
                      <td colSpan={8} className="px-2 py-1">
                        <div className="flex items-center gap-2">
                          <Tag className="w-3 h-3 text-accent-purple" />
                          <span className="text-accent-purple font-semibold">
                            {label.name}
                          </span>
                          {label.type === "function" && (
                            <span className="text-[10px] text-text-secondary">
                              (function)
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}

                  <tr
                    key={idx}
                    ref={isSelected ? currentRowRef : undefined}
                    onClick={() => navigateTo(insn.address)}
                    onMouseEnter={() => setHoveredAddress(insn.address)}
                    onMouseLeave={() => setHoveredAddress(null)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? "bg-accent-blue/20 border-l-2 border-accent-blue"
                        : isCurrent
                        ? "bg-accent-yellow/10"
                        : hoveredAddress === insn.address
                        ? "bg-bg-hover"
                        : ""
                    }`}
                  >
                    {/* Current Instruction Indicator */}
                    <td className="w-6 px-1 py-0.5 text-center">
                      {isCurrent && (
                        <ChevronRight className="w-3 h-3 text-accent-yellow inline" />
                      )}
                    </td>

                    {/* Bookmark/Comment indicators */}
                    <td className="w-6 px-1 py-0.5 text-center">
                      {bookmark && (
                        <Bookmark className="w-3 h-3 text-accent-orange inline" />
                      )}
                      {comment && !bookmark && (
                        <MessageSquare className="w-3 h-3 text-accent-cyan inline" />
                      )}
                    </td>

                    {/* Address */}
                    <td className="w-24 px-2 py-0.5 text-accent-blue font-mono">
                      {insn.address}
                    </td>

                    {/* Xrefs count */}
                    <td className="w-8 px-1 py-0.5 text-center">
                      {xrefs.length > 0 && (
                        <span className="text-[10px] px-1 py-0.5 bg-bg-tertiary rounded text-text-secondary">
                          {xrefs.length}
                        </span>
                      )}
                    </td>

                    {/* Bytes */}
                    <td className="w-32 px-2 py-0.5 text-text-secondary text-xs font-mono">
                      {insn.bytes}
                    </td>

                    {/* Mnemonic */}
                    <td
                      className={`w-20 px-2 py-0.5 font-semibold ${getMnemonicColor(
                        insn.mnemonic
                      )}`}
                    >
                      {insn.mnemonic}
                    </td>

                    {/* Operands */}
                    <td className="px-2 py-0.5 text-text-primary">
                      {isJumpOrCall && jumpTarget ? (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            navigateTo(jumpTarget);
                          }}
                          className="text-accent-purple hover:underline"
                        >
                          {formatOperands(insn.op_str)}
                        </button>
                      ) : (
                        formatOperands(insn.op_str)
                      )}
                    </td>

                    {/* Comment */}
                    <td className="w-48 px-2 py-0.5 text-text-secondary text-xs truncate">
                      {comment ? (
                        <span className="text-accent-cyan">{`; ${comment}`}</span>
                      ) : (
                        getAutoComment(insn.mnemonic, insn.op_str)
                      )}
                    </td>
                  </tr>
                </>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Status Bar */}
      <div className="h-5 bg-bg-secondary border-t border-border flex items-center justify-between px-2 text-[10px] text-text-secondary shrink-0">
        <span>
          {instructions.length.toLocaleString()} instructions
          {isStaticAnalysis && " (static analysis)"}
        </span>
        <div className="flex items-center gap-3">
          {historyIndex > 0 && (
            <span>History: {historyIndex + 1}/{addressHistory.length}</span>
          )}
          {bookmarks.length > 0 && (
            <span>{bookmarks.length} bookmark(s)</span>
          )}
        </div>
      </div>
    </div>
  );
}

function getMnemonicColor(mnemonic: string): string {
  const m = mnemonic.toLowerCase();

  // Jumps and calls
  if (m.startsWith("j") || m === "call" || m === "ret" || m === "retn") {
    return "text-accent-purple";
  }

  // Stack operations
  if (m === "push" || m === "pop") {
    return "text-accent-green";
  }

  // Moves
  if (m.startsWith("mov") || m === "lea" || m === "xchg") {
    return "text-accent-blue";
  }

  // Arithmetic
  if (
    ["add", "sub", "mul", "div", "inc", "dec", "neg", "imul", "idiv"].includes(m)
  ) {
    return "text-accent-yellow";
  }

  // Logic
  if (
    ["and", "or", "xor", "not", "shl", "shr", "sar", "rol", "ror"].includes(m)
  ) {
    return "text-accent-orange";
  }

  // Comparison
  if (m === "cmp" || m === "test") {
    return "text-accent-yellow";
  }

  // NOP
  if (m === "nop") {
    return "text-text-secondary";
  }

  // Int/syscall
  if (m === "int" || m === "syscall") {
    return "text-accent-red";
  }

  // Loop
  if (m.startsWith("loop") || m === "rep" || m.startsWith("rep")) {
    return "text-accent-cyan";
  }

  return "text-text-primary";
}

function formatOperands(ops: string): React.ReactNode {
  if (!ops) return null;

  // Simple coloring for registers and immediates
  const parts = ops.split(/([,\s\[\]]+)/);

  return parts.map((part, idx) => {
    const trimmed = part.trim();

    // Register (ax, bx, cx, dx, si, di, sp, bp, eax, ebx, etc)
    if (
      /^(r[a-z][xdi0-9]+|e?[a-z]{2}|[a-z][hlx]|[cdefgs]s|[sd]i|[sb]p)$/i.test(
        trimmed
      )
    ) {
      return (
        <span key={idx} className="text-accent-green">
          {part}
        </span>
      );
    }

    // Hex immediate
    if (/^0x[0-9a-f]+$/i.test(trimmed) || /^[0-9a-f]+h$/i.test(trimmed)) {
      return (
        <span key={idx} className="text-accent-orange">
          {part}
        </span>
      );
    }

    // Decimal immediate
    if (/^-?\d+$/.test(trimmed)) {
      return (
        <span key={idx} className="text-accent-orange">
          {part}
        </span>
      );
    }

    // Memory reference brackets
    if (trimmed === "[" || trimmed === "]") {
      return (
        <span key={idx} className="text-accent-yellow">
          {part}
        </span>
      );
    }

    // Size specifiers
    if (
      ["byte", "word", "dword", "qword", "ptr"].includes(trimmed.toLowerCase())
    ) {
      return (
        <span key={idx} className="text-text-secondary">
          {part}
        </span>
      );
    }

    return <span key={idx}>{part}</span>;
  });
}

function getAutoComment(mnemonic: string, operands: string): string | null {
  const m = mnemonic.toLowerCase();
  const ops = operands.toLowerCase();

  // DOS interrupts
  if (m === "int" && ops.includes("21")) {
    return "; DOS service call";
  }

  if (m === "int" && ops.includes("10")) {
    return "; BIOS video service";
  }

  if (m === "int" && ops.includes("16")) {
    return "; BIOS keyboard service";
  }

  // Common patterns
  if (m === "xor" && ops.includes(",")) {
    const [op1, op2] = ops.split(",").map((s) => s.trim());
    if (op1 === op2) {
      return `; Zero ${op1}`;
    }
  }

  if (m === "mov" && ops.includes("ah,")) {
    const val = ops.split(",")[1]?.trim();
    if (val) {
      const dosFunc = getDosFunction(val);
      if (dosFunc) return `; DOS: ${dosFunc}`;
    }
  }

  if (m === "ret" || m === "retn") {
    return "; Return from procedure";
  }

  if (m === "nop") {
    return "; No operation";
  }

  return null;
}

function getDosFunction(val: string): string | null {
  const v = val.replace(/h$/i, "").toLowerCase();
  const funcs: Record<string, string> = {
    "1": "Read char with echo",
    "01": "Read char with echo",
    "2": "Write character",
    "02": "Write character",
    "9": "Print string",
    "09": "Print string",
    "0x9": "Print string",
    "4c": "Exit program",
    "0x4c": "Exit program",
    "3d": "Open file",
    "0x3d": "Open file",
    "3f": "Read file",
    "0x3f": "Read file",
    "40": "Write file",
    "0x40": "Write file",
    "41": "Delete file",
    "0x41": "Delete file",
    "4e": "Find first file",
    "0x4e": "Find first file",
  };

  return funcs[v] || null;
}
