import { useState } from "react";
import { useSessionStore } from "../../stores/sessionStore";
import { useAnalysisStore } from "../../stores/analysisStore";
import { Cpu, ChevronDown, ChevronRight } from "lucide-react";

type RegisterMode = "64" | "32" | "16";

export function CpuPanel() {
  const { registers, prevRegisters } = useSessionStore();
  const { result: analysisResult } = useAnalysisStore();
  const [mode, setMode] = useState<RegisterMode>(
    analysisResult?.file_info.arch.includes("16") ? "16" :
    analysisResult?.file_info.arch.includes("32") ? "32" : "64"
  );
  const [showSegments, setShowSegments] = useState(true);
  const [showFlags, setShowFlags] = useState(true);

  // For static analysis, show expected initial state
  const isStatic = !registers && !!analysisResult;

  // Get initial registers from backend analysis (real data)
  const initRegs = analysisResult?.initial_registers;

  // Build register display based on mode
  const getRegs = () => {
    if (mode === "16") {
      if (isStatic && initRegs) {
        return [
          { name: "AX", value: String(initRegs.AX || "0000") },
          { name: "BX", value: String(initRegs.BX || "0000") },
          { name: "CX", value: String(initRegs.CX || "00FF") },
          { name: "DX", value: String(initRegs.DX || "0000") },
          { name: "SI", value: String(initRegs.SI || "0100") },
          { name: "DI", value: String(initRegs.DI || "FFFE") },
          { name: "BP", value: String(initRegs.BP || "0000") },
          { name: "SP", value: String(initRegs.SP || "FFFE") },
          { name: "IP", value: String(initRegs.IP || "0100"), highlight: true },
        ];
      }
      // Extract 16-bit from 64-bit regs
      return registers ? [
        { name: "AX", value: registers.rax.slice(-4), prev: prevRegisters?.rax.slice(-4) },
        { name: "BX", value: registers.rbx.slice(-4), prev: prevRegisters?.rbx.slice(-4) },
        { name: "CX", value: registers.rcx.slice(-4), prev: prevRegisters?.rcx.slice(-4) },
        { name: "DX", value: registers.rdx.slice(-4), prev: prevRegisters?.rdx.slice(-4) },
        { name: "SI", value: registers.rsi.slice(-4), prev: prevRegisters?.rsi.slice(-4) },
        { name: "DI", value: registers.rdi.slice(-4), prev: prevRegisters?.rdi.slice(-4) },
        { name: "BP", value: registers.rbp.slice(-4), prev: prevRegisters?.rbp.slice(-4) },
        { name: "SP", value: registers.rsp.slice(-4), prev: prevRegisters?.rsp.slice(-4) },
        { name: "IP", value: registers.rip.slice(-4), prev: prevRegisters?.rip.slice(-4), highlight: true },
      ] : [];
    } else if (mode === "32") {
      if (isStatic && initRegs) {
        return [
          { name: "EAX", value: String(initRegs.EAX || "00000000") },
          { name: "EBX", value: String(initRegs.EBX || "00000000") },
          { name: "ECX", value: String(initRegs.ECX || "00000000") },
          { name: "EDX", value: String(initRegs.EDX || "00000000") },
          { name: "ESI", value: String(initRegs.ESI || "00000000") },
          { name: "EDI", value: String(initRegs.EDI || "00000000") },
          { name: "EBP", value: String(initRegs.EBP || "00000000") },
          { name: "ESP", value: String(initRegs.ESP || "0012FF00") },
          { name: "EIP", value: String(initRegs.EIP || "00400000"), highlight: true },
        ];
      }
      return registers ? [
        { name: "EAX", value: registers.rax.slice(-8), prev: prevRegisters?.rax.slice(-8) },
        { name: "EBX", value: registers.rbx.slice(-8), prev: prevRegisters?.rbx.slice(-8) },
        { name: "ECX", value: registers.rcx.slice(-8), prev: prevRegisters?.rcx.slice(-8) },
        { name: "EDX", value: registers.rdx.slice(-8), prev: prevRegisters?.rdx.slice(-8) },
        { name: "ESI", value: registers.rsi.slice(-8), prev: prevRegisters?.rsi.slice(-8) },
        { name: "EDI", value: registers.rdi.slice(-8), prev: prevRegisters?.rdi.slice(-8) },
        { name: "EBP", value: registers.rbp.slice(-8), prev: prevRegisters?.rbp.slice(-8) },
        { name: "ESP", value: registers.rsp.slice(-8), prev: prevRegisters?.rsp.slice(-8) },
        { name: "EIP", value: registers.rip.slice(-8), prev: prevRegisters?.rip.slice(-8), highlight: true },
      ] : [];
    } else {
      if (isStatic && initRegs) {
        return [
          { name: "RAX", value: String(initRegs.RAX || "0000000000000000") },
          { name: "RBX", value: String(initRegs.RBX || "0000000000000000") },
          { name: "RCX", value: String(initRegs.RCX || "0000000000000000") },
          { name: "RDX", value: String(initRegs.RDX || "0000000000000000") },
          { name: "RSI", value: String(initRegs.RSI || "0000000000000000") },
          { name: "RDI", value: String(initRegs.RDI || "0000000000000000") },
          { name: "RBP", value: String(initRegs.RBP || "0000000000000000") },
          { name: "RSP", value: String(initRegs.RSP || "000000000012F000") },
          { name: "R8", value: String(initRegs.R8 || "0000000000000000") },
          { name: "R9", value: String(initRegs.R9 || "0000000000000000") },
          { name: "R10", value: String(initRegs.R10 || "0000000000000000") },
          { name: "R11", value: String(initRegs.R11 || "0000000000000000") },
          { name: "R12", value: String(initRegs.R12 || "0000000000000000") },
          { name: "R13", value: String(initRegs.R13 || "0000000000000000") },
          { name: "R14", value: String(initRegs.R14 || "0000000000000000") },
          { name: "R15", value: String(initRegs.R15 || "0000000000000000") },
          { name: "RIP", value: String(initRegs.RIP || "0000000140000000"), highlight: true },
        ];
      }
      return registers ? [
        { name: "RAX", value: registers.rax, prev: prevRegisters?.rax },
        { name: "RBX", value: registers.rbx, prev: prevRegisters?.rbx },
        { name: "RCX", value: registers.rcx, prev: prevRegisters?.rcx },
        { name: "RDX", value: registers.rdx, prev: prevRegisters?.rdx },
        { name: "RSI", value: registers.rsi, prev: prevRegisters?.rsi },
        { name: "RDI", value: registers.rdi, prev: prevRegisters?.rdi },
        { name: "RBP", value: registers.rbp, prev: prevRegisters?.rbp },
        { name: "RSP", value: registers.rsp, prev: prevRegisters?.rsp },
        { name: "R8", value: registers.r8, prev: prevRegisters?.r8 },
        { name: "R9", value: registers.r9, prev: prevRegisters?.r9 },
        { name: "R10", value: registers.r10, prev: prevRegisters?.r10 },
        { name: "R11", value: registers.r11, prev: prevRegisters?.r11 },
        { name: "R12", value: registers.r12, prev: prevRegisters?.r12 },
        { name: "R13", value: registers.r13, prev: prevRegisters?.r13 },
        { name: "R14", value: registers.r14, prev: prevRegisters?.r14 },
        { name: "R15", value: registers.r15, prev: prevRegisters?.r15 },
        { name: "RIP", value: registers.rip, prev: prevRegisters?.rip, highlight: true },
      ] : [];
    }
  };

  const regs = getRegs();

  // Parse FLAGS/EFLAGS from backend data
  const getFlagsValue = () => {
    if (isStatic && initRegs) {
      const flagsStr = String(initRegs.FLAGS || initRegs.EFLAGS || initRegs.RFLAGS || "0202");
      return parseInt(flagsStr, 16);
    }
    return registers ? parseInt(registers.eflags, 16) : 0;
  };
  const flagsValue = getFlagsValue();

  const flags = [
    { name: "CF", bit: 0, desc: "Carry" },
    { name: "PF", bit: 2, desc: "Parity" },
    { name: "AF", bit: 4, desc: "Auxiliary" },
    { name: "ZF", bit: 6, desc: "Zero" },
    { name: "SF", bit: 7, desc: "Sign" },
    { name: "TF", bit: 8, desc: "Trap" },
    { name: "IF", bit: 9, desc: "Interrupt" },
    { name: "DF", bit: 10, desc: "Direction" },
    { name: "OF", bit: 11, desc: "Overflow" },
  ];

  // Segment registers from backend
  const getSegments = () => {
    if (isStatic && initRegs) {
      const segs = [
        { name: "CS", value: String(initRegs.CS || "????"), desc: "Code Segment" },
        { name: "DS", value: String(initRegs.DS || "????"), desc: "Data Segment" },
        { name: "SS", value: String(initRegs.SS || "????"), desc: "Stack Segment" },
        { name: "ES", value: String(initRegs.ES || "????"), desc: "Extra Segment" },
      ];
      // Add FS/GS for 32/64-bit
      if (initRegs.FS) segs.push({ name: "FS", value: String(initRegs.FS), desc: "FS (TEB)" });
      if (initRegs.GS) segs.push({ name: "GS", value: String(initRegs.GS), desc: "GS" });
      return segs;
    }
    return [
      { name: "CS", value: "0033", desc: "Code Segment" },
      { name: "DS", value: "002B", desc: "Data Segment" },
      { name: "SS", value: "002B", desc: "Stack Segment" },
      { name: "ES", value: "002B", desc: "Extra Segment" },
      { name: "FS", value: "0053", desc: "FS (TEB)" },
      { name: "GS", value: "002B", desc: "GS" },
    ];
  };
  const segments = getSegments();

  if (regs.length === 0 && !isStatic) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <Cpu className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No CPU state available</p>
          <p className="text-xs mt-1">Debug a target or analyze a file</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto">
      {/* Header with mode selector */}
      <div className="sticky top-0 h-8 bg-bg-secondary border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <Cpu className="w-4 h-4 text-accent-blue" />
          <span className="text-sm font-medium">CPU</span>
          {isStatic && (
            <span className="text-xs text-accent-yellow">(Initial State)</span>
          )}
        </div>
        <div className="flex items-center gap-1">
          {(["16", "32", "64"] as RegisterMode[]).map(m => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-2 py-0.5 text-xs rounded transition-colors ${
                mode === m
                  ? "bg-accent-blue/20 text-accent-blue"
                  : "text-text-secondary hover:text-text-primary"
              }`}
            >
              {m}-bit
            </button>
          ))}
        </div>
      </div>

      <div className="p-2 font-mono text-xs space-y-3">
        {/* General Purpose Registers */}
        <div>
          <div className="text-text-secondary mb-1 text-[10px] uppercase tracking-wider">
            General Purpose
          </div>
          <div className={`grid ${mode === "64" ? "grid-cols-2" : "grid-cols-3"} gap-x-3 gap-y-0.5`}>
            {regs.map((reg) => {
              const regWithPrev = reg as { name: string; value: string; prev?: string; highlight?: boolean };
              const changed = regWithPrev.prev && reg.value !== regWithPrev.prev;
              return (
                <div key={reg.name} className="flex items-center gap-1">
                  <span className={`w-7 ${reg.highlight ? "text-accent-yellow" : "text-accent-blue"}`}>
                    {reg.name}
                  </span>
                  <span
                    className={`font-mono ${
                      changed ? "text-accent-red" :
                      reg.highlight ? "text-accent-yellow" : "text-text-primary"
                    }`}
                  >
                    {reg.value}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Segment Registers */}
        <div>
          <button
            onClick={() => setShowSegments(!showSegments)}
            className="flex items-center gap-1 text-text-secondary text-[10px] uppercase tracking-wider hover:text-text-primary"
          >
            {showSegments ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
            Segments
          </button>
          {showSegments && (
            <div className="grid grid-cols-3 gap-x-3 gap-y-0.5 mt-1">
              {segments.map(seg => (
                <div key={seg.name} className="flex items-center gap-1" title={seg.desc}>
                  <span className="w-5 text-accent-purple">{seg.name}</span>
                  <span className="text-text-primary">{seg.value}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Flags */}
        <div>
          <button
            onClick={() => setShowFlags(!showFlags)}
            className="flex items-center gap-1 text-text-secondary text-[10px] uppercase tracking-wider hover:text-text-primary"
          >
            {showFlags ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
            Flags ({mode === "16" ? "FLAGS" : "EFLAGS"}: {flagsValue.toString(16).toUpperCase().padStart(4, "0")})
          </button>
          {showFlags && (
            <div className="flex flex-wrap gap-1 mt-1">
              {flags.map((flag) => {
                const isSet = (flagsValue & (1 << flag.bit)) !== 0;
                return (
                  <div
                    key={flag.name}
                    title={`${flag.desc} Flag`}
                    className={`px-1.5 py-0.5 rounded text-[10px] ${
                      isSet
                        ? "bg-accent-green/20 text-accent-green"
                        : "bg-bg-tertiary text-text-secondary"
                    }`}
                  >
                    {flag.name}={isSet ? "1" : "0"}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
