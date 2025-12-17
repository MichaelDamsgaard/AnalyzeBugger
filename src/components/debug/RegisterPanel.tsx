import { useSessionStore } from "../../stores/sessionStore";

export function RegisterPanel() {
  const { registers, prevRegisters } = useSessionStore();

  if (!registers) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary text-sm">
        No register data available
      </div>
    );
  }

  const regs = [
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
  ];

  // Parse EFLAGS
  const eflags = parseInt(registers.eflags, 16);
  const flags = [
    { name: "CF", bit: 0 },
    { name: "PF", bit: 2 },
    { name: "AF", bit: 4 },
    { name: "ZF", bit: 6 },
    { name: "SF", bit: 7 },
    { name: "TF", bit: 8 },
    { name: "IF", bit: 9 },
    { name: "DF", bit: 10 },
    { name: "OF", bit: 11 },
  ];

  return (
    <div className="p-2 font-mono text-xs">
      {/* General Purpose Registers */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-1">
        {regs.map((reg) => {
          const changed = reg.prev && reg.value !== reg.prev;
          return (
            <div key={reg.name} className="flex items-center gap-2">
              <span className={`w-8 ${reg.highlight ? "text-accent-yellow" : "text-text-secondary"}`}>
                {reg.name}
              </span>
              <span
                className={`flex-1 ${
                  changed
                    ? "text-accent-red font-bold"
                    : reg.highlight
                    ? "text-accent-yellow"
                    : "text-text-primary"
                }`}
              >
                {reg.value}
              </span>
            </div>
          );
        })}
      </div>

      {/* Separator */}
      <div className="my-3 border-t border-border" />

      {/* EFLAGS */}
      <div className="flex items-center gap-2 mb-2">
        <span className="text-text-secondary">EFLAGS</span>
        <span className="text-text-primary">{registers.eflags}</span>
      </div>

      {/* Flag Bits */}
      <div className="flex flex-wrap gap-2">
        {flags.map((flag) => {
          const isSet = (eflags & (1 << flag.bit)) !== 0;
          return (
            <div
              key={flag.name}
              className={`px-2 py-0.5 rounded text-xs ${
                isSet
                  ? "bg-accent-green/20 text-accent-green"
                  : "bg-bg-tertiary text-text-secondary"
              }`}
            >
              {flag.name}
            </div>
          );
        })}
      </div>
    </div>
  );
}
