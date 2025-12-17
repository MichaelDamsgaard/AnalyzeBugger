import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";

export interface Registers {
  rax: string;
  rbx: string;
  rcx: string;
  rdx: string;
  rsi: string;
  rdi: string;
  rsp: string;
  rbp: string;
  rip: string;
  r8: string;
  r9: string;
  r10: string;
  r11: string;
  r12: string;
  r13: string;
  r14: string;
  r15: string;
  eflags: string;
}

export interface SessionInfo {
  id: string;
  target_path: string;
  state: string;
  process_id: number | null;
  thread_id: number | null;
  current_ip: string | null;
  module_count: number | null;
  breakpoint_count: number | null;
}

export interface ModuleInfo {
  name: string;
  base: string;
  size: number;
  entry: string;
}

export interface Instruction {
  address: string;
  bytes: string;
  mnemonic: string;
  op_str: string;
}

export interface Status {
  dll_loaded: boolean;
  dll_version: string | null;
  session_count: number;
  session: SessionInfo | null;
}

interface SessionState {
  // State
  status: Status | null;
  registers: Registers | null;
  prevRegisters: Registers | null;
  disassembly: Instruction[];
  modules: ModuleInfo[];
  memoryAddress: string;
  memoryData: string;
  isLoading: boolean;
  error: string | null;

  // Actions
  fetchStatus: () => Promise<void>;
  launchTarget: (path: string) => Promise<void>;
  stopSession: () => Promise<void>;
  continueExecution: () => Promise<void>;
  pauseExecution: () => Promise<void>;
  stepInto: () => Promise<void>;
  stepOver: () => Promise<void>;
  fetchRegisters: () => Promise<void>;
  fetchDisassembly: (address: string, length: number) => Promise<void>;
  fetchModules: () => Promise<void>;
  fetchMemory: (address: string, length: number) => Promise<void>;
  setBreakpoint: (address: string) => Promise<number>;
  removeBreakpoint: (bpId: number) => Promise<void>;
  clearError: () => void;
}

export const useSessionStore = create<SessionState>((set, get) => ({
  // Initial state
  status: null,
  registers: null,
  prevRegisters: null,
  disassembly: [],
  modules: [],
  memoryAddress: "0x0",
  memoryData: "",
  isLoading: false,
  error: null,

  // Actions
  fetchStatus: async () => {
    try {
      const result = await invoke<string>("get_status");
      const status = JSON.parse(result) as Status;
      set({ status });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  launchTarget: async (path: string) => {
    set({ isLoading: true, error: null });
    try {
      const result = await invoke<string>("launch_target", { path });
      const data = JSON.parse(result);
      await get().fetchStatus();
      await get().fetchRegisters();
      await get().fetchModules();
      if (data.session?.current_ip) {
        await get().fetchDisassembly(data.session.current_ip, 64);
      }
    } catch (e) {
      set({ error: String(e) });
    } finally {
      set({ isLoading: false });
    }
  },

  stopSession: async () => {
    try {
      await invoke("stop_session");
      await get().fetchStatus();
      set({ registers: null, prevRegisters: null, disassembly: [], modules: [] });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  continueExecution: async () => {
    try {
      await invoke("continue_execution");
      await get().fetchStatus();
    } catch (e) {
      set({ error: String(e) });
    }
  },

  pauseExecution: async () => {
    try {
      await invoke("pause_execution");
      await get().fetchStatus();
      await get().fetchRegisters();
    } catch (e) {
      set({ error: String(e) });
    }
  },

  stepInto: async () => {
    try {
      const prevRegs = get().registers;
      await invoke("step_into");
      set({ prevRegisters: prevRegs });
      await get().fetchStatus();
      await get().fetchRegisters();
      const status = get().status;
      if (status?.session?.current_ip) {
        await get().fetchDisassembly(status.session.current_ip, 64);
      }
    } catch (e) {
      set({ error: String(e) });
    }
  },

  stepOver: async () => {
    try {
      const prevRegs = get().registers;
      await invoke("step_over");
      set({ prevRegisters: prevRegs });
      await get().fetchStatus();
      await get().fetchRegisters();
      const status = get().status;
      if (status?.session?.current_ip) {
        await get().fetchDisassembly(status.session.current_ip, 64);
      }
    } catch (e) {
      set({ error: String(e) });
    }
  },

  fetchRegisters: async () => {
    try {
      const result = await invoke<string>("get_registers");
      const registers = JSON.parse(result) as Registers;
      set({ registers });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  fetchDisassembly: async (address: string, length: number) => {
    try {
      const result = await invoke<string>("disassemble", { address, length });
      const data = JSON.parse(result);
      set({ disassembly: data.instructions || [] });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  fetchModules: async () => {
    try {
      const result = await invoke<string>("get_modules");
      const data = JSON.parse(result);
      set({ modules: data.modules || [] });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  fetchMemory: async (address: string, length: number) => {
    try {
      const result = await invoke<string>("read_memory", { address, length });
      const data = JSON.parse(result);
      set({ memoryAddress: address, memoryData: data.data || "" });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  setBreakpoint: async (address: string): Promise<number> => {
    try {
      const result = await invoke<string>("set_breakpoint", { address, bpType: "software" });
      const data = JSON.parse(result);
      return data.bp_id;
    } catch (e) {
      set({ error: String(e) });
      return -1;
    }
  },

  removeBreakpoint: async (bpId: number) => {
    try {
      await invoke("remove_breakpoint", { bpId });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  clearError: () => set({ error: null }),
}));
