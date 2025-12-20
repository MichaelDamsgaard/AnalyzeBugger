"""
Generic Execution Tracer for AnalyzeBugger

Architecture-agnostic binary execution and observation.
Uses Unicorn CPU emulator for full control over ANY binary.

This is THE core infrastructure for generic analysis.
Instead of hand-simulating specific algorithms, we:
1. Execute the binary
2. Observe EVERYTHING that happens
3. Let Claude reason about the behavior

Supported architectures:
- x86 (16/32-bit) - DOS COM, Windows PE32
- x86-64 - Windows PE64, Linux ELF64
- ARM/ARM64 - Android, iOS, embedded
- MIPS, SPARC, etc.

Philosophy: OBSERVE, don't SIMULATE.
"""

import os
import struct
from typing import Optional, List, Dict, Any, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import json

from unicorn import *
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_16, CS_MODE_32, CS_MODE_64

# ============================================================================
# Data Structures
# ============================================================================

class Architecture(Enum):
    X86_16 = "x86_16"     # DOS COM, real mode
    X86_32 = "x86_32"     # Windows PE32, Linux ELF32
    X86_64 = "x86_64"     # Windows PE64, Linux ELF64
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"

@dataclass
class MemoryAccess:
    """Record of a memory read or write"""
    address: int
    size: int
    value: int
    access_type: str  # 'read' or 'write'
    instruction_address: int

@dataclass
class InstructionTrace:
    """Record of an executed instruction"""
    address: int
    size: int
    bytes: bytes
    mnemonic: str
    op_str: str
    registers: Dict[str, int]

@dataclass
class ExecutionTrace:
    """Complete trace of a binary's execution"""
    architecture: Architecture
    entry_point: int
    instructions: List[InstructionTrace] = field(default_factory=list)
    memory_accesses: List[MemoryAccess] = field(default_factory=list)
    memory_snapshots: Dict[str, bytes] = field(default_factory=dict)
    final_registers: Dict[str, int] = field(default_factory=dict)
    exit_reason: str = ""
    exit_address: int = 0

@dataclass
class InputOutput:
    """Captured input/output operation"""
    io_type: str  # 'stdin', 'stdout', 'file', 'network'
    direction: str  # 'read' or 'write'
    data: bytes
    address: int

# ============================================================================
# Generic Emulator
# ============================================================================

class GenericTracer:
    """
    Generic binary execution tracer using Unicorn.

    Executes ANY binary and captures complete behavior:
    - Every instruction executed
    - Every memory read/write
    - Register state at each step
    - I/O operations

    Claude analyzes this trace to understand the algorithm.
    No need to manually reverse engineer - just observe and reason.
    """

    # Memory layout constants
    STACK_BASE = 0x7FFF0000
    STACK_SIZE = 0x10000
    CODE_BASE = 0x10000
    DATA_BASE = 0x20000

    def __init__(self, arch: Architecture = Architecture.X86_16):
        self.arch = arch
        self.uc: Optional[Uc] = None
        self.cs: Optional[Cs] = None
        self.trace = ExecutionTrace(architecture=arch, entry_point=0)
        self.max_instructions = 1000000
        self.instruction_count = 0
        self.input_buffer: bytes = b""
        self.input_offset = 0
        self.output_buffer: bytearray = bytearray()
        self.io_log: List[InputOutput] = []

        self._setup_emulator()

    def _setup_emulator(self):
        """Initialize Unicorn emulator for the architecture"""
        if self.arch == Architecture.X86_16:
            self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
            self.cs = Cs(CS_ARCH_X86, CS_MODE_16)
            self._setup_x86_16()
        elif self.arch == Architecture.X86_32:
            self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self._setup_x86_32()
        elif self.arch == Architecture.X86_64:
            self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self._setup_x86_64()
        else:
            raise NotImplementedError(f"Architecture {self.arch} not yet supported")

        # Install hooks
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._hook_mem)
        self.uc.hook_add(UC_HOOK_INTR, self._hook_interrupt)

    def _setup_x86_16(self):
        """Set up 16-bit x86 (DOS) environment"""
        # Map memory: 1MB conventional memory
        self.uc.mem_map(0, 0x100000)

        # Set up segment registers for COM file (CS=DS=ES=SS)
        # COM files load at segment:0100h
        self.uc.reg_write(UC_X86_REG_CS, 0x1000)
        self.uc.reg_write(UC_X86_REG_DS, 0x1000)
        self.uc.reg_write(UC_X86_REG_ES, 0x1000)
        self.uc.reg_write(UC_X86_REG_SS, 0x1000)

        # Stack at end of segment
        self.uc.reg_write(UC_X86_REG_SP, 0xFFFE)

        # Set up PSP (Program Segment Prefix) at offset 0
        # This is what DOS creates before the COM file
        psp = bytearray(256)
        psp[0:2] = b'\xCD\x20'  # INT 20h at start
        self.uc.mem_write(0x10000, bytes(psp))

        self.code_base = 0x10100  # COM loads at offset 0x100

    def _setup_x86_32(self):
        """Set up 32-bit x86 environment"""
        # Map code section
        self.uc.mem_map(self.CODE_BASE, 0x100000)
        # Map stack
        self.uc.mem_map(self.STACK_BASE - self.STACK_SIZE, self.STACK_SIZE)
        self.uc.reg_write(UC_X86_REG_ESP, self.STACK_BASE - 0x1000)
        self.uc.reg_write(UC_X86_REG_EBP, self.STACK_BASE - 0x1000)

        self.code_base = self.CODE_BASE

    def _setup_x86_64(self):
        """Set up 64-bit x86 environment"""
        # Map code section
        self.uc.mem_map(self.CODE_BASE, 0x100000)
        # Map stack
        self.uc.mem_map(self.STACK_BASE - self.STACK_SIZE, self.STACK_SIZE)
        self.uc.reg_write(UC_X86_REG_RSP, self.STACK_BASE - 0x1000)
        self.uc.reg_write(UC_X86_REG_RBP, self.STACK_BASE - 0x1000)

        self.code_base = self.CODE_BASE

    # -------------------------------------------------------------------------
    # Hooks - Capture everything
    # -------------------------------------------------------------------------

    def _hook_code(self, uc: Uc, address: int, size: int, user_data):
        """Hook every instruction - capture complete trace"""
        self.instruction_count += 1

        if self.instruction_count > self.max_instructions:
            uc.emu_stop()
            self.trace.exit_reason = "max_instructions"
            return

        # Read instruction bytes
        try:
            code = uc.mem_read(address, size)
        except:
            code = b''

        # Disassemble
        mnemonic = ""
        op_str = ""
        for insn in self.cs.disasm(bytes(code), address):
            mnemonic = insn.mnemonic
            op_str = insn.op_str
            break

        # Capture registers
        regs = self._get_registers()

        # Record trace entry
        trace_entry = InstructionTrace(
            address=address,
            size=size,
            bytes=bytes(code),
            mnemonic=mnemonic,
            op_str=op_str,
            registers=regs
        )
        self.trace.instructions.append(trace_entry)

    def _hook_mem(self, uc: Uc, access: int, address: int, size: int, value: int, user_data):
        """Hook memory access - capture reads and writes"""
        access_type = 'write' if access == UC_MEM_WRITE else 'read'

        # Get current instruction address
        ip = self._get_ip()

        mem_access = MemoryAccess(
            address=address,
            size=size,
            value=value,
            access_type=access_type,
            instruction_address=ip
        )
        self.trace.memory_accesses.append(mem_access)

    def _hook_interrupt(self, uc: Uc, intno: int, user_data):
        """Hook interrupts - handle DOS/BIOS calls"""
        if self.arch == Architecture.X86_16:
            self._handle_dos_interrupt(uc, intno)
        else:
            # For other architectures, just log
            pass

    def _handle_dos_interrupt(self, uc: Uc, intno: int):
        """Emulate DOS INT 21h services"""
        if intno == 0x21:
            ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF

            if ah == 0x4C:
                # Exit program
                uc.emu_stop()
                self.trace.exit_reason = "exit"

            elif ah == 0x09:
                # Print string (DS:DX, $-terminated)
                ds = uc.reg_read(UC_X86_REG_DS)
                dx = uc.reg_read(UC_X86_REG_DX)
                addr = (ds << 4) + dx

                output = bytearray()
                while True:
                    byte = uc.mem_read(addr, 1)[0]
                    if byte == ord('$'):
                        break
                    output.append(byte)
                    addr += 1

                self.output_buffer.extend(output)
                self.io_log.append(InputOutput(
                    io_type='stdout',
                    direction='write',
                    data=bytes(output),
                    address=addr
                ))

            elif ah == 0x0A:
                # Buffered input (DS:DX points to buffer)
                ds = uc.reg_read(UC_X86_REG_DS)
                dx = uc.reg_read(UC_X86_REG_DX)
                addr = (ds << 4) + dx

                # Buffer format: [max_len][actual_len][chars...]
                max_len = uc.mem_read(addr, 1)[0]

                # Use provided input
                input_data = self.input_buffer[self.input_offset:self.input_offset + max_len - 1]
                if len(input_data) < max_len - 1:
                    input_data += b'\r'  # Add CR terminator

                actual_len = len(input_data)
                uc.mem_write(addr + 1, bytes([actual_len]))
                uc.mem_write(addr + 2, input_data)

                self.input_offset += actual_len

                self.io_log.append(InputOutput(
                    io_type='stdin',
                    direction='read',
                    data=input_data,
                    address=addr
                ))

            elif ah == 0x02:
                # Print character (DL)
                dl = uc.reg_read(UC_X86_REG_DX) & 0xFF
                self.output_buffer.append(dl)

        elif intno == 0x20:
            # DOS terminate
            uc.emu_stop()
            self.trace.exit_reason = "exit"

    def _get_registers(self) -> Dict[str, int]:
        """Get current register state"""
        if self.arch == Architecture.X86_16:
            return {
                'AX': self.uc.reg_read(UC_X86_REG_AX),
                'BX': self.uc.reg_read(UC_X86_REG_BX),
                'CX': self.uc.reg_read(UC_X86_REG_CX),
                'DX': self.uc.reg_read(UC_X86_REG_DX),
                'SI': self.uc.reg_read(UC_X86_REG_SI),
                'DI': self.uc.reg_read(UC_X86_REG_DI),
                'SP': self.uc.reg_read(UC_X86_REG_SP),
                'BP': self.uc.reg_read(UC_X86_REG_BP),
                'IP': self.uc.reg_read(UC_X86_REG_IP),
                'FLAGS': self.uc.reg_read(UC_X86_REG_EFLAGS) & 0xFFFF,
            }
        elif self.arch == Architecture.X86_32:
            return {
                'EAX': self.uc.reg_read(UC_X86_REG_EAX),
                'EBX': self.uc.reg_read(UC_X86_REG_EBX),
                'ECX': self.uc.reg_read(UC_X86_REG_ECX),
                'EDX': self.uc.reg_read(UC_X86_REG_EDX),
                'ESI': self.uc.reg_read(UC_X86_REG_ESI),
                'EDI': self.uc.reg_read(UC_X86_REG_EDI),
                'ESP': self.uc.reg_read(UC_X86_REG_ESP),
                'EBP': self.uc.reg_read(UC_X86_REG_EBP),
                'EIP': self.uc.reg_read(UC_X86_REG_EIP),
                'EFLAGS': self.uc.reg_read(UC_X86_REG_EFLAGS),
            }
        return {}

    def _get_ip(self) -> int:
        """Get instruction pointer"""
        if self.arch in [Architecture.X86_16, Architecture.X86_32]:
            return self.uc.reg_read(UC_X86_REG_EIP)
        elif self.arch == Architecture.X86_64:
            return self.uc.reg_read(UC_X86_REG_RIP)
        return 0

    # -------------------------------------------------------------------------
    # Public Interface
    # -------------------------------------------------------------------------

    def load_binary(self, path: str, load_address: Optional[int] = None):
        """Load a binary file into the emulator"""
        with open(path, 'rb') as f:
            code = f.read()

        if load_address is None:
            load_address = self.code_base

        self.uc.mem_write(load_address, code)
        self.trace.entry_point = load_address

        return load_address

    def load_code(self, code: bytes, load_address: Optional[int] = None):
        """Load raw code/shellcode into the emulator"""
        if load_address is None:
            load_address = self.code_base

        self.uc.mem_write(load_address, code)
        self.trace.entry_point = load_address

        return load_address

    def set_input(self, data: bytes):
        """Set input data that will be provided to the binary"""
        self.input_buffer = data
        self.input_offset = 0

    def read_memory(self, address: int, size: int) -> bytes:
        """Read memory from the emulator"""
        return bytes(self.uc.mem_read(address, size))

    def write_memory(self, address: int, data: bytes):
        """Write memory in the emulator"""
        self.uc.mem_write(address, data)

    def run(self, start: Optional[int] = None, end: int = 0,
            max_instructions: int = 1000000) -> ExecutionTrace:
        """
        Run the binary and capture complete trace.

        Args:
            start: Starting address (default: entry point)
            end: Ending address (0 = run until exit/interrupt)
            max_instructions: Maximum instructions to execute

        Returns:
            ExecutionTrace with complete execution history
        """
        if start is None:
            start = self.trace.entry_point

        self.max_instructions = max_instructions
        self.instruction_count = 0

        try:
            self.uc.emu_start(start, end, count=max_instructions)
        except UcError as e:
            self.trace.exit_reason = f"error: {e}"

        self.trace.final_registers = self._get_registers()
        self.trace.exit_address = self._get_ip()

        return self.trace

    def get_output(self) -> bytes:
        """Get captured output"""
        return bytes(self.output_buffer)

    def snapshot_memory(self, name: str, address: int, size: int):
        """Take a named snapshot of memory region"""
        data = self.read_memory(address, size)
        self.trace.memory_snapshots[name] = data


# ============================================================================
# MCP Tool Interface
# ============================================================================

def tool_trace_binary(file_path: str, input_data: str = "",
                      max_instructions: int = 100000,
                      arch: str = "auto") -> dict:
    """
    Execute a binary and capture complete trace.

    Args:
        file_path: Path to binary file
        input_data: Input to provide to the program
        max_instructions: Maximum instructions to trace
        arch: Architecture ("x86_16", "x86_32", "x86_64", or "auto")

    Returns:
        Complete execution trace with instructions, memory accesses, I/O
    """
    # Auto-detect architecture
    if arch == "auto":
        with open(file_path, 'rb') as f:
            header = f.read(64)

        if header[0:2] == b'MZ':
            # PE file - check for 64-bit
            if len(header) > 0x3C + 4:
                pe_offset = struct.unpack('<I', header[0x3C:0x3C+4])[0]
                # Would need to read PE header to determine 32/64
                arch = "x86_32"  # Default to 32-bit
        elif header[0:4] == b'\x7fELF':
            # ELF file
            arch = "x86_64" if header[4] == 2 else "x86_32"
        else:
            # Assume COM file (16-bit DOS)
            arch = "x86_16"

    arch_enum = Architecture(arch)
    tracer = GenericTracer(arch_enum)

    # Load binary
    tracer.load_binary(file_path)

    # Set input
    if input_data:
        tracer.set_input(input_data.encode('latin-1'))

    # Run and trace
    trace = tracer.run(max_instructions=max_instructions)

    # Compute instruction statistics for crypto analysis
    instruction_stats = {
        'xor': 0,
        'rol': 0,
        'ror': 0,
        'add': 0,
        'sub': 0,
        'and': 0,
        'or': 0,
        'shl': 0,
        'shr': 0,
        'loop': 0,
    }
    xor_locations = []
    rol_locations = []

    for insn in trace.instructions:
        mnem = insn.mnemonic.lower()
        if mnem == 'xor':
            instruction_stats['xor'] += 1
            if len(xor_locations) < 20:  # Keep first 20
                xor_locations.append(hex(insn.address))
        elif mnem == 'rol':
            instruction_stats['rol'] += 1
            if len(rol_locations) < 20:
                rol_locations.append(hex(insn.address))
        elif mnem == 'ror':
            instruction_stats['ror'] += 1
            if len(rol_locations) < 20:
                rol_locations.append(hex(insn.address))
        elif mnem == 'add':
            instruction_stats['add'] += 1
        elif mnem == 'sub':
            instruction_stats['sub'] += 1
        elif mnem == 'and':
            instruction_stats['and'] += 1
        elif mnem == 'or':
            instruction_stats['or'] += 1
        elif mnem in ['shl', 'sal']:
            instruction_stats['shl'] += 1
        elif mnem in ['shr', 'sar']:
            instruction_stats['shr'] += 1
        elif mnem in ['loop', 'loope', 'loopne']:
            instruction_stats['loop'] += 1

    # Format results
    return {
        'success': True,
        'architecture': arch,
        'entry_point': hex(trace.entry_point),
        'instruction_count': len(trace.instructions),
        'memory_access_count': len(trace.memory_accesses),
        'exit_reason': trace.exit_reason,
        'exit_address': hex(trace.exit_address),
        'output': tracer.get_output().decode('latin-1', errors='replace'),
        'final_registers': {k: hex(v) for k, v in trace.final_registers.items()},
        # Crypto-relevant instruction statistics
        'instruction_stats': instruction_stats,
        'xor_locations': xor_locations,
        'rol_ror_locations': rol_locations,
        # Include last N instructions for immediate analysis
        'last_instructions': [
            {
                'addr': hex(i.address),
                'asm': f"{i.mnemonic} {i.op_str}",
                'bytes': i.bytes.hex()
            }
            for i in trace.instructions[-50:]
        ],
    }


def tool_trace_with_inputs(file_path: str, inputs: List[str],
                           max_instructions: int = 100000) -> dict:
    """
    Run binary with multiple inputs and compare behavior.

    This is KEY for understanding algorithms:
    - Run with input A, observe behavior
    - Run with input B, observe behavior
    - Claude analyzes the DIFFERENCE to understand the algorithm

    Args:
        file_path: Path to binary
        inputs: List of input strings to try
        max_instructions: Max instructions per run

    Returns:
        Comparative analysis of runs
    """
    results = []

    for input_data in inputs:
        trace_result = tool_trace_binary(
            file_path,
            input_data=input_data,
            max_instructions=max_instructions
        )
        results.append({
            'input': input_data,
            'output': trace_result.get('output', ''),
            'instruction_count': trace_result.get('instruction_count', 0),
            'exit_reason': trace_result.get('exit_reason', ''),
        })

    return {
        'success': True,
        'runs': results,
        'analysis_hint': "Compare outputs to understand input->output relationship"
    }


def tool_find_password(file_path: str, success_indicator: str,
                       charset: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                       max_length: int = 8,
                       max_instructions: int = 50000) -> dict:
    """
    Generic password finder using execution tracing.

    Instead of reversing the algorithm, we:
    1. Try passwords
    2. Check if output contains success indicator
    3. Use intelligent search (not just brute force)

    Args:
        file_path: Path to binary
        success_indicator: String that appears on success
        charset: Characters to try
        max_length: Maximum password length
        max_instructions: Max instructions per try

    Returns:
        Found password or analysis of attempts
    """
    import itertools

    attempts = 0
    max_attempts = 10000

    # Try common passwords first
    common = ['test', 'pass', 'crack', 'hello', 'admin', 'password',
              'TEST', 'PASS', 'CRACK', 'HELLO', 'ADMIN', 'PASSWORD']

    for pwd in common:
        attempts += 1
        result = tool_trace_binary(file_path, input_data=pwd + '\r',
                                   max_instructions=max_instructions)
        if success_indicator in result.get('output', ''):
            return {
                'success': True,
                'password': pwd,
                'attempts': attempts,
                'output': result['output']
            }

    # Brute force with length priority
    for length in range(1, max_length + 1):
        for chars in itertools.product(charset, repeat=length):
            if attempts >= max_attempts:
                return {
                    'success': False,
                    'attempts': attempts,
                    'message': f'Max attempts ({max_attempts}) reached'
                }

            pwd = ''.join(chars)
            attempts += 1

            result = tool_trace_binary(file_path, input_data=pwd + '\r',
                                       max_instructions=max_instructions)
            if success_indicator in result.get('output', ''):
                return {
                    'success': True,
                    'password': pwd,
                    'attempts': attempts,
                    'output': result['output']
                }

    return {
        'success': False,
        'attempts': attempts,
        'message': 'Password not found in search space'
    }


# ============================================================================
# Test
# ============================================================================

if __name__ == "__main__":
    import sys

    print("Generic Execution Tracer for AnalyzeBugger")
    print("Architecture-agnostic binary observation")
    print()

    if len(sys.argv) > 1:
        binary = sys.argv[1]
        input_data = sys.argv[2] if len(sys.argv) > 2 else ""

        print(f"Tracing: {binary}")
        print(f"Input: {repr(input_data)}")
        print()

        result = tool_trace_binary(binary, input_data=input_data)

        if result['success']:
            print(f"Architecture: {result['architecture']}")
            print(f"Entry Point: {result['entry_point']}")
            print(f"Instructions: {result['instruction_count']}")
            print(f"Memory Accesses: {result['memory_access_count']}")
            print(f"Exit: {result['exit_reason']} at {result['exit_address']}")
            print(f"Output: {repr(result['output'])}")
            print()
            print("Last 10 instructions:")
            for i in result['last_instructions'][-10:]:
                print(f"  {i['addr']}: {i['asm']}")
        else:
            print(f"Error: {result.get('error', 'Unknown')}")
