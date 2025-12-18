"""
AI-Powered Generic Unpacker for AnalyzeBugger

Philosophy: Claude analyzes the ALGORITHM, not pattern-matches known packers.
If it's deterministic, Claude computes it. Period.

This unpacker works in stages:
1. DETECT  - Is this packed? (entropy analysis, stub detection)
2. TRACE   - Execute and trace, let Claude analyze what's happening
3. FIND    - Claude identifies OEP based on semantic analysis
4. DUMP    - Memory snapshot at OEP
5. REBUILD - IAT reconstruction, PE fixup

Unlike traditional unpackers that rely on signatures (UPX, ASPack, etc.),
this uses Claude to understand the packing algorithm dynamically.

References:
- IDA Pro Universal Unpacker (uunp) methodology
- https://marcoramilli.com/ida-pro-universal-unpacker/
- https://hex-rays.com/products/ida/support/tutorials/unpack_pe/
"""

import os
import struct
import math
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

# ============================================================================
# Data Structures
# ============================================================================

class PackingType(Enum):
    NONE = "none"
    COMPRESSED = "compressed"
    ENCRYPTED = "encrypted"
    VIRTUALIZED = "virtualized"
    MULTI_LAYER = "multi_layer"
    UNKNOWN = "unknown"

@dataclass
class MemoryRegion:
    """A snapshot of a memory region"""
    base: int
    size: int
    data: bytes
    protection: str  # rwx
    name: str = ""

@dataclass
class ImportEntry:
    """Reconstructed import"""
    dll: str
    function: str
    ordinal: Optional[int]
    iat_address: int
    resolved_address: int

@dataclass
class UnpackResult:
    """Result of unpacking operation"""
    success: bool
    oep: Optional[int] = None
    original_ep: Optional[int] = None
    memory_dump: Optional[bytes] = None
    imports: List[ImportEntry] = field(default_factory=list)
    sections: List[MemoryRegion] = field(default_factory=list)
    packing_type: PackingType = PackingType.UNKNOWN
    layers_unpacked: int = 0
    analysis_log: List[str] = field(default_factory=list)
    error: Optional[str] = None

@dataclass
class TraceEntry:
    """Single trace event"""
    address: int
    instruction: str
    registers: Dict[str, int]
    memory_accesses: List[Tuple[int, str, int]]  # (addr, r/w, size)

@dataclass
class UnpackerState:
    """Current state of unpacker analysis"""
    stage: str  # detect, trace, find_oep, dump, rebuild
    entry_point: int
    current_address: int
    traces: List[TraceEntry] = field(default_factory=list)
    breakpoints: List[int] = field(default_factory=list)
    memory_writes: Dict[int, bytes] = field(default_factory=dict)
    suspected_oeps: List[Tuple[int, float]] = field(default_factory=list)  # (addr, confidence)

# ============================================================================
# Entropy Analysis
# ============================================================================

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data (0-8 bits)"""
    if not data:
        return 0.0

    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    entropy = 0.0
    length = len(data)
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy

def analyze_section_entropy(data: bytes, section_size: int = 4096) -> List[Tuple[int, float]]:
    """Analyze entropy per section to find packed regions"""
    results = []
    for offset in range(0, len(data), section_size):
        chunk = data[offset:offset + section_size]
        entropy = calculate_entropy(chunk)
        results.append((offset, entropy))
    return results

# ============================================================================
# Packing Detection
# ============================================================================

def detect_packing(file_data: bytes) -> Tuple[PackingType, float, str]:
    """
    Detect if binary is packed using entropy and structural analysis.
    Returns (packing_type, confidence, reason)

    Claude will later refine this with semantic analysis.
    """
    # Overall entropy
    total_entropy = calculate_entropy(file_data)

    # Section-by-section entropy
    section_entropies = analyze_section_entropy(file_data)
    high_entropy_sections = sum(1 for _, e in section_entropies if e > 7.0)

    # Check for common packer signatures (just as hints, not definitive)
    signatures = {
        b'UPX!': 'UPX',
        b'PKLITE': 'PKLITE',
        b'ASPack': 'ASPack',
        b'PECompact': 'PECompact',
        b'.nsp': 'NsPack',
        b'MEW': 'MEW',
        b'FSG!': 'FSG',
    }

    detected_sig = None
    for sig, name in signatures.items():
        if sig in file_data:
            detected_sig = name
            break

    # Decision logic
    if total_entropy > 7.5:
        if detected_sig:
            return (PackingType.COMPRESSED, 0.95, f"High entropy ({total_entropy:.2f}) + {detected_sig} signature")
        else:
            return (PackingType.ENCRYPTED, 0.85, f"Very high entropy ({total_entropy:.2f}), likely encrypted")

    elif total_entropy > 6.8:
        if high_entropy_sections > len(section_entropies) // 2:
            return (PackingType.COMPRESSED, 0.75, f"Multiple high-entropy sections ({high_entropy_sections})")
        else:
            return (PackingType.UNKNOWN, 0.5, f"Elevated entropy ({total_entropy:.2f}), possible packing")

    elif detected_sig:
        return (PackingType.COMPRESSED, 0.70, f"Signature found: {detected_sig}")

    else:
        return (PackingType.NONE, 0.85, f"Normal entropy ({total_entropy:.2f}), likely not packed")

# ============================================================================
# OEP Detection Heuristics (for Claude to refine)
# ============================================================================

class OEPHeuristics:
    """
    Heuristics for OEP detection that Claude will use as hints.
    These are NOT definitive - Claude analyzes the actual code semantics.
    """

    @staticmethod
    def check_pushad_popad_pattern(traces: List[TraceEntry]) -> Optional[int]:
        """
        Classic UPX pattern: PUSHAD ... POPAD ... JMP OEP
        Returns suspected OEP address if pattern found.
        """
        pushad_idx = None
        for i, trace in enumerate(traces):
            if 'pushad' in trace.instruction.lower() or 'pusha' in trace.instruction.lower():
                pushad_idx = i
            elif pushad_idx and ('popad' in trace.instruction.lower() or 'popa' in trace.instruction.lower()):
                # Look for JMP after POPAD
                for j in range(i + 1, min(i + 10, len(traces))):
                    if traces[j].instruction.lower().startswith('jmp'):
                        # The jump target is likely OEP
                        return traces[j].address
        return None

    @staticmethod
    def check_tail_jump(traces: List[TraceEntry], entry_point: int) -> Optional[int]:
        """
        Look for "tail jump" - a JMP to a far address that's likely OEP.
        Common pattern: stub code jumps far away to original code.
        """
        for i, trace in enumerate(traces):
            if trace.instruction.lower().startswith('jmp'):
                # Check if this is a far jump (> 0x1000 bytes from entry)
                # The actual target would need to be extracted from instruction
                pass
        return None

    @staticmethod
    def check_entropy_transition(traces: List[TraceEntry], memory_writes: Dict[int, bytes]) -> Optional[int]:
        """
        OEP often follows entropy transition:
        High entropy packed data -> Low entropy unpacked code
        """
        # Track when execution moves from high-entropy to low-entropy region
        pass
        return None

    @staticmethod
    def check_stack_stabilization(traces: List[TraceEntry]) -> Optional[int]:
        """
        ESP typically stabilizes at OEP after packer cleanup.
        """
        if len(traces) < 10:
            return None

        esp_values = [t.registers.get('ESP', 0) for t in traces]

        # Look for ESP stabilization (same value for multiple instructions)
        for i in range(len(esp_values) - 5):
            window = esp_values[i:i+5]
            if len(set(window)) == 1:  # ESP stable for 5 instructions
                return traces[i].address

        return None

# ============================================================================
# AI Unpacker Core
# ============================================================================

class AIUnpacker:
    """
    Generic AI-powered unpacker.

    Unlike signature-based unpackers, this uses Claude to:
    1. Understand what the packer is doing semantically
    2. Identify OEP based on code analysis, not patterns
    3. Make decisions about when code is "unpacked enough"

    The human provides: the binary, strategic guidance
    Claude provides: all mechanical computation and analysis
    """

    def __init__(self, debug_engine=None, claude_api=None):
        """
        Args:
            debug_engine: Debugger interface (IDA, our engine, or emulator)
            claude_api: Claude API client for AI analysis
        """
        self.debug_engine = debug_engine
        self.claude_api = claude_api
        self.state = None
        self.result = UnpackResult(success=False)

    def log(self, message: str):
        """Add to analysis log"""
        self.result.analysis_log.append(message)
        print(f"[AIUnpacker] {message}")

    # -------------------------------------------------------------------------
    # Stage 1: Detection
    # -------------------------------------------------------------------------

    def detect(self, file_path: str) -> Tuple[PackingType, float, str]:
        """
        Detect if binary is packed.
        First uses heuristics, then asks Claude for semantic analysis.
        """
        self.log(f"Stage 1: DETECT - Analyzing {file_path}")

        with open(file_path, 'rb') as f:
            data = f.read()

        packing_type, confidence, reason = detect_packing(data)
        self.log(f"  Heuristic result: {packing_type.value} ({confidence:.0%}) - {reason}")

        self.result.packing_type = packing_type

        # TODO: Ask Claude for deeper analysis
        # claude_assessment = self.ask_claude_packing_analysis(data)

        return packing_type, confidence, reason

    # -------------------------------------------------------------------------
    # Stage 2: Tracing
    # -------------------------------------------------------------------------

    def trace(self, file_path: str, max_instructions: int = 100000) -> List[TraceEntry]:
        """
        Execute binary under trace, recording all instructions.
        Claude will analyze this trace to understand the unpacking algorithm.
        """
        self.log(f"Stage 2: TRACE - Executing under trace (max {max_instructions} instructions)")

        if not self.debug_engine:
            self.log("  ERROR: No debug engine available")
            self.result.error = "No debug engine configured"
            return []

        traces = []

        # Set up tracing breakpoints
        # - Memory write to executable sections
        # - VirtualProtect/VirtualAlloc calls
        # - Known unpacker exit patterns

        # TODO: Implement actual tracing via debug_engine
        # For now, return empty - will be implemented with IDA integration

        self.log(f"  Collected {len(traces)} trace entries")
        return traces

    # -------------------------------------------------------------------------
    # Stage 3: Find OEP
    # -------------------------------------------------------------------------

    def find_oep(self, traces: List[TraceEntry]) -> Optional[int]:
        """
        Find Original Entry Point using AI analysis.

        Traditional unpackers use fixed patterns (PUSHAD/POPAD, signatures).
        We let Claude analyze the trace semantically.
        """
        self.log("Stage 3: FIND OEP - Analyzing traces for original entry point")

        # Run heuristics as hints
        heuristics = OEPHeuristics()

        hints = []

        oep = heuristics.check_pushad_popad_pattern(traces)
        if oep:
            hints.append(('pushad_popad', oep, 0.7))

        oep = heuristics.check_stack_stabilization(traces)
        if oep:
            hints.append(('stack_stable', oep, 0.5))

        self.log(f"  Heuristic hints: {hints}")

        # TODO: Ask Claude to analyze traces and identify OEP
        # Claude can understand:
        # - What the unpacking loop is doing
        # - When the transition to "real" code happens
        # - Semantic indicators (e.g., "this looks like compiler-generated code")

        if hints:
            # For now, use best heuristic
            best = max(hints, key=lambda x: x[2])
            self.log(f"  Best OEP candidate: 0x{best[1]:X} ({best[0]}, {best[2]:.0%})")
            self.result.oep = best[1]
            return best[1]

        self.log("  No OEP found")
        return None

    # -------------------------------------------------------------------------
    # Stage 4: Memory Dump
    # -------------------------------------------------------------------------

    def dump(self, oep: int) -> Optional[bytes]:
        """
        Dump memory at OEP to capture unpacked code.
        """
        self.log(f"Stage 4: DUMP - Capturing memory at OEP 0x{oep:X}")

        if not self.debug_engine:
            self.log("  ERROR: No debug engine available")
            return None

        # TODO: Use debug_engine to dump memory
        # - Dump all executable sections
        # - Capture IAT region
        # - Record section mappings

        return None

    # -------------------------------------------------------------------------
    # Stage 5: IAT Reconstruction
    # -------------------------------------------------------------------------

    def rebuild_iat(self, memory_dump: bytes, base_address: int) -> List[ImportEntry]:
        """
        Reconstruct Import Address Table from memory dump.

        Claude analyzes call targets to identify API functions.
        """
        self.log("Stage 5: REBUILD - Reconstructing IAT")

        imports = []

        # TODO:
        # 1. Find IAT region (typically in .rdata or near imports section)
        # 2. For each pointer in IAT, resolve to DLL!Function
        # 3. Use debug engine's symbol resolution or API database

        self.result.imports = imports
        return imports

    # -------------------------------------------------------------------------
    # Main Entry Point
    # -------------------------------------------------------------------------

    def unpack(self, file_path: str) -> UnpackResult:
        """
        Main unpacking routine.

        Runs all stages, with Claude making decisions at each step.
        """
        self.log(f"=== AI Unpacker starting on {file_path} ===")

        # Stage 1: Detection
        packing_type, confidence, reason = self.detect(file_path)

        if packing_type == PackingType.NONE and confidence > 0.8:
            self.log("Binary appears unpacked, skipping unpack stages")
            self.result.success = True
            return self.result

        # Stage 2: Tracing
        traces = self.trace(file_path)

        if not traces:
            self.log("No traces collected, cannot proceed")
            self.result.error = "Tracing failed"
            return self.result

        # Stage 3: Find OEP
        oep = self.find_oep(traces)

        if not oep:
            self.log("Could not identify OEP")
            self.result.error = "OEP not found"
            return self.result

        # Stage 4: Memory Dump
        memory = self.dump(oep)

        if not memory:
            self.log("Memory dump failed")
            self.result.error = "Dump failed"
            return self.result

        self.result.memory_dump = memory

        # Stage 5: IAT Reconstruction
        imports = self.rebuild_iat(memory, 0)  # TODO: actual base

        self.result.success = True
        self.result.layers_unpacked = 1

        self.log(f"=== Unpacking complete: OEP=0x{oep:X}, {len(imports)} imports ===")

        return self.result

# ============================================================================
# Claude Integration Prompts
# ============================================================================

CLAUDE_PACKING_ANALYSIS_PROMPT = """
You are analyzing a binary to determine if it is packed/encrypted.

Entropy analysis shows: {entropy_info}
Section breakdown: {section_info}
Signature matches: {signature_info}

Based on this data:
1. Is this binary packed? (yes/no/uncertain)
2. What type of packing? (compression/encryption/virtualization/none)
3. Confidence level (0-100%)
4. What unpacking approach would you recommend?

Be precise. If you cannot determine, say so.
"""

CLAUDE_OEP_ANALYSIS_PROMPT = """
You are analyzing an execution trace to find the Original Entry Point (OEP).

The binary starts at 0x{entry_point:X}.
Trace summary: {trace_summary}

Key observations:
{observations}

Based on this:
1. Where is the OEP? (address)
2. Confidence (0-100%)
3. What evidence supports this?
4. What is the packer doing before OEP?

Show your reasoning. No guessing.
"""

CLAUDE_IAT_ANALYSIS_PROMPT = """
You are reconstructing the Import Address Table from a memory dump.

IAT region: 0x{iat_start:X} - 0x{iat_end:X}
Pointer values found: {pointers}

For each pointer:
1. What DLL does it belong to?
2. What function is it?
3. How confident are you?

Use the memory layout and calling conventions to infer imports.
"""

# ============================================================================
# Test / Demo
# ============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python ai_unpacker.py <binary>")
        print()
        print("AI-Powered Generic Unpacker")
        print("Claude analyzes the algorithm, not pattern-matches.")
        sys.exit(1)

    unpacker = AIUnpacker()
    result = unpacker.unpack(sys.argv[1])

    print()
    print("=== Results ===")
    print(f"Success: {result.success}")
    print(f"Packing type: {result.packing_type.value}")
    print(f"OEP: {hex(result.oep) if result.oep else 'Not found'}")
    print(f"Layers unpacked: {result.layers_unpacked}")
    print(f"Imports found: {len(result.imports)}")
    if result.error:
        print(f"Error: {result.error}")
    print()
    print("Analysis log:")
    for line in result.analysis_log:
        print(f"  {line}")
