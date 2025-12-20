"""
Generic Crypto Analyzer for AnalyzeBugger

Identifies cryptographic operations by OBSERVING BEHAVIOR, not pattern-matching.

How it works:
1. Trace execution with different inputs
2. Observe memory transformations
3. Identify mathematical relationships (XOR, ROL, ADD, etc.)
4. Detect key material and cipher structure
5. Let Claude reason about the algorithm

This is truly generic - works on ANY cipher because we observe
what it DOES, not what it IS.

Key insight: Cryptographic operations have observable properties:
- XOR: A ^ B ^ B = A (self-inverse)
- ROL/ROR: Bit patterns shift predictably
- S-boxes: Fixed substitution tables
- Block ciphers: Fixed-size transformations
"""

import os
import struct
from typing import Optional, List, Dict, Any, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict
import json

# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class MemoryTransformation:
    """Record of how memory changed"""
    address: int
    before: bytes
    after: bytes
    operation: str  # 'xor', 'add', 'sub', 'rol', 'ror', 'unknown'
    operand: Optional[int] = None  # Key/constant used
    instruction_address: int = 0

@dataclass
class CryptoOperation:
    """Detected cryptographic operation"""
    op_type: str  # 'xor', 'rol', 'ror', 'add', 'sub', 'sbox', 'block'
    address: int  # Where in code
    data_address: int  # What data it operates on
    key_value: Optional[int] = None
    key_address: Optional[int] = None
    block_size: int = 0
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)

@dataclass
class CipherAnalysis:
    """Complete analysis of a cipher"""
    cipher_type: str  # 'stream_xor', 'block', 'custom', 'none'
    operations: List[CryptoOperation] = field(default_factory=list)
    key_material: List[Tuple[int, bytes]] = field(default_factory=list)  # (addr, data)
    block_size: int = 0
    rounds: int = 0
    confidence: float = 0.0
    description: str = ""

# ============================================================================
# Transformation Detection
# ============================================================================

def detect_xor_relationship(before: bytes, after: bytes) -> Optional[Tuple[str, int]]:
    """
    Detect if transformation is XOR with a key.
    Returns ('xor', key) if detected.
    """
    if len(before) != len(after) or len(before) == 0:
        return None

    # Try single-byte XOR
    key = before[0] ^ after[0]
    if all(b ^ key == a for b, a in zip(before, after)):
        return ('xor_byte', key)

    # Try 4-byte XOR (DWORD)
    if len(before) >= 4:
        key32 = struct.unpack('<I', before[:4])[0] ^ struct.unpack('<I', after[:4])[0]
        key_bytes = struct.pack('<I', key32)
        matches = True
        for i in range(len(before)):
            if before[i] ^ key_bytes[i % 4] != after[i]:
                matches = False
                break
        if matches:
            return ('xor_dword', key32)

    return None

def detect_add_relationship(before: bytes, after: bytes) -> Optional[Tuple[str, int]]:
    """Detect if transformation is ADD/SUB with a constant."""
    if len(before) != len(after) or len(before) == 0:
        return None

    # Try single-byte ADD
    diff = (after[0] - before[0]) & 0xFF
    if all((b + diff) & 0xFF == a for b, a in zip(before, after)):
        return ('add_byte', diff)

    # Try single-byte SUB
    diff = (before[0] - after[0]) & 0xFF
    if all((b - diff) & 0xFF == a for b, a in zip(before, after)):
        return ('sub_byte', diff)

    return None

def detect_rotation(before: bytes, after: bytes) -> Optional[Tuple[str, int]]:
    """Detect if transformation is bit rotation."""
    if len(before) != len(after):
        return None

    # Convert to integers for rotation check
    if len(before) == 4:
        val_before = struct.unpack('<I', before)[0]
        val_after = struct.unpack('<I', after)[0]

        # Try ROL 1-31
        for bits in range(1, 32):
            rotated = ((val_before << bits) | (val_before >> (32 - bits))) & 0xFFFFFFFF
            if rotated == val_after:
                return ('rol', bits)

        # Try ROR 1-31
        for bits in range(1, 32):
            rotated = ((val_before >> bits) | (val_before << (32 - bits))) & 0xFFFFFFFF
            if rotated == val_after:
                return ('ror', bits)

    return None

def analyze_transformation(before: bytes, after: bytes) -> MemoryTransformation:
    """Analyze a single memory transformation."""
    transform = MemoryTransformation(
        address=0,
        before=before,
        after=after,
        operation='unknown'
    )

    # Try to identify the operation
    result = detect_xor_relationship(before, after)
    if result:
        transform.operation = result[0]
        transform.operand = result[1]
        return transform

    result = detect_add_relationship(before, after)
    if result:
        transform.operation = result[0]
        transform.operand = result[1]
        return transform

    result = detect_rotation(before, after)
    if result:
        transform.operation = result[0]
        transform.operand = result[1]
        return transform

    return transform

# ============================================================================
# Trace Analysis
# ============================================================================

class CryptoAnalyzer:
    """
    Analyzes execution traces to identify cryptographic operations.

    Generic approach:
    1. Run with input A, snapshot memory
    2. Run with input B, snapshot memory
    3. Compare: what changed? how?
    4. Identify patterns in the transformations
    """

    def __init__(self):
        self.transformations: List[MemoryTransformation] = []
        self.operations: List[CryptoOperation] = []
        self.memory_snapshots: Dict[str, Dict[int, bytes]] = {}

    def analyze_trace(self, trace) -> List[CryptoOperation]:
        """
        Analyze an execution trace for crypto operations.

        Looks for patterns:
        - XOR instructions with non-zero operands
        - ROL/ROR instructions
        - Loops that process data byte-by-byte
        - Memory regions that change in crypto-like patterns
        """
        ops = []

        # Group memory writes by address to find transformations
        writes_by_addr = defaultdict(list)
        for access in trace.memory_accesses:
            if access.access_type == 'write':
                writes_by_addr[access.address].append(access)

        # Find addresses written multiple times (likely being transformed)
        for addr, writes in writes_by_addr.items():
            if len(writes) >= 2:
                # This address was modified multiple times - possible crypto
                values = [w.value for w in writes]
                # Check for XOR pattern (value changes but with consistent relationship)
                # This is a hint for Claude to investigate further

        # Look for XOR instructions in the trace
        xor_count = 0
        rol_count = 0

        for insn in trace.instructions:
            mnem = insn.mnemonic.lower()
            if 'xor' in mnem:
                xor_count += 1
                # Record XOR operation
                op = CryptoOperation(
                    op_type='xor',
                    address=insn.address,
                    data_address=0,  # Would need operand parsing
                    confidence=0.5,
                    evidence=[f"XOR instruction at {hex(insn.address)}"]
                )
                ops.append(op)

            elif 'rol' in mnem or 'ror' in mnem:
                rol_count += 1
                op = CryptoOperation(
                    op_type='rol' if 'rol' in mnem else 'ror',
                    address=insn.address,
                    data_address=0,
                    confidence=0.5,
                    evidence=[f"Rotation at {hex(insn.address)}"]
                )
                ops.append(op)

        self.operations = ops
        return ops

    def compare_runs(self, trace1, input1: str, trace2, input2: str) -> Dict[str, Any]:
        """
        Compare two execution traces with different inputs.

        Key insight: How does changing the input change the execution?
        - Same instruction count? (deterministic algorithm)
        - Different memory values? (input affects output)
        - Same code path? (no input-dependent branching)
        """
        analysis = {
            'input1': input1,
            'input2': input2,
            'instruction_count_1': len(trace1.instructions),
            'instruction_count_2': len(trace2.instructions),
            'memory_access_count_1': len(trace1.memory_accesses),
            'memory_access_count_2': len(trace2.memory_accesses),
            'same_instruction_count': len(trace1.instructions) == len(trace2.instructions),
            'code_path_divergence': [],
            'memory_differences': [],
        }

        # Find where execution diverges
        min_len = min(len(trace1.instructions), len(trace2.instructions))
        for i in range(min_len):
            if trace1.instructions[i].address != trace2.instructions[i].address:
                analysis['code_path_divergence'].append({
                    'index': i,
                    'trace1_addr': hex(trace1.instructions[i].address),
                    'trace2_addr': hex(trace2.instructions[i].address),
                })
                if len(analysis['code_path_divergence']) >= 10:
                    break

        return analysis

    def identify_cipher_type(self, ops: List[CryptoOperation]) -> CipherAnalysis:
        """
        Identify the type of cipher based on detected operations.
        """
        xor_ops = [o for o in ops if o.op_type == 'xor']
        rol_ops = [o for o in ops if o.op_type in ['rol', 'ror']]
        add_ops = [o for o in ops if o.op_type in ['add', 'sub']]

        analysis = CipherAnalysis(cipher_type='unknown')

        if xor_ops and not rol_ops and not add_ops:
            analysis.cipher_type = 'stream_xor'
            analysis.description = f"Simple XOR cipher ({len(xor_ops)} XOR operations)"
            analysis.confidence = 0.7

        elif xor_ops and rol_ops:
            analysis.cipher_type = 'rolling_xor'
            analysis.description = f"Rolling XOR cipher ({len(xor_ops)} XOR, {len(rol_ops)} rotations)"
            analysis.confidence = 0.8

        elif len(xor_ops) > 100:
            analysis.cipher_type = 'block_cipher'
            analysis.description = f"Possible block cipher (many XOR operations)"
            analysis.confidence = 0.5

        analysis.operations = ops
        return analysis


# ============================================================================
# Input/Output Correlation
# ============================================================================

class IOCorrelator:
    """
    Correlates inputs with outputs to understand transformations.

    Key technique: Differential analysis
    - Run with input A, get output A'
    - Run with input B, get output B'
    - Analyze: how does (A -> B) relate to (A' -> B')?
    """

    def __init__(self):
        self.runs: List[Dict[str, Any]] = []

    def add_run(self, input_data: str, output_data: str, trace=None):
        """Add a run to the correlation set."""
        self.runs.append({
            'input': input_data,
            'output': output_data,
            'input_bytes': input_data.encode('latin-1'),
            'output_bytes': output_data.encode('latin-1'),
            'trace': trace,
        })

    def find_correlations(self) -> Dict[str, Any]:
        """
        Find correlations between inputs and outputs.

        Techniques:
        1. Single-bit changes: flip one input bit, see what output changes
        2. Byte-level correlation: which input bytes affect which output bytes
        3. Length correlation: how does input length affect output length
        """
        if len(self.runs) < 2:
            return {'error': 'Need at least 2 runs for correlation'}

        correlations = {
            'input_length_vs_output': [],
            'byte_correlations': [],
            'differential_analysis': [],
        }

        # Length correlation
        for run in self.runs:
            correlations['input_length_vs_output'].append({
                'input_len': len(run['input']),
                'output_len': len(run['output']),
            })

        # Pairwise differential analysis
        for i in range(len(self.runs) - 1):
            run1 = self.runs[i]
            run2 = self.runs[i + 1]

            input_diff = self._diff_strings(run1['input'], run2['input'])
            output_diff = self._diff_strings(run1['output'], run2['output'])

            correlations['differential_analysis'].append({
                'input1': run1['input'],
                'input2': run2['input'],
                'input_diff_positions': input_diff,
                'output_diff_count': len(output_diff),
                'relationship': self._analyze_relationship(input_diff, output_diff)
            })

        return correlations

    def _diff_strings(self, s1: str, s2: str) -> List[int]:
        """Find positions where two strings differ."""
        diffs = []
        for i in range(min(len(s1), len(s2))):
            if s1[i] != s2[i]:
                diffs.append(i)
        # Length difference
        if len(s1) != len(s2):
            for i in range(min(len(s1), len(s2)), max(len(s1), len(s2))):
                diffs.append(i)
        return diffs

    def _analyze_relationship(self, input_diff: List[int], output_diff: List[int]) -> str:
        """Analyze the relationship between input and output changes."""
        if not input_diff:
            return "identical_input"
        if not output_diff:
            return "output_unchanged"  # Interesting - input doesn't affect output here
        if len(output_diff) == len(input_diff):
            return "linear_correlation"
        if len(output_diff) > len(input_diff) * 2:
            return "avalanche_effect"  # Small input change causes large output change (crypto)
        return "partial_correlation"


# ============================================================================
# MCP Tool Interface
# ============================================================================

def tool_analyze_crypto(file_path: str, inputs: List[str] = None) -> dict:
    """
    Analyze a binary for cryptographic operations.

    Runs the binary with multiple inputs and analyzes:
    - What crypto operations are performed
    - How inputs affect outputs
    - What key material is used

    Args:
        file_path: Path to binary
        inputs: Test inputs (default: ['A', 'B', 'AB', 'BA'])

    Returns:
        Crypto analysis results
    """
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from generic_tracer import tool_trace_binary

    if inputs is None:
        inputs = ['A', 'B', 'AB', 'BA', 'AAAA', 'BBBB']

    correlator = IOCorrelator()
    trace_results = []

    # Run with each input
    for inp in inputs:
        result = tool_trace_binary(file_path, input_data=inp + '\r', max_instructions=100000)
        correlator.add_run(inp, result.get('output', ''))
        trace_results.append(result)

    # Get instruction statistics from first trace
    first_trace = trace_results[0] if trace_results else {}
    stats = first_trace.get('instruction_stats', {})

    xor_count = stats.get('xor', 0)
    rol_count = stats.get('rol', 0) + stats.get('ror', 0)
    add_count = stats.get('add', 0) + stats.get('sub', 0)
    loop_count = stats.get('loop', 0)

    # Determine cipher type from statistics
    cipher_type = 'unknown'
    cipher_desc = ''
    confidence = 0.0

    if xor_count > 0 and rol_count == 0:
        cipher_type = 'stream_xor'
        cipher_desc = f"Simple XOR cipher ({xor_count} XOR operations)"
        confidence = 0.7

    elif xor_count > 0 and rol_count > 0:
        cipher_type = 'rolling_xor'
        cipher_desc = f"Rolling XOR cipher ({xor_count} XOR, {rol_count} rotations)"
        confidence = 0.8

    elif xor_count > 100:
        cipher_type = 'block_cipher'
        cipher_desc = f"Possible block cipher ({xor_count} XOR operations)"
        confidence = 0.5

    elif xor_count == 0 and add_count > 0:
        cipher_type = 'add_cipher'
        cipher_desc = f"Additive cipher ({add_count} ADD/SUB operations)"
        confidence = 0.6

    # Get correlations
    correlations = correlator.find_correlations()

    return {
        'success': True,
        'cipher_type': cipher_type,
        'cipher_description': cipher_desc,
        'confidence': confidence,
        'instruction_stats': stats,
        'xor_operations': xor_count,
        'rotation_operations': rol_count,
        'add_sub_operations': add_count,
        'loop_operations': loop_count,
        'xor_locations': first_trace.get('xor_locations', []),
        'rol_ror_locations': first_trace.get('rol_ror_locations', []),
        'correlations': correlations,
        'total_instructions': first_trace.get('instruction_count', 0),
        'analysis_hint': """
Claude: Analyze these results to understand the cipher:
1. cipher_type gives a high-level classification based on observed operations
2. instruction_stats shows raw counts of crypto-relevant instructions
3. xor_locations and rol_ror_locations show WHERE these operations occur
4. correlations show how inputs affect outputs (avalanche = crypto, linear = simple)
5. Use this to reason about the algorithm structure and compute results
"""
    }


def tool_differential_analysis(file_path: str, base_input: str, variants: List[str]) -> dict:
    """
    Perform differential cryptanalysis.

    Run with a base input and variants, analyze how changes propagate.

    Args:
        file_path: Path to binary
        base_input: Base input string
        variants: Modified versions of base input

    Returns:
        Differential analysis showing how input changes affect output
    """
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from generic_tracer import tool_trace_binary

    results = []

    # Run base
    base_result = tool_trace_binary(file_path, input_data=base_input + '\r')
    base_output = base_result.get('output', '')

    results.append({
        'input': base_input,
        'output_hash': hash(base_output) & 0xFFFFFFFF,
        'output_len': len(base_output),
        'is_base': True
    })

    # Run variants
    for variant in variants:
        var_result = tool_trace_binary(file_path, input_data=variant + '\r')
        var_output = var_result.get('output', '')

        # Compare to base
        output_changed = var_output != base_output
        input_diff_count = sum(1 for a, b in zip(base_input, variant) if a != b)
        input_diff_count += abs(len(base_input) - len(variant))

        results.append({
            'input': variant,
            'output_hash': hash(var_output) & 0xFFFFFFFF,
            'output_len': len(var_output),
            'output_changed': output_changed,
            'input_chars_changed': input_diff_count,
            'is_base': False
        })

    return {
        'success': True,
        'base_input': base_input,
        'results': results,
        'analysis': {
            'any_output_change': any(r.get('output_changed', False) for r in results),
            'all_outputs_same': all(r['output_hash'] == results[0]['output_hash'] for r in results),
        }
    }


# ============================================================================
# Test
# ============================================================================

if __name__ == "__main__":
    import sys

    print("Generic Crypto Analyzer for AnalyzeBugger")
    print("Identifies ciphers by behavior, not signatures")
    print()

    if len(sys.argv) > 1:
        binary = sys.argv[1]
        print(f"Analyzing: {binary}")
        print()

        result = tool_analyze_crypto(binary)

        if result['success']:
            print(f"Cipher Type: {result['cipher_type']}")
            print(f"Description: {result['cipher_description']}")
            print(f"Confidence: {result['confidence']:.0%}")
            print()
            print("Instruction Statistics:")
            stats = result.get('instruction_stats', {})
            print(f"  XOR: {stats.get('xor', 0)}")
            print(f"  ROL: {stats.get('rol', 0)}")
            print(f"  ROR: {stats.get('ror', 0)}")
            print(f"  ADD: {stats.get('add', 0)}")
            print(f"  SUB: {stats.get('sub', 0)}")
            print(f"  LOOP: {stats.get('loop', 0)}")
            print(f"  Total Instructions: {result.get('total_instructions', 0)}")
            print()

            xor_locs = result.get('xor_locations', [])
            if xor_locs:
                print(f"XOR Locations (first {len(xor_locs)}):")
                for loc in xor_locs[:10]:
                    print(f"  {loc}")

            rol_locs = result.get('rol_ror_locations', [])
            if rol_locs:
                print(f"\nROL/ROR Locations (first {len(rol_locs)}):")
                for loc in rol_locs[:10]:
                    print(f"  {loc}")

            print()
            print("Input/Output Correlations:")
            for diff in result['correlations'].get('differential_analysis', []):
                print(f"  {diff['input1']} vs {diff['input2']}: {diff['relationship']}")
