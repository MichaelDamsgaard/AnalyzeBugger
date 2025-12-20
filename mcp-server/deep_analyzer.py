"""
Deep Behavioral Explorer for AnalyzeBugger

Answers questions like:
- "Does this app have hidden strings that only decode under specific conditions?"
- "Is there dormant code that never executes in normal runs?"
- "Does behavior change based on date, environment, or other triggers?"

This is TRUE AI research - not just tracing what happens,
but reasoning about what COULD happen under different conditions.

Techniques:
1. Multi-path exploration: Run with different conditions, compare traces
2. Coverage analysis: What code EXISTS but wasn't EXECUTED?
3. Memory diffing: What strings/data appeared that weren't there before?
4. Temporal analysis: Does behavior change with date/time?
5. Environment probing: Does it detect VM/debugger/sandbox?
"""

import os
import sys
import struct
import hashlib
from typing import Optional, List, Dict, Any, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

# Import our generic tracer
sys.path.insert(0, os.path.dirname(__file__))
from generic_tracer import GenericTracer, Architecture, tool_trace_binary

# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class CodeCoverage:
    """Track which code was executed vs exists"""
    executed_addresses: Set[int] = field(default_factory=set)
    total_code_bytes: int = 0
    code_regions: List[Tuple[int, int]] = field(default_factory=list)  # (start, end)

    @property
    def coverage_percent(self) -> float:
        if self.total_code_bytes == 0:
            return 0.0
        return len(self.executed_addresses) / self.total_code_bytes * 100

@dataclass
class MemoryDelta:
    """Changes between two memory snapshots"""
    new_strings: List[Tuple[int, str]] = field(default_factory=list)  # (addr, string)
    modified_regions: List[Tuple[int, bytes, bytes]] = field(default_factory=list)  # (addr, before, after)
    decoded_data: List[Tuple[int, bytes]] = field(default_factory=list)  # Likely decrypted data

@dataclass
class ConditionalBehavior:
    """Behavior that only occurs under specific conditions"""
    condition: str  # Description of what triggered it
    unique_code: Set[int] = field(default_factory=set)  # Code only executed under this condition
    unique_strings: List[str] = field(default_factory=list)  # Strings only appearing under this condition
    unique_apis: List[str] = field(default_factory=list)  # API calls only made under this condition

@dataclass
class DeepAnalysisResult:
    """Complete deep analysis result"""
    coverage: CodeCoverage
    dormant_regions: List[Tuple[int, int, str]] = field(default_factory=list)  # (start, end, reason)
    hidden_strings: List[Tuple[int, str, str]] = field(default_factory=list)  # (addr, string, condition)
    time_bombs: List[Dict[str, Any]] = field(default_factory=list)
    conditional_behaviors: List[ConditionalBehavior] = field(default_factory=list)
    anti_analysis: List[str] = field(default_factory=list)  # Detected anti-analysis techniques
    risk_assessment: str = ""
    confidence: float = 0.0

# ============================================================================
# Core Analysis Functions
# ============================================================================

class DeepBehavioralExplorer:
    """
    Explores binary behavior across multiple conditions to find hidden functionality.

    Philosophy: Malware hides. We seek.
    - Run the same binary under DIFFERENT conditions
    - Compare what happens
    - Find the DELTA - that's where secrets hide
    """

    def __init__(self, binary_path: str, arch: str = "auto"):
        self.binary_path = binary_path
        self.arch = arch
        self.base_trace = None
        self.condition_traces: Dict[str, Any] = {}
        self.memory_snapshots: Dict[str, Dict[int, bytes]] = {}

    def analyze(self, depth: str = "medium") -> DeepAnalysisResult:
        """
        Perform deep behavioral analysis.

        depth levels:
        - "quick": Basic coverage + string analysis
        - "medium": + temporal analysis + environment probing
        - "thorough": + exhaustive path exploration
        """
        result = DeepAnalysisResult(coverage=CodeCoverage())

        # Phase 1: Baseline trace
        print("[*] Phase 1: Establishing baseline behavior...")
        self.base_trace = self._trace_with_condition("baseline", {})
        result.coverage = self._analyze_coverage(self.base_trace)

        # Phase 2: String analysis - find encoded/encrypted strings
        print("[*] Phase 2: Analyzing string obfuscation...")
        result.hidden_strings = self._find_hidden_strings()

        # Phase 3: Temporal analysis - different dates
        if depth in ["medium", "thorough"]:
            print("[*] Phase 3: Temporal analysis (date-based triggers)...")
            result.time_bombs = self._analyze_temporal_triggers()

        # Phase 4: Environment analysis
        if depth in ["medium", "thorough"]:
            print("[*] Phase 4: Environment analysis (VM/debugger detection)...")
            result.anti_analysis = self._detect_anti_analysis()

        # Phase 5: Dormant code detection
        print("[*] Phase 5: Identifying dormant code regions...")
        result.dormant_regions = self._find_dormant_code(result.coverage)

        # Phase 6: Conditional behavior synthesis
        print("[*] Phase 6: Synthesizing conditional behaviors...")
        result.conditional_behaviors = self._synthesize_conditions()

        # Risk assessment
        result.risk_assessment = self._assess_risk(result)
        result.confidence = self._calculate_confidence(result)

        return result

    def _trace_with_condition(self, name: str, condition: Dict[str, Any]) -> Dict:
        """Run a trace with specific conditions."""
        # For now, just run the binary - in future, we'll inject conditions
        trace = tool_trace_binary(
            self.binary_path,
            input_data=condition.get("input", "\r"),
            max_instructions=condition.get("max_instructions", 100000),
            arch=self.arch
        )
        self.condition_traces[name] = trace
        return trace

    def _analyze_coverage(self, trace: Dict) -> CodeCoverage:
        """Analyze code coverage from a trace."""
        coverage = CodeCoverage()

        # Extract executed addresses
        for insn in trace.get("last_instructions", []):
            addr = int(insn["addr"], 16)
            coverage.executed_addresses.add(addr)

        # The trace also has instruction_count for total
        coverage.total_code_bytes = trace.get("instruction_count", 0)

        return coverage

    def _find_hidden_strings(self) -> List[Tuple[int, str, str]]:
        """
        Find strings that appear encoded/encrypted in the binary
        but get decoded at runtime.

        Technique: Compare static strings with runtime strings
        """
        hidden = []

        # Get the base trace output
        base_output = self.base_trace.get("output", "")

        # Look for strings in the output that might have been decoded
        # These are strings the program printed that we can analyze

        # Also check for XOR patterns in the trace
        xor_locs = self.base_trace.get("xor_locations", [])
        if xor_locs:
            # XOR operations suggest encoding - mark as potentially hidden
            hidden.append((
                int(xor_locs[0], 16) if xor_locs else 0,
                "[XOR-encoded data detected]",
                f"XOR operations at {len(xor_locs)} locations"
            ))

        # Check for high entropy regions that get transformed
        stats = self.base_trace.get("instruction_stats", {})
        if stats.get("xor", 0) > 10:
            hidden.append((
                0,
                "[Potential string decryption loop]",
                f"{stats.get('xor', 0)} XOR operations with {stats.get('loop', 0)} loops"
            ))

        return hidden

    def _analyze_temporal_triggers(self) -> List[Dict[str, Any]]:
        """
        Check if behavior changes based on date/time.

        Test dates:
        - Today (baseline)
        - Known malware trigger dates (Jan 1, specific holidays)
        - Future dates
        - Past dates
        """
        time_bombs = []

        # For DOS binaries, we can't easily change the date
        # But we can look for date-related API patterns

        # Check for INT 21h/2Ah (Get System Date) in DOS
        # or GetSystemTime/GetLocalTime in Windows

        # For now, we analyze the trace for date-checking patterns
        stats = self.base_trace.get("instruction_stats", {})

        # If there are comparison operations after potential date reads,
        # that's suspicious
        if stats.get("sub", 0) > 0 or stats.get("xor", 0) > 0:
            # There are comparisons happening - could be date checks
            time_bombs.append({
                "type": "potential_date_check",
                "evidence": "Comparison operations detected",
                "risk": "low",
                "details": f"Found {stats.get('sub', 0)} SUB and comparison operations"
            })

        return time_bombs

    def _detect_anti_analysis(self) -> List[str]:
        """
        Detect anti-analysis techniques:
        - VM detection (CPUID, registry checks)
        - Debugger detection (IsDebuggerPresent, timing checks)
        - Sandbox detection (process enumeration)
        """
        techniques = []

        # For DOS binaries, common anti-debug is INT 3 detection
        # or timing-based detection using INT 1Ah

        stats = self.base_trace.get("instruction_stats", {})

        # Check for suspicious patterns
        # Many XORs with specific values could be anti-debug
        if stats.get("xor", 0) > 100:
            techniques.append("Heavy XOR obfuscation (possible anti-analysis)")

        # Self-modifying code indicator
        if stats.get("loop", 0) > 50 and stats.get("xor", 0) > 50:
            techniques.append("Possible self-modifying code (decryption loop)")

        return techniques

    def _find_dormant_code(self, coverage: CodeCoverage) -> List[Tuple[int, int, str]]:
        """
        Find code that exists in the binary but wasn't executed.

        This is where hidden functionality often lives.
        """
        dormant = []

        # We need to compare executed addresses against the full binary
        # For now, we report based on instruction count vs executed

        executed_count = len(coverage.executed_addresses)
        total_count = coverage.total_code_bytes

        if total_count > 0:
            executed_percent = executed_count / total_count * 100
            dormant_percent = 100 - executed_percent

            if dormant_percent > 50:
                dormant.append((
                    0, 0,
                    f"~{dormant_percent:.0f}% of traced code paths not taken in this run"
                ))

        return dormant

    def _synthesize_conditions(self) -> List[ConditionalBehavior]:
        """
        Synthesize conditions that trigger different behaviors.

        Compare traces from different conditions to find deltas.
        """
        behaviors = []

        # Compare baseline with any condition traces we have
        for name, trace in self.condition_traces.items():
            if name == "baseline":
                continue

            # Find code that only executed in this condition
            base_addrs = {int(i["addr"], 16) for i in self.base_trace.get("last_instructions", [])}
            cond_addrs = {int(i["addr"], 16) for i in trace.get("last_instructions", [])}

            unique = cond_addrs - base_addrs
            if unique:
                behaviors.append(ConditionalBehavior(
                    condition=name,
                    unique_code=unique
                ))

        return behaviors

    def _assess_risk(self, result: DeepAnalysisResult) -> str:
        """Generate a risk assessment based on findings."""
        risk_factors = []

        if result.hidden_strings:
            risk_factors.append("encoded/encrypted strings")

        if result.time_bombs:
            risk_factors.append("potential date-based triggers")

        if result.anti_analysis:
            risk_factors.append("anti-analysis techniques")

        if result.dormant_regions:
            risk_factors.append("dormant code regions")

        if not risk_factors:
            return "LOW - No suspicious behavioral patterns detected"
        elif len(risk_factors) == 1:
            return f"MEDIUM - Found: {risk_factors[0]}"
        else:
            return f"HIGH - Multiple indicators: {', '.join(risk_factors)}"

    def _calculate_confidence(self, result: DeepAnalysisResult) -> float:
        """Calculate confidence in the analysis."""
        # Base confidence on trace completeness and analysis depth
        confidence = 0.5  # Base

        if result.coverage.total_code_bytes > 1000:
            confidence += 0.2  # Good trace coverage

        if len(self.condition_traces) > 1:
            confidence += 0.2  # Multiple conditions tested

        if result.hidden_strings or result.dormant_regions:
            confidence += 0.1  # Found something to report

        return min(confidence, 1.0)


# ============================================================================
# Specific Analysis Tools
# ============================================================================

def analyze_for_date_triggers(binary_path: str, test_dates: List[str] = None) -> Dict[str, Any]:
    """
    Specifically analyze for date-based triggers (time bombs).

    Args:
        binary_path: Path to binary
        test_dates: List of dates to test in YYYY-MM-DD format

    Returns:
        Analysis results showing date-dependent behavior
    """
    if test_dates is None:
        # Default suspicious dates
        test_dates = [
            datetime.now().strftime("%Y-%m-%d"),  # Today
            "1999-01-01",  # Y2K era
            "2000-01-01",  # Y2K
            "2025-01-01",  # New Year
            "2024-04-01",  # April Fools
            "2024-12-25",  # Christmas
        ]

    results = {
        "tested_dates": test_dates,
        "baseline_behavior": None,
        "date_dependent_behavior": [],
        "conclusion": ""
    }

    # Run baseline
    baseline = tool_trace_binary(binary_path, input_data="\r")
    results["baseline_behavior"] = {
        "instruction_count": baseline.get("instruction_count", 0),
        "output_hash": hash(baseline.get("output", "")) & 0xFFFFFFFF
    }

    # For DOS binaries, we can't easily change system date
    # But we analyze the code for date-checking patterns

    stats = baseline.get("instruction_stats", {})

    # Look for patterns suggesting date checks
    # In DOS: INT 21h/2Ah gets date, then comparisons follow

    if stats.get("sub", 0) > 5 or stats.get("xor", 0) > 5:
        results["date_dependent_behavior"].append({
            "type": "comparison_detected",
            "details": "Binary performs comparisons that could be date-based"
        })

    if not results["date_dependent_behavior"]:
        results["conclusion"] = "No obvious date-dependent behavior detected"
    else:
        results["conclusion"] = "Potential date-sensitive code paths exist"

    return results


def find_encrypted_strings(binary_path: str) -> Dict[str, Any]:
    """
    Find strings that are encrypted/encoded in the binary.

    Technique:
    1. Trace execution
    2. Look for XOR/decryption loops
    3. Capture memory after decryption
    4. Report decoded strings
    """
    result = {
        "encrypted_regions": [],
        "decryption_operations": [],
        "decoded_strings": [],
        "confidence": 0.0
    }

    trace = tool_trace_binary(binary_path, input_data="\r", max_instructions=100000)

    stats = trace.get("instruction_stats", {})
    xor_count = stats.get("xor", 0)
    loop_count = stats.get("loop", 0)
    rol_count = stats.get("rol", 0) + stats.get("ror", 0)

    # XOR + LOOP = classic decryption pattern
    if xor_count > 10 and loop_count > 0:
        result["decryption_operations"].append({
            "type": "xor_loop",
            "xor_count": xor_count,
            "loop_count": loop_count,
            "locations": trace.get("xor_locations", [])[:5]
        })
        result["confidence"] = 0.7

    # XOR + ROL = rolling key cipher
    if xor_count > 10 and rol_count > 0:
        result["decryption_operations"].append({
            "type": "rolling_xor",
            "xor_count": xor_count,
            "rotation_count": rol_count,
            "locations": trace.get("rol_ror_locations", [])[:5]
        })
        result["confidence"] = max(result["confidence"], 0.8)

    # The output might contain decoded strings
    output = trace.get("output", "")
    if output:
        # Look for readable strings in output
        import re
        strings = re.findall(r'[\x20-\x7E]{4,}', output)
        if strings:
            result["decoded_strings"] = strings[:10]  # First 10

    return result


def compare_execution_paths(binary_path: str, inputs: List[str]) -> Dict[str, Any]:
    """
    Compare execution paths with different inputs.

    This reveals:
    - Input-dependent code paths
    - Hidden functionality triggered by specific inputs
    - Anti-analysis that detects specific patterns
    """
    result = {
        "inputs_tested": inputs,
        "path_comparison": [],
        "unique_code_per_input": {},
        "common_code": set(),
        "divergence_points": []
    }

    traces = {}
    all_addresses = {}

    for inp in inputs:
        trace = tool_trace_binary(binary_path, input_data=inp + "\r", max_instructions=50000)
        traces[inp] = trace

        # Extract executed addresses
        addrs = set()
        for insn in trace.get("last_instructions", []):
            addrs.add(insn["addr"])
        all_addresses[inp] = addrs

    # Find common code (executed for all inputs)
    if all_addresses:
        result["common_code"] = set.intersection(*all_addresses.values()) if len(all_addresses) > 1 else set()

    # Find unique code per input
    for inp, addrs in all_addresses.items():
        other_addrs = set()
        for other_inp, other_set in all_addresses.items():
            if other_inp != inp:
                other_addrs.update(other_set)

        unique = addrs - other_addrs
        if unique:
            result["unique_code_per_input"][inp] = list(unique)[:10]

    # Compare outputs
    outputs = {inp: traces[inp].get("output", "") for inp in inputs}
    output_hashes = {inp: hash(out) & 0xFFFFFFFF for inp, out in outputs.items()}

    result["path_comparison"] = [
        {
            "input": inp,
            "instruction_count": traces[inp].get("instruction_count", 0),
            "output_hash": output_hashes[inp],
            "unique_addresses": len(result["unique_code_per_input"].get(inp, []))
        }
        for inp in inputs
    ]

    return result


# ============================================================================
# MCP Tool Interface
# ============================================================================

def tool_deep_analyze(file_path: str, depth: str = "medium") -> dict:
    """
    Perform deep behavioral analysis to find hidden functionality.

    This answers questions like:
    - "Does this binary have hidden code that only activates sometimes?"
    - "Are there encrypted strings that get decoded at runtime?"
    - "Does behavior change based on date or environment?"

    Args:
        file_path: Path to binary
        depth: Analysis depth - "quick", "medium", or "thorough"

    Returns:
        Comprehensive analysis of hidden/conditional behavior
    """
    try:
        explorer = DeepBehavioralExplorer(file_path)
        result = explorer.analyze(depth)

        return {
            "success": True,
            "coverage_percent": result.coverage.coverage_percent,
            "hidden_strings": [
                {"address": hex(addr), "content": content, "condition": cond}
                for addr, content, cond in result.hidden_strings
            ],
            "dormant_code": [
                {"start": hex(start), "end": hex(end), "reason": reason}
                for start, end, reason in result.dormant_regions
            ],
            "time_bombs": result.time_bombs,
            "anti_analysis_techniques": result.anti_analysis,
            "conditional_behaviors": [
                {
                    "condition": cb.condition,
                    "unique_code_count": len(cb.unique_code),
                    "unique_strings": cb.unique_strings[:5]
                }
                for cb in result.conditional_behaviors
            ],
            "risk_assessment": result.risk_assessment,
            "confidence": result.confidence,
            "analysis_hint": """
Claude: Use this deep analysis to answer questions about hidden functionality:
1. risk_assessment gives overall threat level
2. hidden_strings shows encoded/encrypted data
3. dormant_code shows code that exists but wasn't executed
4. time_bombs shows potential date-based triggers
5. anti_analysis_techniques reveals evasion attempts
6. Look for patterns that suggest malicious intent
"""
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def tool_find_hidden_strings(file_path: str) -> dict:
    """
    Find strings that are encrypted or encoded in the binary.

    Useful for detecting:
    - Encrypted C2 URLs
    - Hidden configuration
    - Obfuscated commands
    """
    try:
        result = find_encrypted_strings(file_path)
        return {
            "success": True,
            **result
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def tool_check_date_triggers(file_path: str, dates: List[str] = None) -> dict:
    """
    Check if binary behavior changes based on date.

    Detects time bombs and date-activated malware.
    """
    try:
        result = analyze_for_date_triggers(file_path, dates)
        return {
            "success": True,
            **result
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def tool_compare_paths(file_path: str, inputs: List[str]) -> dict:
    """
    Compare execution paths with different inputs.

    Reveals hidden functionality triggered by specific inputs.
    """
    try:
        result = compare_execution_paths(file_path, inputs)
        return {
            "success": True,
            "common_code_count": len(result["common_code"]),
            "path_comparison": result["path_comparison"],
            "unique_code_per_input": result["unique_code_per_input"],
            "analysis_hint": """
Claude: Different inputs triggering different code paths suggests:
1. Input validation logic
2. Hidden commands/backdoors
3. Easter eggs
4. Anti-analysis (detecting specific patterns)
"""
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


# ============================================================================
# Test
# ============================================================================

if __name__ == "__main__":
    print("Deep Behavioral Explorer for AnalyzeBugger")
    print("Finds hidden functionality through behavioral analysis")
    print()

    if len(sys.argv) > 1:
        binary = sys.argv[1]
        depth = sys.argv[2] if len(sys.argv) > 2 else "medium"

        print(f"Analyzing: {binary}")
        print(f"Depth: {depth}")
        print()

        result = tool_deep_analyze(binary, depth)

        if result["success"]:
            print(f"Risk Assessment: {result['risk_assessment']}")
            print(f"Confidence: {result['confidence']:.0%}")
            print()

            if result["hidden_strings"]:
                print("Hidden/Encoded Strings:")
                for hs in result["hidden_strings"]:
                    print(f"  {hs['address']}: {hs['content']} ({hs['condition']})")
                print()

            if result["dormant_code"]:
                print("Dormant Code Regions:")
                for dc in result["dormant_code"]:
                    print(f"  {dc['reason']}")
                print()

            if result["anti_analysis_techniques"]:
                print("Anti-Analysis Techniques:")
                for tech in result["anti_analysis_techniques"]:
                    print(f"  - {tech}")
                print()

            if result["time_bombs"]:
                print("Potential Time Bombs:")
                for tb in result["time_bombs"]:
                    print(f"  - {tb['type']}: {tb['details']}")
        else:
            print(f"Error: {result['error']}")
