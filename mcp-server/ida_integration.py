"""
IDA Pro Integration for AnalyzeBugger

Provides headless IDA Pro 9.0 access via library mode (idapro module).

Capabilities:
- Static analysis (disassembly, functions, strings, xrefs)
- Hex-Rays decompilation
- FLIRT signature matching
- Debugger tracing for unpacking

This is THE heavy artillery. When Claude needs deep analysis,
IDA Pro provides ground truth.
"""

import os
import sys
import json
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from pathlib import Path

# ============================================================================
# IDA Pro Detection
# ============================================================================

IDA_PATHS = [
    r"C:\Program Files\IDA Professional 9.0",
    r"C:\Program Files\IDA Pro 9.0",
    r"C:\Program Files (x86)\IDA Professional 9.0",
]

def find_ida_installation() -> Optional[str]:
    """Find IDA Pro installation directory"""
    for path in IDA_PATHS:
        if os.path.isdir(path):
            return path

    # Check environment variable
    ida_dir = os.environ.get('IDADIR')
    if ida_dir and os.path.isdir(ida_dir):
        return ida_dir

    return None

IDA_DIR = find_ida_installation()

# ============================================================================
# IDA Library Mode Wrapper
# ============================================================================

class IDASession:
    """
    Wrapper for IDA Pro library mode session.

    Usage:
        with IDASession("binary.exe") as ida:
            funcs = ida.get_functions()
            decomp = ida.decompile(0x401000)
    """

    def __init__(self, binary_path: str, auto_analysis: bool = True):
        self.binary_path = os.path.abspath(binary_path)
        self.auto_analysis = auto_analysis
        self.is_open = False
        self._ida_modules_imported = False

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _import_ida_modules(self):
        """Import IDA modules (must be done after idapro.open_database)"""
        if self._ida_modules_imported:
            return

        global ida_funcs, ida_segment, ida_bytes, ida_name, ida_hexrays
        global ida_lines, ida_ua, idautils, ida_idaapi, ida_ida, ida_dbg

        import ida_funcs
        import ida_segment
        import ida_bytes
        import ida_name
        import ida_hexrays
        import ida_lines
        import ida_ua
        import idautils
        import ida_idaapi
        import ida_ida
        import ida_dbg

        self._ida_modules_imported = True

    def open(self):
        """Open database for the binary"""
        if self.is_open:
            return

        try:
            import idapro
            idapro.open_database(self.binary_path, self.auto_analysis)
            self._import_ida_modules()
            self.is_open = True
        except ImportError:
            raise RuntimeError(
                "idapro module not available. "
                "Ensure IDA Pro 9.0 is installed and IDADIR is set."
            )
        except Exception as e:
            raise RuntimeError(f"Failed to open database: {e}")

    def close(self):
        """Close the database"""
        if not self.is_open:
            return

        try:
            import idapro
            idapro.close_database()
            self.is_open = False
        except:
            pass

    # -------------------------------------------------------------------------
    # Analysis Functions
    # -------------------------------------------------------------------------

    def get_entry_point(self) -> int:
        """Get the program entry point"""
        self._require_open()
        return ida_ida.inf_get_start_ip()

    def get_functions(self) -> List[Dict[str, Any]]:
        """Get all functions in the database"""
        self._require_open()

        functions = []
        for ea in idautils.Functions():
            func = ida_funcs.get_func(ea)
            if func:
                name = ida_name.get_name(ea) or f"sub_{ea:X}"
                functions.append({
                    'address': ea,
                    'name': name,
                    'size': func.size(),
                    'start': func.start_ea,
                    'end': func.end_ea,
                })
        return functions

    def get_function_at(self, address: int) -> Optional[Dict[str, Any]]:
        """Get function containing address"""
        self._require_open()

        func = ida_funcs.get_func(address)
        if not func:
            return None

        name = ida_name.get_name(func.start_ea) or f"sub_{func.start_ea:X}"
        return {
            'address': func.start_ea,
            'name': name,
            'size': func.size(),
            'start': func.start_ea,
            'end': func.end_ea,
        }

    def get_disassembly(self, start: int, count: int = 50) -> List[Dict[str, Any]]:
        """Get disassembly lines starting at address"""
        self._require_open()

        lines = []
        ea = start

        for _ in range(count):
            if ea == ida_idaapi.BADADDR:
                break

            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, ea)

            if length <= 0:
                # Not an instruction, try next byte
                ea += 1
                continue

            # Get disassembly text
            disasm = ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_REMOVE_TAGS)

            # Get bytes
            insn_bytes = ida_bytes.get_bytes(ea, length)

            lines.append({
                'address': ea,
                'bytes': insn_bytes.hex() if insn_bytes else '',
                'disasm': disasm,
                'mnemonic': insn.get_canon_mnem(),
                'size': length,
            })

            ea += length

        return lines

    def get_strings(self, min_length: int = 4) -> List[Dict[str, Any]]:
        """Get all strings in the database"""
        self._require_open()

        strings = []
        for s in idautils.Strings():
            if s.length >= min_length:
                strings.append({
                    'address': s.ea,
                    'value': str(s),
                    'length': s.length,
                    'type': s.strtype,
                })
        return strings

    def get_imports(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all imports grouped by DLL"""
        self._require_open()

        imports = {}

        # IDA 9.0 uses ida_nalt for import enumeration
        try:
            import ida_nalt

            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                dll_name = ida_nalt.get_import_module_name(i)
                if not dll_name:
                    continue

                imports[dll_name] = []

                def imp_cb(ea, name, ordinal):
                    imports[dll_name].append({
                        'address': ea,
                        'name': name or f"ord_{ordinal}",
                        'ordinal': ordinal,
                    })
                    return True

                ida_nalt.enum_import_names(i, imp_cb)
        except Exception as e:
            # Fallback: no imports for this file type (e.g., COM files)
            pass

        return imports

    def get_exports(self) -> List[Dict[str, Any]]:
        """Get all exports"""
        self._require_open()

        exports = []
        try:
            # IDA 9.0 uses ida_entry for exports
            import ida_entry

            for i in range(ida_entry.get_entry_qty()):
                ordinal = ida_entry.get_entry_ordinal(i)
                ea = ida_entry.get_entry(ordinal)
                name = ida_entry.get_entry_name(ordinal) or f"export_{ordinal}"
                exports.append({
                    'address': ea,
                    'name': name,
                    'ordinal': ordinal,
                })
        except Exception as e:
            # Fallback: no exports for this file type (e.g., COM files)
            pass

        return exports

    def get_segments(self) -> List[Dict[str, Any]]:
        """Get all segments"""
        self._require_open()

        segments = []
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg:
                segments.append({
                    'start': seg.start_ea,
                    'end': seg.end_ea,
                    'name': ida_segment.get_segm_name(seg),
                    'size': seg.size(),
                    'perm': seg.perm,
                })
        return segments

    def get_xrefs_to(self, address: int) -> List[Dict[str, Any]]:
        """Get cross-references TO an address"""
        self._require_open()

        xrefs = []
        for xref in idautils.XrefsTo(address):
            xrefs.append({
                'from': xref.frm,
                'to': xref.to,
                'type': xref.type,
            })
        return xrefs

    def get_xrefs_from(self, address: int) -> List[Dict[str, Any]]:
        """Get cross-references FROM an address"""
        self._require_open()

        xrefs = []
        for xref in idautils.XrefsFrom(address):
            xrefs.append({
                'from': xref.frm,
                'to': xref.to,
                'type': xref.type,
            })
        return xrefs

    def read_bytes(self, address: int, size: int) -> bytes:
        """Read bytes from the database"""
        self._require_open()
        return ida_bytes.get_bytes(address, size) or b''

    # -------------------------------------------------------------------------
    # Hex-Rays Decompilation
    # -------------------------------------------------------------------------

    def decompile(self, address: int) -> Optional[str]:
        """Decompile function at address using Hex-Rays"""
        self._require_open()

        if not ida_hexrays.init_hexrays_plugin():
            return None  # Hex-Rays not available

        func = ida_funcs.get_func(address)
        if not func:
            return None

        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if cfunc:
                return str(cfunc)
        except ida_hexrays.DecompilationFailure:
            pass

        return None

    def decompile_all(self) -> Dict[int, str]:
        """Decompile all functions"""
        self._require_open()

        if not ida_hexrays.init_hexrays_plugin():
            return {}

        results = {}
        for ea in idautils.Functions():
            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    results[ea] = str(cfunc)
            except:
                pass

        return results

    # -------------------------------------------------------------------------
    # FLIRT Signatures
    # -------------------------------------------------------------------------

    def apply_flirt_signature(self, sig_name: str) -> bool:
        """Apply a FLIRT signature file"""
        self._require_open()

        try:
            ida_funcs.plan_to_apply_idasgn(sig_name)
            return True
        except:
            return False

    def get_available_signatures(self) -> List[str]:
        """List available FLIRT signatures"""
        self._require_open()

        sig_dir = os.path.join(IDA_DIR, "sig") if IDA_DIR else None
        if not sig_dir or not os.path.isdir(sig_dir):
            return []

        return [f[:-4] for f in os.listdir(sig_dir) if f.endswith('.sig')]

    # -------------------------------------------------------------------------
    # Debugger Integration (for unpacking)
    # -------------------------------------------------------------------------

    def trace_to_oep(self, max_instructions: int = 100000) -> List[Dict[str, Any]]:
        """
        Trace execution to find OEP.

        Uses IDA's debugger to single-step and record trace.
        This is the core of the AI unpacker's TRACE stage.
        """
        self._require_open()

        # Load appropriate debugger
        file_type = ida_ida.inf_get_filetype()
        if file_type == ida_ida.f_PE:
            ida_dbg.load_debugger("win32", 0)
        elif file_type == ida_ida.f_ELF:
            ida_dbg.load_debugger("linux", 0)
        else:
            # For COM files, use DOS debugger if available
            # Or emulation via Bochs
            pass

        traces = []
        # TODO: Implement actual tracing
        # This would use DBG_Hooks similar to automatic_steps.py

        return traces

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _require_open(self):
        """Ensure database is open"""
        if not self.is_open:
            raise RuntimeError("Database not open. Call open() first.")


# ============================================================================
# MCP Tool Wrappers
# ============================================================================

def tool_ida_analyze(file_path: str) -> dict:
    """
    Analyze a binary with IDA Pro.

    Returns comprehensive analysis including:
    - Entry point
    - Functions
    - Strings
    - Imports/Exports
    - Segments
    """
    try:
        with IDASession(file_path) as ida:
            return {
                'success': True,
                'entry_point': ida.get_entry_point(),
                'functions': ida.get_functions(),
                'strings': ida.get_strings(),
                'imports': ida.get_imports(),
                'exports': ida.get_exports(),
                'segments': ida.get_segments(),
            }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
        }


def tool_ida_disassemble(file_path: str, address: int, count: int = 50) -> dict:
    """Get disassembly at address"""
    try:
        with IDASession(file_path) as ida:
            return {
                'success': True,
                'disassembly': ida.get_disassembly(address, count),
            }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
        }


def tool_ida_decompile(file_path: str, address: int) -> dict:
    """Decompile function at address"""
    try:
        with IDASession(file_path) as ida:
            code = ida.decompile(address)
            if code:
                return {
                    'success': True,
                    'pseudocode': code,
                }
            else:
                return {
                    'success': False,
                    'error': 'Decompilation failed (Hex-Rays unavailable or invalid function)',
                }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
        }


def tool_ida_xrefs(file_path: str, address: int, direction: str = "to") -> dict:
    """Get cross-references to/from address"""
    try:
        with IDASession(file_path) as ida:
            if direction == "to":
                xrefs = ida.get_xrefs_to(address)
            else:
                xrefs = ida.get_xrefs_from(address)

            return {
                'success': True,
                'xrefs': xrefs,
            }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
        }


# ============================================================================
# Test
# ============================================================================

if __name__ == "__main__":
    print("IDA Pro Integration for AnalyzeBugger")
    print(f"IDA Installation: {IDA_DIR or 'NOT FOUND'}")

    if len(sys.argv) > 1:
        binary = sys.argv[1]
        print(f"\nAnalyzing: {binary}")

        result = tool_ida_analyze(binary)
        if result['success']:
            print(f"  Entry Point: 0x{result['entry_point']:X}")
            print(f"  Functions: {len(result['functions'])}")
            print(f"  Strings: {len(result['strings'])}")
            print(f"  Segments: {len(result['segments'])}")
        else:
            print(f"  Error: {result['error']}")
