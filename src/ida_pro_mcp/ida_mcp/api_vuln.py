"""IDA Pro MCP Vulnerability Scanner

This module provides vulnerability scanning capabilities for binary analysis.
It identifies potentially dangerous function calls and categorizes them by
vulnerability type for AI-assisted analysis.

Key features:
- Identifies dangerous functions (format string, buffer overflow, command injection, etc.)
- Checks if dangerous parameters are controllable (non-constant)
- Saves detailed results to project folder to minimize token usage
- Returns a summary directory for AI to select areas for deep analysis
"""

import os
import json
import time
from datetime import datetime
from typing import Annotated, Optional
from dataclasses import dataclass, field, asdict

import idaapi
import idautils
import ida_funcs
import ida_name
import ida_bytes
import ida_xref
import ida_typeinf
import ida_nalt
import idc

from .rpc import tool
from .sync import idasync
from .utils import parse_address, get_function


# ============================================================================
# Vulnerability Categories and Dangerous Functions
# ============================================================================

# Dangerous function definitions with parameter indices that should be checked
# Format: {function_name: {"category": str, "dangerous_params": [indices], "description": str}}
DANGEROUS_FUNCTIONS = {
    # Format String Vulnerabilities - param[0] is format string
    "printf": {"category": "Format String", "dangerous_params": [0], "desc": "Format string in arg0"},
    "printk": {"category": "Format String", "dangerous_params": [0], "desc": "Format string in arg0"},
    "vprintf": {"category": "Format String", "dangerous_params": [0], "desc": "Format string in arg0"},
    "wprintf": {"category": "Format String", "dangerous_params": [0], "desc": "Format string in arg0"},
    "NSLog": {"category": "Format String", "dangerous_params": [0], "desc": "Format string in arg0"},
    
    # Format String - param[1] is format string
    "fprintf": {"category": "Format String", "dangerous_params": [1], "desc": "Format string in arg1"},
    "sprintf": {"category": "Format String", "dangerous_params": [1], "desc": "Format string in arg1"},
    "vsprintf": {"category": "Format String", "dangerous_params": [1], "desc": "Format string in arg1"},
    "asprintf": {"category": "Format String", "dangerous_params": [1], "desc": "Format string in arg1"},
    "dprintf": {"category": "Format String", "dangerous_params": [1], "desc": "Format string in arg1"},
    "sscanf": {"category": "Format String", "dangerous_params": [1], "desc": "Format string in arg1"},
    "fscanf": {"category": "Format String", "dangerous_params": [1], "desc": "Format string in arg1"},
    
    # Format String - param[2] is format string
    "snprintf": {"category": "Format String", "dangerous_params": [2], "desc": "Format string in arg2"},
    "vsnprintf": {"category": "Format String", "dangerous_params": [2], "desc": "Format string in arg2"},
    "swprintf": {"category": "Format String", "dangerous_params": [2], "desc": "Format string in arg2"},
    
    # Buffer Overflow - strcpy family (source in param[1])
    "strcpy": {"category": "Buffer Overflow", "dangerous_params": [1], "desc": "Unbounded copy from arg1"},
    "wcscpy": {"category": "Buffer Overflow", "dangerous_params": [1], "desc": "Unbounded copy from arg1"},
    "lstrcpy": {"category": "Buffer Overflow", "dangerous_params": [1], "desc": "Unbounded copy from arg1"},
    "lstrcpyA": {"category": "Buffer Overflow", "dangerous_params": [1], "desc": "Unbounded copy from arg1"},
    "lstrcpyW": {"category": "Buffer Overflow", "dangerous_params": [1], "desc": "Unbounded copy from arg1"},
    "strcat": {"category": "Buffer Overflow", "dangerous_params": [1], "desc": "Unbounded concat from arg1"},
    "wcscat": {"category": "Buffer Overflow", "dangerous_params": [1], "desc": "Unbounded concat from arg1"},
    "lstrcat": {"category": "Buffer Overflow", "dangerous_params": [1], "desc": "Unbounded concat from arg1"},
    
    # Buffer Overflow - size controlled (size in param[2])
    "strncpy": {"category": "Buffer Overflow", "dangerous_params": [2], "desc": "Size in arg2 may be controllable"},
    "strncat": {"category": "Buffer Overflow", "dangerous_params": [2], "desc": "Size in arg2 may be controllable"},
    "memcpy": {"category": "Buffer Overflow", "dangerous_params": [2], "desc": "Size in arg2 may be controllable"},
    "memmove": {"category": "Buffer Overflow", "dangerous_params": [2], "desc": "Size in arg2 may be controllable"},
    "wmemcpy": {"category": "Buffer Overflow", "dangerous_params": [2], "desc": "Size in arg2 may be controllable"},
    "bcopy": {"category": "Buffer Overflow", "dangerous_params": [2], "desc": "Size in arg2 may be controllable"},
    
    # Buffer Overflow - gets (always dangerous)
    "gets": {"category": "Buffer Overflow", "dangerous_params": [], "desc": "Always dangerous - no bounds checking"},
    
    # Command Injection
    "system": {"category": "Command Injection", "dangerous_params": [0], "desc": "Command in arg0"},
    "popen": {"category": "Command Injection", "dangerous_params": [0], "desc": "Command in arg0"},
    "execl": {"category": "Command Injection", "dangerous_params": [0], "desc": "Path in arg0"},
    "execlp": {"category": "Command Injection", "dangerous_params": [0], "desc": "File in arg0"},
    "execle": {"category": "Command Injection", "dangerous_params": [0], "desc": "Path in arg0"},
    "execv": {"category": "Command Injection", "dangerous_params": [0], "desc": "Path in arg0"},
    "execvp": {"category": "Command Injection", "dangerous_params": [0], "desc": "File in arg0"},
    "execve": {"category": "Command Injection", "dangerous_params": [0], "desc": "Path in arg0"},
    "ShellExecute": {"category": "Command Injection", "dangerous_params": [2, 3], "desc": "File/params in arg2,3"},
    "ShellExecuteA": {"category": "Command Injection", "dangerous_params": [2, 3], "desc": "File/params in arg2,3"},
    "ShellExecuteW": {"category": "Command Injection", "dangerous_params": [2, 3], "desc": "File/params in arg2,3"},
    "WinExec": {"category": "Command Injection", "dangerous_params": [0], "desc": "Command in arg0"},
    "CreateProcess": {"category": "Command Injection", "dangerous_params": [0, 1], "desc": "App/cmdline in arg0,1"},
    "CreateProcessA": {"category": "Command Injection", "dangerous_params": [0, 1], "desc": "App/cmdline in arg0,1"},
    "CreateProcessW": {"category": "Command Injection", "dangerous_params": [0, 1], "desc": "App/cmdline in arg0,1"},
    
    # Integer Overflow
    "malloc": {"category": "Integer Overflow", "dangerous_params": [0], "desc": "Size in arg0 may overflow"},
    "calloc": {"category": "Integer Overflow", "dangerous_params": [0, 1], "desc": "Count*size may overflow"},
    "realloc": {"category": "Integer Overflow", "dangerous_params": [1], "desc": "Size in arg1 may overflow"},
    "alloca": {"category": "Integer Overflow", "dangerous_params": [0], "desc": "Size in arg0 may overflow"},
    
    # Use After Free / Double Free
    "free": {"category": "Use After Free", "dangerous_params": [0], "desc": "Pointer in arg0 - check for UAF/double-free"},
    
    # Path Traversal
    "fopen": {"category": "Path Traversal", "dangerous_params": [0], "desc": "Path in arg0"},
    "open": {"category": "Path Traversal", "dangerous_params": [0], "desc": "Path in arg0"},
    "openat": {"category": "Path Traversal", "dangerous_params": [1], "desc": "Path in arg1"},
    "access": {"category": "Path Traversal", "dangerous_params": [0], "desc": "Path in arg0"},
    "stat": {"category": "Path Traversal", "dangerous_params": [0], "desc": "Path in arg0"},
    "lstat": {"category": "Path Traversal", "dangerous_params": [0], "desc": "Path in arg0"},
    "readlink": {"category": "Path Traversal", "dangerous_params": [0], "desc": "Path in arg0"},
    "unlink": {"category": "Path Traversal", "dangerous_params": [0], "desc": "Path in arg0"},
    "rename": {"category": "Path Traversal", "dangerous_params": [0, 1], "desc": "Paths in arg0,1"},
    "mkdir": {"category": "Path Traversal", "dangerous_params": [0], "desc": "Path in arg0"},
    "rmdir": {"category": "Path Traversal", "dangerous_params": [0], "desc": "Path in arg0"},
    "chdir": {"category": "Path Traversal", "dangerous_params": [0], "desc": "Path in arg0"},
    
    # Race Condition (TOCTOU)
    "access": {"category": "Race Condition", "dangerous_params": [0], "desc": "TOCTOU if followed by open"},
    
    # Dangerous Read/Write
    "read": {"category": "Buffer Overflow", "dangerous_params": [2], "desc": "Size in arg2 may be controllable"},
    "write": {"category": "Information Leak", "dangerous_params": [2], "desc": "Size in arg2 may leak data"},
    "recv": {"category": "Buffer Overflow", "dangerous_params": [2], "desc": "Size in arg2 may be controllable"},
    "recvfrom": {"category": "Buffer Overflow", "dangerous_params": [2], "desc": "Size in arg2 may be controllable"},
    "send": {"category": "Information Leak", "dangerous_params": [2], "desc": "Size in arg2 may leak data"},
    
    # SQL Injection (if using embedded SQL)
    "sqlite3_exec": {"category": "SQL Injection", "dangerous_params": [1], "desc": "SQL in arg1"},
    "mysql_query": {"category": "SQL Injection", "dangerous_params": [1], "desc": "SQL in arg1"},
    "mysql_real_query": {"category": "SQL Injection", "dangerous_params": [1], "desc": "SQL in arg1"},
}


@dataclass
class VulnerabilityFinding:
    """Represents a single vulnerability finding"""
    category: str
    function_name: str  # The dangerous function being called
    caller_name: str    # The function containing the call
    caller_addr: str    # Address of the caller function
    call_addr: str      # Address of the call instruction
    dangerous_params: list[int]  # Which parameters are dangerous
    param_info: list[dict]  # Info about each parameter
    risk_level: str     # "High", "Medium", "Low"
    description: str
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResults:
    """Container for all scan results"""
    binary_name: str
    binary_path: str
    scan_time: str
    total_findings: int
    findings_by_category: dict[str, list[dict]] = field(default_factory=dict)
    summary: dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return asdict(self)


def _is_constant_operand(ea: int, op_index: int) -> bool:
    """Check if an operand at the given address is a constant value"""
    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, ea) == 0:
        return False
    
    if op_index >= len(insn.ops):
        return False
    
    op = insn.ops[op_index]
    # o_imm = immediate value, o_void = no operand
    return op.type in (idaapi.o_imm, idaapi.o_void)


def _get_param_info(call_ea: int, param_indices: list[int]) -> list[dict]:
    """Get information about function call parameters
    
    This is a simplified version - we check if parameters appear to be
    constants or variables. Full data flow analysis would require more
    sophisticated techniques.
    """
    params = []
    
    # Try to use Hex-Rays if available
    try:
        import ida_hexrays
        cfunc = ida_hexrays.decompile(call_ea)
        if cfunc:
            # Find the call in the decompiled code
            class CallFinder(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.call_args = None
                    self.target_ea = call_ea
                
                def visit_expr(self, expr):
                    if expr.op == ida_hexrays.cot_call and expr.ea == self.target_ea:
                        self.call_args = expr.a
                        return 1  # Stop
                    return 0
            
            finder = CallFinder()
            finder.apply_to(cfunc.body, None)
            
            if finder.call_args:
                for i, idx in enumerate(param_indices):
                    if idx < len(finder.call_args):
                        arg = finder.call_args[idx]
                        is_const = arg.op in (ida_hexrays.cot_num, ida_hexrays.cot_str, ida_hexrays.cot_obj)
                        params.append({
                            "index": idx,
                            "is_constant": is_const,
                            "type": "decompiled"
                        })
                    else:
                        params.append({
                            "index": idx,
                            "is_constant": None,
                            "type": "out_of_range"
                        })
                return params
    except:
        pass
    
    # Fallback: simple heuristic based on disassembly
    for idx in param_indices:
        params.append({
            "index": idx,
            "is_constant": None,  # Unknown without decompiler
            "type": "disasm_only"
        })
    
    return params


def _determine_risk_level(func_info: dict, param_info: list[dict]) -> str:
    """Determine risk level based on function and parameter analysis"""
    # gets() is always high risk
    if not func_info.get("dangerous_params"):
        return "High"
    
    # Check if any dangerous parameter is non-constant
    has_non_constant = False
    has_unknown = False
    
    for p in param_info:
        if p.get("is_constant") is False:
            has_non_constant = True
        elif p.get("is_constant") is None:
            has_unknown = True
    
    if has_non_constant:
        return "High"
    elif has_unknown:
        return "Medium"
    else:
        return "Low"


def _scan_for_dangerous_calls() -> list[VulnerabilityFinding]:
    """Scan the binary for calls to dangerous functions"""
    findings = []
    
    # Build a map of function names to their addresses
    func_name_to_ea = {}
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea)
        if name:
            # Normalize name (remove leading underscore, case insensitive)
            normalized = name.lstrip('_').lower()
            func_name_to_ea[normalized] = ea
            # Also store original name
            func_name_to_ea[name.lower()] = ea
    
    # Also check imports
    for i in range(ida_nalt.get_import_module_qty()):
        def imp_cb(ea, name, ordinal):
            if name:
                normalized = name.lstrip('_').lower()
                func_name_to_ea[normalized] = ea
                func_name_to_ea[name.lower()] = ea
            return True
        ida_nalt.enum_import_names(i, imp_cb)
    
    # Find all calls to dangerous functions
    for func_name, func_info in DANGEROUS_FUNCTIONS.items():
        normalized_name = func_name.lower()
        
        # Check if this function exists in the binary
        target_ea = func_name_to_ea.get(normalized_name)
        if target_ea is None:
            # Try with underscore prefix
            target_ea = func_name_to_ea.get('_' + normalized_name)
        
        if target_ea is None:
            continue
        
        # Find all cross-references to this function
        for xref in idautils.XrefsTo(target_ea, 0):
            if not xref.iscode:
                continue
            
            call_ea = xref.frm
            
            # Get the caller function
            caller_func = idaapi.get_func(call_ea)
            if not caller_func:
                continue
            
            caller_name = ida_funcs.get_func_name(caller_func.start_ea) or f"sub_{caller_func.start_ea:x}"
            
            # Get parameter info
            param_info = _get_param_info(call_ea, func_info["dangerous_params"])
            
            # Determine risk level
            risk_level = _determine_risk_level(func_info, param_info)
            
            finding = VulnerabilityFinding(
                category=func_info["category"],
                function_name=func_name,
                caller_name=caller_name,
                caller_addr=hex(caller_func.start_ea),
                call_addr=hex(call_ea),
                dangerous_params=func_info["dangerous_params"],
                param_info=param_info,
                risk_level=risk_level,
                description=func_info["desc"]
            )
            findings.append(finding)
    
    return findings


def _save_results_to_file(results: ScanResults, output_dir: str) -> str:
    """Save detailed scan results to a JSON file"""
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"vulnscan_{results.binary_name}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(results.to_dict(), f, indent=2, ensure_ascii=False)
    
    return filepath


# ============================================================================
# MCP Tool Interface
# ============================================================================


@tool
@idasync
def vuln_scan(
    output_dir: Annotated[Optional[str], "Directory to save detailed results (default: .ida-mcp-vuln)"] = None,
    categories: Annotated[Optional[list[str]], "Filter by categories (default: all)"] = None,
    min_risk: Annotated[str, "Minimum risk level: High, Medium, or Low (default: Low)"] = "Low",
) -> dict:
    """Scan binary for potential vulnerabilities by identifying dangerous function calls
    
    This tool identifies calls to dangerous functions (format string, buffer overflow,
    command injection, etc.) and checks if the dangerous parameters are controllable.
    
    The detailed results are saved to a file to minimize token usage. This tool returns
    a summary directory that can be used to select specific vulnerability categories
    for deeper AI-assisted analysis.
    
    Workflow:
    1. Call vuln_scan() to get the summary
    2. Review the categories and counts
    3. Use vuln_scan_details(category) to get findings for a specific category
    4. Use decompile() and other tools to analyze specific functions
    
    Returns:
        Summary with categories, counts, and path to detailed results file
    """
    # Get binary info
    binary_path = idc.get_input_file_path()
    binary_name = os.path.basename(binary_path) if binary_path else "unknown"
    
    # Set output directory
    if output_dir is None:
        # Use directory relative to IDB
        idb_path = idc.get_idb_path()
        if idb_path:
            output_dir = os.path.join(os.path.dirname(idb_path), ".ida-mcp-vuln")
        else:
            output_dir = ".ida-mcp-vuln"
    
    # Risk level filter
    risk_levels = {"High": 3, "Medium": 2, "Low": 1}
    min_risk_value = risk_levels.get(min_risk, 1)
    
    # Perform scan
    all_findings = _scan_for_dangerous_calls()
    
    # Filter by risk level
    filtered_findings = [
        f for f in all_findings
        if risk_levels.get(f.risk_level, 0) >= min_risk_value
    ]
    
    # Filter by categories if specified
    if categories:
        categories_lower = [c.lower() for c in categories]
        filtered_findings = [
            f for f in filtered_findings
            if f.category.lower() in categories_lower
        ]
    
    # Group by category
    findings_by_category: dict[str, list[dict]] = {}
    for finding in filtered_findings:
        cat = finding.category
        if cat not in findings_by_category:
            findings_by_category[cat] = []
        findings_by_category[cat].append(finding.to_dict())
    
    # Create summary
    summary = {cat: len(findings) for cat, findings in findings_by_category.items()}
    
    # Create results object
    results = ScanResults(
        binary_name=binary_name,
        binary_path=binary_path or "",
        scan_time=datetime.now().isoformat(),
        total_findings=len(filtered_findings),
        findings_by_category=findings_by_category,
        summary=summary
    )
    
    # Save detailed results
    results_file = _save_results_to_file(results, output_dir)
    
    # Return summary (not full details to save tokens)
    return {
        "status": "completed",
        "binary_name": binary_name,
        "total_findings": len(filtered_findings),
        "summary_by_category": summary,
        "categories": list(findings_by_category.keys()),
        "risk_filter": min_risk,
        "results_file": results_file,
        "hint": "Use vuln_scan_details(category) to get detailed findings for a specific category, or read the results file directly."
    }


@tool
@idasync
def vuln_scan_details(
    category: Annotated[str, "Vulnerability category to get details for"],
    limit: Annotated[int, "Maximum number of findings to return (default: 20)"] = 20,
    offset: Annotated[int, "Skip first N findings (default: 0)"] = 0,
    risk_level: Annotated[Optional[str], "Filter by risk level: High, Medium, Low"] = None,
) -> dict:
    """Get detailed findings for a specific vulnerability category
    
    After running vuln_scan(), use this tool to get detailed information about
    findings in a specific category. This allows for targeted analysis without
    overwhelming the context with all findings at once.
    
    Args:
        category: The vulnerability category (e.g., "Format String", "Buffer Overflow")
        limit: Maximum findings to return
        offset: Skip first N findings for pagination
        risk_level: Optional filter by risk level
    
    Returns:
        Detailed findings including caller function, call address, and parameter info
    """
    # Get binary info
    binary_path = idc.get_input_file_path()
    binary_name = os.path.basename(binary_path) if binary_path else "unknown"
    
    # Perform scan (or could cache results)
    all_findings = _scan_for_dangerous_calls()
    
    # Filter by category
    category_lower = category.lower()
    filtered = [f for f in all_findings if f.category.lower() == category_lower]
    
    # Filter by risk level if specified
    if risk_level:
        filtered = [f for f in filtered if f.risk_level.lower() == risk_level.lower()]
    
    # Apply pagination
    total = len(filtered)
    paginated = filtered[offset:offset + limit]
    
    # Convert to dicts
    findings_list = [f.to_dict() for f in paginated]
    
    return {
        "category": category,
        "total_in_category": total,
        "returned": len(findings_list),
        "offset": offset,
        "findings": findings_list,
        "cursor": {"next": offset + limit} if offset + limit < total else {"done": True},
        "hint": "Use decompile(caller_addr) to analyze the calling function in detail."
    }


@tool
@idasync
def vuln_scan_function(
    addr: Annotated[str, "Function address to scan for vulnerabilities"],
) -> dict:
    """Scan a specific function for vulnerability patterns
    
    This tool analyzes a single function for calls to dangerous functions.
    Useful for targeted analysis after identifying interesting functions.
    
    Args:
        addr: Address of the function to analyze
    
    Returns:
        List of dangerous function calls within the specified function
    """
    try:
        func_ea = parse_address(addr)
        func = idaapi.get_func(func_ea)
        if not func:
            return {"addr": addr, "error": "Function not found", "findings": []}
        
        func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
        
        # Scan for dangerous calls
        all_findings = _scan_for_dangerous_calls()
        
        # Filter to this function only
        func_findings = [
            f.to_dict() for f in all_findings
            if f.caller_addr == hex(func.start_ea)
        ]
        
        return {
            "addr": addr,
            "function_name": func_name,
            "findings_count": len(func_findings),
            "findings": func_findings
        }
    except Exception as e:
        return {"addr": addr, "error": str(e), "findings": []}


@tool
@idasync
def vuln_categories() -> dict:
    """List all vulnerability categories that can be scanned
    
    Returns the list of vulnerability categories and the dangerous functions
    associated with each category.
    """
    categories: dict[str, list[str]] = {}
    
    for func_name, info in DANGEROUS_FUNCTIONS.items():
        cat = info["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(func_name)
    
    return {
        "categories": list(categories.keys()),
        "functions_by_category": categories,
        "total_dangerous_functions": len(DANGEROUS_FUNCTIONS)
    }
