"""IDA Pro MCP Vulnerability Scanner

This module provides comprehensive vulnerability scanning capabilities for binary analysis.
It identifies potentially dangerous function calls and categorizes them by vulnerability type
for AI-assisted analysis.

Key features:
- Identifies dangerous functions (format string, buffer overflow, command injection, etc.)
- Checks if dangerous parameters are controllable (non-constant)
- Analyzes format strings for dangerous specifiers (%s without width limit)
- Checks for strlen usage before copy operations
- Detects unchecked return values
- Saves detailed results to project folder to minimize token usage

Vulnerability Categories:
- Format String: Non-constant format strings in printf/scanf family
- Buffer Overflow: Unbounded copies, controllable sizes, %s in scanf
- Command Injection: Non-constant commands in system/exec family
- Integer Overflow: Potentially overflowing sizes in malloc/calloc
- Use After Free: Potential UAF/double-free patterns
- Path Traversal: Controllable paths in file operations
- Unchecked Return: Missing return value checks (scanf, malloc, etc.)
- Information Leak: Potentially leaking data via write/send
- SQL Injection: Non-constant SQL queries
- Race Condition: TOCTOU patterns (access followed by open)
- Signed Comparison: Size parameters checked with signed comparison
"""

import os
import json
import re
from datetime import datetime
from typing import Annotated, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum

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
# Vulnerability Categories
# ============================================================================

class VulnCategory:
    """Vulnerability category constants"""
    FORMAT_STRING = "Format String"
    BUFFER_OVERFLOW = "Buffer Overflow"
    COMMAND_INJECTION = "Command Injection"
    INTEGER_OVERFLOW = "Integer Overflow"
    USE_AFTER_FREE = "Use After Free"
    PATH_TRAVERSAL = "Path Traversal"
    UNCHECKED_RETURN = "Unchecked Return"
    INFO_LEAK = "Information Leak"
    SQL_INJECTION = "SQL Injection"
    RACE_CONDITION = "Race Condition"
    SIGNED_COMPARISON = "Signed Comparison"
    NULL_DEREF = "Null Pointer Dereference"


class RiskLevel:
    """Risk level constants"""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


# ============================================================================
# Rule Types for Different Detection Logic
# ============================================================================

class RuleType(Enum):
    """Types of detection rules"""
    PARAM_NOT_CONST = "param_not_const"           # Check if param is non-constant
    ALWAYS_DANGEROUS = "always_dangerous"          # Always flag (e.g., gets)
    FORMAT_STRING = "format_string"                # Check format string param
    FORMAT_WITH_S = "format_with_s"                # Check for %s in format string
    SIZE_CONTROLLABLE = "size_controllable"        # Size param may be controllable
    UNCHECKED_RETURN = "unchecked_return"          # Return value not checked
    NEED_STRLEN = "need_strlen"                    # Should have strlen before
    SECURE_VARIANT = "secure_variant"              # _s variants (size param check)


# ============================================================================
# Comprehensive Dangerous Function Definitions
# ============================================================================

# Each entry contains:
# - category: Vulnerability category
# - rule_type: How to evaluate the function
# - fmt_param: Index of format string parameter (for format string functions)
# - size_param: Index of size parameter (for size-checked functions)
# - dangerous_params: Parameter indices to check for non-constant values
# - desc: Description of the vulnerability
# - check_strlen: Whether strlen should be called before
# - check_return: Whether return value should be checked

DANGEROUS_FUNCTIONS = {
    # ========================================================================
    # Format String Vulnerabilities - Format string in param[0]
    # ========================================================================
    "printf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 0,
        "dangerous_params": [0],
        "desc": "Format string in arg0 - non-constant format allows arbitrary read/write"
    },
    "printk": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 0,
        "dangerous_params": [0],
        "desc": "Kernel printf - format string in arg0"
    },
    "vprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 0,
        "dangerous_params": [0],
        "desc": "Format string in arg0"
    },
    "wprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 0,
        "dangerous_params": [0],
        "desc": "Wide format string in arg0"
    },
    "vwprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 0,
        "dangerous_params": [0],
        "desc": "Wide format string in arg0"
    },
    "NSLog": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 0,
        "dangerous_params": [0],
        "desc": "Objective-C logging - format string in arg0"
    },
    "syslog": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Syslog - format string in arg1"
    },

    # scanf family - Format string in param[0], also check for %s buffer overflow
    "scanf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_WITH_S,
        "fmt_param": 0,
        "dangerous_params": [0],
        "desc": "Format string in arg0 - %s without width causes buffer overflow"
    },
    "vscanf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_WITH_S,
        "fmt_param": 0,
        "dangerous_params": [0],
        "desc": "Format string in arg0 - %s without width causes buffer overflow"
    },
    "wscanf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_WITH_S,
        "fmt_param": 0,
        "dangerous_params": [0],
        "desc": "Wide format string in arg0 - %s without width causes buffer overflow"
    },
    "_isoc99_scanf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_WITH_S,
        "fmt_param": 0,
        "dangerous_params": [0],
        "desc": "ISO C99 scanf - %s without width causes buffer overflow"
    },

    # ========================================================================
    # Format String Vulnerabilities - Format string in param[1]
    # ========================================================================
    "fprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Format string in arg1"
    },
    "vfprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Format string in arg1"
    },
    "sprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_WITH_S,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Format string in arg1 - %s may overflow destination buffer"
    },
    "vsprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_WITH_S,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Format string in arg1 - %s may overflow destination buffer"
    },
    "wsprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_WITH_S,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Windows sprintf - format string in arg1"
    },
    "wsprintfA": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_WITH_S,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Windows sprintf ANSI - format string in arg1"
    },
    "wsprintfW": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_WITH_S,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Windows sprintf Wide - format string in arg1"
    },
    "asprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Format string in arg1"
    },
    "vasprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Format string in arg1"
    },
    "dprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Format string in arg1"
    },
    "fwprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Wide format string in arg1"
    },
    "swprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Wide format string in arg1"
    },

    # scanf family with format in param[1]
    "sscanf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_WITH_S,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Format string in arg1 - %s without width causes buffer overflow"
    },
    "fscanf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_WITH_S,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Format string in arg1 - %s without width causes buffer overflow"
    },
    "vsscanf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_WITH_S,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Format string in arg1 - %s without width causes buffer overflow"
    },
    "vfscanf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_WITH_S,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Format string in arg1 - %s without width causes buffer overflow"
    },
    "fwscanf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_WITH_S,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Wide format string in arg1 - %s without width causes buffer overflow"
    },
    "swscanf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_WITH_S,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Wide format string in arg1 - %s without width causes buffer overflow"
    },

    # ========================================================================
    # Format String Vulnerabilities - Format string in param[2]
    # ========================================================================
    "snprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 2,
        "size_param": 1,
        "dangerous_params": [2],
        "desc": "Format string in arg2"
    },
    "vsnprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 2,
        "size_param": 1,
        "dangerous_params": [2],
        "desc": "Format string in arg2"
    },
    "vswprintf": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 2,
        "size_param": 1,
        "dangerous_params": [2],
        "desc": "Wide format string in arg2"
    },

    # glibc checked variants - Format string in param[2]
    "__printf_chk": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Fortified printf - format string in arg1"
    },
    "__fprintf_chk": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 2,
        "dangerous_params": [2],
        "desc": "Fortified fprintf - format string in arg2"
    },
    "__sprintf_chk": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 3,
        "dangerous_params": [3],
        "desc": "Fortified sprintf - format string in arg3"
    },
    "__snprintf_chk": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 4,
        "dangerous_params": [4],
        "desc": "Fortified snprintf - format string in arg4"
    },
    "__vprintf_chk": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 1,
        "dangerous_params": [1],
        "desc": "Fortified vprintf - format string in arg1"
    },
    "__vfprintf_chk": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 2,
        "dangerous_params": [2],
        "desc": "Fortified vfprintf - format string in arg2"
    },
    "__vsprintf_chk": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 3,
        "dangerous_params": [3],
        "desc": "Fortified vsprintf - format string in arg3"
    },
    "__vsnprintf_chk": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.FORMAT_STRING,
        "fmt_param": 4,
        "dangerous_params": [4],
        "desc": "Fortified vsnprintf - format string in arg4"
    },

    # ========================================================================
    # Buffer Overflow - Unbounded copy operations (source in param[1])
    # ========================================================================
    "strcpy": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.NEED_STRLEN,
        "dangerous_params": [1],
        "check_strlen": True,
        "desc": "Unbounded copy - no length check, use strncpy or check strlen before"
    },
    "wcscpy": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.NEED_STRLEN,
        "dangerous_params": [1],
        "check_strlen": True,
        "desc": "Wide unbounded copy - no length check"
    },
    "mbscpy": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.NEED_STRLEN,
        "dangerous_params": [1],
        "check_strlen": True,
        "desc": "Multibyte unbounded copy - no length check"
    },
    "lstrcpy": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.NEED_STRLEN,
        "dangerous_params": [1],
        "check_strlen": True,
        "desc": "Windows unbounded copy - no length check"
    },
    "lstrcpyA": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.NEED_STRLEN,
        "dangerous_params": [1],
        "check_strlen": True,
        "desc": "Windows ANSI unbounded copy - no length check"
    },
    "lstrcpyW": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.NEED_STRLEN,
        "dangerous_params": [1],
        "check_strlen": True,
        "desc": "Windows Wide unbounded copy - no length check"
    },
    "strcat": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.NEED_STRLEN,
        "dangerous_params": [1],
        "check_strlen": True,
        "desc": "Unbounded concat - no length check"
    },
    "wcscat": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.NEED_STRLEN,
        "dangerous_params": [1],
        "check_strlen": True,
        "desc": "Wide unbounded concat - no length check"
    },
    "mbscat": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.NEED_STRLEN,
        "dangerous_params": [1],
        "check_strlen": True,
        "desc": "Multibyte unbounded concat - no length check"
    },
    "lstrcat": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.NEED_STRLEN,
        "dangerous_params": [1],
        "check_strlen": True,
        "desc": "Windows unbounded concat - no length check"
    },
    "lstrcatA": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.NEED_STRLEN,
        "dangerous_params": [1],
        "check_strlen": True,
        "desc": "Windows ANSI unbounded concat - no length check"
    },
    "lstrcatW": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.NEED_STRLEN,
        "dangerous_params": [1],
        "check_strlen": True,
        "desc": "Windows Wide unbounded concat - no length check"
    },

    # ========================================================================
    # Buffer Overflow - Size controlled operations (size in param[2])
    # ========================================================================
    "strncpy": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 may be controllable or not null-terminated"
    },
    "wcsncpy": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Wide size in arg2 may be controllable"
    },
    "strncat": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 may be controllable"
    },
    "wcsncat": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Wide size in arg2 may be controllable"
    },
    "lstrcpyn": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Windows - size in arg2 may be controllable"
    },
    "lstrcpynA": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Windows ANSI - size in arg2 may be controllable"
    },
    "lstrcpynW": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Windows Wide - size in arg2 may be controllable"
    },
    "memcpy": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 may be controllable - verify bounds"
    },
    "memmove": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 may be controllable"
    },
    "wmemcpy": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Wide size in arg2 may be controllable"
    },
    "wmemmove": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Wide size in arg2 may be controllable"
    },
    "bcopy": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "BSD copy - size in arg2 may be controllable"
    },
    "memset": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 may be controllable"
    },
    "wmemset": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Wide size in arg2 may be controllable"
    },

    # ========================================================================
    # Buffer Overflow - MSVC Secure variants (_s suffix)
    # ========================================================================
    "strcpy_s": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SECURE_VARIANT,
        "size_param": 1,
        "dangerous_params": [1],
        "desc": "MSVC secure - but size (arg1) should be constant or validated"
    },
    "wcscpy_s": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SECURE_VARIANT,
        "size_param": 1,
        "dangerous_params": [1],
        "desc": "MSVC secure wide - size (arg1) should be constant or validated"
    },
    "mbscpy_s": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SECURE_VARIANT,
        "size_param": 1,
        "dangerous_params": [1],
        "desc": "MSVC secure multibyte - size (arg1) should be constant or validated"
    },
    "strcat_s": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SECURE_VARIANT,
        "size_param": 1,
        "dangerous_params": [1],
        "desc": "MSVC secure concat - size (arg1) should be constant or validated"
    },
    "wcscat_s": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SECURE_VARIANT,
        "size_param": 1,
        "dangerous_params": [1],
        "desc": "MSVC secure wide concat - size (arg1) should be constant or validated"
    },
    "strncpy_s": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SECURE_VARIANT,
        "size_param": 1,
        "dangerous_params": [1, 3],
        "desc": "MSVC secure - sizes (arg1, arg3) should be validated"
    },
    "wcsncpy_s": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SECURE_VARIANT,
        "size_param": 1,
        "dangerous_params": [1, 3],
        "desc": "MSVC secure wide - sizes should be validated"
    },
    "memcpy_s": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SECURE_VARIANT,
        "size_param": 1,
        "dangerous_params": [1, 3],
        "desc": "MSVC secure memcpy - sizes (arg1, arg3) should be validated"
    },
    "memmove_s": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SECURE_VARIANT,
        "size_param": 1,
        "dangerous_params": [1, 3],
        "desc": "MSVC secure memmove - sizes should be validated"
    },
    "sprintf_s": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.SECURE_VARIANT,
        "fmt_param": 2,
        "size_param": 1,
        "dangerous_params": [1, 2],
        "desc": "MSVC secure sprintf - size (arg1) should be validated"
    },
    "snprintf_s": {
        "category": VulnCategory.FORMAT_STRING,
        "rule_type": RuleType.SECURE_VARIANT,
        "fmt_param": 3,
        "size_param": 1,
        "dangerous_params": [1, 3],
        "desc": "MSVC secure snprintf - size (arg1) should be validated"
    },

    # ========================================================================
    # Buffer Overflow - Always dangerous functions
    # ========================================================================
    "gets": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.ALWAYS_DANGEROUS,
        "dangerous_params": [],
        "desc": "CRITICAL: Always dangerous - no bounds checking, removed in C11"
    },
    "gets_s": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 1,
        "dangerous_params": [1],
        "desc": "Size in arg1 should be validated"
    },

    # ========================================================================
    # Buffer Overflow - Read/Recv operations
    # ========================================================================
    "read": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 may be controllable - verify buffer size"
    },
    "recv": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 may be controllable - verify buffer size"
    },
    "recvfrom": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 may be controllable - verify buffer size"
    },
    "recvmsg": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "Message buffer in arg1 - verify sizes in msghdr"
    },
    "fread": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 1,
        "dangerous_params": [1, 2],
        "desc": "Size*count may overflow or exceed buffer - verify arg1*arg2"
    },
    "fgets": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 1,
        "dangerous_params": [1],
        "desc": "Size in arg1 may be controllable - safer than gets but verify"
    },
    "realpath": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "Output buffer (arg1) must be PATH_MAX bytes - may overflow"
    },
    "getwd": {
        "category": VulnCategory.BUFFER_OVERFLOW,
        "rule_type": RuleType.ALWAYS_DANGEROUS,
        "dangerous_params": [],
        "desc": "Deprecated - no size parameter, use getcwd instead"
    },

    # ========================================================================
    # Command Injection
    # ========================================================================
    "system": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Command in arg0 - shell metacharacter injection possible"
    },
    "popen": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Command in arg0 - shell metacharacter injection possible"
    },
    "wpopen": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Wide command in arg0 - shell injection possible"
    },
    "_popen": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Command in arg0 - shell injection possible"
    },
    "_wpopen": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Wide command in arg0 - shell injection possible"
    },
    "execl": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - command injection if path controllable"
    },
    "execlp": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "File in arg0 - PATH search may be abused"
    },
    "execle": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - command injection if path controllable"
    },
    "execv": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "Path/args in arg0,1 - injection if controllable"
    },
    "execvp": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "File/args in arg0,1 - PATH search may be abused"
    },
    "execve": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "Path/args in arg0,1 - injection if controllable"
    },
    "execvpe": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "File/args in arg0,1 - PATH search may be abused"
    },
    "fexecve": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "Args in arg1 - argument injection possible"
    },
    "posix_spawn": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [2, 4],
        "desc": "Path/args may be controllable"
    },
    "posix_spawnp": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [2, 4],
        "desc": "File/args may be controllable - PATH search may be abused"
    },

    # Windows command execution
    "ShellExecute": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [2, 3],
        "desc": "File/params in arg2,3 - command injection possible"
    },
    "ShellExecuteA": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [2, 3],
        "desc": "ANSI file/params in arg2,3 - command injection possible"
    },
    "ShellExecuteW": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [2, 3],
        "desc": "Wide file/params in arg2,3 - command injection possible"
    },
    "ShellExecuteEx": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "SHELLEXECUTEINFO struct may contain controllable data"
    },
    "ShellExecuteExA": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "ANSI SHELLEXECUTEINFO may contain controllable data"
    },
    "ShellExecuteExW": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Wide SHELLEXECUTEINFO may contain controllable data"
    },
    "WinExec": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Command in arg0 - DEPRECATED, command injection possible"
    },
    "CreateProcess": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "App/cmdline in arg0,1 - argument injection possible"
    },
    "CreateProcessA": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "ANSI app/cmdline - argument injection possible"
    },
    "CreateProcessW": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "Wide app/cmdline - argument injection possible"
    },
    "CreateProcessAsUser": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1, 2],
        "desc": "App/cmdline - privilege escalation risk"
    },
    "CreateProcessAsUserA": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1, 2],
        "desc": "ANSI - privilege escalation risk"
    },
    "CreateProcessAsUserW": {
        "category": VulnCategory.COMMAND_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1, 2],
        "desc": "Wide - privilege escalation risk"
    },

    # ========================================================================
    # Integer Overflow / Memory Allocation
    # ========================================================================
    "malloc": {
        "category": VulnCategory.INTEGER_OVERFLOW,
        "rule_type": RuleType.UNCHECKED_RETURN,
        "dangerous_params": [0],
        "check_return": True,
        "desc": "Size in arg0 may overflow - also check return for NULL"
    },
    "calloc": {
        "category": VulnCategory.INTEGER_OVERFLOW,
        "rule_type": RuleType.UNCHECKED_RETURN,
        "dangerous_params": [0, 1],
        "check_return": True,
        "desc": "Count*size (arg0*arg1) may overflow - check return for NULL"
    },
    "realloc": {
        "category": VulnCategory.INTEGER_OVERFLOW,
        "rule_type": RuleType.UNCHECKED_RETURN,
        "dangerous_params": [1],
        "check_return": True,
        "desc": "Size in arg1 may overflow - check return for NULL"
    },
    "reallocarray": {
        "category": VulnCategory.INTEGER_OVERFLOW,
        "rule_type": RuleType.UNCHECKED_RETURN,
        "dangerous_params": [1, 2],
        "check_return": True,
        "desc": "Count*size may overflow - check return for NULL"
    },
    "alloca": {
        "category": VulnCategory.INTEGER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "dangerous_params": [0],
        "desc": "Size in arg0 may overflow - stack allocation, no NULL return"
    },
    "_alloca": {
        "category": VulnCategory.INTEGER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "dangerous_params": [0],
        "desc": "MSVC stack allocation - size may overflow"
    },
    "_malloca": {
        "category": VulnCategory.INTEGER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "dangerous_params": [0],
        "desc": "MSVC hybrid allocation - size may overflow"
    },
    "VirtualAlloc": {
        "category": VulnCategory.INTEGER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "dangerous_params": [1],
        "desc": "Size in arg1 may be controllable"
    },
    "VirtualAllocEx": {
        "category": VulnCategory.INTEGER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "dangerous_params": [2],
        "desc": "Size in arg2 may be controllable"
    },
    "HeapAlloc": {
        "category": VulnCategory.INTEGER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "dangerous_params": [2],
        "desc": "Size in arg2 may be controllable"
    },
    "GlobalAlloc": {
        "category": VulnCategory.INTEGER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "dangerous_params": [1],
        "desc": "Size in arg1 may be controllable"
    },
    "LocalAlloc": {
        "category": VulnCategory.INTEGER_OVERFLOW,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "dangerous_params": [1],
        "desc": "Size in arg1 may be controllable"
    },

    # ========================================================================
    # Use After Free / Double Free
    # ========================================================================
    "free": {
        "category": VulnCategory.USE_AFTER_FREE,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Pointer in arg0 - check for double-free, set to NULL after"
    },
    "delete": {
        "category": VulnCategory.USE_AFTER_FREE,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "C++ delete - check for double-free, set to nullptr after"
    },
    "HeapFree": {
        "category": VulnCategory.USE_AFTER_FREE,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [2],
        "desc": "Pointer in arg2 - check for double-free"
    },
    "GlobalFree": {
        "category": VulnCategory.USE_AFTER_FREE,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Handle in arg0 - check for double-free"
    },
    "LocalFree": {
        "category": VulnCategory.USE_AFTER_FREE,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Handle in arg0 - check for double-free"
    },
    "VirtualFree": {
        "category": VulnCategory.USE_AFTER_FREE,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Address in arg0 - check for double-free"
    },

    # ========================================================================
    # Path Traversal / File Operations
    # ========================================================================
    "fopen": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - check for ../ traversal"
    },
    "fopen64": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - check for ../ traversal"
    },
    "freopen": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - check for traversal"
    },
    "_wfopen": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Wide path in arg0 - check for traversal"
    },
    "open": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - check for traversal"
    },
    "open64": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - check for traversal"
    },
    "openat": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "Path in arg1 - check for traversal"
    },
    "openat64": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "Path in arg1 - check for traversal"
    },
    "creat": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - check for traversal"
    },
    "access": {
        "category": VulnCategory.RACE_CONDITION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "TOCTOU: check-then-use race if followed by open"
    },
    "faccessat": {
        "category": VulnCategory.RACE_CONDITION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "TOCTOU: check-then-use race"
    },
    "stat": {
        "category": VulnCategory.RACE_CONDITION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "TOCTOU: stat-then-use race"
    },
    "stat64": {
        "category": VulnCategory.RACE_CONDITION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "TOCTOU: stat-then-use race"
    },
    "lstat": {
        "category": VulnCategory.RACE_CONDITION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "TOCTOU: lstat-then-use race"
    },
    "fstatat": {
        "category": VulnCategory.RACE_CONDITION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "TOCTOU: stat-then-use race"
    },
    "readlink": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Symlink path in arg0 - may point to sensitive files"
    },
    "readlinkat": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "Symlink path in arg1"
    },
    "symlink": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "Symlink creation - can point to sensitive files"
    },
    "link": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "Hard link creation"
    },
    "unlink": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - arbitrary file deletion"
    },
    "unlinkat": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "Path in arg1 - arbitrary file deletion"
    },
    "rename": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "Paths in arg0,1 - file manipulation"
    },
    "renameat": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1, 3],
        "desc": "Paths - file manipulation"
    },
    "mkdir": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - directory creation"
    },
    "mkdirat": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "Path in arg1 - directory creation"
    },
    "rmdir": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - directory deletion"
    },
    "chdir": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - working directory change"
    },
    "chroot": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - jail escape if improperly used"
    },
    "chmod": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - permission modification"
    },
    "chown": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - ownership modification"
    },
    "CreateFile": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - check for traversal"
    },
    "CreateFileA": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "ANSI path in arg0 - check for traversal"
    },
    "CreateFileW": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Wide path in arg0 - check for traversal"
    },
    "DeleteFile": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Path in arg0 - arbitrary file deletion"
    },
    "DeleteFileA": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "ANSI path - arbitrary file deletion"
    },
    "DeleteFileW": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0],
        "desc": "Wide path - arbitrary file deletion"
    },
    "CopyFile": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "Paths - file copy manipulation"
    },
    "CopyFileA": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "ANSI paths - file copy manipulation"
    },
    "CopyFileW": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "Wide paths - file copy manipulation"
    },
    "MoveFile": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "Paths - file move manipulation"
    },
    "MoveFileA": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "ANSI paths - file move manipulation"
    },
    "MoveFileW": {
        "category": VulnCategory.PATH_TRAVERSAL,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [0, 1],
        "desc": "Wide paths - file move manipulation"
    },

    # ========================================================================
    # Information Leak
    # ========================================================================
    "write": {
        "category": VulnCategory.INFO_LEAK,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 may leak more data than intended"
    },
    "send": {
        "category": VulnCategory.INFO_LEAK,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 may leak data"
    },
    "sendto": {
        "category": VulnCategory.INFO_LEAK,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 may leak data"
    },
    "sendmsg": {
        "category": VulnCategory.INFO_LEAK,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "Message struct - check buffer sizes"
    },
    "fwrite": {
        "category": VulnCategory.INFO_LEAK,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 1,
        "dangerous_params": [1, 2],
        "desc": "Size*count may leak extra data"
    },

    # ========================================================================
    # SQL Injection
    # ========================================================================
    "sqlite3_exec": {
        "category": VulnCategory.SQL_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "SQL in arg1 - use prepared statements"
    },
    "sqlite3_prepare": {
        "category": VulnCategory.SQL_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "SQL in arg1 - verify parameterized"
    },
    "sqlite3_prepare_v2": {
        "category": VulnCategory.SQL_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "SQL in arg1 - verify parameterized"
    },
    "sqlite3_prepare_v3": {
        "category": VulnCategory.SQL_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "SQL in arg1 - verify parameterized"
    },
    "mysql_query": {
        "category": VulnCategory.SQL_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "SQL in arg1 - use prepared statements"
    },
    "mysql_real_query": {
        "category": VulnCategory.SQL_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "SQL in arg1 - use prepared statements"
    },
    "PQexec": {
        "category": VulnCategory.SQL_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "PostgreSQL query in arg1 - use PQexecParams"
    },
    "PQexecParams": {
        "category": VulnCategory.SQL_INJECTION,
        "rule_type": RuleType.PARAM_NOT_CONST,
        "dangerous_params": [1],
        "desc": "PostgreSQL query - verify parameters properly escaped"
    },

    # ========================================================================
    # Signed Comparison Issues
    # ========================================================================
    "strncmp": {
        "category": VulnCategory.SIGNED_COMPARISON,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 - if signed and negative, comparison bypassed"
    },
    "wcsncmp": {
        "category": VulnCategory.SIGNED_COMPARISON,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 - if signed and negative, comparison bypassed"
    },
    "memcmp": {
        "category": VulnCategory.SIGNED_COMPARISON,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 - if signed and negative, comparison bypassed"
    },
    "memchr": {
        "category": VulnCategory.SIGNED_COMPARISON,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 - verify unsigned comparison"
    },
    "memrchr": {
        "category": VulnCategory.SIGNED_COMPARISON,
        "rule_type": RuleType.SIZE_CONTROLLABLE,
        "size_param": 2,
        "dangerous_params": [2],
        "desc": "Size in arg2 - verify unsigned comparison"
    },

    # ========================================================================
    # Unchecked Return Value
    # ========================================================================
    "setuid": {
        "category": VulnCategory.UNCHECKED_RETURN,
        "rule_type": RuleType.UNCHECKED_RETURN,
        "dangerous_params": [],
        "check_return": True,
        "desc": "Return value MUST be checked - privilege drop may fail"
    },
    "setgid": {
        "category": VulnCategory.UNCHECKED_RETURN,
        "rule_type": RuleType.UNCHECKED_RETURN,
        "dangerous_params": [],
        "check_return": True,
        "desc": "Return value MUST be checked - privilege drop may fail"
    },
    "seteuid": {
        "category": VulnCategory.UNCHECKED_RETURN,
        "rule_type": RuleType.UNCHECKED_RETURN,
        "dangerous_params": [],
        "check_return": True,
        "desc": "Return value MUST be checked"
    },
    "setegid": {
        "category": VulnCategory.UNCHECKED_RETURN,
        "rule_type": RuleType.UNCHECKED_RETURN,
        "dangerous_params": [],
        "check_return": True,
        "desc": "Return value MUST be checked"
    },
    "setreuid": {
        "category": VulnCategory.UNCHECKED_RETURN,
        "rule_type": RuleType.UNCHECKED_RETURN,
        "dangerous_params": [],
        "check_return": True,
        "desc": "Return value MUST be checked"
    },
    "setregid": {
        "category": VulnCategory.UNCHECKED_RETURN,
        "rule_type": RuleType.UNCHECKED_RETURN,
        "dangerous_params": [],
        "check_return": True,
        "desc": "Return value MUST be checked"
    },
    "chdir": {
        "category": VulnCategory.UNCHECKED_RETURN,
        "rule_type": RuleType.UNCHECKED_RETURN,
        "dangerous_params": [0],
        "check_return": True,
        "desc": "Return value should be checked - may fail"
    },
}


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class ParamAnalysis:
    """Analysis result for a function parameter"""
    index: int
    is_constant: Optional[bool]
    string_value: Optional[str]
    numeric_value: Optional[int]
    analysis_type: str  # "decompiled", "disasm_only", "unknown"
    has_strlen_before: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class VulnerabilityFinding:
    """Represents a single vulnerability finding"""
    category: str
    function_name: str      # The dangerous function being called
    caller_name: str        # The function containing the call
    caller_addr: str        # Address of the caller function
    call_addr: str          # Address of the call instruction
    dangerous_params: list[int]
    param_analysis: list[dict]
    risk_level: str         # "High", "Medium", "Low", "Info"
    description: str
    rule_type: str          # The type of rule that matched
    additional_info: dict = field(default_factory=dict)

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
    risk_summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ============================================================================
# Analysis Helper Functions
# ============================================================================

def _check_format_string_for_dangerous_specifiers(fmt_str: str) -> dict:
    """Check format string for dangerous specifiers like %s without width"""
    result = {
        "has_dangerous_s": False,
        "s_count": 0,
        "s_without_width": 0,
        "specifiers": []
    }

    if not fmt_str:
        return result

    # Pattern to match format specifiers
    # %[flags][width][.precision][length]specifier
    fmt_pattern = r'%[-+0 #]*(\d+|\*)?(\.\d+|\.\*)?[hlLzjt]*([diouxXeEfFgGaAcspn%])'

    for match in re.finditer(fmt_pattern, fmt_str):
        specifier = match.group(3)
        width = match.group(1)

        if specifier == 's':
            result["s_count"] += 1
            result["specifiers"].append({
                "full": match.group(0),
                "specifier": specifier,
                "has_width": width is not None and width != '*'
            })
            if width is None or width == '*':
                result["s_without_width"] += 1
                result["has_dangerous_s"] = True

    return result


def _get_string_at_address(ea: int) -> Optional[str]:
    """Get string constant at address"""
    if ea == 0 or ea == idaapi.BADADDR:
        return None

    str_type = idc.get_str_type(ea)
    if str_type is not None and str_type >= 0:
        s = idc.get_strlit_contents(ea, -1, str_type)
        if s:
            try:
                return s.decode('utf-8', errors='replace')
            except:
                return str(s)
    return None


class HexRaysCallAnalyzer:
    """Analyzes function calls using Hex-Rays decompiler"""

    def __init__(self, call_ea: int):
        self.call_ea = call_ea
        self.cfunc = None
        self.call_expr = None
        self.args = None
        self._init_decompiler()

    def _init_decompiler(self):
        """Initialize Hex-Rays decompiler for the function containing the call"""
        try:
            import ida_hexrays
            self.ida_hexrays = ida_hexrays

            func = idaapi.get_func(self.call_ea)
            if not func:
                return

            self.cfunc = ida_hexrays.decompile(func.start_ea)
            if not self.cfunc:
                return

            # Find the call expression
            class CallFinder(ida_hexrays.ctree_visitor_t):
                def __init__(self, target_ea):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.target_ea = target_ea
                    self.call_expr = None
                    self.args = None

                def visit_expr(self, expr):
                    if expr.op == ida_hexrays.cot_call and expr.ea == self.target_ea:
                        self.call_expr = expr
                        self.args = expr.a
                        return 1
                    return 0

            finder = CallFinder(self.call_ea)
            finder.apply_to(self.cfunc.body, None)
            self.call_expr = finder.call_expr
            self.args = finder.args

        except ImportError:
            pass
        except Exception:
            pass

    def analyze_param(self, param_idx: int) -> ParamAnalysis:
        """Analyze a specific parameter"""
        if not self.args or param_idx >= len(self.args):
            return ParamAnalysis(
                index=param_idx,
                is_constant=None,
                string_value=None,
                numeric_value=None,
                analysis_type="out_of_range"
            )

        try:
            arg = self.args[param_idx]
            return self._analyze_expr(arg, param_idx)
        except Exception:
            return ParamAnalysis(
                index=param_idx,
                is_constant=None,
                string_value=None,
                numeric_value=None,
                analysis_type="error"
            )

    def _analyze_expr(self, expr, param_idx: int) -> ParamAnalysis:
        """Analyze a Hex-Rays expression"""
        ida_hexrays = self.ida_hexrays

        # Direct number
        if expr.op == ida_hexrays.cot_num:
            return ParamAnalysis(
                index=param_idx,
                is_constant=True,
                string_value=None,
                numeric_value=expr.n._value if hasattr(expr.n, '_value') else expr.numval(),
                analysis_type="decompiled"
            )

        # String literal
        if expr.op == ida_hexrays.cot_str:
            return ParamAnalysis(
                index=param_idx,
                is_constant=True,
                string_value=expr.string,
                numeric_value=None,
                analysis_type="decompiled"
            )

        # Object reference (may be string)
        if expr.op == ida_hexrays.cot_obj:
            str_val = _get_string_at_address(expr.obj_ea)
            return ParamAnalysis(
                index=param_idx,
                is_constant=str_val is not None,
                string_value=str_val,
                numeric_value=None if str_val else expr.obj_ea,
                analysis_type="decompiled"
            )

        # Cast expression - unwrap and analyze inner
        if expr.op == ida_hexrays.cot_cast:
            return self._analyze_expr(expr.x, param_idx)

        # Reference expression
        if expr.op == ida_hexrays.cot_ref:
            if hasattr(expr.x, 'obj_ea'):
                str_val = _get_string_at_address(expr.x.obj_ea)
                return ParamAnalysis(
                    index=param_idx,
                    is_constant=str_val is not None,
                    string_value=str_val,
                    numeric_value=None,
                    analysis_type="decompiled"
                )

        # Variable - not constant
        return ParamAnalysis(
            index=param_idx,
            is_constant=False,
            string_value=None,
            numeric_value=None,
            analysis_type="decompiled"
        )

    def check_strlen_before(self, param_idx: int) -> bool:
        """Check if strlen was called on this parameter before the current call"""
        if not self.cfunc or not self.args or param_idx >= len(self.args):
            return False

        try:
            ida_hexrays = self.ida_hexrays
            arg = self.args[param_idx]

            # Look for strlen calls in the function that use the same variable
            class StrlenFinder(ida_hexrays.ctree_visitor_t):
                def __init__(self, target_var, call_ea):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.found = False
                    self.target_var = target_var
                    self.call_ea = call_ea

                def visit_expr(self, expr):
                    if expr.op == ida_hexrays.cot_call:
                        # Check if this is a strlen call before our target call
                        if expr.ea < self.call_ea:
                            callee = expr.x
                            if hasattr(callee, 'obj_ea'):
                                name = ida_name.get_name(callee.obj_ea)
                                if name and 'strlen' in name.lower():
                                    # Check if strlen is called with same variable
                                    if expr.a and len(expr.a) > 0:
                                        self.found = True
                                        return 1
                    return 0

            finder = StrlenFinder(arg, self.call_ea)
            finder.apply_to(self.cfunc.body, None)
            return finder.found

        except Exception:
            return False

    def check_return_used(self) -> bool:
        """Check if the return value of this call is used (assigned or compared)"""
        if not self.cfunc or not self.call_expr:
            return False

        try:
            ida_hexrays = self.ida_hexrays

            # Check if the call's parent is an assignment or comparison
            class ReturnChecker(ida_hexrays.ctree_visitor_t):
                def __init__(self, call_expr):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)
                    self.call_expr = call_expr
                    self.return_used = False

                def visit_expr(self, expr):
                    # Check if we've found our call
                    if expr.ea == self.call_expr.ea and expr.op == ida_hexrays.cot_call:
                        # Check parent
                        parent = self.parent_expr()
                        if parent:
                            # Assignment
                            if parent.op == ida_hexrays.cot_asg:
                                self.return_used = True
                            # Comparison operators
                            elif parent.op in (ida_hexrays.cot_eq, ida_hexrays.cot_ne,
                                              ida_hexrays.cot_slt, ida_hexrays.cot_sle,
                                              ida_hexrays.cot_sgt, ida_hexrays.cot_sge,
                                              ida_hexrays.cot_ult, ida_hexrays.cot_ule,
                                              ida_hexrays.cot_ugt, ida_hexrays.cot_uge):
                                self.return_used = True
                            # Logical operators
                            elif parent.op in (ida_hexrays.cot_lor, ida_hexrays.cot_land,
                                              ida_hexrays.cot_lnot):
                                self.return_used = True
                        return 1
                    return 0

            checker = ReturnChecker(self.call_expr)
            checker.apply_to_exprs(self.cfunc.body, None)
            return checker.return_used

        except Exception:
            return False


def _analyze_call_disasm(call_ea: int, param_indices: list[int]) -> list[ParamAnalysis]:
    """Fallback analysis using disassembly when Hex-Rays is not available"""
    results = []

    for idx in param_indices:
        # Simple heuristic: look for string references near the call
        str_found = None

        # Search backwards for string references (within 10 instructions)
        ea = call_ea
        for _ in range(10):
            ea = idc.prev_head(ea)
            if ea == idaapi.BADADDR:
                break

            # Check for string references in operands
            for op_idx in range(2):
                op_type = idc.get_operand_type(ea, op_idx)
                if op_type == idc.o_mem or op_type == idc.o_imm:
                    op_val = idc.get_operand_value(ea, op_idx)
                    str_val = _get_string_at_address(op_val)
                    if str_val:
                        str_found = str_val
                        break

        results.append(ParamAnalysis(
            index=idx,
            is_constant=str_found is not None,
            string_value=str_found,
            numeric_value=None,
            analysis_type="disasm_only"
        ))

    return results


# ============================================================================
# Vulnerability Detection Logic
# ============================================================================

def _evaluate_rule(func_name: str, func_info: dict, call_ea: int,
                   analyzer: Optional[HexRaysCallAnalyzer]) -> Optional[VulnerabilityFinding]:
    """Evaluate a vulnerability rule and return finding if matched"""

    rule_type = func_info.get("rule_type", RuleType.PARAM_NOT_CONST)
    dangerous_params = func_info.get("dangerous_params", [])

    # Analyze parameters
    param_analysis = []
    if analyzer and analyzer.args:
        for idx in dangerous_params:
            param_analysis.append(analyzer.analyze_param(idx))
    else:
        param_analysis = _analyze_call_disasm(call_ea, dangerous_params)

    # Get caller info
    caller_func = idaapi.get_func(call_ea)
    if not caller_func:
        return None
    caller_name = ida_funcs.get_func_name(caller_func.start_ea) or f"sub_{caller_func.start_ea:x}"

    risk_level = RiskLevel.INFO
    additional_info = {}

    # Evaluate based on rule type
    if rule_type == RuleType.ALWAYS_DANGEROUS:
        risk_level = RiskLevel.HIGH

    elif rule_type == RuleType.FORMAT_STRING:
        # Check if format string parameter is non-constant
        fmt_param_idx = func_info.get("fmt_param", 0)
        fmt_analysis = None

        if analyzer and analyzer.args and fmt_param_idx < len(analyzer.args):
            fmt_analysis = analyzer.analyze_param(fmt_param_idx)
        elif param_analysis:
            for pa in param_analysis:
                if pa.index == fmt_param_idx:
                    fmt_analysis = pa
                    break

        if fmt_analysis:
            if fmt_analysis.is_constant is False:
                risk_level = RiskLevel.HIGH
            elif fmt_analysis.is_constant is None:
                risk_level = RiskLevel.MEDIUM
            else:
                risk_level = RiskLevel.LOW

    elif rule_type == RuleType.FORMAT_WITH_S:
        # Check format string for dangerous %s specifiers
        fmt_param_idx = func_info.get("fmt_param", 0)
        fmt_analysis = None

        if analyzer and analyzer.args and fmt_param_idx < len(analyzer.args):
            fmt_analysis = analyzer.analyze_param(fmt_param_idx)

        if fmt_analysis:
            if fmt_analysis.is_constant is False:
                # Non-constant format string - high risk
                risk_level = RiskLevel.HIGH
                additional_info["reason"] = "Non-constant format string"
            elif fmt_analysis.string_value:
                # Check for %s without width limit
                fmt_check = _check_format_string_for_dangerous_specifiers(fmt_analysis.string_value)
                additional_info["format_analysis"] = fmt_check

                if fmt_check["has_dangerous_s"]:
                    risk_level = RiskLevel.HIGH
                    additional_info["reason"] = f"Format has {fmt_check['s_without_width']} %s without width limit"
                elif fmt_check["s_count"] > 0:
                    risk_level = RiskLevel.MEDIUM
                    additional_info["reason"] = f"Format has {fmt_check['s_count']} %s specifiers with width limits"
                else:
                    risk_level = RiskLevel.LOW
            elif fmt_analysis.is_constant is None:
                risk_level = RiskLevel.MEDIUM
            else:
                risk_level = RiskLevel.LOW

    elif rule_type == RuleType.SIZE_CONTROLLABLE:
        # Check if size parameter is non-constant
        has_non_const = False
        has_unknown = False

        for pa in param_analysis:
            if pa.is_constant is False:
                has_non_const = True
            elif pa.is_constant is None:
                has_unknown = True

        if has_non_const:
            risk_level = RiskLevel.HIGH
        elif has_unknown:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

    elif rule_type == RuleType.NEED_STRLEN:
        # Check if source is non-constant and strlen wasn't called before
        has_non_const = False
        has_strlen = False

        for pa in param_analysis:
            if pa.is_constant is False:
                has_non_const = True
                if analyzer:
                    has_strlen = analyzer.check_strlen_before(pa.index)
                    pa.has_strlen_before = has_strlen

        if has_non_const:
            if has_strlen:
                risk_level = RiskLevel.MEDIUM
                additional_info["reason"] = "strlen called before, but still using unbounded function"
            else:
                risk_level = RiskLevel.HIGH
                additional_info["reason"] = "No strlen check before unbounded copy"
        else:
            risk_level = RiskLevel.LOW

    elif rule_type == RuleType.SECURE_VARIANT:
        # _s variants - check if size parameter is controllable
        has_non_const_size = False

        for pa in param_analysis:
            if pa.is_constant is False:
                has_non_const_size = True

        if has_non_const_size:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

    elif rule_type == RuleType.UNCHECKED_RETURN:
        # Check if return value is used
        if analyzer:
            return_checked = analyzer.check_return_used()
            additional_info["return_checked"] = return_checked

            if not return_checked:
                risk_level = RiskLevel.HIGH
                additional_info["reason"] = "Return value not checked"
            else:
                risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.MEDIUM
            additional_info["reason"] = "Could not determine if return checked (no decompiler)"

    elif rule_type == RuleType.PARAM_NOT_CONST:
        # Generic check for non-constant parameters
        has_non_const = False
        has_unknown = False

        for pa in param_analysis:
            if pa.is_constant is False:
                has_non_const = True
            elif pa.is_constant is None:
                has_unknown = True

        if has_non_const:
            risk_level = RiskLevel.HIGH
        elif has_unknown:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

    return VulnerabilityFinding(
        category=func_info["category"],
        function_name=func_name,
        caller_name=caller_name,
        caller_addr=hex(caller_func.start_ea),
        call_addr=hex(call_ea),
        dangerous_params=dangerous_params,
        param_analysis=[pa.to_dict() for pa in param_analysis],
        risk_level=risk_level,
        description=func_info.get("desc", ""),
        rule_type=rule_type.value if isinstance(rule_type, RuleType) else str(rule_type),
        additional_info=additional_info
    )


def _scan_for_dangerous_calls() -> list[VulnerabilityFinding]:
    """Scan the binary for calls to dangerous functions"""
    findings = []

    # Build a map of function names to their addresses
    func_name_to_ea = {}

    # Scan defined functions
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea)
        if name:
            normalized = name.lstrip('_').lower()
            func_name_to_ea[normalized] = ea
            func_name_to_ea[name.lower()] = ea

    # Scan imports
    for i in range(ida_nalt.get_import_module_qty()):
        def imp_cb(ea, name, ordinal):
            if name:
                normalized = name.lstrip('_').lower()
                func_name_to_ea[normalized] = ea
                func_name_to_ea[name.lower()] = ea
            return True
        ida_nalt.enum_import_names(i, imp_cb)

    # Find calls to dangerous functions
    for func_name, func_info in DANGEROUS_FUNCTIONS.items():
        normalized_name = func_name.lower()

        # Find function address
        target_ea = func_name_to_ea.get(normalized_name)
        if target_ea is None:
            target_ea = func_name_to_ea.get('_' + normalized_name)
        if target_ea is None:
            continue

        # Find all xrefs to this function
        for xref in idautils.XrefsTo(target_ea, 0):
            if not xref.iscode:
                continue

            call_ea = xref.frm
            caller_func = idaapi.get_func(call_ea)
            if not caller_func:
                continue

            # Initialize Hex-Rays analyzer
            analyzer = HexRaysCallAnalyzer(call_ea)

            # Evaluate the rule
            finding = _evaluate_rule(func_name, func_info, call_ea, analyzer)
            if finding:
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
    min_risk: Annotated[str, "Minimum risk level: High, Medium, Low, or Info (default: Low)"] = "Low",
) -> dict:
    """Scan binary for potential vulnerabilities by identifying dangerous function calls

    This tool performs comprehensive vulnerability scanning including:
    - Format string vulnerabilities (non-constant format strings)
    - Buffer overflow (unbounded copies, controllable sizes, %s without width)
    - Command injection (non-constant commands)
    - Integer overflow (potentially overflowing allocations)
    - Use-after-free patterns
    - Path traversal (controllable paths)
    - Unchecked return values (malloc, setuid, etc.)
    - SQL injection (non-constant queries)
    - Race conditions (TOCTOU)

    Detection features:
    - Checks if dangerous parameters are constants or variables
    - Analyzes format strings for dangerous %s specifiers
    - Checks for strlen usage before unbounded copy operations
    - Verifies if return values are properly checked

    Workflow:
    1. Call vuln_scan() to get the summary
    2. Review the categories and risk levels
    3. Use vuln_scan_details(category) for specific findings
    4. Use decompile() to analyze flagged functions

    Returns:
        Summary with categories, counts, risk distribution, and results file path
    """
    binary_path = idc.get_input_file_path()
    binary_name = os.path.basename(binary_path) if binary_path else "unknown"

    if output_dir is None:
        idb_path = idc.get_idb_path()
        if idb_path:
            output_dir = os.path.join(os.path.dirname(idb_path), ".ida-mcp-vuln")
        else:
            output_dir = ".ida-mcp-vuln"

    risk_levels = {RiskLevel.HIGH: 4, RiskLevel.MEDIUM: 3, RiskLevel.LOW: 2, RiskLevel.INFO: 1}
    min_risk_value = risk_levels.get(min_risk, 2)

    # Perform scan
    all_findings = _scan_for_dangerous_calls()

    # Filter by risk level
    filtered_findings = [
        f for f in all_findings
        if risk_levels.get(f.risk_level, 0) >= min_risk_value
    ]

    # Filter by categories
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

    # Create summaries
    summary = {cat: len(findings) for cat, findings in findings_by_category.items()}

    risk_summary = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 0, RiskLevel.LOW: 0, RiskLevel.INFO: 0}
    for finding in filtered_findings:
        risk_summary[finding.risk_level] = risk_summary.get(finding.risk_level, 0) + 1

    # Create results
    results = ScanResults(
        binary_name=binary_name,
        binary_path=binary_path or "",
        scan_time=datetime.now().isoformat(),
        total_findings=len(filtered_findings),
        findings_by_category=findings_by_category,
        summary=summary,
        risk_summary=risk_summary
    )

    results_file = _save_results_to_file(results, output_dir)

    return {
        "status": "completed",
        "binary_name": binary_name,
        "total_findings": len(filtered_findings),
        "summary_by_category": summary,
        "risk_summary": risk_summary,
        "categories": list(findings_by_category.keys()),
        "risk_filter": min_risk,
        "results_file": results_file,
        "hint": "Use vuln_scan_details(category) to get detailed findings for a specific category."
    }


@tool
@idasync
def vuln_scan_details(
    category: Annotated[str, "Vulnerability category to get details for"],
    limit: Annotated[int, "Maximum number of findings to return (default: 20)"] = 20,
    offset: Annotated[int, "Skip first N findings (default: 0)"] = 0,
    risk_level: Annotated[Optional[str], "Filter by risk level: High, Medium, Low, Info"] = None,
) -> dict:
    """Get detailed findings for a specific vulnerability category

    After running vuln_scan(), use this tool to get detailed information about
    findings in a specific category including:
    - Caller function name and address
    - Call site address
    - Parameter analysis (constant vs variable)
    - Format string analysis (for format string bugs)
    - Risk assessment with reasoning

    Returns:
        Detailed findings with parameter analysis and risk assessment
    """
    binary_path = idc.get_input_file_path()
    binary_name = os.path.basename(binary_path) if binary_path else "unknown"

    all_findings = _scan_for_dangerous_calls()

    category_lower = category.lower()
    filtered = [f for f in all_findings if f.category.lower() == category_lower]

    if risk_level:
        filtered = [f for f in filtered if f.risk_level.lower() == risk_level.lower()]

    total = len(filtered)
    paginated = filtered[offset:offset + limit]
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

    Analyzes a single function for calls to dangerous functions including:
    - All vulnerability categories
    - Parameter analysis
    - Risk assessment

    Useful for targeted analysis after identifying interesting functions.

    Returns:
        List of dangerous function calls within the specified function
    """
    try:
        func_ea = parse_address(addr)
        func = idaapi.get_func(func_ea)
        if not func:
            return {"addr": addr, "error": "Function not found", "findings": []}

        func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"

        all_findings = _scan_for_dangerous_calls()

        func_findings = [
            f.to_dict() for f in all_findings
            if f.caller_addr == hex(func.start_ea)
        ]

        # Sort by risk level
        risk_order = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2, RiskLevel.INFO: 3}
        func_findings.sort(key=lambda x: risk_order.get(x.get("risk_level", "Info"), 4))

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
    """List all vulnerability categories and associated dangerous functions

    Returns comprehensive information about:
    - All vulnerability categories
    - Dangerous functions in each category
    - Detection rules used for each function
    - Total number of dangerous functions tracked
    """
    categories: dict[str, list[dict]] = {}

    for func_name, info in DANGEROUS_FUNCTIONS.items():
        cat = info["category"]
        if cat not in categories:
            categories[cat] = []

        rule_type = info.get("rule_type", RuleType.PARAM_NOT_CONST)
        categories[cat].append({
            "name": func_name,
            "rule_type": rule_type.value if isinstance(rule_type, RuleType) else str(rule_type),
            "description": info.get("desc", "")
        })

    # Sort functions within each category
    for cat in categories:
        categories[cat].sort(key=lambda x: x["name"])

    category_summary = {cat: len(funcs) for cat, funcs in categories.items()}

    return {
        "categories": list(categories.keys()),
        "category_summary": category_summary,
        "functions_by_category": categories,
        "total_dangerous_functions": len(DANGEROUS_FUNCTIONS),
        "rule_types": [rt.value for rt in RuleType]
    }