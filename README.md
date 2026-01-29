# IDA Pro MCP Multi

[English](README.md) | [中文](README_zh-CN.md)

> 📌 **Based on**: This project is developed based on [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp), extending it with multi-instance support and vulnerability scanning capabilities.

A powerful [MCP Server](https://modelcontextprotocol.io/introduction) for AI-assisted reverse engineering in IDA Pro, with support for analyzing multiple binaries simultaneously.

## Why This Project?

The original [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) is an excellent tool for AI-assisted reverse engineering, but we encountered limitations in real-world scenarios:

### Problem 1: Single Instance Limitation

When reverse engineering complex software, you often need to analyze multiple related binaries:
- A main executable (`main.exe`)
- Multiple DLLs/shared libraries (`helper.dll`, `crypto.dll`, etc.)
- Third-party libraries

The original project only supports **one IDA instance at a time**, making cross-binary analysis tedious and inefficient.

### Problem 2: No Built-in Vulnerability Detection

Security researchers need to quickly identify potentially dangerous code patterns. Manually searching for vulnerable function calls is time-consuming.

## New Features

### 🔗 Multi-Instance Support

Analyze multiple binaries simultaneously with a Gateway architecture:

```
AI Client ──MCP──> Gateway (port 13337) ──> IDA Instance 1 (main.exe, port 13338)
                                        ──> IDA Instance 2 (helper.dll, port 13339)
                                        ──> IDA Instance 3 (crypto.dll, port 13340)
```

**How It Works:**

1. The first IDA instance automatically starts a **Gateway Server** (port 13337)
2. Each subsequent IDA instance registers with the Gateway and gets a unique port
3. AI clients connect to the Gateway, which routes requests to the appropriate instance

**Instance Management Tools:**

| Tool | Description |
|------|-------------|
| `list_instances()` | List all registered IDA instances |
| `switch_instance(target)` | Switch the default target instance (by ID or binary name) |
| `get_current_instance()` | Get info about the current default instance |
| `check_instance_health(target)` | Check if an instance is responding |

**Targeting Specific Instances:**

Most tools accept an optional `target` parameter:

```json
{
  "method": "decompile",
  "params": {
    "addr": "0x401000",
    "target": "helper.dll"
  }
}
```

**Legacy Mode:**

To disable multi-instance support:
```sh
IDA_MCP_LEGACY=1
```

### 🔍 Vulnerability Scanning

AI-assisted vulnerability scanning to identify potentially dangerous function calls:

**Tools:**

| Tool | Description |
|------|-------------|
| `vuln_scan(output_dir, categories, min_risk)` | Scan binary for vulnerabilities, returns summary |
| `vuln_scan_details(category, limit, offset, risk_level)` | Get detailed findings for a specific category |
| `vuln_scan_function(addr)` | Scan a specific function for vulnerability patterns |
| `vuln_categories()` | List all vulnerability categories and associated functions |

**Supported Vulnerability Categories:**

| Category | Dangerous Functions | Description |
|----------|---------------------|-------------|
| **Format String** | printf, sprintf, fprintf, etc. | Non-constant format strings |
| **Buffer Overflow** | strcpy, memcpy, gets, etc. | Unbounded copies, controllable sizes |
| **Command Injection** | system, popen, exec*, etc. | Non-constant commands |
| **Integer Overflow** | malloc, calloc, realloc | Potentially overflowing sizes |
| **Use After Free** | free() | Potential UAF/double-free |
| **Path Traversal** | fopen, open, etc. | Controllable paths |
| **SQL Injection** | sqlite3_exec, mysql_query | Non-constant SQL |

**Workflow:**

1. Ask AI to "scan for vulnerabilities"
2. AI calls `vuln_scan()` to get a summary by category
3. Review the summary and select categories for deep analysis
4. AI uses `vuln_scan_details(category)` and `decompile()` to analyze specific findings

**Note:** Detailed results are saved to `.ida-mcp-vuln/` folder to minimize token usage.

## Prerequisites

- [IDA Pro](https://hex-rays.com/ida-pro) (8.3 or higher, 9 recommended)
- Any MCP-compatible client (Claude, Cursor, VS Code, Roo Code, etc.)

## Installation

### For Users Who Have Installed the Original ida-pro-mcp

If you have previously installed the original [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp), you need to uninstall it first and then force reinstall:

```bash
# Uninstall old versions
"D:\your\path\to\ida\python311\python.exe" -m pip uninstall -y ida-pro-mcp ida-pro-mcp-multi

# Force reinstall the new version
"D:\your\path\to\ida\python311\python.exe" -m pip install --no-cache-dir --force-reinstall --upgrade git+https://github.com/QYmag1c/ida-pro-mcp-multi

# Reinstall IDA plugin and configure MCP clients
"D:\your\path\to\ida\python311\Scripts\ida-pro-mcp.exe" --install

# View MCP configuration
"D:\your\path\to\ida\python311\Scripts\ida-pro-mcp.exe" --config
```

Then restart IDA Pro and your MCP client.

---

### Fresh Installation

### Step 1: Set Environment Variable

Add IDA's Python `site-packages` directory to your environment variables:

**Windows:**
```
D:\your\path\to\ida\python311\Lib\site-packages
```

Add this path to your system's `PYTHONPATH` environment variable.

### Step 2: Install MCP Package

Open a terminal in IDA's Python directory and run:

```bash
# Navigate to IDA's Python directory
cd "D:\your\path\to\ida\python311"

# Install the MCP package
python.exe -m pip install --upgrade git+https://github.com/QYmag1c/ida-pro-mcp-multi
```

### Step 3: Install IDA Plugin and Configure MCP Clients

```bash
# Install IDA plugin and configure MCP clients
"D:\your\path\to\ida\python311\Scripts\ida-pro-mcp.exe" --install

# View MCP configuration for manual setup
"D:\your\path\to\ida\python311\Scripts\ida-pro-mcp.exe" --config
```

**Note:** Replace `D:\your\path\to\ida` with your actual IDA Pro installation path.

### Step 4: Restart

**Important**: Restart IDA Pro and your MCP client completely for the installation to take effect.

### Verify Installation

1. Open IDA Pro and load a binary
2. Go to **Edit → Plugins → MCP** (or press `Ctrl+Alt+M`)
3. You should see `[MCP] Server started` in the output window

## Architecture

```
src/ida_pro_mcp/
├── server.py              # MCP server + instance management tools
├── gateway.py             # Gateway Server for multi-instance routing
├── ida_mcp.py             # IDA plugin loader (registers with Gateway)
└── ida_mcp/
    ├── api_core.py        # Core functions (decompile, disasm, etc.)
    ├── api_analysis.py    # Analysis operations
    ├── api_vuln.py        # Vulnerability scanning (NEW)
    ├── api_memory.py      # Memory operations
    ├── api_types.py       # Type operations
    ├── api_modify.py      # Modification operations
    ├── api_stack.py       # Stack frame operations
    ├── api_debug.py       # Debugger operations
    └── ...
```

## All Available Tools

This project includes all tools from the original project, plus the new multi-instance and vulnerability scanning features.

### Instance Management (NEW)
- `list_instances()`, `switch_instance()`, `get_current_instance()`, `check_instance_health()`

### Vulnerability Scanning (NEW)
- `vuln_scan()`, `vuln_scan_details()`, `vuln_scan_function()`, `vuln_categories()`

### Core Functions
- `lookup_funcs()`, `int_convert()`, `list_funcs()`, `list_globals()`, `imports()`, `decompile()`, `disasm()`, `xrefs_to()`, `callees()`

### Modification Operations
- `set_comments()`, `patch_asm()`, `declare_type()`, `rename()`

### Memory Operations
- `get_bytes()`, `get_int()`, `get_string()`, `get_global_value()`, `patch()`, `put_int()`

### Analysis Operations
- `py_eval()`, `analyze_funcs()`, `find_regex()`, `find_bytes()`, `find_insns()`, `find()`, `basic_blocks()`, `callgraph()`

### Type Operations
- `set_type()`, `infer_types()`, `read_struct()`, `search_structs()`

### Stack Operations
- `stack_frame()`, `declare_stack()`, `delete_stack()`

### Debugger Operations (requires `--unsafe` flag)
- `dbg_start()`, `dbg_exit()`, `dbg_continue()`, `dbg_step_into()`, `dbg_step_over()`, etc.

## Acknowledgments

- Original project: [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)

## License

MIT License - See [LICENSE](LICENSE) for details.
