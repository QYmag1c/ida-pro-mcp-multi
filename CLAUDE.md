# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

IDA Pro MCP Server - enables LLM-assisted reverse engineering by bridging IDA Pro with Model Context Protocol clients through a JSON-RPC HTTP server.

**Architecture**: Multi-instance Gateway design
- **MCP Server** (`server.py`): Python >=3.11, runs via `uv`, proxies to Gateway
- **Gateway Server** (`gateway.py`): Routes requests to multiple IDA instances (port 13337)
- **IDA Plugin** (`ida_mcp.py`): Runs inside IDA Pro, registers with Gateway, exposes MCP server over HTTP (ports 13338+)

```
AI Client ──MCP──> Gateway (port 13337) ──> IDA Instance 1 (port 13338)
                                        ──> IDA Instance 2 (port 13339)
                                        ──> IDA Instance N (port 1333N+1)
```

## Development Commands

### Testing MCP Server
```bash
# Interactive MCP inspector (web UI at http://localhost:5173)
uv run mcp dev src/ida_pro_mcp/server.py
```

### Installation
```bash
# Install package + configure all MCP clients + install IDA plugin
pip install https://github.com/mrexodia/ida-pro-mcp/archive/refs/heads/main.zip
ida-pro-mcp --install

# Manual plugin install (creates symlinks or copies to IDA plugins folder)
uv run ida-pro-mcp --install

# Uninstall everything
uv run ida-pro-mcp --uninstall
```

### Running
```bash
# Standard stdio transport (used by most MCP clients)
uv run ida-pro-mcp

# SSE transport for headless/remote use
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse

# Headless mode with idalib (no GUI)
uv run idalib-mcp --host 127.0.0.1 --port 8745 path/to/binary

# Enable unsafe debugger functions
uv run ida-pro-mcp --unsafe
```

### Changelog Generation
```bash
# Direct commits to main since tag
git log --first-parent --no-merges 1.2.0..main "--pretty=- %s"
```

## Architecture Deep Dive

### Plugin Architecture (ida_mcp/)

**Modular API**: 9 specialized modules
- `api_core.py`: IDB metadata, function/string/import listing
- `api_analysis.py`: Decompilation, disassembly, xrefs, paths, patterns
- `api_memory.py`: Read bytes/integers/strings, patch operations
- `api_types.py`: Structures, type inference, type application
- `api_modify.py`: Comments, assembly patching, renaming
- `api_stack.py`: Stack frame operations
- `api_debug.py`: Debugger control (unsafe, requires `--unsafe` flag)
- `api_python.py`: Python code execution in IDA context
- `api_resources.py`: MCP resources (24 URI patterns for RESTful access via `ida://` URIs)

**Infrastructure**:
- `rpc.py`: JSON-RPC registry + type checking (`@tool`, `@resource`, `@unsafe` decorators)
- `sync.py`: IDA thread synchronization (`@idasync` decorator)
- `zeromcp/mcp.py`: HTTP/SSE server implementation (Streamable HTTP + SSE transports)
- `utils.py`: TypedDict schemas, address parsing, pagination helpers

**Vulnerability Scanning** (`api_vuln.py`):
- `vuln_scan()`: Scan binary for dangerous function calls
- `vuln_scan_details()`: Get detailed findings by category
- `vuln_scan_function()`: Scan specific function
- `vuln_categories()`: List supported vulnerability categories

### Decorator Chain Pattern

Every API function follows this pattern:
```python
@tool             # 1. Register MCP tool
@idasync          # 2. Execute on IDA's main thread
def my_api(param: Annotated[str, "description"]) -> ReturnType:
    """Docstring becomes MCP tool description"""
    # Implementation uses IDA SDK
```

### Thread Safety

**All IDA SDK calls MUST run on main thread** - enforced by `@idasync`:
- Use `@idasync` for all IDA SDK operations (both read and write)
- Implementation: `sync_wrapper()` uses `idaapi.execute_sync()` with queue-based result passing

### Type Annotations

**Batch-first API convention**: Most functions accept `str` (comma-separated) OR `list`:
```python
def my_api(addrs: Annotated[str, "Addresses (0x401000, 0x402000) or list"]):
    parsed = normalize_list_input(addrs)  # Handles both formats
```

**Annotated types**: Description text becomes MCP parameter description
```python
count: Annotated[int, "Maximum number of results"]
```

## Adding New API Functions

### Step-by-step

1. Choose the appropriate `api_*.py` file (or create new one following `api_*.py` pattern)
2. Import required IDA SDK modules and decorators:
   ```python
   from .rpc import tool
   from .sync import idasync
   ```
3. Define function with full type hints:
   ```python
   @tool
   @idasync
   def my_function(param: Annotated[str, "param description"]) -> dict:
       """Tool description (first line used in MCP schema)"""
       # Use IDA SDK here
       return {"result": value}
   ```
4. Test with MCP inspector: `uv run mcp dev src/ida_pro_mcp/server.py`

**No other changes needed** - AST parsing auto-discovers and registers the function.

### Unsafe Functions

Mark debugger operations or destructive actions as unsafe:
```python
@unsafe           # Requires --unsafe flag
@tool
@idasync
def dangerous_op():
    pass
```

### MCP Resources

Expose RESTful URI-based access to IDA data using `@resource`:
```python
@resource(uri="ida://functions/{pattern}")
@idasync
def functions_resource(pattern: str = "*") -> list[dict]:
    """Get functions matching pattern via ida://functions/pattern URI"""
    # Return data accessible via MCP resource protocol
    return filtered_functions
```

Resources provide read-only access to IDA data via URI patterns. All resources use `@idasync`.

## Common Patterns

### Address Parsing
```python
addr = parse_address(input_str)  # Handles hex, decimal, function names
```

### Batch Operations
```python
addrs = normalize_list_input(input)  # "0x401000, main" -> [0x401000, 0x140001000]
results = []
for addr in addrs:
    try:
        results.append({"addr": addr, "data": process(addr), "error": None})
    except Exception as e:
        results.append({"addr": addr, "error": str(e)})
return results
```

### Pagination
```python
from .utils import paginate, Page

@tool
@idasync
def list_items(queries: Annotated[str, "offset:count or pattern"]) -> Page:
    all_items = get_all_items()
    return paginate(all_items, queries)
```

### Pattern Filtering
```python
from .utils import pattern_filter

filtered = pattern_filter(items, "name", pattern)  # Glob-style matching
```

## Testing Workflow

1. **Install plugin symlink**: `uv run ida-pro-mcp --install` (one-time)
2. **Load binary in IDA**: Plugin appears under Edit → Plugins → MCP (Ctrl+Alt+M)
3. **Start MCP server**: Click plugin menu item or hotkey
4. **Test via MCP inspector**: `uv run mcp dev src/ida_pro_mcp/server.py`
5. **Direct JSON-RPC testing**: POST to `http://localhost:13337/mcp`:
   ```json
   {"jsonrpc": "2.0", "method": "my_function", "params": ["arg"], "id": 1}
   ```

## Error Handling

- **IDAError**: Raised for IDA-specific errors (function not found, invalid address)
- **JSONRPCError**: Protocol-level errors (invalid params, method not found)
- **IDASyncError**: Thread synchronization failures (should never happen in production)

## Transport Modes

1. **stdio** (default): Standard MCP client transport
2. **Streamable HTTP**: `POST /mcp` with `Mcp-Session-Id` header
3. **SSE**: `GET /sse` for connection, `POST /sse?session=X` for requests

Server auto-negotiates based on client request.

## Prompting Best Practices

**Critical for LLM accuracy**:
- Always use `int_convert` tool for number base conversions (LLMs hallucinate on hex/decimal)
- Remove obfuscation before LLM analysis (string encryption, control flow flattening)
- Use FLIRT/Lumina to resolve library functions first
- Avoid asking LLM to brute force - derive solutions from disassembly

**Recommended prompt template** (from README:169-182):
> - Inspect decompilation and add comments
> - Rename variables to sensible names
> - Change types if necessary (especially pointers/arrays)
> - NEVER convert number bases yourself - use `int_convert` MCP tool
> - Do not brute force - derive solutions from disassembly

## File Structure

```
src/ida_pro_mcp/
├── server.py              # MCP server + instance management tools + installer
├── gateway.py             # Gateway Server for multi-instance routing
├── idalib_server.py       # Headless idalib support
├── ida_mcp.py             # IDA plugin loader (registers with Gateway)
└── ida_mcp/
    ├── __init__.py        # Package exports
    ├── rpc.py             # JSON-RPC registry
    ├── sync.py            # IDA thread sync
    ├── utils.py           # Shared helpers
    ├── http.py            # IDA-specific HTTP handler
    ├── zeromcp/           # Vendored MCP server implementation
    │   ├── mcp.py         # HTTP/SSE server
    │   └── jsonrpc.py     # JSON-RPC protocol
    └── api_*.py           # Modular API implementations
```

## Multi-Instance Architecture

### Gateway Server (`gateway.py`)

The Gateway Server manages multiple IDA instances:

- **Auto-start**: First IDA instance spawns Gateway as detached process
- **Port allocation**: Gateway assigns ports 13338-13400 to IDA instances
- **Request routing**: Routes requests based on `target` parameter
- **Auto-shutdown**: Closes 30s after all instances unregister

### Instance Management Tools (in `server.py`)

```python
@mcp.tool
def list_instances() -> dict:
    """List all registered IDA instances"""

@mcp.tool
def switch_instance(target: str) -> dict:
    """Switch default target instance"""

@mcp.tool
def get_current_instance() -> dict:
    """Get current default instance info"""

@mcp.tool
def check_instance_health(target: str = None) -> dict:
    """Check if instance is responding"""
```

### IDA Plugin Registration (`ida_mcp.py`)

On startup:
1. Check if Gateway is running (port 13337)
2. If not, spawn Gateway as detached process
3. Register with Gateway, receive assigned port
4. Start HTTP server on assigned port

On shutdown:
1. Unregister from Gateway
2. Stop HTTP server

### Legacy Mode

Set `IDA_MCP_LEGACY=1` to disable Gateway and use fixed port 13337 (single instance).

## Installation Mechanics

**Plugin installation**:
- Tries symlink first (development-friendly)
- Falls back to copy on Windows/permission issues
- Installs both `ida_mcp.py` (loader) and `ida_mcp/` (package)

**MCP client configuration**:
- Auto-detects Cline/Roo Code/Claude/Cursor/Windsurf/etc config paths
- Injects server config into JSON/TOML files
- Sets `autoApprove`/`alwaysAllow` for safe functions (non-debugger)

## Python Version Requirements

- **Server**: Python >=3.11 (uses vendored zeromcp MCP implementation)
- **Plugin**: Python >=3.11
- **IDA Pro**: 8.3+ (9.0 recommended), **IDA Free not supported** (no plugin API)

Use `idapyswitch` to upgrade IDA's Python interpreter if needed.
