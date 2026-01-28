"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.

Multi-instance support:
- When started, the plugin registers with the Gateway Server
- If Gateway is not running, it starts one automatically
- Each IDA instance gets a unique port assigned by the Gateway
"""

import os
import sys
import json
import socket
import subprocess
import time
import http.client
import idaapi
import idc
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from . import ida_mcp

# Gateway configuration
GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 13337
LEGACY_MODE = os.environ.get("IDA_MCP_LEGACY", "0") == "1"


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


def is_port_in_use(port: int, host: str = GATEWAY_HOST) -> bool:
    """Check if a port is in use"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0


def start_gateway_process() -> bool:
    """Start the Gateway Server as a detached process
    
    Returns:
        True if Gateway is available after starting
    """
    # Find the gateway module
    try:
        from ida_pro_mcp import gateway
        gateway_script = gateway.__file__
    except ImportError:
        # Try to find it relative to this file
        script_dir = os.path.dirname(os.path.realpath(__file__))
        gateway_script = os.path.join(script_dir, "gateway.py")
        if not os.path.exists(gateway_script):
            print("[MCP] Gateway script not found")
            return False
    
    print(f"[MCP] Starting Gateway Server...")
    
    if sys.platform == 'win32':
        # Windows: use CREATE_NEW_PROCESS_GROUP and DETACHED_PROCESS
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        DETACHED_PROCESS = 0x00000008
        subprocess.Popen(
            [sys.executable, gateway_script],
            creationflags=CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
            close_fds=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        # Unix: use start_new_session for daemon
        subprocess.Popen(
            [sys.executable, gateway_script],
            start_new_session=True,
            close_fds=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    
    # Wait for Gateway to start
    for _ in range(50):  # Max 5 seconds
        if is_port_in_use(GATEWAY_PORT):
            print("[MCP] Gateway Server started")
            return True
        time.sleep(0.1)
    
    print("[MCP] Failed to start Gateway Server")
    return False


def ensure_gateway_running() -> bool:
    """Ensure Gateway Server is running
    
    Returns:
        True if Gateway is available
    """
    if is_port_in_use(GATEWAY_PORT):
        return True
    return start_gateway_process()


def register_with_gateway(binary_name: str, binary_path: str, metadata: Optional[dict] = None) -> Optional[dict]:
    """Register this IDA instance with the Gateway
    
    Args:
        binary_name: Name of the binary file
        binary_path: Full path to the binary
        metadata: Additional metadata
    
    Returns:
        Registration response or None on failure
    """
    try:
        conn = http.client.HTTPConnection(GATEWAY_HOST, GATEWAY_PORT, timeout=5)
        data = json.dumps({
            "binary_name": binary_name,
            "binary_path": binary_path,
            "metadata": metadata or {},
        })
        conn.request("POST", "/gateway/register", data, {"Content-Type": "application/json"})
        response = conn.getresponse()
        result = json.loads(response.read())
        conn.close()
        return result
    except Exception as e:
        print(f"[MCP] Failed to register with Gateway: {e}")
        return None


def unregister_from_gateway(instance_id: str) -> bool:
    """Unregister this IDA instance from the Gateway
    
    Args:
        instance_id: The instance ID to unregister
    
    Returns:
        True if successful
    """
    try:
        conn = http.client.HTTPConnection(GATEWAY_HOST, GATEWAY_PORT, timeout=5)
        data = json.dumps({"instance_id": instance_id})
        conn.request("POST", "/gateway/unregister", data, {"Content-Type": "application/json"})
        response = conn.getresponse()
        result = json.loads(response.read())
        conn.close()
        return result.get("success", False)
    except Exception as e:
        print(f"[MCP] Failed to unregister from Gateway: {e}")
        return False


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    # Configuration
    HOST = "127.0.0.1"
    LEGACY_PORT = 13337  # Used in legacy mode

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if sys.platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.instance_id: Optional[str] = None
        self.port: Optional[int] = None
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        # Stop existing server if running
        if self.mcp:
            self._stop_server()

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches

        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        # Get binary info
        binary_path = idc.get_input_file_path()
        binary_name = os.path.basename(binary_path) if binary_path else "unknown"
        
        # Collect metadata (compatible with IDA 8.x and 9.x)
        try:
            # IDA 9.0+ uses ida_ida module
            import ida_ida
            processor = ida_ida.inf_get_procname()
        except (ImportError, AttributeError):
            # IDA 8.x uses get_inf_structure()
            try:
                processor = idaapi.get_inf_structure().procname
            except AttributeError:
                processor = "unknown"
        
        try:
            bits = 64 if idaapi.inf_is_64bit() else 32
        except AttributeError:
            bits = 64  # Default to 64-bit
        
        try:
            base_addr = hex(idaapi.get_imagebase())
        except AttributeError:
            base_addr = "0x0"
        
        metadata = {
            "processor": processor,
            "bits": bits,
            "base_addr": base_addr,
        }

        if LEGACY_MODE:
            # Legacy mode: use fixed port, no Gateway
            self._start_legacy_mode(MCP_SERVER, IdaMcpHttpRequestHandler)
        else:
            # Multi-instance mode: register with Gateway
            self._start_gateway_mode(MCP_SERVER, IdaMcpHttpRequestHandler, binary_name, binary_path, metadata)

    def _start_legacy_mode(self, mcp_server, request_handler):
        """Start in legacy mode with fixed port"""
        print("[MCP] Starting in legacy mode (single instance)")
        try:
            mcp_server.serve(
                self.HOST, self.LEGACY_PORT, request_handler=request_handler
            )
            print(f"  Config: http://{self.HOST}:{self.LEGACY_PORT}/config.html")
            self.mcp = mcp_server
            self.port = self.LEGACY_PORT
        except OSError as e:
            if e.errno in (48, 98, 10048):  # Address already in use
                print(f"[MCP] Error: Port {self.LEGACY_PORT} is already in use")
            else:
                raise

    def _start_gateway_mode(self, mcp_server, request_handler, binary_name: str, binary_path: str, metadata: dict):
        """Start in multi-instance mode with Gateway"""
        # Ensure Gateway is running
        if not ensure_gateway_running():
            print("[MCP] Gateway not available, falling back to legacy mode")
            self._start_legacy_mode(mcp_server, request_handler)
            return
        
        # Register with Gateway
        result = register_with_gateway(binary_name, binary_path, metadata)
        if not result or not result.get("success"):
            error = result.get("error", "Unknown error") if result else "Connection failed"
            print(f"[MCP] Registration failed: {error}, falling back to legacy mode")
            self._start_legacy_mode(mcp_server, request_handler)
            return
        
        self.instance_id = result["instance_id"]
        self.port = result["port"]
        
        print(f"[MCP] Registered as instance '{self.instance_id}'")
        
        # Start server on assigned port
        try:
            mcp_server.serve(
                self.HOST, self.port, request_handler=request_handler
            )
            print(f"[MCP] Server started:")
            print(f"  Instance ID: {self.instance_id}")
            print(f"  Binary: {binary_name}")
            print(f"  Direct URL: http://{self.HOST}:{self.port}/mcp")
            print(f"  Gateway URL: http://{GATEWAY_HOST}:{GATEWAY_PORT}/mcp")
            print(f"  Config: http://{self.HOST}:{self.port}/config.html")
            self.mcp = mcp_server
        except OSError as e:
            if e.errno in (48, 98, 10048):  # Address already in use
                print(f"[MCP] Error: Port {self.port} is already in use")
                # Try to unregister since we couldn't start
                if self.instance_id:
                    unregister_from_gateway(self.instance_id)
                    self.instance_id = None
            else:
                raise

    def _stop_server(self):
        """Stop the MCP server and unregister from Gateway"""
        if self.mcp:
            self.mcp.stop()
            self.mcp = None
        
        if self.instance_id:
            unregister_from_gateway(self.instance_id)
            print(f"[MCP] Unregistered instance '{self.instance_id}'")
            self.instance_id = None
        
        self.port = None

    def term(self):
        self._stop_server()


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
