"""IDA Pro MCP Gateway Server

This module implements a Gateway Server that manages multiple IDA Pro instances.
It acts as a single entry point for AI clients, routing requests to the appropriate
IDA instance based on the target parameter.

Architecture:
    AI Client <--MCP--> Gateway (port 13337) <--JSON-RPC--> IDA Instances (ports 13338+)
"""

import os
import sys
import json
import time
import socket
import signal
import logging
import argparse
import threading
import http.client
from datetime import datetime
from dataclasses import dataclass, field
from typing import Any, Optional
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[Gateway] %(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Constants
GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 13337
INSTANCE_PORT_START = 13338
INSTANCE_PORT_END = 13400
SHUTDOWN_DELAY = 30  # seconds to wait before shutdown when no instances


@dataclass
class IDAInstance:
    """Represents a registered IDA Pro instance"""
    instance_id: str
    binary_name: str
    binary_path: str
    port: int
    registered_at: datetime = field(default_factory=datetime.now)
    metadata: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "instance_id": self.instance_id,
            "binary_name": self.binary_name,
            "binary_path": self.binary_path,
            "port": self.port,
            "registered_at": self.registered_at.isoformat(),
            "metadata": self.metadata,
        }


class InstanceRegistry:
    """Thread-safe registry for IDA instances"""
    
    def __init__(self):
        self._instances: dict[str, IDAInstance] = {}
        self._current_instance_id: Optional[str] = None
        self._lock = threading.RLock()
        self._next_port = INSTANCE_PORT_START
        self._instance_counter = 0
    
    def _allocate_port(self) -> int:
        """Allocate the next available port"""
        with self._lock:
            # Find next available port
            used_ports = {inst.port for inst in self._instances.values()}
            for port in range(INSTANCE_PORT_START, INSTANCE_PORT_END + 1):
                if port not in used_ports and not self._is_port_in_use(port):
                    return port
            raise RuntimeError("No available ports in range")
    
    def _is_port_in_use(self, port: int) -> bool:
        """Check if a port is already in use"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex((GATEWAY_HOST, port)) == 0
    
    def _generate_instance_id(self) -> str:
        """Generate a unique instance ID"""
        with self._lock:
            self._instance_counter += 1
            base_id = f"ida_{self._instance_counter}"
            # Ensure uniqueness
            while base_id in self._instances:
                self._instance_counter += 1
                base_id = f"ida_{self._instance_counter}"
            return base_id
    
    def register(
        self,
        binary_name: str,
        binary_path: str,
        preferred_port: Optional[int] = None,
        preferred_id: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> IDAInstance:
        """Register a new IDA instance"""
        with self._lock:
            # Allocate port
            if preferred_port and preferred_port not in {i.port for i in self._instances.values()}:
                if not self._is_port_in_use(preferred_port):
                    port = preferred_port
                else:
                    port = self._allocate_port()
            else:
                port = self._allocate_port()
            
            # Generate instance ID
            if preferred_id and preferred_id not in self._instances:
                instance_id = preferred_id
            else:
                instance_id = self._generate_instance_id()
            
            # Create instance
            instance = IDAInstance(
                instance_id=instance_id,
                binary_name=binary_name,
                binary_path=binary_path,
                port=port,
                metadata=metadata or {},
            )
            
            self._instances[instance_id] = instance
            
            # Set as current if first instance
            if self._current_instance_id is None:
                self._current_instance_id = instance_id
            
            logger.info(f"Registered instance: {instance_id} ({binary_name}) on port {port}")
            return instance
    
    def unregister(self, instance_id: str) -> bool:
        """Unregister an IDA instance"""
        with self._lock:
            if instance_id not in self._instances:
                return False
            
            instance = self._instances.pop(instance_id)
            logger.info(f"Unregistered instance: {instance_id} ({instance.binary_name})")
            
            # Update current instance if needed
            if self._current_instance_id == instance_id:
                if self._instances:
                    self._current_instance_id = next(iter(self._instances.keys()))
                else:
                    self._current_instance_id = None
            
            return True
    
    def get(self, instance_id: str) -> Optional[IDAInstance]:
        """Get an instance by ID"""
        with self._lock:
            return self._instances.get(instance_id)
    
    def get_by_name(self, binary_name: str) -> Optional[IDAInstance]:
        """Get an instance by binary name"""
        with self._lock:
            for instance in self._instances.values():
                if instance.binary_name == binary_name:
                    return instance
            return None
    
    def get_current(self) -> Optional[IDAInstance]:
        """Get the current default instance"""
        with self._lock:
            if self._current_instance_id:
                return self._instances.get(self._current_instance_id)
            return None
    
    def set_current(self, instance_id: str) -> bool:
        """Set the current default instance"""
        with self._lock:
            if instance_id in self._instances:
                self._current_instance_id = instance_id
                return True
            return False
    
    def list_all(self) -> list[dict]:
        """List all registered instances"""
        with self._lock:
            return [
                {**inst.to_dict(), "is_current": inst.instance_id == self._current_instance_id}
                for inst in self._instances.values()
            ]
    
    def is_empty(self) -> bool:
        """Check if registry is empty"""
        with self._lock:
            return len(self._instances) == 0
    
    def count(self) -> int:
        """Get number of registered instances"""
        with self._lock:
            return len(self._instances)


# Global registry
registry = InstanceRegistry()


class GatewayRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Gateway Server"""
    
    server_version = "ida-mcp-gateway/1.0.0"
    
    def log_message(self, format, *args):
        """Override to use our logger"""
        logger.debug(f"{self.address_string()} - {format % args}")
    
    def send_json_response(self, status: int, data: Any):
        """Send a JSON response"""
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)
    
    def send_error_response(self, status: int, message: str):
        """Send an error response"""
        self.send_json_response(status, {"error": message})
    
    def _send_cors_headers(self):
        """Send CORS headers for localhost"""
        origin = self.headers.get("Origin", "")
        if origin:
            parsed = urlparse(origin)
            if parsed.hostname in ("localhost", "127.0.0.1", "::1"):
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")
    
    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests"""
        path = urlparse(self.path).path
        
        if path == "/gateway/instances":
            self._handle_list_instances()
        elif path == "/gateway/status":
            self._handle_status()
        elif path == "/sse":
            # SSE endpoint - proxy to current instance
            self._proxy_sse_request()
        else:
            self.send_error_response(404, "Not Found")
    
    def do_POST(self):
        """Handle POST requests"""
        path = urlparse(self.path).path
        
        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        
        if path == "/gateway/register":
            self._handle_register(body)
        elif path == "/gateway/unregister":
            self._handle_unregister(body)
        elif path == "/gateway/switch":
            self._handle_switch(body)
        elif path == "/mcp":
            self._handle_mcp_request(body)
        elif path == "/sse":
            # SSE POST - proxy to current instance
            self._proxy_sse_post(body)
        else:
            self.send_error_response(404, "Not Found")
    
    def _handle_register(self, body: bytes):
        """Handle instance registration"""
        try:
            data = json.loads(body)
            binary_name = data.get("binary_name", "unknown")
            binary_path = data.get("binary_path", "")
            preferred_port = data.get("preferred_port")
            preferred_id = data.get("preferred_id")
            metadata = data.get("metadata", {})
            
            instance = registry.register(
                binary_name=binary_name,
                binary_path=binary_path,
                preferred_port=preferred_port,
                preferred_id=preferred_id,
                metadata=metadata,
            )
            
            self.send_json_response(200, {
                "success": True,
                "instance_id": instance.instance_id,
                "port": instance.port,
                "gateway_url": f"http://{GATEWAY_HOST}:{GATEWAY_PORT}",
            })
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            self.send_error_response(500, str(e))
    
    def _handle_unregister(self, body: bytes):
        """Handle instance unregistration"""
        try:
            data = json.loads(body)
            instance_id = data.get("instance_id")
            
            if not instance_id:
                self.send_error_response(400, "Missing instance_id")
                return
            
            if registry.unregister(instance_id):
                self.send_json_response(200, {"success": True})
            else:
                self.send_error_response(404, f"Instance not found: {instance_id}")
        except Exception as e:
            logger.error(f"Unregistration failed: {e}")
            self.send_error_response(500, str(e))
    
    def _handle_switch(self, body: bytes):
        """Handle switching the current default instance"""
        try:
            data = json.loads(body)
            target = data.get("target")
            
            if not target:
                self.send_error_response(400, "Missing target parameter")
                return
            
            # Try to find by ID first, then by name
            instance = registry.get(target) or registry.get_by_name(target)
            if not instance:
                self.send_json_response(200, {
                    "success": False,
                    "error": f"Instance not found: {target}",
                    "available_instances": [
                        {"id": inst["instance_id"], "binary": inst["binary_name"]}
                        for inst in registry.list_all()
                    ]
                })
                return
            
            # Set as current instance
            if registry.set_current(instance.instance_id):
                logger.info(f"Switched current instance to: {instance.instance_id} ({instance.binary_name})")
                self.send_json_response(200, {
                    "success": True,
                    "message": f"Switched to instance '{instance.instance_id}' ({instance.binary_name})",
                    "instance": instance.to_dict()
                })
            else:
                self.send_json_response(200, {
                    "success": False,
                    "error": f"Failed to switch to instance: {target}"
                })
        except Exception as e:
            logger.error(f"Switch failed: {e}")
            self.send_error_response(500, str(e))
    
    def _handle_list_instances(self):
        """Handle list instances request"""
        instances = registry.list_all()
        current = registry.get_current()
        self.send_json_response(200, {
            "instances": instances,
            "count": len(instances),
            "current_instance_id": current.instance_id if current else None,
        })
    
    def _handle_status(self):
        """Handle status request"""
        self.send_json_response(200, {
            "status": "running",
            "instance_count": registry.count(),
            "gateway_port": GATEWAY_PORT,
        })
    
    def _handle_mcp_request(self, body: bytes):
        """Handle MCP request - route to appropriate instance"""
        try:
            # Parse request to check for target parameter
            request = json.loads(body)
            target = None
            
            # Instance management tools that should be handled by Gateway, not forwarded
            INSTANCE_MANAGEMENT_TOOLS = (
                "list_instances",
                "switch_instance",
                "get_current_instance",
                "check_instance_health",
                "open_library",
            )
            
            # Check if this is a tools/call request
            if request.get("method") == "tools/call":
                params = request.get("params", {})
                if isinstance(params, dict):
                    tool_name = params.get("name", "")
                    arguments = params.get("arguments", {})
                    
                    # Handle instance management tools locally
                    if tool_name in INSTANCE_MANAGEMENT_TOOLS:
                        self._handle_instance_management_tool(request, tool_name, arguments)
                        return
                    
                    # For other tools, extract target parameter for routing
                    if isinstance(arguments, dict):
                        target = arguments.pop("target", None)
                        # Update the request with modified arguments
                        if not arguments:
                            params.pop("arguments", None)
                        body = json.dumps(request).encode("utf-8")
            
            # Determine target instance
            instance = None
            if target:
                # Try to find by ID first, then by name
                instance = registry.get(target) or registry.get_by_name(target)
                if not instance:
                    self._send_mcp_error(request.get("id"), f"Instance not found: {target}")
                    return
            else:
                instance = registry.get_current()
                if not instance:
                    self._send_mcp_error(request.get("id"), "No IDA instance available. Start IDA and enable the MCP plugin.")
                    return
            
            # Forward request to instance
            self._forward_to_instance(instance, body, request.get("id"))
            
        except json.JSONDecodeError as e:
            self.send_error_response(400, f"Invalid JSON: {e}")
        except Exception as e:
            logger.error(f"MCP request failed: {e}")
            self.send_error_response(500, str(e))
    
    def _handle_instance_management_tool(self, request: dict, tool_name: str, arguments: dict):
        """Handle instance management tools locally in Gateway"""
        request_id = request.get("id")
        
        try:
            if tool_name == "list_instances":
                result = self._tool_list_instances()
            elif tool_name == "switch_instance":
                target = arguments.get("target")
                if not target:
                    self._send_mcp_error(request_id, "Missing required parameter: target")
                    return
                result = self._tool_switch_instance(target)
            elif tool_name == "get_current_instance":
                result = self._tool_get_current_instance()
            elif tool_name == "check_instance_health":
                target = arguments.get("target")
                result = self._tool_check_instance_health(target)
            elif tool_name == "open_library":
                name = arguments.get("name")
                if not name:
                    self._send_mcp_error(request_id, "Missing required parameter: name")
                    return
                search_dir = arguments.get("search_dir")
                ida_path = arguments.get("ida_path")
                result = self._tool_open_library(name, search_dir, ida_path)
            else:
                self._send_mcp_error(request_id, f"Unknown instance management tool: {tool_name}")
                return
            
            # Send successful response
            self.send_json_response(200, {
                "jsonrpc": "2.0",
                "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]},
                "id": request_id,
            })
        except Exception as e:
            logger.error(f"Instance management tool {tool_name} failed: {e}")
            self._send_mcp_error(request_id, str(e))
    
    def _tool_list_instances(self) -> dict:
        """List all registered IDA instances"""
        instances = registry.list_all()
        current = registry.get_current()
        return {
            "instances": instances,
            "count": len(instances),
            "current_instance_id": current.instance_id if current else None,
        }
    
    def _tool_switch_instance(self, target: str) -> dict:
        """Switch the current default instance"""
        # Try to find by ID first, then by name
        instance = registry.get(target) or registry.get_by_name(target)
        if not instance:
            return {
                "success": False,
                "error": f"Instance not found: {target}",
                "available_instances": [
                    {"id": inst["instance_id"], "binary": inst["binary_name"]}
                    for inst in registry.list_all()
                ]
            }
        
        # Set as current instance
        if registry.set_current(instance.instance_id):
            logger.info(f"Switched current instance to: {instance.instance_id} ({instance.binary_name})")
            return {
                "success": True,
                "message": f"Switched to instance '{instance.instance_id}' ({instance.binary_name})",
                "instance": instance.to_dict()
            }
        else:
            return {
                "success": False,
                "error": f"Failed to switch to instance: {target}"
            }
    
    def _tool_get_current_instance(self) -> dict:
        """Get information about the current default instance"""
        current = registry.get_current()
        if not current:
            return {"error": "No IDA instance available"}
        
        return {
            "instance": {**current.to_dict(), "is_current": True},
            "total_instances": registry.count()
        }
    
    def _tool_check_instance_health(self, target: Optional[str] = None) -> dict:
        """Check if an IDA instance is responding"""
        import time
        
        # Find target instance
        if target:
            instance = registry.get(target) or registry.get_by_name(target)
            if not instance:
                return {"error": f"Instance not found: {target}"}
        else:
            instance = registry.get_current()
            if not instance:
                return {"error": "No current instance available"}
        
        # Ping the instance directly
        start_time = time.time()
        try:
            ping_conn = http.client.HTTPConnection(
                GATEWAY_HOST, instance.port, timeout=5
            )
            ping_request = json.dumps({
                "jsonrpc": "2.0",
                "method": "ping",
                "params": {},
                "id": 1
            })
            ping_conn.request("POST", "/mcp", ping_request, {"Content-Type": "application/json"})
            ping_response = ping_conn.getresponse()
            ping_data = json.loads(ping_response.read())
            ping_conn.close()
            
            elapsed = (time.time() - start_time) * 1000  # ms
            
            if "error" in ping_data:
                return {
                    "healthy": False,
                    "instance": instance.to_dict(),
                    "error": ping_data["error"]
                }
            
            return {
                "healthy": True,
                "instance": instance.to_dict(),
                "response_time_ms": round(elapsed, 2)
            }
        except Exception as e:
            return {
                "healthy": False,
                "instance": instance.to_dict(),
                "error": str(e)
            }
    
    def _tool_open_library(self, name: str, search_dir: Optional[str] = None, ida_path: Optional[str] = None) -> dict:
        """Open a library file in a new IDA Pro instance"""
        import os
        
        # Try to import library_opener
        try:
            from . import library_opener
        except ImportError:
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    "library_opener",
                    os.path.join(os.path.dirname(__file__), "library_opener.py")
                )
                library_opener = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(library_opener)
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Failed to import library_opener: {e}"
                }
        
        # Get current instance info for search_dir and ida_path
        current_instance_ida_path = None
        current = registry.get_current()
        if current:
            if search_dir is None:
                binary_path = current.binary_path
                if binary_path:
                    search_dir = os.path.dirname(binary_path)
            
            metadata = current.metadata
            if metadata.get("ida_path"):
                ida_path_from_metadata = metadata["ida_path"]
                if os.path.exists(ida_path_from_metadata):
                    current_instance_ida_path = ida_path_from_metadata
        
        # Use defaults
        if search_dir is None:
            search_dir = "."
        
        if ida_path is None and current_instance_ida_path:
            ida_path = current_instance_ida_path
        
        # Check if name is already a full path
        if os.path.exists(name):
            library_path = os.path.abspath(name)
        else:
            # Search for the library
            library_path = library_opener.find_library(name, [search_dir])
            if library_path is None:
                return {
                    "success": False,
                    "error": f"Library not found: {name}",
                    "search_dir": search_dir,
                    "hint": "Try specifying the full path or a different search directory"
                }
        
        # Detect architecture
        processor, bitness = library_opener.detect_architecture(library_path)
        
        # Open in IDA
        try:
            success = library_opener.open_library_in_ida(
                library_path,
                ida_path=ida_path,
                auto_start_mcp=True,
            )
            
            if success:
                return {
                    "success": True,
                    "library_path": library_path,
                    "architecture": f"{processor} {bitness}-bit",
                    "ida_path_used": ida_path,
                    "message": f"Opening {os.path.basename(library_path)} in IDA Pro. It will register with the Gateway once loaded.",
                    "hint": "Use list_instances() to see when the new instance is ready"
                }
            else:
                ida_exists = os.path.exists(ida_path) if ida_path else False
                return {
                    "success": False,
                    "library_path": library_path,
                    "ida_path_attempted": ida_path,
                    "ida_path_exists": ida_exists,
                    "error": "Failed to start IDA Pro - check the logs for details",
                    "hint": "Check if IDA Pro is installed and accessible"
                }
        except Exception as e:
            import traceback
            return {
                "success": False,
                "library_path": library_path,
                "ida_path_attempted": ida_path,
                "error": f"Exception while starting IDA: {str(e)}",
                "traceback": traceback.format_exc(),
                "hint": "Check if IDA Pro is installed and accessible"
            }
    
    def _forward_to_instance(self, instance: IDAInstance, body: bytes, request_id: Any):
        """Forward a request to an IDA instance"""
        conn = http.client.HTTPConnection(GATEWAY_HOST, instance.port, timeout=30)
        try:
            conn.request("POST", "/mcp", body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            data = response.read()
            
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(data)
            
        except Exception as e:
            logger.error(f"Failed to forward to instance {instance.instance_id}: {e}")
            self._send_mcp_error(request_id, f"Failed to connect to IDA instance '{instance.instance_id}': {e}")
        finally:
            conn.close()
    
    def _send_mcp_error(self, request_id: Any, message: str):
        """Send an MCP-formatted error response"""
        response = {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": message,
            },
            "id": request_id,
        }
        self.send_json_response(200, response)
    
    def _proxy_sse_request(self):
        """Proxy SSE GET request to current instance"""
        instance = registry.get_current()
        if not instance:
            self.send_error_response(503, "No IDA instance available")
            return
        
        # For SSE, we need to proxy the connection
        # This is a simplified implementation - full SSE proxy would need more work
        self.send_error_response(501, "SSE proxy not implemented - use direct connection to instance")
    
    def _proxy_sse_post(self, body: bytes):
        """Proxy SSE POST request to current instance"""
        instance = registry.get_current()
        if not instance:
            self.send_error_response(503, "No IDA instance available")
            return
        
        # Forward to instance
        conn = http.client.HTTPConnection(GATEWAY_HOST, instance.port, timeout=30)
        try:
            query = urlparse(self.path).query
            path = f"/sse?{query}" if query else "/sse"
            conn.request("POST", path, body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            data = response.read()
            
            self.send_response(response.status)
            for header, value in response.getheaders():
                if header.lower() not in ('transfer-encoding', 'connection'):
                    self.send_header(header, value)
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            logger.error(f"SSE proxy failed: {e}")
            self.send_error_response(500, str(e))
        finally:
            conn.close()


class GatewayServer:
    """Gateway Server that manages multiple IDA instances"""
    
    def __init__(self, host: str = GATEWAY_HOST, port: int = GATEWAY_PORT):
        self.host = host
        self.port = port
        self._server: Optional[ThreadingHTTPServer] = None
        self._running = False
        self._shutdown_timer: Optional[threading.Timer] = None
        self._shutdown_lock = threading.Lock()
    
    def start(self, background: bool = False):
        """Start the Gateway Server"""
        if self._running:
            logger.warning("Gateway already running")
            return
        
        self._server = ThreadingHTTPServer(
            (self.host, self.port),
            GatewayRequestHandler,
        )
        self._server.allow_reuse_address = True
        self._running = True
        
        logger.info(f"Gateway Server started on http://{self.host}:{self.port}")
        
        if background:
            thread = threading.Thread(target=self._serve_forever, daemon=True)
            thread.start()
        else:
            self._serve_forever()
    
    def _serve_forever(self):
        """Serve requests forever"""
        try:
            if self._server:
                self._server.serve_forever()
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self._running = False
    
    def stop(self):
        """Stop the Gateway Server"""
        if not self._running:
            return
        
        self._running = False
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        
        logger.info("Gateway Server stopped")
    
    def schedule_shutdown_if_empty(self):
        """Schedule shutdown if no instances are registered"""
        with self._shutdown_lock:
            if self._shutdown_timer:
                self._shutdown_timer.cancel()
            
            if registry.is_empty():
                logger.info(f"No instances registered, scheduling shutdown in {SHUTDOWN_DELAY}s")
                self._shutdown_timer = threading.Timer(SHUTDOWN_DELAY, self._check_and_shutdown)
                self._shutdown_timer.start()
    
    def _check_and_shutdown(self):
        """Check if still empty and shutdown"""
        if registry.is_empty():
            logger.info("No instances registered, shutting down")
            self.stop()
            os._exit(0)
        else:
            logger.info("New instance registered, cancelling shutdown")


# Global server instance
_gateway_server: Optional[GatewayServer] = None


def is_port_in_use(port: int, host: str = GATEWAY_HOST) -> bool:
    """Check if a port is in use"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0


def start_gateway_if_needed() -> bool:
    """Start the Gateway Server if not already running
    
    Returns:
        True if Gateway is available (either started or already running)
    """
    if is_port_in_use(GATEWAY_PORT):
        logger.info(f"Gateway already running on port {GATEWAY_PORT}")
        return True
    
    # Start Gateway in a new process
    import subprocess
    
    gateway_script = __file__
    
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
            logger.info("Gateway started successfully")
            return True
        time.sleep(0.1)
    
    logger.error("Failed to start Gateway")
    return False


def register_instance(
    binary_name: str,
    binary_path: str,
    preferred_port: Optional[int] = None,
    metadata: Optional[dict] = None,
) -> Optional[dict]:
    """Register an IDA instance with the Gateway
    
    Args:
        binary_name: Name of the binary file
        binary_path: Full path to the binary
        preferred_port: Preferred port (optional)
        metadata: Additional metadata (optional)
    
    Returns:
        Registration response dict or None on failure
    """
    try:
        conn = http.client.HTTPConnection(GATEWAY_HOST, GATEWAY_PORT, timeout=5)
        data = json.dumps({
            "binary_name": binary_name,
            "binary_path": binary_path,
            "preferred_port": preferred_port,
            "metadata": metadata or {},
        })
        conn.request("POST", "/gateway/register", data, {"Content-Type": "application/json"})
        response = conn.getresponse()
        result = json.loads(response.read())
        conn.close()
        return result
    except Exception as e:
        logger.error(f"Failed to register with Gateway: {e}")
        return None


def unregister_instance(instance_id: str) -> bool:
    """Unregister an IDA instance from the Gateway
    
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
        logger.error(f"Failed to unregister from Gateway: {e}")
        return False


def main():
    """Main entry point for Gateway Server"""
    parser = argparse.ArgumentParser(description="IDA Pro MCP Gateway Server")
    parser.add_argument("--host", default=GATEWAY_HOST, help="Host to bind to")
    parser.add_argument("--port", type=int, default=GATEWAY_PORT, help="Port to bind to")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Setup signal handlers
    def signal_handler(signum, frame):
        logger.info("Received shutdown signal")
        if _gateway_server:
            _gateway_server.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start server
    global _gateway_server
    _gateway_server = GatewayServer(args.host, args.port)
    _gateway_server.start(background=False)


if __name__ == "__main__":
    main()
