"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.

Multi-instance support:
- Set IDA_MCP_SERVER environment variable to the MCP server URL
  (e.g., http://127.0.0.1:8744) to enable automatic registration.
- When registered, this IDA instance can be selected by MCP clients
  using the ida_select tool.
"""

import os
import sys
import json
import uuid
import threading
import http.client
import idaapi
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

if TYPE_CHECKING:
    from . import ida_mcp


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


class InstanceRegistration:
    """Handles registration with the MCP server for multi-instance support"""

    HEARTBEAT_INTERVAL = 60.0  # seconds - send heartbeat every minute

    def __init__(self, instance_id: str, host: str, port: int, server_url: str):
        self.instance_id = instance_id
        self.host = host
        self.port = port
        self.server_url = server_url
        self._parsed_url = urlparse(server_url)
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._running = False
        self._registered = False

    def _get_binary_info(self) -> tuple[str, str, str]:
        """Get binary name, path, and base address from IDA"""
        binary_path = idaapi.get_input_file_path()
        binary_name = idaapi.get_root_filename()
        base_addr = hex(idaapi.get_imagebase())
        return binary_name, binary_path, base_addr

    def _send_request(self, endpoint: str, data: dict) -> bool:
        """Send HTTP request to MCP server"""
        if self._parsed_url.hostname is None:
            return False

        try:
            conn = http.client.HTTPConnection(
                self._parsed_url.hostname,
                self._parsed_url.port or 80,
                timeout=5
            )
            try:
                body = json.dumps(data).encode("utf-8")
                conn.request("POST", endpoint, body, {"Content-Type": "application/json"})
                response = conn.getresponse()
                return response.status == 200
            finally:
                conn.close()
        except Exception as e:
            print(f"[MCP] Registration request failed: {e}")
            return False

    def register(self) -> bool:
        """Register this instance with the MCP server"""
        binary_name, binary_path, base_addr = self._get_binary_info()

        data = {
            "id": self.instance_id,
            "host": self.host,
            "port": self.port,
            "binary": binary_name,
            "path": binary_path,
            "base": base_addr,
        }

        if self._send_request("/register", data):
            self._registered = True
            print(f"[MCP] Registered with server at {self.server_url}")
            self._start_heartbeat()
            return True
        else:
            print(f"[MCP] Failed to register with server at {self.server_url}")
            return False

    def unregister(self) -> bool:
        """Unregister this instance from the MCP server"""
        self._stop_heartbeat()

        if not self._registered:
            return True

        data = {"id": self.instance_id}
        if self._send_request("/unregister", data):
            self._registered = False
            print(f"[MCP] Unregistered from server at {self.server_url}")
            return True
        else:
            print(f"[MCP] Failed to unregister from server at {self.server_url}")
            return False

    def _start_heartbeat(self):
        """Start the heartbeat thread"""
        if self._running:
            return

        self._running = True
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name="MCP-Heartbeat"
        )
        self._heartbeat_thread.start()

    def _stop_heartbeat(self):
        """Stop the heartbeat thread"""
        self._running = False
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=2.0)
            self._heartbeat_thread = None

    def _heartbeat_loop(self):
        """Background thread that sends periodic heartbeats"""
        import time
        while self._running:
            time.sleep(self.HEARTBEAT_INTERVAL)
            if not self._running:
                break
            data = {"id": self.instance_id}
            if not self._send_request("/heartbeat", data):
                # Try to re-register if heartbeat fails
                if self._running:
                    print("[MCP] Heartbeat failed, attempting re-registration...")
                    self.register()


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    # Server configuration
    HOST = "127.0.0.1"
    BASE_PORT = 13337
    MAX_PORT_TRIES = 10

    # MCP server URL for multi-instance registration (from environment)
    MCP_SERVER_URL = os.environ.get("IDA_MCP_SERVER", None)

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        if self.MCP_SERVER_URL:
            print(f"[MCP] Multi-instance mode: will register with {self.MCP_SERVER_URL}")

        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.instance_id: str = str(uuid.uuid4())
        self.registration: Optional[InstanceRegistration] = None
        self.current_port: Optional[int] = None
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        # Stop existing server if running
        if self.mcp:
            self._stop_server()

        # Generate new instance ID for this session
        self.instance_id = str(uuid.uuid4())

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler

        for i in range(self.MAX_PORT_TRIES):
            port = self.BASE_PORT + i
            try:
                MCP_SERVER.serve(
                    self.HOST, port, request_handler=IdaMcpHttpRequestHandler
                )
                if TYPE_CHECKING:
                    from .ida_mcp.rpc import set_download_base_url
                else:
                    from ida_mcp.rpc import set_download_base_url
                set_download_base_url(f"http://{self.HOST}:{port}")
                print(f"  Config: http://{self.HOST}:{port}/config.html")
                self.mcp = MCP_SERVER
                self.current_port = port

                # Register with MCP server if configured
                if self.MCP_SERVER_URL:
                    self.registration = InstanceRegistration(
                        instance_id=self.instance_id,
                        host=self.HOST,
                        port=port,
                        server_url=self.MCP_SERVER_URL
                    )
                    self.registration.register()

                break
            except OSError as e:
                if e.errno in (48, 98, 10048):  # Address already in use
                    if i == self.MAX_PORT_TRIES - 1:
                        print(
                            f"[MCP] Error: Could not find available port in range {self.BASE_PORT}-{self.BASE_PORT + self.MAX_PORT_TRIES - 1}"
                        )
                        return
                    continue
                raise

    def _stop_server(self):
        """Stop the MCP server and unregister from MCP server"""
        # Unregister first
        if self.registration:
            self.registration.unregister()
            self.registration = None

        # Then stop the server
        if self.mcp:
            self.mcp.stop()
            self.mcp = None
            self.current_port = None

    def term(self):
        self._stop_server()


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
