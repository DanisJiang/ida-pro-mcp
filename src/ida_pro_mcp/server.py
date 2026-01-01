import os
import sys
import json
import shutil
import argparse
import http.client
import tempfile
import traceback
import tomllib
import tomli_w
from typing import TYPE_CHECKING, Annotated, Optional
from urllib.parse import urlparse
import glob

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer, McpHttpRequestHandler
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest
    from ida_pro_mcp.instance_manager import InstanceManager, get_instance_manager
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer, McpHttpRequestHandler
    from zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest

    sys.path.pop(0)  # Clean up

    from ida_pro_mcp.instance_manager import get_instance_manager

# Legacy single-instance mode settings (used when --ida-rpc is specified)
IDA_HOST = "127.0.0.1"
IDA_PORT = 13337

# Multi-instance mode flag
_multi_instance_mode = False

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch


# ============================================================================
# Instance Management MCP Tools (only available in multi-instance mode)
# ============================================================================


@mcp.tool
def ida_instances() -> list[dict]:
    """List all connected IDA Pro instances.

    Returns a list of IDA instances with their details including:
    - id: Unique instance identifier
    - binary: Name of the binary being analyzed
    - path: Full path to the binary
    - port: Port number the instance is listening on
    - base: Image base address
    - selected: Whether this instance is currently selected
    """
    manager = get_instance_manager()
    instances = manager.get_instances()
    if not instances:
        return [{"message": "No IDA instances connected. Open a binary in IDA Pro and start the MCP plugin."}]
    return instances


@mcp.tool
def ida_select(
    instance: Annotated[str, "Instance selector: binary name (supports wildcards), port number, or instance ID"]
) -> dict:
    """Select an IDA Pro instance to work with.

    All subsequent MCP tool calls will be routed to the selected instance.
    You can select an instance by:
    - Binary name (e.g., 'crackme.exe' or 'crack*' for wildcard matching)
    - Port number (e.g., '13337')
    - Instance ID or prefix (e.g., 'a1b2c3d4' or 'a1b2')
    """
    manager = get_instance_manager()
    selected = manager.select(instance)
    if selected is None:
        instances = manager.get_instances()
        if not instances:
            return {
                "error": "No IDA instances connected",
                "hint": "Open a binary in IDA Pro and start the MCP plugin (Ctrl+Alt+M)"
            }
        return {
            "error": f"No instance matching '{instance}' found",
            "available": [
                {"binary": inst["binary"], "port": inst["port"], "id": inst["id"][:8]}
                for inst in instances
            ]
        }
    return {
        "selected": True,
        "binary": selected.binary,
        "path": selected.path,
        "port": selected.port,
        "base": selected.base,
        "id": selected.id
    }


@mcp.tool
def ida_current() -> dict:
    """Get information about the currently selected IDA Pro instance."""
    manager = get_instance_manager()
    current = manager.get_current()
    if current is None:
        instances = manager.get_instances()
        if not instances:
            return {
                "error": "No IDA instances connected",
                "hint": "Open a binary in IDA Pro and start the MCP plugin (Ctrl+Alt+M)"
            }
        return {
            "error": "No instance selected",
            "hint": "Use ida_select to choose an instance",
            "available": len(instances)
        }
    return {
        "binary": current.binary,
        "path": current.path,
        "port": current.port,
        "base": current.base,
        "id": current.id,
        "host": current.host
    }


# ============================================================================
# Request Dispatching
# ============================================================================


# Tools that are handled locally (not forwarded to IDA)
LOCAL_TOOLS = {"ida_instances", "ida_select", "ida_current"}


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests to the MCP server registry or forward to IDA"""
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    method = request_obj["method"]

    # MCP protocol methods - handle locally
    if method == "initialize":
        return dispatch_original(request)
    elif method.startswith("notifications/"):
        return dispatch_original(request)

    # In multi-instance mode, check if this is a local tool or needs forwarding
    if _multi_instance_mode:
        # tools/call with local tool name
        if method == "tools/call":
            tool_name = request_obj.get("params", {}).get("name", "")
            if tool_name in LOCAL_TOOLS:
                return dispatch_original(request)

        # tools/list - merge local tools with IDA tools
        if method == "tools/list":
            return _handle_tools_list(request, request_obj)

        # Get target instance
        manager = get_instance_manager()
        instance = manager.get_current()

        if instance is None:
            id = request_obj.get("id")
            if id is None:
                return None

            # Check if any instances are connected
            instances = manager.get_instances()
            if not instances:
                return JsonRpcResponse(
                    {
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32000,
                            "message": "No IDA Pro instances connected. Open a binary in IDA and start the MCP plugin (Ctrl+Alt+M).",
                        },
                        "id": id,
                    }
                )
            else:
                return JsonRpcResponse(
                    {
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32000,
                            "message": f"No IDA instance selected. Use ida_select to choose from {len(instances)} connected instance(s).",
                        },
                        "id": id,
                    }
                )

        # Forward to the selected IDA instance
        return _forward_to_ida(instance.host, instance.port, request, request_obj)
    else:
        # Legacy single-instance mode
        return _forward_to_ida(IDA_HOST, IDA_PORT, request, request_obj)


def _handle_tools_list(request: dict | str | bytes | bytearray, request_obj: dict) -> JsonRpcResponse:
    """Handle tools/list in multi-instance mode by merging local and IDA tools"""
    # Get local tools (ida_instances, ida_select, ida_current)
    local_response = dispatch_original(request)
    if local_response is None:
        local_tools = []
    elif "error" in local_response:
        return local_response
    else:
        local_tools = local_response.get("result", {}).get("tools", [])

    # Try to get tools from the current IDA instance
    manager = get_instance_manager()
    instance = manager.get_current()

    if instance is not None:
        # Forward tools/list to IDA instance
        ida_response = _forward_to_ida(instance.host, instance.port, request, request_obj)
        if ida_response is not None and "error" not in ida_response:
            ida_tools = ida_response.get("result", {}).get("tools", [])
            # Merge tools: local tools first, then IDA tools
            all_tools = local_tools + ida_tools
            return JsonRpcResponse({
                "jsonrpc": "2.0",
                "result": {"tools": all_tools},
                "id": request_obj.get("id"),
            })

    # No IDA instance or failed to get tools - just return local tools
    return JsonRpcResponse({
        "jsonrpc": "2.0",
        "result": {"tools": local_tools},
        "id": request_obj.get("id"),
    })


def _forward_to_ida(
    host: str,
    port: int,
    request: dict | str | bytes | bytearray,
    request_obj: dict
) -> JsonRpcResponse | None:
    """Forward a request to an IDA Pro instance"""
    conn = http.client.HTTPConnection(host, port, timeout=30)
    try:
        if isinstance(request, dict):
            request = json.dumps(request)
        elif isinstance(request, str):
            request = request.encode("utf-8")
        conn.request("POST", "/mcp", request, {"Content-Type": "application/json"})
        response = conn.getresponse()
        data = response.read().decode()
        return json.loads(data)
    except Exception as e:
        full_info = traceback.format_exc()
        id = request_obj.get("id")
        if id is None:
            return None  # Notification, no response needed

        if sys.platform == "darwin":
            shortcut = "Ctrl+Option+M"
        else:
            shortcut = "Ctrl+Alt+M"

        if _multi_instance_mode:
            msg = f"Failed to connect to IDA Pro at {host}:{port}. The instance may have disconnected.\n{full_info}"
        else:
            msg = f"Failed to connect to IDA Pro! Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n{full_info}"

        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": msg,
                    "data": str(e),
                },
                "id": id,
            }
        )
    finally:
        conn.close()


mcp.registry.dispatch = dispatch_proxy


# ============================================================================
# Multi-Instance HTTP Server
# ============================================================================


class MultiInstanceHttpRequestHandler(McpHttpRequestHandler):
    """HTTP request handler that also handles instance registration"""

    def do_POST(self):
        """Handle POST requests including registration endpoints"""
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/register":
            self._handle_register()
        elif path == "/unregister":
            self._handle_unregister()
        elif path == "/heartbeat":
            self._handle_heartbeat()
        else:
            super().do_POST()

    def do_GET(self):
        """Handle GET requests including instance list endpoint"""
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/instances":
            self._handle_instances_get()
        else:
            super().do_GET()

    def _send_json_response(self, status: int, data: dict):
        """Send a JSON response"""
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Optional[dict]:
        """Read and parse JSON body from request"""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return None
        try:
            body = self.rfile.read(content_length)
            return json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _handle_register(self):
        """Handle instance registration from IDA plugin"""
        data = self._read_json_body()
        if data is None:
            self._send_json_response(400, {"error": "Invalid JSON body"})
            return

        required_fields = ["id", "host", "port", "binary", "path", "base"]
        missing = [f for f in required_fields if f not in data]
        if missing:
            self._send_json_response(400, {"error": f"Missing fields: {missing}"})
            return

        manager = get_instance_manager()
        success = manager.register(
            id=data["id"],
            host=data["host"],
            port=data["port"],
            binary=data["binary"],
            path=data["path"],
            base=data["base"],
        )

        if success:
            self._send_json_response(200, {"status": "registered", "id": data["id"]})
        else:
            self._send_json_response(409, {"error": "Registration failed"})

    def _handle_unregister(self):
        """Handle instance unregistration from IDA plugin"""
        data = self._read_json_body()
        if data is None or "id" not in data:
            self._send_json_response(400, {"error": "Missing 'id' field"})
            return

        manager = get_instance_manager()
        success = manager.unregister(data["id"])

        if success:
            self._send_json_response(200, {"status": "unregistered"})
        else:
            self._send_json_response(404, {"error": "Instance not found"})

    def _handle_heartbeat(self):
        """Handle heartbeat from IDA plugin"""
        data = self._read_json_body()
        if data is None or "id" not in data:
            self._send_json_response(400, {"error": "Missing 'id' field"})
            return

        manager = get_instance_manager()
        success = manager.heartbeat(data["id"])

        if success:
            self._send_json_response(200, {"status": "ok"})
        else:
            self._send_json_response(404, {"error": "Instance not found"})

    def _handle_instances_get(self):
        """Handle GET /instances for debugging"""
        manager = get_instance_manager()
        instances = manager.get_instances()
        self._send_json_response(200, {"instances": instances})


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_PLUGIN_PKG = os.path.join(SCRIPT_DIR, "ida_mcp")
IDA_PLUGIN_LOADER = os.path.join(SCRIPT_DIR, "ida_mcp.py")

# NOTE: This is in the global scope on purpose
if not os.path.exists(IDA_PLUGIN_PKG):
    raise RuntimeError(
        f"IDA plugin package not found at {IDA_PLUGIN_PKG} (did you move it?)"
    )
if not os.path.exists(IDA_PLUGIN_LOADER):
    raise RuntimeError(
        f"IDA plugin loader not found at {IDA_PLUGIN_LOADER} (did you move it?)"
    )


def get_python_executable():
    """Get the path to the Python executable"""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")

        split = path.split(os.sep)
        if split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)

            if os.path.exists(python_executable):
                return python_executable
    return sys.executable


def copy_python_env(env: dict[str, str]):
    # Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    # MCP servers are run without inheriting the environment, so we need to forward
    # the environment variables that affect Python's dependency resolution by hand.
    # Issue: https://github.com/mrexodia/ida-pro-mcp/issues/111
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result


def generate_mcp_config(*, stdio: bool):
    if stdio:
        mcp_config = {
            "command": get_python_executable(),
            "args": [
                __file__,
                "--ida-rpc",
                f"http://{IDA_HOST}:{IDA_PORT}",
            ],
        }
        env = {}
        if copy_python_env(env):
            print("[WARNING] Custom Python environment variables detected")
            mcp_config["env"] = env
        return mcp_config
    else:
        return {"type": "http", "url": f"http://{IDA_HOST}:{IDA_PORT}/mcp"}


def print_mcp_config():
    print("[HTTP MCP CONFIGURATION]")
    print(
        json.dumps(
            {"mcpServers": {mcp.name: generate_mcp_config(stdio=False)}}, indent=2
        )
    )
    print("\n[STDIO MCP CONFIGURATION]")
    print(
        json.dumps(
            {"mcpServers": {mcp.name: generate_mcp_config(stdio=True)}}, indent=2
        )
    )


def install_mcp_servers(*, stdio: bool = False, uninstall=False, quiet=False):
    # Map client names to their JSON key paths for clients that don't use "mcpServers"
    # Format: client_name -> (top_level_key, nested_key)
    # None means use default "mcpServers" at top level
    special_json_structures = {
        "VS Code": ("mcp", "servers"),
        "Visual Studio 2022": (None, "servers"),  # servers at top level
    }

    if sys.platform == "win32":
        configs = {
            "Cline": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(os.getenv("APPDATA", ""), "Claude"),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Zed": (
                os.path.join(os.getenv("APPDATA", ""), "Zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "darwin":
        configs = {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Claude"
                ),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Zed"
                ),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "BoltAI": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "BoltAI",
                ),
                "config.json",
            ),
            "Perplexity": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Perplexity",
                ),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "linux":
        configs = {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            # Claude not supported on Linux
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(os.path.expanduser("~"), ".config", "zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
        }
    else:
        print(f"Unsupported platform: {sys.platform}")
        return

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        is_toml = config_file.endswith(".toml")

        if not os.path.exists(config_dir):
            action = "uninstall" if uninstall else "installation"
            if not quiet:
                print(f"Skipping {name} {action}\n  Config: {config_path} (not found)")
            continue

        # Read existing config
        if not os.path.exists(config_path):
            config = {}
        else:
            with open(
                config_path,
                "rb" if is_toml else "r",
                encoding=None if is_toml else "utf-8",
            ) as f:
                if is_toml:
                    data = f.read()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = tomllib.loads(data.decode("utf-8"))
                        except tomllib.TOMLDecodeError:
                            if not quiet:
                                print(
                                    f"Skipping {name} uninstall\n  Config: {config_path} (invalid TOML)"
                                )
                            continue
                else:
                    data = f.read().strip()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = json.loads(data)
                        except json.decoder.JSONDecodeError:
                            if not quiet:
                                print(
                                    f"Skipping {name} uninstall\n  Config: {config_path} (invalid JSON)"
                                )
                            continue

        # Handle TOML vs JSON structure
        if is_toml:
            if "mcp_servers" not in config:
                config["mcp_servers"] = {}
            mcp_servers = config["mcp_servers"]
        else:
            # Check if this client uses a special JSON structure
            if name in special_json_structures:
                top_key, nested_key = special_json_structures[name]
                if top_key is None:
                    # servers at top level (e.g., Visual Studio 2022)
                    if nested_key not in config:
                        config[nested_key] = {}
                    mcp_servers = config[nested_key]
                else:
                    # nested structure (e.g., VS Code uses mcp.servers)
                    if top_key not in config:
                        config[top_key] = {}
                    if nested_key not in config[top_key]:
                        config[top_key][nested_key] = {}
                    mcp_servers = config[top_key][nested_key]
            else:
                # Default: mcpServers at top level
                if "mcpServers" not in config:
                    config["mcpServers"] = {}
                mcp_servers = config["mcpServers"]

        # Migrate old name
        old_name = "github.com/mrexodia/ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers[mcp.name] = mcp_servers[old_name]
            del mcp_servers[old_name]

        if uninstall:
            if mcp.name not in mcp_servers:
                if not quiet:
                    print(
                        f"Skipping {name} uninstall\n  Config: {config_path} (not installed)"
                    )
                continue
            del mcp_servers[mcp.name]
        else:
            mcp_servers[mcp.name] = generate_mcp_config(stdio=stdio)

        # Atomic write: temp file + rename
        suffix = ".toml" if is_toml else ".json"
        fd, temp_path = tempfile.mkstemp(
            dir=config_dir, prefix=".tmp_", suffix=suffix, text=True
        )
        try:
            with os.fdopen(
                fd, "wb" if is_toml else "w", encoding=None if is_toml else "utf-8"
            ) as f:
                if is_toml:
                    f.write(tomli_w.dumps(config).encode("utf-8"))
                else:
                    json.dump(config, f, indent=2)
            os.replace(temp_path, config_path)
        except:
            os.unlink(temp_path)
            raise

        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(
                f"{action} {name} MCP server (restart required)\n  Config: {config_path}"
            )
        installed += 1
    if not uninstall and installed == 0:
        print(
            "No MCP servers installed. For unsupported MCP clients, use the following config:\n"
        )
        print_mcp_config()


def install_ida_plugin(
    *, uninstall: bool = False, quiet: bool = False, allow_ida_free: bool = False
):
    if sys.platform == "win32":
        ida_folder = os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")
    if not allow_ida_free:
        free_licenses = glob.glob(os.path.join(ida_folder, "idafree_*.hexlic"))
        if len(free_licenses) > 0:
            print(
                "IDA Free does not support plugins and cannot be used. Purchase and install IDA Pro instead."
            )
            sys.exit(1)
    ida_plugin_folder = os.path.join(ida_folder, "plugins")

    # Install both the loader file and package directory
    loader_source = IDA_PLUGIN_LOADER
    loader_destination = os.path.join(ida_plugin_folder, "ida_mcp.py")

    pkg_source = IDA_PLUGIN_PKG
    pkg_destination = os.path.join(ida_plugin_folder, "ida_mcp")

    # Clean up old plugin if it exists
    old_plugin = os.path.join(ida_plugin_folder, "mcp-plugin.py")

    if uninstall:
        # Remove loader
        if os.path.lexists(loader_destination):
            os.remove(loader_destination)
            if not quiet:
                print(f"Uninstalled IDA plugin loader\n  Path: {loader_destination}")

        # Remove package
        if os.path.exists(pkg_destination):
            if os.path.isdir(pkg_destination) and not os.path.islink(pkg_destination):
                shutil.rmtree(pkg_destination)
            else:
                os.remove(pkg_destination)
            if not quiet:
                print(f"Uninstalled IDA plugin package\n  Path: {pkg_destination}")

        # Remove old plugin if it exists
        if os.path.lexists(old_plugin):
            os.remove(old_plugin)
            if not quiet:
                print(f"Removed old plugin\n  Path: {old_plugin}")
    else:
        # Create IDA plugins folder
        if not os.path.exists(ida_plugin_folder):
            os.makedirs(ida_plugin_folder)

        # Remove old plugin if it exists
        if os.path.lexists(old_plugin):
            os.remove(old_plugin)
            if not quiet:
                print(f"Removed old plugin file\n  Path: {old_plugin}")

        installed_items = []

        # Install loader file
        loader_realpath = (
            os.path.realpath(loader_destination)
            if os.path.lexists(loader_destination)
            else None
        )
        if loader_realpath != loader_source:
            if os.path.lexists(loader_destination):
                os.remove(loader_destination)

            try:
                os.symlink(loader_source, loader_destination)
                installed_items.append(f"loader: {loader_destination}")
            except OSError:
                shutil.copy(loader_source, loader_destination)
                installed_items.append(f"loader: {loader_destination}")

        # Install package directory
        pkg_realpath = (
            os.path.realpath(pkg_destination)
            if os.path.lexists(pkg_destination)
            else None
        )
        if pkg_realpath != pkg_source:
            if os.path.lexists(pkg_destination):
                if os.path.isdir(pkg_destination) and not os.path.islink(
                    pkg_destination
                ):
                    shutil.rmtree(pkg_destination)
                else:
                    os.remove(pkg_destination)

            try:
                os.symlink(pkg_source, pkg_destination)
                installed_items.append(f"package: {pkg_destination}")
            except OSError:
                shutil.copytree(pkg_source, pkg_destination)
                installed_items.append(f"package: {pkg_destination}")

        if not quiet:
            if installed_items:
                print("Installed IDA Pro plugin (IDA restart required)")
                for item in installed_items:
                    print(f"  {item}")
            else:
                print("Skipping IDA plugin installation (already up to date)")


def main():
    global IDA_HOST, IDA_PORT, _multi_instance_mode
    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install", action="store_true", help="Install the MCP Server and IDA plugin"
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Uninstall the MCP Server and IDA plugin",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)",
    )
    parser.add_argument(
        "--ida-rpc",
        type=str,
        default=None,
        help=f"IDA RPC server to use for single-instance mode (default: multi-instance mode)",
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    args = parser.parse_args()

    # Determine mode: single-instance (legacy) or multi-instance
    if args.ida_rpc is not None:
        # Legacy single-instance mode
        ida_rpc = urlparse(args.ida_rpc)
        if ida_rpc.hostname is None or ida_rpc.port is None:
            raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
        IDA_HOST = ida_rpc.hostname
        IDA_PORT = ida_rpc.port
        _multi_instance_mode = False
        print(f"[MCP] Single-instance mode: connecting to {IDA_HOST}:{IDA_PORT}")
    else:
        # Multi-instance mode (default)
        _multi_instance_mode = True
        print("[MCP] Multi-instance mode: IDA instances will register dynamically")

    if args.install and args.uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if args.install:
        install_ida_plugin(allow_ida_free=args.allow_ida_free)
        install_mcp_servers(stdio=(args.transport == "stdio"))
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True, allow_ida_free=args.allow_ida_free)
        install_mcp_servers(uninstall=True)
        return

    if args.config:
        print_mcp_config()
        return

    try:
        if args.transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            if _multi_instance_mode:
                # Use custom handler for multi-instance registration
                mcp.serve(url.hostname, url.port, request_handler=MultiInstanceHttpRequestHandler)
                print(f"[MCP] Registration endpoint: http://{url.hostname}:{url.port}/register")
            else:
                mcp.serve(url.hostname, url.port)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        if _multi_instance_mode:
            # Stop the instance manager cleanup thread
            manager = get_instance_manager()
            manager.stop()


if __name__ == "__main__":
    main()
