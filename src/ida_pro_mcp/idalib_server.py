import sys
import signal
import logging
import argparse
import json
import uuid
import threading
import http.client
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional

# idapro must go first to initialize idalib
import idapro
import ida_auto
import idaapi

from ida_pro_mcp.ida_mcp import MCP_SERVER

logger = logging.getLogger(__name__)


class IdalibRegistration:
    """Handles registration with the MCP server for idalib multi-instance support"""

    HEARTBEAT_INTERVAL = 60.0  # seconds - send heartbeat every minute

    def __init__(self, instance_id: str, host: str, port: int, server_url: str):
        self.instance_id = instance_id
        self.host = host
        self.port = port
        self.server_url = server_url
        self._parsed_url = urlparse(server_url)
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()  # For interruptible sleep
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
            logger.warning(f"Registration request failed: {e}")
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
            logger.info(f"Registered with server at {self.server_url}")
            self._start_heartbeat()
            return True
        else:
            logger.warning(f"Failed to register with server at {self.server_url}")
            return False

    def unregister(self) -> bool:
        """Unregister this instance from the MCP server"""
        self._stop_heartbeat()

        if not self._registered:
            return True

        data = {"id": self.instance_id}
        if self._send_request("/unregister", data):
            self._registered = False
            logger.info(f"Unregistered from server at {self.server_url}")
            return True
        else:
            logger.warning(f"Failed to unregister from server at {self.server_url}")
            return False

    def _start_heartbeat(self):
        """Start the heartbeat thread"""
        if self._running:
            return

        self._running = True
        self._stop_event.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name="idalib-Heartbeat"
        )
        self._heartbeat_thread.start()

    def _stop_heartbeat(self):
        """Stop the heartbeat thread"""
        self._running = False
        self._stop_event.set()  # Wake up the heartbeat thread immediately
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=2.0)
            self._heartbeat_thread = None

    def _heartbeat_loop(self):
        """Background thread that sends periodic heartbeats"""
        while self._running:
            # Use event.wait() instead of time.sleep() so we can be interrupted
            if self._stop_event.wait(timeout=self.HEARTBEAT_INTERVAL):
                break  # Event was set, stop requested
            if not self._running:
                break
            data = {"id": self.instance_id}
            if not self._send_request("/heartbeat", data):
                # Try to re-register if heartbeat fails
                if self._running:
                    logger.warning("Heartbeat failed, attempting re-registration...")
                    self.register()


def main():
    parser = argparse.ArgumentParser(description="MCP server for IDA Pro via idalib")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show debug messages"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to listen on, default: 127.0.0.1",
    )
    parser.add_argument(
        "--port", type=int, default=8745, help="Port to listen on, default: 8745"
    )
    parser.add_argument(
        "--mcp-server",
        type=str,
        default=None,
        help="MCP server URL for multi-instance registration (e.g., http://127.0.0.1:8744)",
    )
    parser.add_argument(
        "--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)"
    )
    parser.add_argument(
        "input_path", type=Path, help="Path to the input file to analyze."
    )
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
        idapro.enable_console_messages(True)
    else:
        log_level = logging.INFO
        idapro.enable_console_messages(False)

    logging.basicConfig(level=log_level)

    # reset logging levels that might be initialized in idapythonrc.py
    # which is evaluated during import of idalib.
    logging.getLogger().setLevel(log_level)

    if not args.input_path.exists():
        raise FileNotFoundError(f"Input file not found: {args.input_path}")

    # TODO: add a tool for specifying the idb/input file (sandboxed)
    logger.info("opening database: %s", args.input_path)
    if idapro.open_database(str(args.input_path), run_auto_analysis=True):
        raise RuntimeError("failed to analyze input file")

    logger.debug("idalib: waiting for analysis...")
    ida_auto.auto_wait()

    # Multi-instance registration
    registration: Optional[IdalibRegistration] = None
    instance_id = str(uuid.uuid4())

    if args.mcp_server:
        registration = IdalibRegistration(
            instance_id=instance_id,
            host=args.host,
            port=args.port,
            server_url=args.mcp_server
        )
        registration.register()

    # Setup signal handlers to ensure IDA database is properly closed on shutdown.
    # When a signal arrives, our handlers execute first, allowing us to close the
    # IDA database cleanly before the process terminates.
    def cleanup_and_exit(signum, frame):
        if registration:
            registration.unregister()
        logger.info("Closing IDA database...")
        idapro.close_database()
        logger.info("IDA database closed.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    # NOTE: npx -y @modelcontextprotocol/inspector for debugging
    # TODO: with background=True the main thread (this one) does not fake any
    # work from @idasync, so we deadlock.
    from ida_pro_mcp.ida_mcp.rpc import set_download_base_url

    set_download_base_url(f"http://{args.host}:{args.port}")
    MCP_SERVER.serve(host=args.host, port=args.port, background=False)


if __name__ == "__main__":
    main()
