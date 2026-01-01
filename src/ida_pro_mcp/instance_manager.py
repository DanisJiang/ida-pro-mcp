"""IDA Instance Manager - Manages multiple IDA Pro instances

This module provides centralized management of multiple IDA Pro instances
that connect to the MCP server, enabling multi-binary analysis workflows.
"""

import time
import threading
import http.client
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IDAInstance:
    """Represents a connected IDA Pro instance"""

    id: str  # Unique identifier (UUID)
    host: str  # Instance host (usually 127.0.0.1)
    port: int  # Instance port (13337, 13338, ...)
    binary: str  # Binary filename (e.g., "crackme.exe")
    path: str  # Full path to the binary
    base: str  # Image base address (hex)
    registered_at: float = field(default_factory=time.time)  # Registration timestamp
    last_heartbeat: float = field(default_factory=time.time)  # Last heartbeat timestamp

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "host": self.host,
            "port": self.port,
            "binary": self.binary,
            "path": self.path,
            "base": self.base,
            "registered_at": self.registered_at,
            "last_heartbeat": self.last_heartbeat,
        }


class InstanceManager:
    """Manages multiple IDA Pro instances with thread-safe operations"""

    # Heartbeat timeout in seconds - instances without heartbeat for this long are removed
    # 5 minutes - allows for network hiccups and long IDA operations
    HEARTBEAT_TIMEOUT = 300.0

    # Cleanup interval in seconds
    CLEANUP_INTERVAL = 60.0

    def __init__(self):
        self._instances: dict[str, IDAInstance] = {}  # id -> instance
        self._current_id: Optional[str] = None  # Currently selected instance ID
        self._lock = threading.RLock()  # Reentrant lock for thread safety
        self._cleanup_thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        """Start the instance manager and cleanup thread"""
        if self._running:
            return

        self._running = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="InstanceManager-Cleanup"
        )
        self._cleanup_thread.start()

    def stop(self):
        """Stop the instance manager"""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5.0)
            self._cleanup_thread = None

    def _cleanup_loop(self):
        """Background thread that removes stale instances"""
        while self._running:
            time.sleep(self.CLEANUP_INTERVAL)
            if not self._running:
                break
            self._cleanup_stale_instances()

    def _cleanup_stale_instances(self):
        """Remove instances that haven't sent heartbeat within timeout"""
        now = time.time()
        with self._lock:
            stale_ids = [
                id
                for id, instance in self._instances.items()
                if now - instance.last_heartbeat > self.HEARTBEAT_TIMEOUT
            ]

            for id in stale_ids:
                instance = self._instances.pop(id)
                print(
                    f"[MCP] Removed stale instance: {instance.binary} (port {instance.port})"
                )

                # If the current instance was removed, try to select another
                if self._current_id == id:
                    self._current_id = None
                    if self._instances:
                        # Auto-select the first remaining instance
                        first_id = next(iter(self._instances))
                        self._current_id = first_id
                        print(
                            f"[MCP] Auto-selected instance: {self._instances[first_id].binary}"
                        )

    def register(
        self,
        id: str,
        host: str,
        port: int,
        binary: str,
        path: str,
        base: str,
    ) -> bool:
        """Register a new IDA instance

        Args:
            id: Unique identifier for the instance
            host: Host address of the instance
            port: Port number of the instance
            binary: Name of the binary being analyzed
            path: Full path to the binary
            base: Image base address (hex string)

        Returns:
            True if registration successful, False if ID already exists
        """
        with self._lock:
            # Check for port conflict (same port, different ID)
            # First collect IDs to remove, then remove them (can't modify dict during iteration)
            conflicting_ids = [
                existing.id
                for existing in self._instances.values()
                if existing.port == port and existing.id != id
            ]
            for conflicting_id in conflicting_ids:
                print(
                    f"[MCP] Port conflict: removing old instance on port {port}"
                )
                self._instances.pop(conflicting_id)
                if self._current_id == conflicting_id:
                    self._current_id = None

            instance = IDAInstance(
                id=id,
                host=host,
                port=port,
                binary=binary,
                path=path,
                base=base,
            )
            self._instances[id] = instance
            print(f"[MCP] Registered instance: {binary} (port {port}, id={id[:8]}...)")

            # Auto-select if this is the first/only instance
            if self._current_id is None or len(self._instances) == 1:
                self._current_id = id
                print(f"[MCP] Auto-selected instance: {binary}")

            return True

    def unregister(self, id: str) -> bool:
        """Unregister an IDA instance

        Args:
            id: Instance ID to unregister

        Returns:
            True if unregistration successful, False if ID not found
        """
        with self._lock:
            if id not in self._instances:
                return False

            instance = self._instances.pop(id)
            print(
                f"[MCP] Unregistered instance: {instance.binary} (port {instance.port})"
            )

            # If the unregistered instance was current, select another
            if self._current_id == id:
                self._current_id = None
                if self._instances:
                    first_id = next(iter(self._instances))
                    self._current_id = first_id
                    print(
                        f"[MCP] Auto-selected instance: {self._instances[first_id].binary}"
                    )

            return True

    def heartbeat(self, id: str) -> bool:
        """Update heartbeat timestamp for an instance

        Args:
            id: Instance ID

        Returns:
            True if heartbeat updated, False if ID not found
        """
        with self._lock:
            if id not in self._instances:
                return False
            self._instances[id].last_heartbeat = time.time()
            return True

    def get_instances(self) -> list[dict]:
        """Get list of all registered instances

        Returns:
            List of instance dictionaries with 'selected' field added
        """
        with self._lock:
            result = []
            for id, instance in self._instances.items():
                info = instance.to_dict()
                info["selected"] = id == self._current_id
                result.append(info)
            return result

    def get_instance(self, id: str) -> Optional[IDAInstance]:
        """Get a specific instance by ID

        Args:
            id: Instance ID

        Returns:
            IDAInstance or None if not found
        """
        with self._lock:
            return self._instances.get(id)

    def get_current(self) -> Optional[IDAInstance]:
        """Get the currently selected instance

        Returns:
            Currently selected IDAInstance or None
        """
        with self._lock:
            if self._current_id is None:
                return None
            return self._instances.get(self._current_id)

    def select(self, selector: str) -> Optional[IDAInstance]:
        """Select an instance by ID, binary name, or port number

        Args:
            selector: Instance ID (or prefix), binary name (with wildcard support), or port number

        Returns:
            Selected IDAInstance or None if not found
        """
        with self._lock:
            if not self._instances:
                return None

            # Try to match by ID (exact or prefix)
            for id, instance in self._instances.items():
                if id == selector or id.startswith(selector):
                    self._current_id = id
                    return instance

            # Try to match by port number
            try:
                port = int(selector)
                for id, instance in self._instances.items():
                    if instance.port == port:
                        self._current_id = id
                        return instance
            except ValueError:
                pass

            # Try to match by binary name (case-insensitive, supports wildcards)
            import fnmatch

            selector_lower = selector.lower()
            for id, instance in self._instances.items():
                binary_lower = instance.binary.lower()
                # Exact match
                if binary_lower == selector_lower:
                    self._current_id = id
                    return instance
                # Wildcard match
                if fnmatch.fnmatch(binary_lower, selector_lower):
                    self._current_id = id
                    return instance
                # Substring match (for convenience)
                if selector_lower in binary_lower:
                    self._current_id = id
                    return instance

            return None

    def is_healthy(self, instance: IDAInstance, timeout: float = 5.0) -> bool:
        """Check if an instance is responsive

        Args:
            instance: Instance to check
            timeout: Connection timeout in seconds

        Returns:
            True if instance responds to health check
        """
        try:
            conn = http.client.HTTPConnection(
                instance.host, instance.port, timeout=timeout
            )
            try:
                # Send a simple ping request
                request = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "ping",
                        "params": {},
                        "id": "health-check",
                    }
                )
                conn.request("POST", "/mcp", request, {"Content-Type": "application/json"})
                response = conn.getresponse()
                return response.status == 200
            finally:
                conn.close()
        except Exception:
            return False

    def __len__(self) -> int:
        """Return number of registered instances"""
        with self._lock:
            return len(self._instances)

    def __bool__(self) -> bool:
        """Return True if any instances are registered"""
        with self._lock:
            return bool(self._instances)


# Global instance manager singleton
_instance_manager: Optional[InstanceManager] = None


def get_instance_manager() -> InstanceManager:
    """Get the global InstanceManager singleton"""
    global _instance_manager
    if _instance_manager is None:
        _instance_manager = InstanceManager()
        _instance_manager.start()
    return _instance_manager
