"""
Network Sensor — monitors active network connections.
Detects connection floods and rapid port probing.
"""
import asyncio
from collections import defaultdict, deque
from datetime import datetime, timedelta

from config.settings import settings
from core.sensors.base import BaseSensor, ThreatEvent

MONITORED_PORTS = {8000, 8001, 8501}
SCAN_BURST_THRESHOLD = 15
CONNECTION_FLOOD_THRESHOLD = 50

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False


class NetworkSensor(BaseSensor):
    def __init__(self):
        super().__init__("network_sensor")
        self._ip_connections: dict[str, deque] = defaultdict(lambda: deque())
        self._ip_ports: dict[str, deque] = defaultdict(lambda: deque())

    async def run(self):
        if not _PSUTIL_AVAILABLE:
            self.logger.warning("[NetworkSensor] psutil not available — network sensor is passive")
            while self._running:
                await asyncio.sleep(10)
            return

        self.logger.info("[NetworkSensor] Monitoring network connections")
        while self._running:
            await self._check_connections()
            await asyncio.sleep(3)

    async def _check_connections(self):
        now = datetime.utcnow()
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            self.logger.debug("No permission to read connections")
            return

        for conn in connections:
            if conn.status != "ESTABLISHED":
                continue
            if conn.laddr and conn.laddr.port not in MONITORED_PORTS:
                continue
            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

            self._ip_connections[remote_ip].append(now)
            self._ip_ports[remote_ip].append((now, remote_port))

        for ip, conn_times in list(self._ip_connections.items()):
            self._prune_deque(conn_times, 30)
            if len(conn_times) >= CONNECTION_FLOOD_THRESHOLD:
                await self.emit(ThreatEvent(
                    source="network_sensor",
                    event_type="connection_flood",
                    source_ip=ip,
                    target_endpoint=f"port:{list(MONITORED_PORTS)}",
                    severity="high",
                    payload_sample=f"{len(conn_times)} connections from {ip} in 30s",
                    raw_data={"connection_count": len(conn_times)},
                    confidence=0.78,
                ))
                self._ip_connections[ip].clear()

        for ip, port_times in list(self._ip_ports.items()):
            self._prune_path_deque(port_times, 10)
            unique_ports = {p for _, p in port_times}
            if len(unique_ports) >= SCAN_BURST_THRESHOLD:
                await self.emit(ThreatEvent(
                    source="network_sensor",
                    event_type="port_scan",
                    source_ip=ip,
                    target_endpoint="multiple_ports",
                    severity="medium",
                    payload_sample=f"Probed {len(unique_ports)} unique ports in 10s",
                    raw_data={"probed_ports": list(unique_ports)[:20]},
                    confidence=0.82,
                ))
                self._ip_ports[ip].clear()

    @staticmethod
    def _prune_deque(dq: deque, window_seconds: int):
        cutoff = datetime.utcnow() - timedelta(seconds=window_seconds)
        while dq and dq[0] < cutoff:
            dq.popleft()

    @staticmethod
    def _prune_path_deque(dq: deque, window_seconds: int):
        cutoff = datetime.utcnow() - timedelta(seconds=window_seconds)
        while dq and dq[0][0] < cutoff:
            dq.popleft()
