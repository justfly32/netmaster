"""
Ping Tool — ICMP Ping implementation
"""
import socket
import subprocess
import sys
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("netmaster.protocols.ping")


@dataclass
class PingResult:
    host: str
    ip: str = ""
    packets_sent: int = 0
    packets_received: int = 0
    packets_lost: int = 0
    loss_pct: float = 0.0
    min_ms: float = 0.0
    max_ms: float = 0.0
    avg_ms: float = 0.0
    jitter_ms: float = 0.0
    rtts: list = field(default_factory=list)
    resolved: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "host": self.host, "ip": self.ip,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "packets_lost": self.packets_lost,
            "loss_pct": self.loss_pct,
            "min_ms": self.min_ms, "max_ms": self.max_ms,
            "avg_ms": self.avg_ms, "jitter_ms": self.jitter_ms,
            "resolved": self.resolved, "error": self.error,
        }


class PingTool:
    def __init__(self, config=None):
        self.config = config or {}
        self.default_count = self.config.get("ping_count", 4)
        self.timeout = self.config.get("ping_timeout", 2)

    def ping(self, host, count=None, interval=1.0):
        if count is None:
            count = self.default_count
        result = PingResult(host=host, packets_sent=count)
        try:
            result.ip = socket.gethostbyname(host)
            result.resolved = True
        except socket.gaierror:
            result.error = f"Cannot resolve {host}"
            return result.to_dict()
        rtts = self._subprocess_ping(result.ip, count)
        result.rtts = rtts
        result.packets_received = len(rtts)
        result.packets_lost = count - len(rtts)
        result.loss_pct = (result.packets_lost / count) * 100 if count > 0 else 0
        if rtts:
            result.min_ms = round(min(rtts), 2)
            result.max_ms = round(max(rtts), 2)
            result.avg_ms = round(sum(rtts) / len(rtts), 2)
            if len(rtts) > 1:
                diffs = [abs(rtts[i] - rtts[i-1]) for i in range(1, len(rtts))]
                result.jitter_ms = round(sum(diffs) / len(diffs), 2)
        return result.to_dict()

    def _subprocess_ping(self, ip, count):
        import re
        rtts = []
        try:
            param = "-n" if subprocess.os.name == "nt" else "-c"
            if subprocess.os.name == "nt":
                timeout_args = ["-w", str(int(self.timeout * 1000))]
            elif sys.platform == "darwin":
                timeout_args = ["-W", str(int(self.timeout * 1000))]
            else:
                timeout_args = ["-W", str(int(self.timeout))]
            result = subprocess.run(
                ["ping", param, str(count), *timeout_args, ip],
                capture_output=True, text=True, timeout=self.timeout * count + 5)
            for line in result.stdout.splitlines():
                m = re.search(r"time[=<]([\d.]+)\s*ms", line)
                if m:
                    rtts.append(float(m.group(1)))
            if not rtts:
                m = re.search(r"min/avg/max.*=\s*([\d.]+)/([\d.]+)/([\d.]+)", result.stdout)
                if m:
                    rtts = [float(m.group(1)), float(m.group(2)), float(m.group(3))]
        except Exception as e:
            logger.error(f"Ping failed: {e}")
        return rtts
