"""
Traceroute Tool — Network path tracing
"""
import socket
import subprocess
import sys
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger("netmaster.protocols.traceroute")


@dataclass
class TracerouteHop:
    hop_num: int
    ip: str = ""
    hostname: str = ""
    rtt_ms: list = field(default_factory=list)
    avg_ms: float = 0.0
    status: str = "unknown"

    def to_dict(self) -> dict:
        return {
            "hop": self.hop_num, "ip": self.ip,
            "hostname": self.hostname,
            "rtt_ms": self.rtt_ms, "avg_ms": self.avg_ms,
            "status": self.status,
        }


class TracerouteTool:
    def __init__(self, config=None):
        self.config = config or {}
        self.max_hops = self.config.get("traceroute_max_hops", 30)
        self.timeout = self.config.get("traceroute_timeout", 2)

    def trace(self, host, max_hops=None):
        if max_hops is None:
            max_hops = self.max_hops
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return {"host": host, "error": f"Cannot resolve {host}", "hops": []}

        hops = []
        timeout_per_hop = self.timeout
        try:
            if subprocess.os.name == "nt":
                cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout_per_hop * 1000)), host]
            elif sys.platform == "darwin":
                cmd = ["traceroute", "-n", "-q", "1", "-m", str(max_hops), "-w", str(int(timeout_per_hop)), host]
            else:
                cmd = ["traceroute", "-n", "-q", "1", "-m", str(max_hops), "-w", str(int(timeout_per_hop)), host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_per_hop * max_hops + 30)
            hops = self._parse_output(result.stdout)
        except subprocess.TimeoutExpired:
            logger.warning(f"Traceroute timed out, parsing partial output")
            hops = self._parse_output(result.stdout)
        except Exception as e:
            logger.error(f"Traceroute failed: {e}")

        return {
            "host": host, "target_ip": ip, "max_hops": max_hops,
            "hops_found": len(hops),
            "hops": [h.to_dict() for h in hops],
            "completed": len(hops) > 0 and (hops[-1].status == "ok" or hops[-1].ip == ip),
        }

    def _parse_output(self, output):
        hops = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.match(r"^\s*(\d+)", line)
            if not m:
                continue
            hop = TracerouteHop(hop_num=int(m.group(1)))
            if "*" in line:
                hop.status = "timeout"
            else:
                ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if ip_m:
                    hop.ip = ip_m.group(1)
                    hop.status = "ok"
                    rtt_ms = re.findall(r"([\d.]+)\s*ms", line)
                    if rtt_ms:
                        hop.rtt_ms = [float(r) for r in rtt_ms]
                        hop.avg_ms = round(sum(hop.rtt_ms) / len(hop.rtt_ms), 2)
            hops.append(hop)
        return hops
