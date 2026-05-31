"""
Network Scanner — Device Discovery Engine
네트워크 디바이스 발견, ARP 스캔, 포트 스캔
"""
import socket
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.all import ARP, Ether, srp, conf

logger = logging.getLogger("netmaster.scanner")


class NetworkScanner:
    """네트워크 디바이스 발견 엔진"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.timeout = self.config.get("scan_timeout", 30)
        self.max_threads = self.config.get("scan_threads", 50)
        self.target_subnet = None

    def get_interfaces(self) -> list:
        """시스템 네트워크 인터페이스 목록"""
        try:
            import netifaces
            interfaces = []
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                ipv4 = addrs.get(netifaces.AF_INET, [{}])
                ipv6 = addrs.get(netifaces.AF_INET6, [{}])
                mac = addrs.get(netifaces.AF_LINK, [{}])
                interfaces.append({
                    "name": iface,
                    "ipv4": ipv4[0].get("addr", "N/A") if ipv4 else "N/A",
                    "netmask": ipv4[0].get("netmask", "N/A") if ipv4 else "N/A",
                    "ipv6": ipv6[0].get("addr", "N/A") if ipv6 else "N/A",
                    "mac": mac[0].get("addr", "N/A") if mac else "N/A",
                })
            return interfaces
        except ImportError:
            return self._fallback_interfaces()

    def _fallback_interfaces(self) -> list:
        try:
            result = subprocess.run(["ifconfig"], capture_output=True, text=True)
            return [{"raw": result.stdout}]
        except FileNotFoundError:
            return [{"error": "ifconfig not found"}]

    def get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def get_subnet(self, ip: str = None, netmask: str = "255.255.255.0") -> str:
        if ip is None:
            ip = self.get_local_ip()
        from netaddr import IPNetwork
        network = IPNetwork(f"{ip}/{netmask}")
        return str(network.cidr)

    def arp_scan(self, subnet: str = None) -> dict:
        if subnet is None:
            subnet = self.target_subnet or self.get_subnet()
        devices = {}
        try:
            conf.verb = 0
            result = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=3, retry=2)
            for sent, received in result[0]:
                devices[received.psrc] = {
                    "ip": received.psrc, "mac": received.hwsrc,
                    "hostname": self._resolve_hostname(received.psrc),
                    "vendor": self._lookup_vendor(received.hwsrc),
                    "status": "up", "method": "arp",
                }
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
        return devices

    def ping_sweep(self, subnet: str = None) -> dict:
        if subnet is None:
            subnet = self.target_subnet or self.get_subnet()
        from netaddr import IPNetwork
        devices = {}
        network = IPNetwork(subnet)
        hosts = [str(ip) for ip in network.iter_hosts()][1:]
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._ping_host, ip): ip for ip in hosts}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    is_up, latency = future.result()
                    if is_up:
                        devices[ip] = {"ip": ip, "status": "up", "latency_ms": latency, "method": "ping"}
                except Exception as e:
                    logger.debug(f"Ping sweep host {ip} failed: {e}")
        return devices

    def _ping_host(self, ip: str) -> tuple:
        try:
            param = "-n" if subprocess.os.name == "nt" else "-c"
            timeout_param = "-w" if subprocess.os.name == "nt" else "-W"
            result = subprocess.run(
                ["ping", param, "1", timeout_param, "1", ip],
                capture_output=True, text=True, timeout=3)
            is_up = result.returncode == 0
            return is_up, None
        except Exception:
            return False, None

    def discover(self, subnet: str = None) -> dict:
        if subnet:
            self.target_subnet = subnet
        all_devices = {}
        all_devices.update(self.arp_scan(subnet))
        all_devices.update(self.ping_sweep(subnet))
        return all_devices

    @staticmethod
    def _resolve_hostname(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    @staticmethod
    def _lookup_vendor(mac: str) -> str:
        try:
            from netaddr import EUI
            return EUI(mac).oui.registration().get("org", "Unknown")
        except Exception:
            return "Unknown"
