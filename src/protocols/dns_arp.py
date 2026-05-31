"""
DNS & ARP Tools
DNS lookup, reverse DNS, ARP table, MAC resolution
"""
import socket
import logging
import subprocess
from typing import Optional
from dataclasses import dataclass, field

import dns.resolver
import dns.reversename
import dns.query

logger = logging.getLogger("netmaster.protocols.dns_arp")


# ─── DNS ───────────────────────────────────────────

@dataclass
class DNSRecord:
    domain: str
    record_type: str
    value: str
    ttl: int = 0
    priority: int = 0  # MX record

    def to_dict(self) -> dict:
        d = {"domain": self.domain, "type": self.record_type,
             "value": self.value, "ttl": self.ttl}
        if self.record_type == "MX":
            d["priority"] = self.priority
        return d


class DNSTool:
    """DNS 조회 도구"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.dns_servers = self.config.get("dns_servers", ["8.8.8.8", "1.1.1.1"])
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = self.dns_servers
        self.resolver.timeout = 5
        self.resolver.lifetime = 10

    def lookup(self, domain: str, record_type: str = "A",
               dns_server: str = None) -> dict:
        """DNS 정방향 조회"""
        if dns_server:
            self.resolver.nameservers = [dns_server]

        result = {
            "domain": domain,
            "record_type": record_type,
            "server": dns_server or self.dns_servers[0],
            "records": [],
            "error": None,
        }

        try:
            answers = self.resolver.resolve(domain, record_type)
            for rdata in answers:
                record = DNSRecord(
                    domain=domain,
                    record_type=record_type,
                    value=str(rdata),
                    ttl=answers.rrset.ttl if answers.rrset else 0,
                )
                if record_type == "MX":
                    record.priority = rdata.preference
                    record.value = str(rdata.exchange)
                result["records"].append(record.to_dict())

        except dns.resolver.NXDOMAIN:
            result["error"] = f"Domain {domain} does not exist"
        except dns.resolver.NoAnswer:
            result["error"] = f"No {record_type} records for {domain}"
        except dns.resolver.NoNameservers:
            result["error"] = "No nameservers available"
        except Exception as e:
            result["error"] = str(e)

        return result

    def reverse_lookup(self, ip: str) -> dict:
        """역방향 DNS 조회 (IP → 도메인)"""
        result = {"ip": ip, "hostname": "", "error": None}
        try:
            reversed_dns = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(reversed_dns, "PTR")
            result["hostname"] = str(answers[0]).rstrip(".")
        except Exception as e:
            result["error"] = str(e)
        return result

    def full_dns_report(self, domain: str) -> dict:
        """모든 DNS 레코드 종합 조회"""
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "SRV"]
        report = {"domain": domain, "records": {}, "errors": []}

        for rtype in record_types:
            try:
                result = self.lookup(domain, rtype)
                if result["records"]:
                    report["records"][rtype] = result["records"]
                elif result["error"]:
                    report["errors"].append(f"{rtype}: {result['error']}")
            except Exception as e:
                report["errors"].append(f"{rtype}: {str(e)}")

        return report

    def dns_propagation_check(self, domain: str, record_type: str = "A",
                                servers: list = None) -> dict:
        """DNS 전파 확인 (여러 서버에서 조회 비교)"""
        if servers is None:
            servers = ["8.8.8.8", "1.1.1.1", "208.67.222.222",
                      "9.9.9.9", "76.76.76.76"]

        results = {}
        unique_values = set()
        for server in servers:
            result = self.lookup(domain, record_type, dns_server=server)
            values = [r["value"] for r in result.get("records", [])]
            results[server] = values
            unique_values.update(values)

        return {
            "domain": domain,
            "record_type": record_type,
            "server_results": results,
            "propagated": len(unique_values) <= 1,
            "unique_values": list(unique_values),
            "servers_checked": len(servers),
        }

    def nslookup_interactive(self, domain: str, dns_server: str = None) -> dict:
        """nslookup 스타일 대화형 조회"""
        original_servers = self.resolver.nameservers[:]
        if dns_server:
            self.resolver.nameservers = [dns_server]

        result = {
            "domain": domain,
            "server": dns_server or original_servers[0],
            "addresses": [],
            "aliases": [],
            "nameservers": [],
        }

        try:
            # A record
            for r in self.resolver.resolve(domain, "A"):
                result["addresses"].append(str(r))
        except Exception:
            pass

        # CNAME
        try:
            for r in self.resolver.resolve(domain, "CNAME"):
                result["aliases"].append(str(r))
        except Exception:
            pass

        # NS
        try:
            for r in self.resolver.resolve(domain, "NS"):
                result["nameservers"].append(str(r).rstrip("."))
        except Exception:
            pass

        self.resolver.nameservers = original_servers
        return result


# ─── ARP ───────────────────────────────────────────

class ARPTool:
    """ARP 테이블 관리 도구"""

    def __init__(self, config: dict = None):
        self.config = config or {}

    def get_arp_table(self) -> dict:
        """시스템 ARP 테이블 조회"""
        entries = []
        try:
            if subprocess.os.name == "nt":
                output = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=10
                ).stdout
                entries = self._parse_windows_arp(output)
            else:
                # Linux/macOS
                output = subprocess.run(
                    ["arp", "-an"], capture_output=True, text=True, timeout=10
                ).stdout
                entries = self._parse_unix_arp(output)
        except Exception as e:
            logger.error(f"ARP table read failed: {e}")

        return {
            "total_entries": len(entries),
            "entries": entries,
        }

    def _parse_windows_arp(self, output: str) -> list:
        """Windows ARP 출력 파싱"""
        import re
        entries = []
        for line in output.splitlines():
            match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\s+([\w-]+)\s+(\w+)", line
            )
            if match:
                ip, mac, type_ = match.groups()
                if mac != "ff-ff-ff-ff-ff-ff" and mac != "00-00-00-00-00-00":
                    entries.append({
                        "ip": ip,
                        "mac": mac.lower().replace("-", ":"),
                        "type": type_,
                        "vendor": self._lookup_vendor(mac),
                    })
        return entries

    def _parse_unix_arp(self, output: str) -> list:
        """Unix ARP 출력 파싱"""
        import re
        entries = []
        for line in output.splitlines():
            match = re.search(
                r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([\w:]+)", line
            )
            if match:
                ip, mac = match.groups()
                iface_match = re.search(r"on\s+(\w+)", line)
                iface = iface_match.group(1) if iface_match else ""
                if mac != "(incomplete)":
                    entries.append({
                        "ip": ip,
                        "mac": mac.lower(),
                        "interface": iface,
                        "type": "dynamic" if "PERM" not in line else "static",
                        "vendor": self._lookup_vendor(mac),
                    })
        return entries

    def scan_arp(self, subnet: str = None) -> dict:
        """Scapy로 ARP 스캔 후 테이블 갱신"""
        from scapy.all import ARP, Ether, srp, conf

        if subnet is None:
            scanner = self.config.get("scanner")
            if scanner:
                subnet = scanner.get_subnet()
            else:
                subnet = "192.168.1.0/24"

        devices = {}
        try:
            conf.verb = 0
            arp = ARP(pdst=subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            result = srp(ether / arp, timeout=3, retry=2)

            for sent, received in result[0]:
                devices[received.psrc] = {
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "vendor": self._lookup_vendor(received.hwsrc),
                }
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")

        return {"subnet": subnet, "devices_found": len(devices), "devices": devices}

    def clear_arp_cache(self) -> bool:
        """ARP 캐시 초기화"""
        try:
            if subprocess.os.name == "nt":
                subprocess.run(["arp", "-d", "*"], capture_output=True, timeout=5)
            else:
                subprocess.run(["ip", "-s", "-s", "neigh", "flush", "all"],
                              capture_output=True, timeout=5)
            return True
        except Exception as e:
            logger.error(f"ARP cache clear failed: {e}")
        return False

    def arp_poison_detect(self) -> dict:
        """ARP 스푸핑 감지"""
        table = self.get_arp_table()
        entries = table.get("entries", [])

        # 같은 MAC에 여러 IP가 매핑되는지 확인
        mac_to_ips = {}
        for entry in entries:
            mac = entry.get("mac", "")
            ip = entry.get("ip", "")
            if mac and ip:
                mac_to_ips.setdefault(mac, []).append(ip)

        suspicious = {
            mac: ips for mac, ips in mac_to_ips.items()
            if len(ips) > 1
        }

        return {
            "suspicious": len(suspicious) > 0,
            "details": suspicious,
            "recommendation": "Potential ARP spoofing detected" if suspicious else "OK",
        }

    @staticmethod
    def _lookup_vendor(mac: str) -> str:
        """MAC 주소에서 제조사 조회"""
        try:
            from netaddr import EUI
            m = mac.replace("-", ":").lower()
            eui = EUI(m)
            return eui.oui.registration().get("org", "Unknown")
        except Exception:
            return "Unknown"
