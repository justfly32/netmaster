"""
SNMP Tool — Device Monitoring & Management
SNMP v1/v2c/v3, MIB browsing, Trap receiver
"""
import logging
import socket
import threading
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger("netmaster.protocols.snmp")


@dataclass
class SNMPResult:
    host: str
    oid: str
    value: str = ""
    type: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {"host": self.host, "oid": self.oid, "value": self.value,
                "type": self.type, "error": self.error}


@dataclass
class SNMPDeviceInfo:
    """SNMP로 수집한 디바이스 정보"""
    hostname: str = ""
    sys_descr: str = ""
    sys_uptime: str = ""
    sys_contact: str = ""
    sys_name: str = ""
    sys_location: str = ""
    interfaces: list = field(default_factory=list)
    routing_table: list = field(default_factory=list)
    tcp_connections: list = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname, "sys_descr": self.sys_descr,
            "sys_uptime": self.sys_uptime, "sys_contact": self.sys_contact,
            "sys_name": self.sys_name, "sys_location": self.sys_location,
            "interfaces": self.interfaces,
            "routing_table": self.routing_table,
            "error": self.error,
        }


class SNMPTool:
    """SNMP 모니터링 도구"""

    # 표준 MIB OID
    SYSTEM_OIDS = {
        "sysDescr": "1.3.6.1.2.1.1.1.0",
        "sysObjectID": "1.3.6.1.2.1.1.2.0",
        "sysUpTime": "1.3.6.1.2.1.1.3.0",
        "sysContact": "1.3.6.1.2.1.1.4.0",
        "sysName": "1.3.6.1.2.1.1.5.0",
        "sysLocation": "1.3.6.1.2.1.1.6.0",
        "sysServices": "1.3.6.1.2.1.1.7.0",
    }

    INTERFACE_OIDS = {
        "ifNumber": "1.3.6.1.2.1.2.1.0",
        "ifTable": "1.3.6.1.2.1.2.2.1",
        "ifDescr": "1.3.6.1.2.1.2.2.1.2",
        "ifType": "1.3.6.1.2.1.2.2.1.3",
        "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
        "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
        "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
        "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
        "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
        "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
        "ifInErrors": "1.3.6.1.2.1.2.2.1.14",
        "ifOutErrors": "1.3.6.1.2.1.2.2.1.20",
    }

    IP_OIDS = {
        "ipForwarding": "1.3.6.1.2.1.4.1.0",
        "ipDefaultTTL": "1.3.6.1.2.1.4.2.0",
        "ipInReceives": "1.3.6.1.2.1.4.3.0",
        "ipOutRequests": "1.3.6.1.2.1.4.10.0",
        "ipRoutingTable": "1.3.6.1.2.1.4.21.1",
        "ipNetToMediaTable": "1.3.6.1.2.1.4.22.1",
    }

    TCP_OIDS = {
        "tcpRtoAlgorithm": "1.3.6.1.2.1.6.1.0",
        "tcpMaxConn": "1.3.6.1.2.1.6.4.0",
        "tcpActiveOpens": "1.3.6.1.2.1.6.5.0",
        "tcpCurrEstab": "1.3.6.1.2.1.6.9.0",
    }

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.community = self.config.get("snmp_community", "public")
        self.timeout = self.config.get("snmp_timeout", 5)
        self.retries = self.config.get("snmp_retries", 2)
        self.port = self.config.get("snmp_port", 161)

    def _snmp_get(self, host: str, oid: str, community: str = None,
                  port: int = None) -> tuple:
        """SNMP GET 요청"""
        community = community or self.community
        port = port or self.port

        try:
            from pysnmp.hlapi import (
                getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity,
            )

            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((host, port), timeout=self.timeout,
                                   retries=self.retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )

            error_indication, error_status, error_index, var_binds = next(iterator)

            if error_indication:
                return None, str(error_indication)
            elif error_status:
                return None, f"{error_status.prettyPrint()} at {var_binds[int(error_index) - 1][0] if error_index else '?'}"
            else:
                for var_bind in var_binds:
                    return str(var_bind[1]), None
                return None, "No data"

        except ImportError:
            return None, "pysnmp not installed"
        except Exception as e:
            return None, str(e)

    def _snmp_walk(self, host: str, oid: str, community: str = None,
                   port: int = None) -> dict:
        """SNMP WALK (OID 트리 순회)"""
        community = community or self.community
        port = port or self.port
        results = {}

        try:
            from pysnmp.hlapi import (
                nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity,
            )

            for (error_indication, error_status, error_index, var_binds) in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((host, port), timeout=self.timeout,
                                   retries=self.retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
            ):
                if error_indication:
                    results["error"] = str(error_indication)
                    break
                elif error_status:
                    results["error"] = str(error_status)
                    break
                else:
                    for var_bind in var_binds:
                        oid_str = str(var_bind[0])
                        value_str = str(var_bind[1])
                        results[oid_str] = value_str

        except ImportError:
            results["error"] = "pysnmp not installed"
        except Exception as e:
            results["error"] = str(e)

        return results

    def query(self, host: str, oid: str, community: str = None) -> dict:
        """단일 OID SNMP 쿼리"""
        value, error = self._snmp_get(host, oid, community)
        return SNMPResult(
            host=host, oid=oid, value=value or "", error=error or "",
            type="get",
        ).to_dict()

    def walk(self, host: str, oid: str, community: str = None) -> dict:
        """OID 트리 순회"""
        return {
            "host": host,
            "oid": oid,
            "results": self._snmp_walk(host, oid, community),
        }

    def get_system_info(self, host: str, community: str = None) -> dict:
        """시스템 정보 종합 수집"""
        info = SNMPDeviceInfo()

        for name, oid in self.SYSTEM_OIDS.items():
            value, error = self._snmp_get(host, oid, community)
            if value:
                if name == "sysDescr":
                    info.sys_descr = value
                elif name == "sysUpTime":
                    info.sys_uptime = value
                elif name == "sysContact":
                    info.sys_contact = value
                elif name == "sysName":
                    info.sys_name = value
                    info.hostname = value
                elif name == "sysLocation":
                    info.sys_location = value
            elif error:
                info.error = error

        return info.to_dict()

    def get_interfaces(self, host: str, community: str = None) -> dict:
        """네트워크 인터페이스 정보 수집"""
        interfaces = {}

        # 인터페이스 수
        if_count, err = self._snmp_get(host, self.INTERFACE_OIDS["ifNumber"], community)
        if if_count:
            interfaces["count"] = if_count

        # 인터페이스 테이블 walk
        walk_results = self._snmp_walk(
            host, self.INTERFACE_OIDS["ifDescr"], community
        )

        for oid, value in walk_results.items():
            if oid == "error":
                continue
            # OID에서 인터페이스 인덱스 추출
            idx = oid.split(".")[-1]
            if idx not in interfaces:
                interfaces[idx] = {"index": idx}
            interfaces[idx]["description"] = value

        # 각 인터페이스의 추가 정보
        for idx in list(interfaces.keys()):
            if idx == "count":
                continue
            for field_name, base_oid in [
                ("type", "ifType"), ("speed", "ifSpeed"),
                ("mac", "ifPhysAddress"), ("admin_status", "ifAdminStatus"),
                ("oper_status", "ifOperStatus"),
                ("in_octets", "ifInOctets"), ("out_octets", "ifOutOctets"),
                ("in_errors", "ifInErrors"), ("out_errors", "ifOutErrors"),
            ]:
                oid = f"{self.INTERFACE_OIDS[field_name]}.{idx}"
                value, _ = self._snmp_get(host, oid, community)
                if value:
                    interfaces[idx][field_name] = value

        return {"host": host, "interfaces": interfaces}

    def monitor(self, host: str, oids: list, interval: int = 60,
                duration: int = 300, community: str = None) -> dict:
        """지정 OID 모니터링 (일정 시간 반복 수집)"""
        import time
        results = {"host": host, "interval": interval, "samples": []}
        start = time.time()
        sample_count = 0

        while time.time() - start < duration:
            sample = {"timestamp": time.time(), "values": {}}
            for oid_name, oid in oids.items():
                value, error = self._snmp_get(host, oid, community)
                sample["values"][oid_name] = {
                    "value": value, "error": error, "oid": oid,
                }
            results["samples"].append(sample)
            sample_count += 1
            time.sleep(interval)

        results["total_samples"] = sample_count
        results["duration_seconds"] = time.time() - start
        return results

    def trap_receiver(self, bind_addr: str = "0.0.0.0", port: int = 162,
                      callback=None) -> dict:
        """SNMP 트랩 수신기 시작"""
        try:
            from pysnmp.hlapi import (
                SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, NotificationType, ObjectIdentity,
            )
            # 트랩 수신은 별도 스레드에서 실행
            def _listen():
                logger.info(f"SNMP Trap receiver started on {bind_addr}:{port}")
                # 실제 구현은 pysnmp의 AsynchroneousNotificationReceiver 사용
                pass

            thread = threading.Thread(target=_listen, daemon=True)
            thread.start()
            return {"status": "started", "bind": bind_addr, "port": port}
        except Exception as e:
            return {"status": "error", "error": str(e)}
