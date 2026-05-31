"""
NetMaster — Network Management All-in-One Tool
Main Application Entry Point
"""
import os
import sys
import yaml
import logging
from pathlib import Path
from datetime import datetime

# 설정
APP_NAME = "NetMaster"
APP_VERSION = "0.1.0"
BASE_DIR = Path(__file__).parent
CONFIG_DIR = BASE_DIR / "config"
OUTPUT_DIR = BASE_DIR / "output"
LOG_DIR = BASE_DIR / "logs"

# src 디렉토리를 모듈 검색 경로에 추가
SRC_DIR = str(BASE_DIR / "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# 디렉토리 생성
for d in [CONFIG_DIR, OUTPUT_DIR, LOG_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / f"netmaster_{datetime.now():%Y%m%d}.log"),
    ],
)
logger = logging.getLogger("netmaster")


def load_config(config_path: str = None) -> dict:
    """설정 파일 로드"""
    if config_path is None:
        config_path = CONFIG_DIR / "config.yaml"

    default_config = {
    "network": {
        "scan_timeout": 30,
        "ping_count": 4,
        "ping_timeout": 2,
        "traceroute_max_hops": 30,
        "traceroute_timeout": 2,
        "snmp_community": "public",
        "snmp_timeout": 5,
        "dns_servers": ["8.8.8.8", "1.1.1.1"],
        "scan_threads": 50,
    },
        "ui": {
            "host": "0.0.0.0",
            "port": 8080,
            "debug": False,
            "refresh_interval": 5,
        },
        "alerts": {
            "enabled": True,
            "latency_threshold_ms": 100,
            "packet_loss_threshold_pct": 10,
            "device_down_alert": True,
        },
        "topology": {
            "auto_scan": True,
            "scan_interval_minutes": 60,
            "layout_algorithm": "spring",
        },
    }

    if Path(config_path).exists():
        with open(config_path) as f:
            user_config = yaml.safe_load(f)
            if user_config:
                # 병합
                for section, values in user_config.items():
                    if section in default_config and isinstance(values, dict):
                        default_config[section].update(values)
                    else:
                        default_config[section] = values

    return default_config


class NetMaster:
    """NetMaster 메인 애플리케이션"""

    def __init__(self, config: dict = None):
        self.config = config or load_config()
        self.devices = {}       # 발견된 디바이스
        self.topology = None    # 토폴로지 그래프
        self.scan_results = {}  # 스캔 결과
        self.alerts = []        # 알림 목록
        self.ssh_tool = None    # SSH 툴 인스턴스 (세션 유지)
        logger.info(f"NetMaster v{APP_VERSION} initialized")

    def discover_network(self, subnet: str = None) -> dict:
        """네트워크 디바이스 발견"""
        from scanner.network_scanner import NetworkScanner

        scanner = NetworkScanner(self.config["network"])
        if subnet:
            scanner.target_subnet = subnet

        self.devices = scanner.discover()
        logger.info(f"Discovered {len(self.devices)} devices")
        return self.devices

    def build_topology(self) -> dict:
        """네트워크 토폴로지 구축"""
        from topology.topology_builder import TopologyBuilder

        builder = TopologyBuilder(self.config["topology"])
        self.topology = builder.build(self.devices)
        logger.info(f"Topology built: {len(self.topology.get('nodes', []))} nodes")
        return self.topology

    def ping(self, host: str, count: int = None) -> dict:
        """Ping 실행"""
        from protocols.ping import PingTool

        tool = PingTool(self.config["network"])
        return tool.ping(host, count=count)

    def traceroute(self, host: str, max_hops: int = None) -> dict:
        """Traceroute 실행"""
        from protocols.traceroute import TracerouteTool

        tool = TracerouteTool(self.config["network"])
        return tool.trace(host, max_hops=max_hops)

    def dns_lookup(self, domain: str, record_type: str = "A") -> dict:
        """DNS 조회"""
        from protocols.dns_arp import DNSTool

        tool = DNSTool(self.config["network"])
        return tool.lookup(domain, record_type)

    def arp_scan(self, subnet: str = None) -> dict:
        """ARP 스캔"""
        from protocols.dns_arp import ARPTool

        tool = ARPTool(self.config["network"])
        return tool.scan(subnet)

    def snmp_query(self, host: str, oid: str, community: str = None) -> dict:
        """SNMP 쿼리"""
        from protocols.snmp_tool import SNMPTool

        tool = SNMPTool(self.config["network"])
        return tool.query(host, oid, community=community)

    def ssh_connect(self, host: str, username: str, password: str = None,
                    key_file: str = None, port: int = 22) -> dict:
        """SSH 접속"""
        from protocols.ssh_telnet import SSHTool

        self.ssh_tool = SSHTool(self.config["network"])
        return self.ssh_tool.connect(host, username, password=password,
                                     key_file=key_file, port=port)

    def execute(self, session_id: str, command: str,
                timeout: int = 30) -> dict:
        """SSH 세션에서 명령 실행"""
        if not self.ssh_tool:
            return {"error": "No SSH session available", "session_id": session_id}
        return self.ssh_tool.execute(session_id, command, timeout)

    def telnet_connect(self, host: str, port: int = 23) -> dict:
        """Telnet 접속"""
        from protocols.ssh_telnet import TelnetTool

        tool = TelnetTool(self.config["network"])
        return tool.connect(host, port)

    def get_status(self) -> dict:
        """전체 상태 요약"""
        return {
            "app": APP_NAME,
            "version": APP_VERSION,
            "devices_found": len(self.devices),
            "topology_built": self.topology is not None,
            "alerts_count": len(self.alerts),
            "config_sections": list(self.config.keys()),
        }


# CLI 엔트리포인트
def main():
    """CLI 모드 실행"""
    import click

    @click.group()
    @click.option("--config", "-c", default=None, help="Config file path")
    @click.pass_context
    def cli(ctx, config):
        ctx.ensure_object(dict)
        ctx.obj["app"] = NetMaster(load_config(config))

    @cli.command()
    @click.argument("host")
    @click.option("--count", "-n", default=4, help="Ping count")
    @click.pass_context
    def ping(ctx, host, count):
        result = ctx.obj["app"].ping(host, count)
        from rich.console import Console
        from rich.json import JSON
        console = Console()
        console.print(JSON.from_data(result))

    @cli.command()
    @click.argument("host")
    @click.option("--max-hops", "-m", default=30, help="Max hops")
    @click.pass_context
    def trace(ctx, host, max_hops):
        result = ctx.obj["app"].traceroute(host, max_hops)
        from rich.console import Console
        from rich.json import JSON
        console = Console()
        console.print(JSON.from_data(result))

    @cli.command()
    @click.argument("domain")
    @click.option("--type", "-t", default="A", help="Record type")
    @click.pass_context
    def dns(ctx, domain, type):
        result = ctx.obj["app"].dns_lookup(domain, type)
        from rich.console import Console
        from rich.json import JSON
        console = Console()
        console.print(JSON.from_data(result))

    @cli.command()
    @click.option("--subnet", "-s", default=None, help="Subnet to scan")
    @click.pass_context
    def discover(ctx, subnet):
        result = ctx.obj["app"].discover_network(subnet)
        from rich.console import Console
        from rich.table import Table
        console = Console()
        table = Table(title="Discovered Devices")
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="green")
        table.add_column("Hostname", style="yellow")
        table.add_column("Status", style="bold")
        for ip, dev in result.items():
            table.add_row(ip, dev.get("mac", ""), dev.get("hostname", ""),
                         dev.get("status", ""))
        console.print(table)

    @cli.command()
    @click.option("--host", "-h", default="0.0.0.0", help="Bind host")
    @click.option("--port", "-p", default=8080, help="Bind port")
    @click.pass_context
    def web(ctx, host, port):
        from ui.app import create_app
        app = create_app(ctx.obj["app"])
        app.run(host=host, port=port, debug=True)

    cli(obj={})


if __name__ == "__main__":
    main()
