"""NetMaster 실제 기능 데모 테스트"""
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import NetMaster
from protocols import PingTool, TracerouteTool, DNSTool, ARPTool
from scanner import NetworkScanner
from topology import TopologyBuilder

print("=" * 60)
print("🌐 NetMaster 실제 기능 데모")
print("=" * 60)

# 1. NetMaster 초기화
app = NetMaster()
print(f"\n✅ NetMaster v0.1.0 초기화 완료")
print(f"   설정: {list(app.config.keys())}")

# 2. Ping 테스트
print(f"\n📡 Ping 테스트")
ping = PingTool(app.config["network"])
result = ping.ping("127.0.0.1", count=3)
print(f"   대상: {result['host']} ({result['ip']})")
print(f"   송신: {result['packets_sent']}, 수신: {result['packets_received']}")
print(f"   손실: {result['loss_pct']:.0f}%")
if result['avg_ms']:
    print(f"   평균 지연: {result['avg_ms']}ms")
    print(f"   최소/최대: {result['min_ms']}ms / {result['max_ms']}ms")

# 3. DNS 조회
print(f"\n🌐 DNS 조회")
dns = DNSTool(app.config["network"])
result = dns.lookup("google.com", "A")
print(f"   도메인: {result['domain']}")
print(f"   레코드: {len(result.get('records', []))}개")
for r in result.get("records", [])[:3]:
    print(f"   → {r['value']} (TTL: {r['ttl']})")

# 4. ARP 테이블
print(f"\n📋 ARP 테이블")
arp = ARPTool()
table = arp.get_arp_table()
print(f"   항목 수: {table['total_entries']}")
for entry in table.get("entries", [])[:5]:
    print(f"   {entry['ip']:16s} {entry['mac']:18s} {entry.get('vendor', '')[:20]}")

# 5. 로컬 네트워크 정보
print(f"\n🔍 로컬 네트워크")
scanner = NetworkScanner(app.config["network"])
local_ip = scanner.get_local_ip()
subnet = scanner.get_subnet()
print(f"   로컬 IP: {local_ip}")
print(f"   서브넷: {subnet}")

interfaces = scanner.get_interfaces()
print(f"   인터페이스: {len(interfaces)}개")
for iface in interfaces[:3]:
    if "name" in iface:
        print(f"   → {iface['name']}: {iface.get('ipv4', 'N/A')}")

# 6. 토폴로지 빌드 테스트
print(f"\n🗺️ 토폴로지 빌드")
tb = TopologyBuilder(app.config["topology"])
sample_devices = {
    "192.168.1.1": {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff",
                     "hostname": "gateway", "status": "up", "type": "router"},
    "192.168.1.10": {"ip": "192.168.1.10", "mac": "11:22:33:44:55:66",
                      "hostname": "server1", "status": "up", "type": "server"},
    "192.168.1.20": {"ip": "192.168.1.20", "mac": "aa:bb:cc:dd:ee:01",
                      "hostname": "pc1", "status": "up", "type": "host"},
    "192.168.1.21": {"ip": "192.168.1.21", "mac": "aa:bb:cc:dd:ee:02",
                      "hostname": "pc2", "status": "up", "type": "host"},
}
topo = tb.build(sample_devices)
print(f"   노드: {topo['stats']['total_nodes']}")
print(f"   엣지: {topo['stats']['total_edges']}")
print(f"   타입: {topo['stats']['node_types']}")

print(f"\n{'=' * 60}")
print("✅ 모든 기능 데모 완료!")
print(f"{'=' * 60}")
print(f"\n웹 대시보드 실행:")
print(f"  cd /Users/bearj/coding_projects/netmaster")
print(f"  python3 -m ui.app")
print(f"  → http://localhost:8080")
