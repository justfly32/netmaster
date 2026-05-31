"""
NetMaster Build Test — 전체 모듈 임포트 및 기능 검증
"""
import sys
import os

# src 디렉토리를 경로에 추가
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))
sys.path.insert(0, PROJECT_ROOT)

passed = 0
failed = 0

def test(name, fn):
    global passed, failed
    try:
        fn()
        passed += 1
        print(f"  ✅ {name}")
    except Exception as e:
        failed += 1
        print(f"  ❌ {name}: {e}")


print("=== NetMaster Build Test ===\n")

# 1. Core imports
def test_import_main():
    from main import NetMaster, load_config, APP_NAME, APP_VERSION
    assert APP_NAME == "NetMaster"

def test_import_scanner():
    from scanner import NetworkScanner
    ns = NetworkScanner({"scan_timeout": 10})
    assert ns.timeout == 10

def test_import_protocols():
    from protocols import PingTool, TracerouteTool, DNSTool, ARPTool, SNMPTool, SSHTool, TelnetTool
    from protocols.dns_arp import DNSTool as DNSTool2

def test_import_topology():
    from topology import TopologyBuilder
    tb = TopologyBuilder({"layout_algorithm": "spring"})
    assert tb.layout_algo == "spring"

def test_import_ui():
    from ui.app import create_app

test("Main module import", test_import_main)
test("Scanner module import", test_import_scanner)
test("Protocol modules import", test_import_protocols)
test("Topology module import", test_import_topology)
test("UI module import", test_import_ui)

# 2. Functional tests
print("\n=== Functional Tests ===\n")

def test_netmaster_init():
    from main import NetMaster
    app = NetMaster()
    status = app.get_status()
    assert status["app"] == "NetMaster"

def test_scanner_local_ip():
    from scanner import NetworkScanner
    ns = NetworkScanner()
    ip = ns.get_local_ip()
    assert ip and len(ip) > 0
    print(f"    Local IP: {ip}")

def test_ping_loopback():
    from protocols import PingTool
    pt = PingTool({"ping_count": 2, "ping_timeout": 2})
    # Just test initialization, not actual ping
    assert pt.default_count == 2

def test_dns_tool_init():
    from protocols import DNSTool
    dt = DNSTool({"dns_servers": ["8.8.8.8"]})
    assert "8.8.8.8" in dt.dns_servers

def test_traceroute_init():
    from protocols import TracerouteTool
    tt = TracerouteTool({"traceroute_max_hops": 5})
    assert tt.max_hops == 5

def test_arp_tool_init():
    from protocols import ARPTool
    at = ARPTool()
    table = at.get_arp_table()
    assert "entries" in table
    print(f"    ARP entries: {table['total_entries']}")

def test_snmp_tool_init():
    from protocols import SNMPTool
    st = SNMPTool({"snmp_community": "public"})
    assert st.community == "public"

def test_ssh_tool_init():
    from protocols import SSHTool
    ssh = SSHTool({"ssh_timeout": 5})
    assert ssh.timeout == 5

def test_telnet_init():
    from protocols import TelnetTool
    tt = TelnetTool({"telnet_timeout": 5})
    assert tt.timeout == 5

def test_topology_builder():
    from topology import TopologyBuilder
    tb = TopologyBuilder()
    devices = {
        "192.168.1.1": {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff",
                         "hostname": "router", "status": "up", "type": "router"},
        "192.168.1.100": {"ip": "192.168.1.100", "mac": "11:22:33:44:55:66",
                           "hostname": "pc1", "status": "up", "type": "host"},
    }
    topo = tb.build(devices)
    assert "nodes" in topo
    assert len(topo["nodes"]) == 2
    print(f"    Topology: {len(topo['nodes'])} nodes, {len(topo['edges'])} edges")

test("NetMaster initialization", test_netmaster_init)
test("Scanner local IP", test_scanner_local_ip)
test("Ping tool init", test_ping_loopback)
test("DNS tool init", test_dns_tool_init)
test("Traceroute tool init", test_traceroute_init)
test("ARP tool init", test_arp_tool_init)
test("SNMP tool init", test_snmp_tool_init)
test("SSH tool init", test_ssh_tool_init)
test("Telnet tool init", test_telnet_init)
test("Topology builder", test_topology_builder)

print(f"\n=== Results: {passed} passed, {failed} failed ===")
if failed == 0:
    print("ALL TESTS PASSED ✅")
else:
    print("SOME TESTS FAILED ❌")
    sys.exit(1)
