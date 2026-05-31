"""
Network Topology Builder — Auto-discovery and visualization
"""
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("netmaster.topology")

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


@dataclass
class TopologyNode:
    id: str
    label: str
    node_type: str = "unknown"
    ip: str = ""
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    layer: int = 0
    properties: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "label": self.label, "type": self.node_type,
            "ip": self.ip, "mac": self.mac, "hostname": self.hostname,
            "vendor": self.vendor, "layer": self.layer, "properties": self.properties,
        }


@dataclass
class TopologyEdge:
    source: str
    target: str
    label: str = ""
    bandwidth: str = ""
    protocol: str = ""
    properties: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source": self.source, "target": self.target,
            "label": self.label, "bandwidth": self.bandwidth,
            "protocol": self.protocol, "properties": self.properties,
        }


class TopologyBuilder:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.layout_algo = self.config.get("layout_algorithm", "spring")

    def build(self, devices: dict) -> dict:
        if not HAS_NETWORKX:
            return {"error": "networkx not installed", "nodes": [], "edges": []}

        G = nx.Graph()
        nodes = []
        edges = []

        for ip, dev in devices.items():
            node_type = self._classify_device(dev)
            node = TopologyNode(
                id=ip,
                label=f"{dev.get('hostname', ip)}\n{ip}",
                node_type=node_type,
                ip=ip,
                mac=dev.get("mac", ""),
                hostname=dev.get("hostname", ""),
                vendor=dev.get("vendor", ""),
                layer=self._determine_layer(dev),
                properties={"status": dev.get("status", "unknown")},
            )
            nodes.append(node.to_dict())
            G.add_node(ip, **node.to_dict())

        edges = self._infer_edges(devices, G)
        d3_data = self._to_d3_format(nodes, edges)
        layout = self._calculate_layout(G)

        return {
            "nodes": nodes, "edges": edges, "d3_data": d3_data,
            "layout": layout,
            "stats": {
                "total_nodes": len(nodes), "total_edges": len(edges),
                "node_types": self._count_node_types(nodes),
            },
        }

    def _classify_device(self, dev):
        hostname = dev.get("hostname", "").lower()
        vendor = dev.get("vendor", "").lower()
        if any(k in hostname for k in ["router", "gw", "gateway"]): return "router"
        if any(k in hostname for k in ["switch", "sw", "ap"]): return "switch"
        if any(k in hostname for k in ["fw", "firewall"]): return "firewall"
        if any(k in vendor for k in ["cisco", "juniper", "huawei"]): return "switch"
        return dev.get("type", "host")

    def _determine_layer(self, dev):
        t = self._classify_device(dev)
        if t in ("router", "firewall"): return 3
        if t == "switch": return 2
        return 2

    def _infer_edges(self, devices, G):
        edges = []
        try:
            from netaddr import IPAddress
            subnet_groups = {}
            for ip in devices:
                try:
                    addr = IPAddress(ip)
                    subnet = str(addr & IPAddress("255.255.255.0"))
                    subnet_groups.setdefault(subnet, []).append(ip)
                except Exception:
                    pass
            for subnet, group in subnet_groups.items():
                if len(group) > 1:
                    gw = group[0]
                    for host in group[1:]:
                        edge = TopologyEdge(source=gw, target=host,
                                          label=f"subnet {subnet}",
                                          properties={"inferred": True})
                        edges.append(edge.to_dict())
                        G.add_edge(gw, host)
        except Exception as e:
            logger.debug(f"Edge inference failed: {e}")
        return edges

    def _to_d3_format(self, nodes, edges):
        return {
            "nodes": [{"id": n["id"], "label": n["label"], "group": n["type"],
                       "ip": n["ip"], "hostname": n.get("hostname", "")} for n in nodes],
            "links": [{"source": e["source"], "target": e["target"],
                       "label": e.get("label", "")} for e in edges],
        }

    def _calculate_layout(self, G):
        if not HAS_NETWORKX or len(G.nodes) == 0:
            return {}
        try:
            algo = self.layout_algo
            if algo == "spring": pos = nx.spring_layout(G, k=2, iterations=50)
            elif algo == "circular": pos = nx.circular_layout(G)
            elif algo == "shell": pos = nx.shell_layout(G)
            else: pos = nx.spring_layout(G)
            return {str(n): {"x": float(x), "y": float(y)} for n, (x, y) in pos.items()}
        except Exception as e:
            logger.debug(f"Layout calculation failed: {e}")
            return {}

    @staticmethod
    def _count_node_types(nodes):
        counts = {}
        for n in nodes:
            t = n.get("type", "unknown")
            counts[t] = counts.get(t, 0) + 1
        return counts
