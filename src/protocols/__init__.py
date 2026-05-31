"""
NetMaster Protocols — All network protocol tools
"""
# Import all tools for easy access
from protocols.ping import PingTool, PingResult
from protocols.traceroute import TracerouteTool, TracerouteHop
from protocols.dns_arp import DNSTool, DNSRecord, ARPTool
from protocols.snmp_tool import SNMPTool, SNMPResult, SNMPDeviceInfo
from protocols.ssh_telnet import SSHTool, SSHResult, TelnetTool, TelnetResult

__all__ = [
    "PingTool", "PingResult",
    "TracerouteTool", "TracerouteHop",
    "DNSTool", "DNSRecord", "ARPTool",
    "SNMPTool", "SNMPResult", "SNMPDeviceInfo",
    "SSHTool", "SSHResult",
    "TelnetTool", "TelnetResult",
]
