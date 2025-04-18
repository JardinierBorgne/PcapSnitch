from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP
from scapy.layers.http import HTTPRequest

class ProtocolFilter:
    def __init__(self, packets):
        self.packets = packets

    def filter_by_protocol(self, protocol):
        protocol = protocol.upper()
        if protocol == "TCP":
            return [pkt for pkt in self.packets if TCP in pkt]
        elif protocol == "UDP":
            return [pkt for pkt in self.packets if UDP in pkt]
        elif protocol == "ICMP":
            return [pkt for pkt in self.packets if ICMP in pkt]
        elif protocol == "DNS":
            return [pkt for pkt in self.packets if DNS in pkt]
        elif protocol == "IP":
            return [pkt for pkt in self.packets if IP in pkt]
        elif protocol == "ARP":
            return [pkt for pkt in self.packets if ARP in pkt]
        elif protocol == "HTTP":
            return [pkt for pkt in self.packets if HTTPRequest in pkt]
        else:
            return(f"[!] Protocole non pris en charge : {protocol}")
            return []

