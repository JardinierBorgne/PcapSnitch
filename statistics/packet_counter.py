from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.packet import Packet
from scapy.layers.l2 import ARP

class PacketCounter:
    def __init__(self, packets):
        self.packets = packets

    def count_by_osi_layer(self):
        counts = {
            "Réseau (IP, ICMP, ARP)": 0,
            "Transport (TCP, UDP)": 0,
            "Application (DNS, HTTP)": 0
        }

        for pkt in self.packets:
            if IP in pkt or ICMP in pkt or ARP in pkt:
                counts["Réseau (IP, ICMP, ARP)"] += 1
            if TCP in pkt or UDP in pkt:
                counts["Transport (TCP, UDP)"] += 1
            if DNS in pkt or HTTPRequest in pkt or HTTPResponse in pkt:
                counts["Application (DNS, HTTP)"] += 1

        return counts
