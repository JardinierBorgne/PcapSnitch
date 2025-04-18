from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP
from scapy.layers.http import HTTPRequest, HTTPResponse
from collections import defaultdict

class ProtocolStats:
    def __init__(self, packets):
        self.packets = packets

    def count_protocols(self):
        protocol_counts = defaultdict(int)

        for pkt in self.packets:
            if TCP in pkt:
                protocol_counts["TCP"] += 1
            if UDP in pkt:
                protocol_counts["UDP"] += 1
            if ICMP in pkt:
                protocol_counts["ICMP"] += 1
            if DNS in pkt:
                protocol_counts["DNS"] += 1
            if IP in pkt:
                protocol_counts["IP"] += 1
            if ARP in pkt:
                protocol_counts["ARP"] += 1
            if HTTPRequest in pkt or HTTPResponse in pkt:
                protocol_counts["HTTP"] += 1
            # En point d'amélioration pour gérer d’autres protocoles, on peux les ajouter ici
            #if <autre_protocole> in pkt:
            #    protocol_counts["<autre_protocole>"] += 1
        
        # Tri décroissant par nombre de paquets
        return dict(sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True))
