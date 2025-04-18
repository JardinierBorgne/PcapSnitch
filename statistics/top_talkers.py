from collections import defaultdict
from scapy.layers.inet import IP

class TopTalkers:
    def __init__(self, packets):
        self.packets = packets

    def get_top_senders(self, top_n=10):
        sender_counts = defaultdict(int)
        for pkt in self.packets:
            if IP in pkt:
                sender_counts[pkt[IP].src] += 1
        return sorted(sender_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]

