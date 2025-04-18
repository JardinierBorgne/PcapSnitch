from collections import defaultdict
from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest
from scapy.layers.l2 import ARP

class TimeSeriesBuilder:
    def __init__(self, packets):
        self.packets = packets

    def build_series(self):
        time_series = defaultdict(lambda: defaultdict(int))
        for pkt in self.packets:
            if not hasattr(pkt, 'time'):
                continue
            ts = int(pkt.time)
            if TCP in pkt: time_series[ts]['TCP'] += 1
            if UDP in pkt: time_series[ts]['UDP'] += 1
            if ICMP in pkt: time_series[ts]['ICMP'] += 1
            if DNS in pkt: time_series[ts]['DNS'] += 1
            if IP in pkt: time_series[ts]['IP'] += 1
            if ARP in pkt: time_series[ts]['ARP'] += 1
            if HTTPRequest in pkt: time_series[ts]['HTTP'] += 1
        return dict(sorted(time_series.items()))
