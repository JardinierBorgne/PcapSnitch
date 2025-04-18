from collections import defaultdict
from scapy.all import IP

class AnomalyDetector:
    def __init__(self, time_series, threshold=10):
        self.time_series = time_series
        self.threshold = threshold

    def detect_peaks(self):
        alerts = []
        protocol_peaks = defaultdict(int)
        timestamps = sorted(self.time_series.keys())
        for i in range(1, len(timestamps)):
            t_prev, t_curr = timestamps[i - 1], timestamps[i]
            for proto in self.time_series[t_curr]:
                delta = self.time_series[t_curr].get(proto, 0) - self.time_series[t_prev].get(proto, 0)
                if delta >= self.threshold:
                    protocol_peaks[proto] += 1
        for proto, count in protocol_peaks.items():
            alerts.append(f"Pic d'activité détecté pour {proto} : {count} occurrence(s)")
        return alerts

    def detect_rare_ports(self, packets):
        alerts = []
        for pkt in packets:
            if hasattr(pkt, 'sport') and pkt.sport > 1024:
                src_ip = pkt[IP].src if IP in pkt else "?"
                alerts.append(f"Port source inhabituel détecté : {pkt.sport} (IP : {src_ip})")
            if hasattr(pkt, 'dport') and pkt.dport > 1024:
                dst_ip = pkt[IP].dst if IP in pkt else "?"
                alerts.append(f"Port destination inhabituel détecté : {pkt.dport} (IP : {dst_ip})")
        return alerts
