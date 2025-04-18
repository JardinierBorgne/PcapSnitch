from scapy.all import rdpcap
import os

class PcapLoader:
    def __init__(self, filepath):
        self.filepath = filepath
        self.packets = []

    def load(self):
        if not os.path.isfile(self.filepath):
            raise FileNotFoundError(f"Fichier introuvable : {self.filepath}")
        self.packets = rdpcap(self.filepath)
        return(f"[✓] {len(self.packets)} paquets chargés depuis {self.filepath}")

    def get_packets(self):
        return self.packets