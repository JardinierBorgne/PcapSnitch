import matplotlib.pyplot as plt
from datetime import datetime
import os

class GraphGenerator:

    @staticmethod
    def plot_top_protocols(protocol_counts, output_file):
        # Inclure les protocoles ARP, ICMP, et HTTP dans les données
        protocols = ["IP", "TCP", "UDP", "DNS", "ARP", "ICMP", "HTTP"]
        counts = [protocol_counts.get(proto, 0) for proto in protocols]

        # Création du graphique
        plt.figure(figsize=(10, 6))
        plt.bar(protocols, counts, color='skyblue')
        plt.title("Protocoles les plus utilisés")
        plt.xlabel("Protocole")
        plt.ylabel("Nombre de paquets")
        plt.tight_layout()

        # Sauvegarde du graphique
        plt.savefig(output_file)
        plt.close()

    @staticmethod
    def plot_top_talkers(ip_counts, output_path="talkers.png"):
        ips = [ip for ip, _ in ip_counts]
        counts = [count for _, count in ip_counts]

        plt.figure(figsize=(10, 5))
        plt.barh(ips, counts, color='salmon')
        plt.title("Top Talkers (IPs les plus actives)")
        plt.xlabel("Nombre de paquets")
        plt.ylabel("Adresse IP")
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()

    @staticmethod
    def plot_time_series(time_series, output_path="time_series.png"):
        # Extraire tous les protocoles connus dans les timestamps
        all_protocols = set()
        for protocols in time_series.values():
            all_protocols.update(protocols.keys())

        # Organiser les données
        times = [datetime.fromtimestamp(t) for t in time_series.keys()]
        protocol_data = {proto: [] for proto in all_protocols}

        for t in time_series.keys():
            for proto in all_protocols:
                protocol_data[proto].append(time_series[t].get(proto, 0))

        # Tracer les courbes
        plt.figure(figsize=(12, 6))
        for proto, counts in protocol_data.items():
            plt.plot(times, counts, label=proto)

        plt.title("Série temporelle des paquets par protocole")
        plt.xlabel("Temps")
        plt.ylabel("Nombre de paquets/seconde")
        plt.legend()
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()
