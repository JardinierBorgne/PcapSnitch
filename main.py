'''
PcapSnitch - Application de traitement de fichiers PCAP
Par Nathan BOËL - MSI1
'''

# Importation des modules nécessaires
from pcap_loader.loader import PcapLoader  # Chargement des fichiers PCAP
from filters.protocol_filter import ProtocolFilter  # Filtrage des paquets par protocole
from statistics.packet_counter import PacketCounter  # Comptage des paquets par couche OSI
from statistics.protocol_stats import ProtocolStats  # Statistiques des protocoles
from statistics.top_talkers import TopTalkers  # Identification des principaux émetteurs
from statistics.time_series import TimeSeriesBuilder  # Construction de séries temporelles
from statistics.anomaly_detector import AnomalyDetector  # Détection d'anomalies
from reporters.graph_generator import GraphGenerator  # Génération de graphiques
from reporters.pdf_report import PDFReport  # Génération de rapports PDF
from utils.helpers import save_csv  # Sauvegarde des données au format CSV

# Importation de Scapy pour la capture réseau
from scapy.all import sniff, wrpcap
from scapy.arch.windows import get_windows_if_list
import sys
import time
import os  # Import pour gérer les chemins

# Définir le dossier de sortie pour les fichiers générés
DATA_DIR = "data"
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)  # Crée le dossier s'il n'existe pas

# Fonction pour capturer le trafic réseau en direct
def live_capture():
    print("\n[📡] Interfaces disponibles :")
    interfaces = get_windows_if_list()  # Liste des interfaces réseau disponibles
    for i, iface in enumerate(interfaces):
        name = iface.get('name', 'Inconnu')  # Nom de l'interface
        description = iface.get('description', '')  # Description de l'interface
        print(f"{i}. {name} - {description}")

    # Sélection de l'interface réseau
    try:
        idx = int(input("Choisissez une interface à écouter : "))
        iface = interfaces[idx]['name']
    except (IndexError, ValueError):
        print("[!] Choix invalide.")
        return

    # Durée de la capture
    try:
        duration = int(input("Durée de capture (en secondes, 0 pour illimité + Ctrl+C) : "))
    except ValueError:
        duration = 0

    print(f"[▶️] Capture en cours sur : {iface} ({'illimitée' if duration == 0 else str(duration)+'s'})")
    try:
        # Capture des paquets
        if duration > 0:
            packets = sniff(iface=iface, timeout=duration, store=True)
        else:
            packets = sniff(iface=iface, store=True)
    except KeyboardInterrupt:
        print("\n[⏹️] Capture stoppée par l'utilisateur.")
        packets = packets if 'packets' in locals() else []

    # Sauvegarde des paquets capturés
    if packets:
        filename = os.path.join(DATA_DIR, f"capture_{int(time.time())}.pcap")
        wrpcap(filename, packets)
        print(f"[✓] {len(packets)} paquets capturés et sauvegardés dans {filename}.")
    else:
        print("[!] Aucune donnée capturée.")

# Fonction principale du menu
def menu():
    packets = None  # Liste des paquets chargés
    loader = None  # Instance du chargeur PCAP
    pcap_path = ""  # Chemin du fichier PCAP

    while True:
        # Affichage du menu principal
        print("\n===== MENU ANALYSE RÉSEAU =====")
        print("1. Charger un fichier PCAP")
        print("2. Filtrer par protocole")
        print("3. Effectuer l’analyse statistique")
        print("4. Générer le rapport PDF")
        print("5. Exporter les statistiques en CSV")
        print("6. Lancer une capture en direct")
        print("7. Quitter")
        choice = input("Choix : ")

        if choice == "1":
            # Chargement d'un fichier PCAP
            pcap_path = input("Chemin du fichier .pcap : ")
            try:
                loader = PcapLoader(pcap_path)
                loader.load()
                packets = loader.get_packets()
            except Exception as e:
                print(f"Erreur : {e}")

        elif choice == "2":
            # Filtrage des paquets par protocole
            if not packets:
                print("Veuillez charger un fichier PCAP d'abord.")
                continue
            proto = input("Protocole à filtrer (TCP, UDP, ICMP, DNS, ARP, HTTP) : ")
            filtered = ProtocolFilter(packets).filter_by_protocol(proto)
            print(f"{len(filtered)} paquets {proto.upper()} trouvés.")

        elif choice == "3":
            # Analyse statistique des paquets
            if not packets:
                print("Veuillez charger un fichier PCAP d'abord.")
                continue
            print("\n[Analyse statistique en cours...]")
            osi_stats = PacketCounter(packets).count_by_osi_layer()  # Comptage par couche OSI
            protocol_counts = ProtocolStats(packets).count_protocols()  # Comptage des protocoles
            talkers = TopTalkers(packets).get_top_senders()  # Principaux émetteurs
            series = TimeSeriesBuilder(packets).build_series()  # Séries temporelles
            # Génération des graphiques
            GraphGenerator.plot_top_protocols(protocol_counts, os.path.join(DATA_DIR, "protocols.png"))
            GraphGenerator.plot_top_talkers(talkers, os.path.join(DATA_DIR, "talkers.png"))
            GraphGenerator.plot_time_series(series, os.path.join(DATA_DIR, "timeline.png"))
            print("[✓] Analyse et graphiques générés.")

        elif choice == "4":
            # Génération d'un rapport PDF
            if not packets:
                print("Veuillez charger un fichier PCAP d'abord.")
                continue
            osi_stats = PacketCounter(packets).count_by_osi_layer()
            protocol_counts = ProtocolStats(packets).count_protocols()
            talkers = TopTalkers(packets).get_top_senders()
            series = TimeSeriesBuilder(packets).build_series()
            
            # Détection des anomalies
            anomalies = AnomalyDetector(series).detect_peaks() + AnomalyDetector(series).detect_rare_ports(packets)
            
            # Suppression des doublons dans les anomalies
            unique_anomalies = list(set(anomalies))  # Utilisation de set pour dédupliquer

            pdf = PDFReport()
            pdf.add_cover_page()  # Ajout de la page de garde
            pdf.add_intro(pcap_path, len(packets))  # Introduction
            pdf.add_osi_table(osi_stats)  # Tableau des couches OSI
            pdf.add_protocol_table(protocol_counts)  # Tableau des protocoles
            pdf.add_image_section("Protocoles les plus utilisés", os.path.join(DATA_DIR, "protocols.png"))  # Graphique des protocoles
            pdf.add_image_section("Top Talkers", os.path.join(DATA_DIR, "talkers.png"))  # Graphique des émetteurs
            pdf.add_image_section("Série temporelle du trafic réseau", os.path.join(DATA_DIR, "timeline.png"))  # Graphique temporel
            pdf.add_anomalies(unique_anomalies)  # Anomalies dédupliquées
            pdf.export(os.path.join(DATA_DIR, "rapport_analyse.pdf"))  # Export du rapport PDF

        elif choice == "5":
            # Export des statistiques en CSV
            if not packets:
                print("Veuillez charger un fichier PCAP d'abord.")
                continue
            protocol_counts = ProtocolStats(packets).count_protocols()
            talkers = TopTalkers(packets).get_top_senders()
            series = TimeSeriesBuilder(packets).build_series()
            print("[📁] Export des données...")
            # Sauvegarde des statistiques
            save_csv(protocol_counts.items(), os.path.join(DATA_DIR, "protocol_stats.csv"), headers=["Protocole", "Nb Paquets"])
            save_csv(talkers, os.path.join(DATA_DIR, "top_talkers.csv"), headers=["Adresse IP", "Nb Paquets"])
            ts_rows = []
            for ts, protos in series.items():
                row = [ts] + [protos.get(p, 0) for p in ["IP", "TCP", "UDP", "ICMP", "DNS", "ARP", "HTTP"]]
                ts_rows.append(row)
            save_csv(ts_rows, os.path.join(DATA_DIR, "time_series.csv"), headers=["Timestamp", "IP", "TCP", "UDP", "ICMP", "DNS", "ARP", "HTTP"])
            print("[✓] Fichiers CSV générés dans le dossier /data/")

        elif choice == "6":
            # Lancement d'une capture réseau en direct
            live_capture()

        elif choice == "7":
            # Quitter l'application
            print("Fermeture de l'application. À bientôt !")
            sys.exit()

        else:
            # Option invalide
            print("Option invalide. Veuillez réessayer.")

# Point d'entrée principal
if __name__ == "__main__":
    menu()