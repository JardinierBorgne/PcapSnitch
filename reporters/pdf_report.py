from fpdf import FPDF
from datetime import datetime
import os

class PDFReport(FPDF):
    def __init__(self, title="Rapport d'Analyse Réseau"):
        super().__init__()
        self.title = title
        self.set_auto_page_break(auto=True, margin=15)
        # Utilisation de la police Arial par défaut pour éviter les problèmes de compatibilité (liste à puces pas compatible avec toutes les polices)
        self.set_font('Arial', '', 12)

    def add_intro(self, filename, packet_count):
        self.set_font("Arial", 'B', 12)
        self.cell(0, 10, "Informations générales", ln=True)
        self.set_font("Arial", '', 11)
        self.cell(0, 8, f"Fichier analysé : {filename}", ln=True)
        self.cell(0, 8, f"Date d'analyse : {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}", ln=True)
        self.ln(10)

    def add_osi_table(self, osi_stats):
        self.set_font("Arial", 'B', 12)
        self.cell(0, 10, "Répartition des paquets par couche OSI", ln=True)
        self.set_font("Arial", '', 11)

        for layer, count in osi_stats.items():
            self.cell(0, 8, f"{layer} : {count} paquets", ln=True)
        self.ln(5)

    def add_protocol_table(self, proto_stats):
        self.set_font("Arial", 'B', 12)
        self.cell(0, 10, "Répartition par protocole", ln=True)
        self.set_font("Arial", '', 11)
        self.multi_cell(0, 8, "Cette section montre la répartition des protocoles dans les différentes couches OSI.")
        self.ln(2)

        # En-tête
        self.set_fill_color(180, 200, 255)
        self.set_font("Arial", 'B', 11)
        self.cell(40, 10, "Protocole", border=1, fill=True)
        self.cell(40, 10, "Nombre de paquets", border=1, fill=True)
        self.ln()

        # Contenu
        self.set_font("Arial", '', 11)
        for proto, count in proto_stats.items():
            self.cell(40, 10, proto, border=1)
            self.cell(40, 10, str(count), border=1)
            self.ln()

    def add_image_section(self, title, image_path):
        # Vérifie si suffisamment d'espace est disponible sur la page (pour éviter les vides entre titres et graphiques ou fusions)
        if self.get_y() + 100 > self.h - self.b_margin:  # 100 est une estimation de la hauteur de l'image
            self.add_page()  # Ajoute une nouvelle page si nécessaire

        # Ajoute le titre
        self.set_font("Arial", 'B', 12)
        self.cell(0, 10, title, ln=True, align="C")  # Titre centré
        self.ln(5)  # Espacement réduit entre le titre et l'image

        # Forcer la position de l'image juste après le titre
        current_y = self.get_y()  # Position actuelle après le titre
        if os.path.exists(image_path):
            self.image(image_path, x=(210 - 180) / 2, y=current_y, w=180)  # Centrer l'image
            self.set_y(current_y + 100)  # Ajuste la position après l'image (100 est une estimation de la hauteur de l'image)
        else:
            self.cell(0, 10, "Image introuvable.", ln=True, align="C")

        self.ln(10)  # Espacement après l'image

    def add_anomalies(self, alert_list):
        self.add_page()
        self.set_font("Arial", 'B', 12)
        self.cell(0, 10, "Anomalies détectées", ln=True)
        self.set_font("Arial", '', 11)

        if not alert_list:
            self.cell(0, 8, "Aucune anomalie détectée.", ln=True)
            return

        for alert in alert_list:
            self.cell(10)  # Indentation pour simuler une liste
            self.cell(0, 8, f"- {alert}", ln=True)  # Remplace • par un tiret

        self.ln(5)

    def add_cover_page(self):
        # Ajouter une nouvelle page
        self.add_page()
        
        # Nom du programme
        self.set_font("Arial", 'B', 36)
        self.cell(0, 20, "PcapSnitch", ln=True, align='C')
        self.ln(20)  # Espacement vertical

        # Titre du rapport
        self.set_font("Arial", 'B', 24)
        self.cell(0, 15, "Rapport d'Analyse Réseau", ln=True, align='C')
        self.ln(15)

        # Date
        self.set_font("Arial", '', 16)
        self.cell(0, 10, datetime.now().strftime("Date : %d/%m/%Y"), ln=True, align='C')
        self.ln(30)  # Espacement vertical

        # Auteur ou description
        self.set_font("Arial", '', 14)
        self.ln(10)
        self.cell(0, 10, "Analyse des fichiers PCAP pour la détection et la visualisation des données réseau.", ln=True, align='C')

        # Passer à une nouvelle page
        self.add_page()

    def export(self, filename="rapport_analyse.pdf"):
        self.output(filename)
        return f"[✓] Rapport PDF généré : {filename}"
