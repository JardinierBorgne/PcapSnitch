# PcapSnitch

**PcapSnitch** est une application Python conçue pour analyser et traiter des fichiers PCAP (Packet Capture). Elle offre une interface simple pour explorer, filtrer et visualiser les données réseau capturées. PcapSnitch permet de générer des rapports détaillés, détecter des anomalies et exporter des statistiques pour une analyse approfondie.

---

## Utilisation

1. Lancement du programme :
    - Lancez le main.py

2. Démarrer l'analyse :
    - Chargez votre fichier pcap avec "1.Charger un fichier PCAP", au besoin vous pouvez lancer une capture en direct et obtenir un fichier PCAP à analyser avec l'option "6. Lancer une capture en direct".

3. Appliquer des filtres pour analyser les paquets :
    - Utilisez l'option "2.Filtrer par protocole" pour filtrer les paquets par protocole.
    
4. Analyser les statistiques :
    - Utilisez l'option "4.Effectuer l'analyse statistique" pour explorer les séries temporelles, détecter des anomalies ou identifier les principaux émetteurs.
    - Les résultats sont exportés sous forme de graphique au format .PNG.

5. Générer des rapports :
    - Sélectionnez "4.Générer le rapport PDF" pour créer un rapport PDF détaillé contenant les graphiques et les statistiques sur les données capturées.

6. Exporter les données :
    - Avec l'option "5.Exporter les statistiques en CSV", sauvegardez les résultats sous forme de fichiers CSV pour une utilisation externe.

## Arborescence du projet

```
PcapSnitch/
├── data/                 # Dossier pour les fichiers de données (CSV, PCAP, etc.)
│    └── capture_*.pcap   # Fichiers PCAP capturés (générés dynamiquement)                
├── filters/              # Module pour le filtrage des paquets
│   └── protocol_filter.py # Classe pour filtrer les paquets par protocole
├── pcap_loader/          # Module pour le chargement des fichiers PCAP
│   └── loader.py         # Classe pour charger et lire les fichiers PCAP
├── reporters/            # Module pour la génération de rapports et graphiques
│   ├── graph_generator.py # Génération de graphiques (protocoles, talkers, etc.)
│   └── pdf_report.py     # Génération de rapports PDF
├── statistics/           # Module pour les analyses statistiques
│   ├── anomaly_detector.py # Détection d'anomalies dans les données
│   ├── packet_counter.py   # Comptage des paquets par couche OSI
│   ├── protocol_stats.py   # Statistiques des protocoles
│   ├── time_series.py      # Construction de séries temporelles
│   └── top_talkers.py      # Identification des principaux émetteurs
├── utils/                # Module utilitaire
│   └── helpers.py        # Fonctions utilitaires (ex. sauvegarde CSV)
├── main.py               # Point d'entrée principal de l'application 
└── README.md             # Documentation du projet
```

## Améliorations possibles

- Gestion de plus de protocoles (définir les plus pertinents)
- Gestion des interfaces réseaux moins verbeuse
- Meilleure GUI (Tkinter, PyQT, questionnary)