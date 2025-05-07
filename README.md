<table>
  <tr>
    <td width="200" align="center" valign="center">
      <img src="static/alpaka.png" alt="ARTIFAKT Logo" width="190">
    </td>
    <td valign="center">
      <h1>ARTIFAKT</h1>
    </td>
  </tr>
</table>

> Artefakt- und Indikator-Fundstelle zur Anlage und Klassifizierung von Threats

[![Lizenz: MIT](https://img.shields.io/badge/Lizenz-MIT-gelb.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8+-blau.svg)](https://www.python.org/downloads/)
[![Framework: Flask](https://img.shields.io/badge/framework-Flask-grün.svg)](https://flask.palletsprojects.com/)

**ARTIFAKT** ist ein modulares Web-Portal, entwickelt mit Python und Flask, das grundlegende Funktionen zur Unterstützung von Threat-Intelligence-Aufgaben bietet. Es dient als zentrale Anlaufstelle zum Sammeln von Artefakten, Einreichen von IoCs (Indicators of Compromise) über eine dynamische Connector-Schnittstelle und zur initialen Analyse von potenziellen Malware-Samples sowie zur Überprüfung von IoC-Reputationen.

---

## ✨ Funktionen

* **Artefakt-Upload:**
    * Hochladen von Dateien (Logs, E-Mails, Dokumente etc.)
    * Hinzufügen von Metadaten: Quellsystem (Pflicht), Casenummer (Pflicht), Kommentar (Optional)
    * Speicherung der Datei zusammen mit `metadata.txt` in einem ZIP-Archiv
* **IoC-Einreichung & Import:**
    * Eingabe von IoCs (IPs, Domains, Hashes, URLs, etc.) über ein Textfeld (ein IoC pro Zeile)
    * Upload von IoC-Listen aus Dateien (`.txt`, `.csv`, `.yar`)
    * Automatische Erkennung des IoC-Typs
    * Dynamischer Aufruf aller **Import-Connectors** im Ordner `internal_import/`
        * Enthaltene Connectors:
            * `misp_import_connector.py`: Fügt Attribut zu konfiguriertem MISP Event hinzu
            * `opencti_import_connector.py`: Erstellt Observable in OpenCTI
* **Malware-Sample Upload & Erstbewertung:**
    * Hochladen einzelner Dateien
    * Berechnung des SHA256-Hashes
    * Dynamischer Aufruf aller **internen Enrichment-Connectors** im Ordner `internal_enrichment/` für den Hash
        * Enthaltene Connectors:
            * `opencti_connector.py`: Prüft Reputation/Existenz in OpenCTI
            * `misp_lookup_connector.py`: Prüft Reputation/Existenz in MISP
    * Sichere Archivierung der Originaldatei als ZIP-Archiv mit konfigurierbarem Passwort (Default: `infected`)
* **Reputation Check (Enrichment):**
    * Eingabemaske zur manuellen Überprüfung eines beliebigen Indikators
    * Auswahlmöglichkeit zur Prüfung gegen:
        * **Nur Intern:** Führt alle Connectors in `internal_enrichment/` aus
        * **Nur Extern:** Führt alle Connectors in `external_enrichment/` aus 
        * **Intern & Extern:** Führt alle Connectors aus beiden Verzeichnissen aus
    * Anzeige der aggregierten Ergebnisse aller ausgeführten Connectors in einer Tabelle

## 🚀 Setup und Installation

1.  **Voraussetzungen:**
    * Python 3.8+
    * `pip` (Python package installer)
    * `git` (zum Klonen des Repositories)
    * Zugang zu einer OpenCTI Instanz mit API-Token (Lese-/Schreibrechte für Observables/Vulnerabilities)
    * Zugang zu einer MISP Instanz mit API Key & Ziel-Event-ID

2.  **Repository klonen:**
    ```bash
    git clone https://github.com/RaikyHH/ARTIFAKT.git
    cd ARTIFAKT
    ```

3.  **Virtuelle Umgebung erstellen:**
    ```bash
    # Linux/macOS
    python3 -m venv venv
    source venv/bin/activate

    # Windows
    python -m venv venv
    .\venv\Scripts\activate
    ```

4.  **Abhängigkeiten installieren:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Konfiguration (Umgebungsvariablen):**
    Erstelle eine `.env`-Datei im Hauptverzeichnis des Projekts oder setze die Umgebungsvariablen direkt

6.  **Anwendung starten (Entwicklungsmodus):**
    Stelle sicher, dass die virtuelle Umgebung aktiviert ist und die `.env`-Datei existiert oder die Variablen gesetzt sind.
    ```bash
    flask run --host=0.0.0.0 --port=8080
    ```
    Oder direkt:
    ```bash
    python app.py
    ```
    Die Anwendung ist unter `http://127.0.0.1:8080` oder `http://<Deine_IP>:8080` erreichbar.

## 🔌 Connector-Architektur

Das System nutzt eine einfache Plugin-Architektur für Anreicherung (Enrichment) und Import:

* **Enrichment Connectors:**
    * Python-Dateien in `internal_enrichment/` oder `external_enrichment/`.
    * Müssen eine Funktion `analyze(indicator_value, indicator_type, config)` implementieren.
    * `config` enthält globale Einstellungen (API Keys, URLs, Proxies - nur für externe Connectors relevant).
    * Müssen ein standardisiertes Ergebnis-Dictionary zurückgeben (siehe `analyze`-Funktionen der vorhandenen Connectors für das Format: `status`, `summary`, `details`, `link`, `error_message`).
* **Import Connectors:**
    * Python-Dateien in `internal_import/`.
    * Müssen eine Funktion `import_indicator(ioc_value, ioc_type, config, source_info)` implementieren.
    * `config` enthält relevante API Keys/URLs. `source_info` enthält Metadaten vom Upload (optional).
    * Müssen ein Status-Dictionary zurückgeben (mindestens: `connector_name`, `success`, `message`).

Neue Connectors können durch Hinzufügen einer `.py`-Datei mit der korrekten Funktion zum entsprechenden Ordner erstellt werden.

## 📄 License

Dieses Projekt steht unter der MIT-Lizenz. Siehe die `LICENSE`-Datei für Details.