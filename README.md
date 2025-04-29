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
    * Hochladen von Dateien (Logs, E-Mails, Dokumente etc.).
    * Hinzufügen von Metadaten: Quellsystem (Pflicht), Casenummer (Pflicht), Kommentar (Optional).
    * Speicherung der Datei zusammen mit `metadata.txt` in einem ZIP-Archiv.
    * Dateiname des Archivs: `JJJJ-MM-TT_HH-MM-SS_Zone_Quellsystem_Casenummer.zip` (z.B. `2024-10-27_15-30-00_UTC_EDR_System_INC12345.zip`).
* **IoC-Einreichung & Import:**
    * Eingabe von IoCs (IPs, Domains, Hashes, URLs, etc.) über ein Textfeld (ein IoC pro Zeile).
    * Upload von IoC-Listen aus Dateien (`.txt`, `.csv`, `.yar` - konfigurierbar).
    * Automatische Erkennung des IoC-Typs.
    * Dynamischer Aufruf aller **Import-Connectors** im Ordner `internal_import/`.
        * Enthaltene Connectors (implementiert):
            * `misp_import_connector.py`: Fügt Attribut zu konfiguriertem MISP Event hinzu.
            * `opencti_import_connector.py`: Erstellt Observable in OpenCTI (prüft auf Existenz).
* **Malware-Sample Upload & Erstbewertung:**
    * Hochladen einzelner Dateien.
    * Berechnung des SHA256-Hashes.
    * Dynamischer Aufruf aller **internen Enrichment-Connectors** im Ordner `internal_enrichment/` für den Hash.
        * Enthaltene Connectors (implementiert):
            * `opencti_connector.py`: Prüft Reputation/Existenz in OpenCTI.
            * `misp_lookup_connector.py`: Prüft Reputation/Existenz in MISP.
    * Sichere Archivierung der Originaldatei als ZIP-Archiv mit konfigurierbarem Passwort (Default: `infected`).
    * Anzeige der Ergebnisse der internen Connectors in einer Übersichtstabelle mit Ampelfarben.
* **Reputation Check (Enrichment):**
    * Eingabemaske zur manuellen Überprüfung eines beliebigen Indikators.
    * Auswahlmöglichkeit zur Prüfung gegen:
        * **Nur Intern:** Führt alle Connectors in `internal_enrichment/` aus (OpenCTI, MISP).
        * **Nur Extern:** Führt alle Connectors in `external_enrichment/` aus (VirusTotal implementiert).
        * **Intern & Extern:** Führt alle Connectors aus beiden Verzeichnissen aus.
    * Anzeige der aggregierten Ergebnisse aller ausgeführten Connectors in einer übersichtlichen Tabelle.

## 🚀 Setup und Installation

1.  **Voraussetzungen:**
    * Python 3.8+
    * `pip` (Python package installer)
    * `git` (zum Klonen des Repositories)
    * Zugang zu einer VirusTotal API (Free oder Premium)
    * Zugang zu einer OpenCTI Instanz mit API-Token (Lese-/Schreibrechte für Observables/Vulnerabilities)
    * Zugang zu einer MISP Instanz mit API Key & Ziel-Event-ID

2.  **Repository klonen:**
    ```bash
    git clone [https://github.com/RaikyHH/ARTIFAKT.git](https://github.com/RaikyHH/ARTIFAKT.git)
    cd ARTIFAKT
    ```

3.  **Virtuelle Umgebung erstellen (Empfohlen):**
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
    *(Stelle sicher, dass `requirements.txt` alle benötigten Pakete enthält, inkl. `Flask`, `python-dotenv`, `pycti`, `pymisp`, `requests`, `pyzipper` [optional], `Flask-Talisman` [optional])*

5.  **Konfiguration (Umgebungsvariablen):**
    Erstelle eine `.env`-Datei im Hauptverzeichnis des Projekts oder setze die Umgebungsvariablen direkt. Eine `.env.example`-Datei könnte so aussehen:

    ```dotenv
    # Flask Konfiguration
    FLASK_SECRET_KEY='DEIN_SEHR_GEHEIMER_SCHLUESSEL_HIER_EINFUEGEN' # Ändern!
    FLASK_ENV='development' # 'production' für den Produktivbetrieb
    # FLASK_LOG_LEVEL='DEBUG' # Optional: INFO, WARNING, ERROR, CRITICAL (Default: INFO)

    # VirusTotal API Key
    VT_API_KEY='DEIN_VT_API_V3_SCHLUESSEL'

    # OpenCTI Konfiguration
    OPENCTI_URL='[https://deine.opencti.instanz](https://deine.opencti.instanz)'
    OPENCTI_TOKEN='DEIN_OPENCTI_API_TOKEN'

    # MISP Konfiguration
    MISP_URL='[https://deine.misp.instanz](https://deine.misp.instanz)'
    MISP_KEY='DEIN_MISP_API_SCHLUESSEL'
    MISP_EVENTID_WRITE='ID_DES_ZIEL_EVENTS' # Die Event-ID, in die importiert wird
    MISP_VERIFY_SSL='False' # Auf 'True' setzen, wenn MISP SSL-Zertifikat valide ist

    # Proxy Konfiguration (Optional)
    PROXY_USED='False' # Auf 'True' setzen, um Proxy zu nutzen
    HTTPS_PROXY='[http://user:pass@proxy.example.com:8080](http://user:pass@proxy.example.com:8080)' # Nur relevant, wenn PROXY_USED=True

    # Malware ZIP Passwort (Optional)
    MALWARE_ZIP_PASSWORD='infected' # Default, wenn nicht gesetzt
    ```

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

    Für den **Produktivbetrieb** wird ein WSGI-Server wie Gunicorn oder uWSGI empfohlen:
    ```bash
    # Beispiel Gunicorn mit 4 Workern
    export FLASK_ENV=production # Sicherstellen, dass der Produktionsmodus aktiv ist
    gunicorn -w 4 -b 0.0.0.0:8080 app:app
    ```

## ⚙️ Konfiguration im Detail

Die Anwendung liest Konfigurationsparameter primär aus Umgebungsvariablen (idealerweise via `.env`-Datei):

* **`FLASK_SECRET_KEY` (Wichtig!)**: Ein langer, zufälliger String für die Session-Sicherheit. **Muss** in Produktion gesetzt werden.
* **`FLASK_ENV`**: `'development'` aktiviert den Debug-Modus und ausführlichere Logs. `'production'` (Default, wenn nicht gesetzt) deaktiviert den Debug-Modus.
* **`FLASK_LOG_LEVEL`**: Detailgrad der Logs (z.B. `DEBUG`, `INFO`, `WARNING`). Default ist `INFO`.
* **`VT_API_KEY`**: Für externe VirusTotal Abfragen (Connector: `external_enrichment/virustotal_connector.py`).
* **`OPENCTI_URL` / `OPENCTI_TOKEN`**: Zugangsdaten für OpenCTI (Connectors: `internal_enrichment/opencti_connector.py`, `internal_import/opencti_import_connector.py`). Benötigt passende Berechtigungen.
* **`MISP_URL` / `MISP_KEY`**: Zugangsdaten für MISP (Connectors: `internal_enrichment/misp_lookup_connector.py`, `internal_import/misp_import_connector.py`).
* **`MISP_EVENTID_WRITE`**: Event ID in MISP, in das neue Attribute über `internal_import/misp_import_connector.py` importiert werden.
* **`MISP_VERIFY_SSL`**: `'True'` oder `'False'` (Default) für SSL-Zertifikatsprüfung bei MISP-Verbindungen.
* **`PROXY_USED`**: `'True'` oder `'False'` (Default) ob ein Proxy genutzt werden soll (wird an *externe* Enrichment-Connectors übergeben).
* **`HTTPS_PROXY`**: Proxy URL (Format: `http://[user:pass@]host:port`), wird verwendet, wenn `PROXY_USED=True`.
* **`MALWARE_ZIP_PASSWORD`**: Passwort für die ZIP-Archive im Malware-Upload (Default: `infected`).

## 💡 Usage

Greife nach dem Start auf die Web-Oberfläche über deinen Browser zu (`http://localhost:8080` o.ä.).

* **Artefakt Upload:** Datei auswählen, Quellsystem & CaseNummer eingeben (Pflicht), optional Kommentar. Nach Upload wird die Datei als ZIP mit Metadaten gespeichert.
* **IoC Eingabe:** IoCs im Textfeld (eins pro Zeile) eingeben oder eine `.txt`/`.csv`/`.yar`-Datei hochladen. Jeder IoC wird auf seinen Typ geprüft und dann an die Import-Connectors (MISP, OpenCTI) gesendet. Status wird per Flash-Nachricht gemeldet.
* **Malware Analyse:** Datei hochladen. SHA256 wird berechnet. Interne Enrichment-Connectors (OpenCTI, MISP Lookups) werden für den Hash ausgeführt. Ergebnisse werden in einer Tabelle angezeigt. Datei wird als passwortgeschütztes ZIP (Passwort siehe Konfiguration) gespeichert.
* **Reputation Check:** IoC eingeben, "Intern", "Extern" oder "Beides" wählen. Die entsprechenden Enrichment-Connectors werden ausgeführt und die Ergebnisse tabellarisch angezeigt.

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