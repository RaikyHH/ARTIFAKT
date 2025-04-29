# coding: utf-8

import os
import re
import hashlib
import zipfile
import random
import ipaddress
import importlib
import pkgutil
import logging
import string
from datetime import datetime, timezone
from urllib.parse import urlparse, quote_plus
try:
    import pyzipper
except ImportError:
    pyzipper = None

from flask import Flask, render_template, request, redirect, url_for, flash, current_app, jsonify
from werkzeug.utils import secure_filename
try:
    from flask_talisman import Talisman
except ImportError:
    Talisman = None

from dotenv import load_dotenv
load_dotenv()


# --- Konfiguration & Konstanten ---

UPLOAD_FOLDER_BASE = 'uploads'
UPLOAD_FOLDER_ARTIFACTS = os.path.join(UPLOAD_FOLDER_BASE, 'artifacts')
UPLOAD_FOLDER_IOCS = os.path.join(UPLOAD_FOLDER_BASE, 'iocs')
UPLOAD_FOLDER_MALWARE = os.path.join(UPLOAD_FOLDER_BASE, 'malware')

ALLOWED_EXTENSIONS_IOC = {'txt', 'yar', 'csv'}
ALLOWED_EXTENSIONS_MALWARE = set() # Erlaubt aktuell alle Dateitypen

INTERNAL_ENRICHMENT_DIR = "internal_enrichment"
EXTERNAL_ENRICHMENT_DIR = "external_enrichment"
INTERNAL_IMPORT_DIR = "internal_import"

MALWARE_ZIP_PASSWORD = os.environ.get('MALWARE_ZIP_PASSWORD', 'infected')

# --- Umgebungsvariablen ---
VT_API_KEY = os.environ.get('VT_API_KEY')
FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'dev_secret_key_insecure_!CHANGE_ME!')
OPENCTI_URL = os.environ.get('OPENCTI_URL')
OPENCTI_TOKEN = os.environ.get('OPENCTI_TOKEN')
MISP_URL = os.environ.get('MISP_URL')
MISP_KEY = os.environ.get('MISP_KEY')
MISP_EVENTID_WRITE = os.environ.get('MISP_EVENTID_WRITE')
MISP_VERIFY_SSL = os.environ.get('MISP_VERIFY_SSL', 'False').lower() in ['true', '1', 'y', 'yes']

PROXY_USED = os.environ.get('PROXY_USED', 'False').lower() in ['true', '1', 't', 'y', 'yes']
proxy_url_from_env = os.environ.get('HTTPS_PROXY')

# --- Flask App Initialisierung ---
app = Flask(__name__)

app.config['UPLOAD_FOLDER_ARTIFACTS'] = UPLOAD_FOLDER_ARTIFACTS
app.config['UPLOAD_FOLDER_IOCS'] = UPLOAD_FOLDER_IOCS
app.config['UPLOAD_FOLDER_MALWARE'] = UPLOAD_FOLDER_MALWARE
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024 # 256 MB Limit
app.secret_key = FLASK_SECRET_KEY

# --- Logging Konfiguration ---
log_level_str = os.environ.get('FLASK_LOG_LEVEL', 'INFO').upper()
log_level = getattr(logging, log_level_str, logging.INFO)
app.logger.setLevel(log_level)
# Optional: File Handler hinzufügen
# try:
#     log_file = os.environ.get('FLASK_LOG_FILE', 'app.log')
#     file_handler = logging.FileHandler(log_file)
#     file_handler.setLevel(log_level)
#     formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s [in %(pathname)s:%(lineno)d]')
#     file_handler.setFormatter(formatter)
#     app.logger.addHandler(file_handler)
# except Exception as log_e:
#     app.logger.error(f"Konnte keinen File Logger konfigurieren: {log_e}")


# --- Security Header (optional) ---
if Talisman:
    talisman = Talisman(app, force_https=False, content_security_policy=None)
    app.logger.info("Flask-Talisman initialisiert (Security Headers aktiviert).")
else:
    app.logger.warning("Flask-Talisman nicht installiert. Security Header werden NICHT gesetzt.")

# --- Proxy Konfiguration ---
proxies = None
if PROXY_USED:
    if proxy_url_from_env:
        try:
            parsed_proxy = urlparse(proxy_url_from_env)
            if parsed_proxy.scheme in ['http', 'https'] and parsed_proxy.netloc:
                proxies = {"http": proxy_url_from_env, "https": proxy_url_from_env}
                app.logger.info(f"Proxy wird verwendet: {proxy_url_from_env}")
            else:
                raise ValueError("Ungültiges Schema oder fehlender Hostname in der Proxy-URL.")
        except Exception as proxy_e:
            app.logger.error(f"Die konfigurierte HTTPS_PROXY URL '{proxy_url_from_env}' ist ungültig! Proxy wird NICHT verwendet. Fehler: {proxy_e}")
    else:
        app.logger.warning("PROXY_USED ist True, aber HTTPS_PROXY Variable ist nicht gesetzt! Proxy wird nicht verwendet.")
else:
    app.logger.info("Proxy wird nicht verwendet (PROXY_USED=False oder nicht gesetzt).")

# --- Start-Checks ---
if not VT_API_KEY: app.logger.warning("VT_API_KEY nicht gesetzt...")
if not OPENCTI_URL or not OPENCTI_TOKEN: app.logger.warning("OpenCTI nicht konfiguriert...")
if not MISP_URL or not MISP_KEY: app.logger.warning("MISP nicht konfiguriert...")
elif not MISP_EVENTID_WRITE: app.logger.warning("MISP_EVENTID_WRITE nicht gesetzt...")
if not FLASK_SECRET_KEY or FLASK_SECRET_KEY == 'dev_secret_key_insecure_!CHANGE_ME!':
    log_method = app.logger.critical if os.environ.get('FLASK_ENV') != 'development' else app.logger.warning
    log_method("FLASK_SECRET_KEY ist nicht gesetzt oder unsicher! Unbedingt in .env setzen.")

# --- Hilfsfunktionen ---

def sanitize_log_input(input_string):
    """Entfernt oder ersetzt potenziell gefährliche Zeichen für Log-Einträge."""
    if not isinstance(input_string, str):
        return input_string
    safe_string = input_string.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    # Optional: Nur druckbare ASCII-Zeichen erlauben
    # safe_string = ''.join(filter(lambda x: x in string.printable, safe_string))
    max_len = 200
    if len(safe_string) > max_len:
        safe_string = safe_string[:max_len] + '...'
    return safe_string

def allowed_file(filename, allowed_extensions):
    """Prüft, ob die Dateiendung in der erlaubten Liste ist."""
    if not filename or '.' not in filename:
        return False
    if not allowed_extensions: # Leere Liste erlaubt alles
        return True
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in allowed_extensions

def create_upload_folders():
    """Erstellt die benötigten Upload-Ordner."""
    folders_to_create = [
        app.config['UPLOAD_FOLDER_ARTIFACTS'],
        app.config['UPLOAD_FOLDER_IOCS'],
        app.config['UPLOAD_FOLDER_MALWARE']
    ]
    try:
        for folder in folders_to_create:
            os.makedirs(folder, exist_ok=True)
        app.logger.info("Upload-Ordner erfolgreich erstellt/gefunden.")
    except OSError as e:
        app.logger.critical(f"Konnte Upload-Ordner nicht erstellen! Fehler: {e}", exc_info=True)
        raise RuntimeError(f"Upload folders could not be created: {e}")

def process_ioc(ioc_string):
    """
    Erkennt den Typ eines IoC-Strings.
    Gibt den Typ-String oder None zurück.
    """
    ioc = ioc_string.strip()
    if not ioc:
        return None

    try:
        ip = ipaddress.ip_address(ioc)
        return 'ip-dst' if ip.version == 4 else 'ipv6-dst'
    except ValueError:
        pass

    if re.fullmatch(r"^[a-fA-F0-9]{32}$", ioc): return 'md5'
    if re.fullmatch(r"^[a-fA-F0-9]{40}$", ioc): return 'sha1'
    if re.fullmatch(r"^[a-fA-F0-9]{64}$", ioc): return 'sha256'
    if re.fullmatch(r"^[a-fA-F0-9]{128}$", ioc): return 'sha512' # Optional

    if re.fullmatch(r"^CVE-\d{4}-\d{4,}$", ioc, re.IGNORECASE): return 'vulnerability'

    if re.fullmatch(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ioc) and '..' not in ioc:
        return 'email'

    try:
        parsed_url = urlparse(ioc)
        if parsed_url.scheme in ['http', 'https', 'ftp', 'sftp'] and parsed_url.netloc:
             try:
                 ipaddress.ip_address(parsed_url.hostname)
                 # Ist eine IP, URL passt aber auch
             except (ValueError, TypeError):
                 if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", parsed_url.netloc.split(':')[0]):
                     return 'url'
    except ValueError: pass

    # Domain - schließt IPs aus und erzwingt TLD
    if '.' in ioc and not ioc.startswith('.') and not ioc.endswith('.') and \
       re.fullmatch(r"^(?!(\d{1,3}\.){3}\d{1,3}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", ioc):
        try:
            ipaddress.ip_address(ioc)
            # Sollte nicht passieren, da Regex IPs ausschließt
        except ValueError:
            return 'domain'

    if re.match(r"^(HKEY_[A-Z_]+|HK[CLU][MR])\\", ioc, re.IGNORECASE): return 'regkey'

    # Dateiname / Pfad (Heuristik)
    if re.search(r"[\\/]", ioc) or ('.' in ioc and not ioc.startswith('.') and len(ioc.rsplit('.', 1)) > 1 and len(ioc.rsplit('.', 1)[1]) <= 5):
        # Schließe bereits erkannte Typen aus
        potential_type = process_ioc(ioc)
        if potential_type not in ['url', 'email', 'domain']:
             return 'filename'

    if re.fullmatch(r"^T\d{4}(\.\d{3})?$", ioc, re.IGNORECASE): return 'attack-pattern'
    if re.fullmatch(r"^TA\d{4}$", ioc, re.IGNORECASE): return 'attack-tactic'

    app.logger.debug(f"Eingabe '{sanitize_log_input(ioc)}' keinem bekannten IoC-Typ zugeordnet.")
    return None

# --- Connector Runner ---

def _load_and_run_connectors(connector_dir, function_name, *args, **kwargs):
    """
    Lädt dynamisch Module aus einem Verzeichnis und führt eine Funktion aus.
    Sammelt Ergebnisse als Dictionaries.
    """
    results = []
    package_path = os.path.dirname(__file__)
    connector_path = os.path.join(package_path, connector_dir)

    if not os.path.isdir(connector_path):
        app.logger.error(f"Connector-Verzeichnis nicht gefunden: {connector_path}")
        return results

    for finder, name, ispkg in pkgutil.iter_modules([connector_path]):
        if name.startswith('_') or ispkg: continue

        module_name = f"{connector_dir}.{name}"
        module = None
        try:
            module = importlib.import_module(module_name)
            if hasattr(module, function_name) and callable(getattr(module, function_name)):
                app.logger.debug(f"Führe {function_name} in {module_name} aus.")
                try:
                    result = getattr(module, function_name)(*args, **kwargs)
                    if result and isinstance(result, dict):
                        results.append(result)
                    else:
                        app.logger.warning(f"Connector {module_name} ({function_name}) lieferte ungültiges Ergebnis (Typ: {type(result)}): {sanitize_log_input(str(result))}")
                        results.append({
                            'connector_name': getattr(module, 'CONNECTOR_NAME', name),
                            'status': 'error', 'success': False,
                            'summary': 'Ungültiges Ergebnisformat vom Connector.',
                            'message': 'Ungültiges Ergebnisformat vom Connector.',
                            'details': {'raw_result': sanitize_log_input(str(result))},
                            'link': None, 'error_message': 'Invalid return format'
                        })
                except Exception as e:
                    app.logger.error(f"Fehler beim Ausführen von {function_name} in {module_name}: {e}", exc_info=True)
                    results.append({
                        'connector_name': getattr(module, 'CONNECTOR_NAME', name) if module else name,
                        'status': 'error', 'success': False,
                        'summary': 'Connector Ausführung fehlgeschlagen.',
                        'message': 'Connector Ausführung fehlgeschlagen.',
                        'details': None, 'link': None, 'error_message': str(e)
                    })
            else:
                 app.logger.warning(f"Connector {module_name} hat keine Funktion '{function_name}'.")
        except ImportError as e:
            app.logger.error(f"Fehler beim Importieren von Connector {module_name}: {e}", exc_info=True)
        except Exception as e:
             app.logger.error(f"Allgemeiner Fehler beim Laden/Ausführen von Connector {module_name}: {e}", exc_info=True)

    return results

def run_enrichment_connectors(indicator_value, enrichment_scope='both'):
    """Führt Enrichment Connectors ('analyze' Funktion) aus."""
    base_config = {
        'VT_API_KEY': VT_API_KEY,
        'OPENCTI_URL': OPENCTI_URL,
        'OPENCTI_TOKEN': OPENCTI_TOKEN,
        'MISP_URL': MISP_URL,
        'MISP_KEY': MISP_KEY,
        'MISP_VERIFY_SSL': MISP_VERIFY_SSL,
    }

    internal_connector_config = base_config.copy()
    internal_connector_config['PROXIES'] = {} # Kein Proxy für interne Connectors

    external_connector_config = base_config.copy()
    external_connector_config['PROXIES'] = proxies # Globales Proxy-Dict verwenden

    indicator_type = process_ioc(indicator_value)
    if not indicator_type:
        app.logger.warning(f"Kein gültiger IoC-Typ für Anreicherung von '{sanitize_log_input(indicator_value)}' erkannt. Überspringe Connectors.")
        return []

    app.logger.info(f"Starte '{enrichment_scope}' Anreicherung für '{sanitize_log_input(indicator_value)}' (Typ: {indicator_type})")
    all_results = []

    if enrichment_scope in ['internal', 'both']:
        app.logger.debug(f"Lade interne Enrichment Connectors...")
        all_results.extend(
            _load_and_run_connectors(INTERNAL_ENRICHMENT_DIR, 'analyze', indicator_value, indicator_type, internal_connector_config)
        )
    if enrichment_scope in ['external', 'both']:
        proxy_info_log = "vorhanden" if external_connector_config.get('PROXIES') else "nicht vorhanden"
        app.logger.debug(f"Lade externe Enrichment Connectors (mit PROXIES={proxy_info_log})...")
        all_results.extend(
            _load_and_run_connectors(EXTERNAL_ENRICHMENT_DIR, 'analyze', indicator_value, indicator_type, external_connector_config)
        )
    app.logger.info(f"Anreicherung für '{sanitize_log_input(indicator_value)}' beendet, {len(all_results)} Ergebnisse erhalten.")
    return all_results

def run_import_connectors(ioc_value, ioc_type, source_info=None):
    """Führt Import Connectors ('import_indicator' Funktion) aus."""
    connector_config = {
        'OPENCTI_URL': OPENCTI_URL,
        'OPENCTI_TOKEN': OPENCTI_TOKEN,
        'MISP_URL': MISP_URL,
        'MISP_KEY': MISP_KEY,
        'MISP_EVENTID_WRITE': MISP_EVENTID_WRITE,
        'MISP_VERIFY_SSL': MISP_VERIFY_SSL,
        'PROXIES': {}, # Kein Proxy für Import Connectors
    }
    app.logger.info(f"Starte Import für '{sanitize_log_input(ioc_value)}' (Typ: {ioc_type})")
    app.logger.debug(f"Import Config (Auszug): PROXIES={connector_config['PROXIES']}")
    results = _load_and_run_connectors(INTERNAL_IMPORT_DIR, 'import_indicator', ioc_value, ioc_type, connector_config, source_info)
    app.logger.info(f"Import für '{sanitize_log_input(ioc_value)}' beendet, {len(results)} Ergebnisse erhalten.")
    return results

# --- Flask Routen ---

@app.context_processor
def inject_now():
    """Stellt das aktuelle Jahr für Templates bereit."""
    return {'current_year': datetime.now(timezone.utc).year}

@app.route('/')
def index():
    """Startseite."""
    return render_template('index.html')


@app.route('/upload_artifact', methods=['GET', 'POST'])
def upload_artifact():
    """Seite zum Hochladen von Artefakten."""
    upload_result = None
    form_data = {'comment': '', 'source_system': '', 'case_number': ''}

    if request.method == 'POST':
        form_data['comment'] = request.form.get('comment', '').strip()
        form_data['source_system'] = request.form.get('source_system', '').strip()
        form_data['case_number'] = request.form.get('case_number', '').strip()

        app.logger.debug(f"POST /upload_artifact - Source: {sanitize_log_input(form_data['source_system'])}, Case: {sanitize_log_input(form_data['case_number'])}")

        if not form_data['source_system'] or not form_data['case_number']:
            flash('Quellsystem und Casenummer sind Pflichtfelder.', 'error')
            return render_template('upload_artifact.html', upload_result=None, **form_data)

        if 'file' not in request.files:
            flash('Kein Dateiteil im Request', 'error')
            return redirect(request.url)

        file = request.files['file']
        original_filename = file.filename

        if not file or not original_filename:
            flash('Keine Datei ausgewählt oder Dateiname fehlt', 'error')
            return redirect(request.url)

        safe_original_filename_log = sanitize_log_input(original_filename)
        original_filename_secure_for_zip = secure_filename(original_filename)
        if not original_filename_secure_for_zip:
             original_filename_secure_for_zip = "uploaded_file"
             app.logger.warning(f"Original filename '{safe_original_filename_log}' ergab leeren secure_filename, verwende 'uploaded_file' im ZIP.")

        try:
            now = datetime.now(timezone.utc)
            timestamp_str = now.strftime("%Y-%m-%d_%H-%M-%S_%Z")
            safe_source_system = re.sub(r'[^\w\-.]+', '_', form_data['source_system'])
            safe_case_number = re.sub(r'[^\w\-.]+', '_', form_data['case_number'])
            zip_filename_base = f"{timestamp_str}_{safe_source_system}_{safe_case_number}"

            max_len_base = 150
            if len(zip_filename_base) > max_len_base:
                zip_filename_base = zip_filename_base[:max_len_base]
            zip_filename = f"{zip_filename_base}.zip"
            zip_filepath = os.path.join(current_app.config['UPLOAD_FOLDER_ARTIFACTS'], zip_filename)

            metadata_content = f"""Upload Timestamp (UTC): {now.isoformat()}
Original Filename: {original_filename}
Source System: {form_data['source_system']}
Case Number: {form_data['case_number']}
Comment:
{form_data['comment']}
"""
            with zipfile.ZipFile(zip_filepath, 'w', zipfile.ZIP_DEFLATED) as zf:
                file.stream.seek(0)
                file_content = file.stream.read()
                zf.writestr(original_filename_secure_for_zip, file_content)
                zf.writestr('metadata.txt', metadata_content.encode('utf-8'))

            upload_result = {
                'success': True, 'original_filename': original_filename,
                'zip_filename': zip_filename, **form_data,
                'message': f'Artefakt "{safe_original_filename_log}" erfolgreich als "{zip_filename}" archiviert.'
            }
            flash(upload_result['message'], 'success')
            app.logger.info(f"Artefakt archiviert: {zip_filename} (Original: '{safe_original_filename_log}')")
            form_data = {'comment': '', 'source_system': '', 'case_number': ''}

        except Exception as e:
            app.logger.error(f"Fehler beim Archivieren von '{safe_original_filename_log}': {e}", exc_info=True)
            error_message = f'Fehler beim Archivieren von "{safe_original_filename_log}": {e}'
            upload_result = {'success': False, 'original_filename': original_filename,
                             'message': error_message, **form_data }
            flash(error_message, 'error')

        return render_template('upload_artifact.html', upload_result=upload_result, **form_data)

    # GET Request
    return render_template('upload_artifact.html', upload_result=None, **form_data)


@app.route('/submit_ioc', methods=['GET', 'POST'])
def submit_ioc():
    """Seite zum Einreichen von IoCs für den Import."""
    if request.method == 'POST':
        ioc_text = request.form.get('ioc_text', '').strip()
        file = request.files.get('file')

        iocs_to_process = []
        source_description_parts = []
        processed_sources = set()

        # Textfeld verarbeiten
        if ioc_text:
            app.logger.debug("Verarbeite IoCs aus Textfeld.")
            lines = ioc_text.splitlines()
            count = 0
            for line_num, line in enumerate(lines):
                ioc = line.strip()
                if ioc and not ioc.startswith('#'):
                    ioc_type = process_ioc(ioc)
                    if ioc_type:
                        iocs_to_process.append({'value': ioc, 'type': ioc_type, 'source': 'Textfeld'})
                        count += 1
                    else:
                        app.logger.debug(f"Zeile {line_num+1} im Textfeld ignoriert (kein gültiger IoC): '{sanitize_log_input(ioc)}'")
            if count > 0:
                source_description_parts.append(f"{count} aus Textfeld")
                processed_sources.add("Textfeld")

        # Datei verarbeiten
        if file and file.filename:
            original_filename = file.filename
            safe_filename_log = sanitize_log_input(original_filename)
            app.logger.debug(f"Verarbeite IoCs aus Datei '{safe_filename_log}'.")

            if allowed_file(original_filename, ALLOWED_EXTENSIONS_IOC):
                filename_secure = secure_filename(original_filename)
                try:
                    content_bytes = file.stream.read()
                    try:
                        content = content_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        app.logger.warning(f"Datei '{safe_filename_log}' ist nicht UTF-8. Versuche Fallback-Dekodierung.")
                        content = content_bytes.decode("latin-1", errors='ignore')

                    lines = content.splitlines()
                    count = 0
                    for line_num, line in enumerate(lines):
                        ioc = line.strip()
                        if ioc and not ioc.startswith('#'):
                             ioc_type = process_ioc(ioc)
                             if ioc_type:
                                 iocs_to_process.append({'value': ioc, 'type': ioc_type, 'source': f"Datei: {filename_secure}"})
                                 count += 1
                             else:
                                 app.logger.debug(f"Zeile {line_num+1} in Datei '{safe_filename_log}' ignoriert: '{sanitize_log_input(ioc)}'")

                    if count > 0:
                        source_description_parts.append(f"{count} aus '{filename_secure}'")
                        processed_sources.add(f"Datei: {filename_secure}")
                    elif "Textfeld" not in processed_sources:
                         flash(f'Keine gültigen IoCs in Datei "{safe_filename_log}" gefunden.', 'warning')

                except Exception as e:
                    flash(f'Fehler beim Lesen der IoC-Datei "{safe_filename_log}": {e}', 'error')
                    app.logger.error(f'Fehler beim Lesen der IoC-Datei "{safe_filename_log}": {e}', exc_info=True)
            else:
                allowed_ext_str = ", ".join(sorted(list(ALLOWED_EXTENSIONS_IOC))) if ALLOWED_EXTENSIONS_IOC else "Alle"
                flash(f'Dateityp von "{safe_filename_log}" nicht erlaubt (Erlaubt: {allowed_ext_str}).', 'error')

        # Prüfen, ob IoCs vorhanden sind
        if not iocs_to_process:
            is_post_request = request.method == 'POST'
            has_input_attempt = bool(ioc_text) or (file and file.filename)
            if is_post_request and has_input_attempt:
                 flash('Keine gültigen IoCs zum Verarbeiten gefunden.', 'warning')
            return render_template('submit_ioc.html')


        # IoCs verarbeiten
        total_iocs_to_process = len(iocs_to_process)
        source_summary = ', '.join(source_description_parts) if source_description_parts else "keine Quelle"
        app.logger.info(f"Starte Import für {total_iocs_to_process} IoC(s) aus: {source_summary}...")

        processed_ioc_count = 0
        total_connector_runs = 0
        total_connectors_succeeded = 0
        connector_errors = {} # {conn_name: count}

        # Deduplizieren
        unique_iocs = {} # {(value, type): source}
        for ioc_data in iocs_to_process:
            key = (ioc_data['value'], ioc_data['type'])
            if key not in unique_iocs:
                unique_iocs[key] = ioc_data['source']

        app.logger.info(f"Verarbeite {len(unique_iocs)} eindeutige IoCs.")

        for (ioc_value, ioc_type), source in unique_iocs.items():
            processed_ioc_count += 1
            source_info_dict = {'origin': source, 'upload_time': datetime.now(timezone.utc).isoformat()}
            import_results = run_import_connectors(ioc_value, ioc_type, source_info=source_info_dict)
            total_connector_runs += len(import_results)
            for res in import_results:
                conn_name = res.get('connector_name', 'Unbekannt')
                if res.get('success'):
                    total_connectors_succeeded += 1
                else:
                    connector_errors[conn_name] = connector_errors.get(conn_name, 0) + 1
                    app.logger.warning(f"Import fehlgeschlagen für IoC '{sanitize_log_input(ioc_value)}' durch Connector '{conn_name}'. Fehler: {res.get('error_message', 'Keine Details')}")


        # Feedback generieren
        total_error_count = sum(connector_errors.values())

        if processed_ioc_count > 0:
            if total_error_count == 0:
                flash(f'{processed_ioc_count} eindeutige IoC(s) erfolgreich an alle verfügbaren Zielsysteme übermittelt ({total_connectors_succeeded} erfolgreiche Aktionen).', 'success')
            elif total_connectors_succeeded > 0:
                error_summary = ", ".join([f"{name} ({count}x)" for name, count in connector_errors.items()])
                flash(f'{processed_ioc_count} eindeutige IoC(s) verarbeitet. {total_connectors_succeeded} Aktionen erfolgreich. Fehler bei Connectors: {error_summary}', 'warning')
            else: # Nur Fehler
                error_summary = ", ".join([f"{name} ({count}x)" for name, count in connector_errors.items()])
                flash(f'Fehler bei der Übermittlung von {processed_ioc_count} IoC(s). Probleme bei: {error_summary}', 'error')

        return render_template('submit_ioc.html')

    # GET Request
    return render_template('submit_ioc.html')


@app.route('/upload_malware', methods=['GET', 'POST'])
def upload_malware():
    """Seite zum Hochladen von Malware-Samples."""
    upload_info = {}

    if request.method == 'POST':
        app.logger.debug("POST /upload_malware: Anfrage erhalten.")

        if 'file' not in request.files:
            flash('Kein Dateiteil im Request', 'error')
            return redirect(request.url)
        file = request.files['file']
        original_filename = file.filename
        if not file or not original_filename:
            flash('Keine Datei ausgewählt oder Dateiname fehlt', 'error')
            return redirect(request.url)

        safe_original_filename_log = sanitize_log_input(original_filename)
        app.logger.info(f"Malware-Upload gestartet für: '{safe_original_filename_log}'")

        upload_info['original_filename'] = original_filename
        file_hash_sha256 = None
        file_content_bytes = None

        # Dateiinhalt lesen
        try:
            file.stream.seek(0)
            file_content_bytes = file.stream.read()
            if not file_content_bytes:
                 flash('Fehler: Hochgeladene Datei ist leer.', 'error')
                 app.logger.error(f"Upload-Fehler: Datei '{safe_original_filename_log}' ist leer.")
                 return redirect(request.url)
        except Exception as e:
             flash(f'Fehler beim Lesen der Datei "{safe_original_filename_log}": {e}', 'error')
             app.logger.error(f'Fehler beim Lesen der Datei "{safe_original_filename_log}": {e}', exc_info=True)
             return redirect(request.url)

        # Hashing (SHA256)
        try:
            app.logger.debug(f"Starte Hashing für '{safe_original_filename_log}'...")
            hasher = hashlib.sha256()
            hasher.update(file_content_bytes)
            file_hash_sha256 = hasher.hexdigest()
            upload_info['file_hash_sha256'] = file_hash_sha256
            app.logger.info(f"SHA256 für '{safe_original_filename_log}': {file_hash_sha256}")
        except Exception as e:
            flash(f'Fehler beim Berechnen des Hash für "{safe_original_filename_log}": {e}', 'error')
            app.logger.error(f'Hash-Fehler für "{safe_original_filename_log}": {e}', exc_info=True)
            file_hash_sha256 = None

        # Interne Enrichment Connectors (nur wenn Hash vorhanden)
        connector_results_list = []
        if file_hash_sha256:
            try:
                app.logger.info(f"Starte interne Anreicherung für Hash {file_hash_sha256[:10]}...")
                connector_results_list = run_enrichment_connectors(file_hash_sha256, enrichment_scope='internal')
                upload_info['connector_results_list'] = connector_results_list
            except Exception as e:
                 flash(f'Fehler bei internen Connectors für Hash {file_hash_sha256[:10]}...: {e}', 'error')
                 app.logger.error(f'Connector-Fehler (internal) für Hash "{file_hash_sha256}": {e}', exc_info=True)
        else:
            app.logger.warning(f"Interne Anreicherung für '{safe_original_filename_log}' übersprungen (kein Hash berechnet).")


        # Zippen mit AES (wenn pyzipper installiert)
        archive_success = None
        zip_filename = "malware_archive.zip" # Fallback
        if file_hash_sha256:
              zip_filename = f"{file_hash_sha256}.zip"
        else:
              now = datetime.now(timezone.utc)
              timestamp_str = now.strftime("%Y%m%d_%H%M%S")
              safe_orig_part = secure_filename(original_filename)[:50]
              zip_filename = f"MALWARE_{timestamp_str}_{safe_orig_part}.zip"
              app.logger.warning(f"Kein Hash vorhanden, verwende Fallback-ZIP-Namen: {zip_filename}")

        zip_filepath = os.path.join(current_app.config['UPLOAD_FOLDER_MALWARE'], zip_filename)
        filename_in_zip = secure_filename(original_filename)
        if not filename_in_zip: filename_in_zip = "malware_sample"

        try:
            if pyzipper:
                app.logger.info(f"Erstelle AES-verschlüsseltes ZIP: {zip_filepath} (PW: '{MALWARE_ZIP_PASSWORD}')")
                password_bytes = MALWARE_ZIP_PASSWORD.encode('utf-8')
                with pyzipper.AESZipFile(zip_filepath,
                                         'w',
                                         compression=pyzipper.ZIP_DEFLATED,
                                         encryption=pyzipper.WZ_AES) as zf:
                    zf.setpassword(password_bytes)
                    zf.writestr(filename_in_zip, file_content_bytes, compress_type=pyzipper.ZIP_DEFLATED)
                upload_info['archive_filename'] = zip_filename
                upload_info['archived'] = True
                upload_info['encryption'] = 'AES (pyzipper)'
                archive_success = True
                flash(f'Datei "{safe_original_filename_log}" erfolgreich AES-verschlüsselt archiviert als "{zip_filename}".', 'success')
            else:
                app.logger.warning("pyzipper nicht gefunden! Erstelle Standard-ZIP (unverschlüsselt!).")
                with zipfile.ZipFile(zip_filepath, 'w', zipfile.ZIP_DEFLATED) as zf_fallback:
                    zf_fallback.writestr(filename_in_zip, file_content_bytes)
                upload_info['archive_filename'] = zip_filename
                upload_info['archived'] = True
                upload_info['encryption'] = 'None (Standard ZIP)'
                archive_success = True
                flash(f'Datei "{safe_original_filename_log}" wurde als Standard-ZIP "{zip_filename}" gespeichert (KEIN Passwortschutz!). Installiere pyzipper für AES.', 'warning')

        except Exception as e:
             flash(f'Fehler beim Erstellen des ZIP-Archivs für "{safe_original_filename_log}": {e}', 'error')
             app.logger.error(f'ZIP-Fehler für "{safe_original_filename_log}" nach "{zip_filepath}": {e}', exc_info=True)
             upload_info['archived'] = False
             upload_info['encryption'] = 'Error'
             archive_success = False

        return render_template('upload_malware.html', upload_info=upload_info)
        # Ende POST

    # GET Request
    return render_template('upload_malware.html', upload_info=upload_info)


@app.route('/lookup', methods=['GET', 'POST'])
def lookup():
    """Seite für manuelle IoC-Abfragen."""
    query = ""
    enrichment_type = "internal"
    results_list = []

    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        enrichment_type = request.form.get('enrichment_type', 'internal')
        safe_query_log = sanitize_log_input(query)

        if not query:
            flash('Bitte geben Sie einen Suchbegriff (IoC) ein.', 'error')
        else:
             ioc_type = process_ioc(query)
             if not ioc_type:
                 flash(f'Eingabe "{safe_query_log}" ist kein unterstützter IoC-Typ für eine Suche.', 'warning')
                 app.logger.warning(f"Lookup abgelehnt für ungültigen IoC-Typ: '{safe_query_log}'")
             else:
                 flash(f'Führe Suche ({enrichment_type}) für "{safe_query_log}" (Typ: {ioc_type}) aus...', 'info')
                 app.logger.info(f"Manueller Lookup ({enrichment_type}) gestartet für: '{safe_query_log}' (Typ: {ioc_type})")
                 try:
                     results_list = run_enrichment_connectors(query, enrichment_type)
                     if not results_list:
                          flash('Keine Ergebnisse von Connectors erhalten.', 'warning')
                 except Exception as e:
                     flash(f'Schwerwiegender Fehler bei der Ausführung der Connectors: {e}', 'error')
                     app.logger.error(f"Fehler in run_enrichment_connectors für '{safe_query_log}': {e}", exc_info=True)

    return render_template('lookup.html',
                           query=query,
                           enrichment_type=enrichment_type,
                           results_list=results_list)


# --- App Startpunkt ---
if __name__ == '__main__':
    try:
        create_upload_folders()
    except RuntimeError as e:
         app.logger.critical(f"Anwendung wird beendet: {e}")
         exit(1)

    is_development = os.environ.get('FLASK_ENV', 'production').lower() == 'development'
    app.logger.info(f"Flask environment: {'development' if is_development else 'production'}")

    if is_development and (not FLASK_SECRET_KEY or FLASK_SECRET_KEY == 'dev_secret_key_insecure_!CHANGE_ME!'):
         app.logger.warning("LAUFE IM DEVELOPMENT MODUS MIT UNSICHEREM SECRET KEY!")
    elif not is_development and (not FLASK_SECRET_KEY or FLASK_SECRET_KEY == 'dev_secret_key_insecure_!CHANGE_ME!'):
         app.logger.critical("PRODUKTIONSMODUS MIT UNSICHEREM SECRET KEY! SOFORT ÄNDERN!")
         # Optional: exit(1) wenn Key im Prod-Modus unsicher ist

    # app.run() nur für Entwicklung. Für Produktion WSGI-Server (Gunicorn/uWSGI) verwenden.
    app.run(debug=is_development, host='0.0.0.0', port=8080)