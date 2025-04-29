import requests
import os
import ipaddress
import re
import base64
import time
from urllib.parse import urlparse, quote_plus
import logging

CONNECTOR_NAME = "VirusTotal"
logger = logging.getLogger(__name__)

def _get_vt_url_id(url):
    """Erzeugt die VirusTotal ID für eine URL."""
    try:
        safe_url_bytes = url.encode('utf-8')
        return base64.urlsafe_b64encode(safe_url_bytes).decode('utf-8').rstrip("=")
    except Exception as e:
        logger.error(f"Fehler beim Kodieren der URL '{url}' für VT ID: {e}")
        return None

def analyze(indicator_value, indicator_type, config):
    """Analysiert einen Indikator mittels VirusTotal API v3."""
    result = {'connector_name': CONNECTOR_NAME, 'status': 'error', 'summary': 'Initial Error', 'details': None, 'link': None, 'error_message': None}
    api_key = config.get('VT_API_KEY')
    proxies = config.get('PROXIES')

    if not api_key:
        result['summary'] = 'API Key nicht konfiguriert.'; result['error_message'] = result['summary']; logger.error(f"{CONNECTOR_NAME}: {result['summary']}"); return result

    indicator = indicator_value.strip()
    if not indicator:
        result['summary'] = 'Leerer Indikator übergeben.'; result['status'] = 'info'; return result

    base_url = "https://www.virustotal.com/api/v3"
    endpoint = None
    vt_gui_type = "search"
    effective_indicator_type = 'unknown'

    is_ip = False
    try: ipaddress.ip_address(indicator); is_ip = True
    except ValueError: pass
    is_hash = (re.fullmatch(r"^[a-fA-F0-9]{32}$", indicator) or re.fullmatch(r"^[a-fA-F0-9]{40}$", indicator) or re.fullmatch(r"^[a-fA-F0-9]{64}$", indicator))
    is_url = False
    url_id = None
    try:
        parsed = urlparse(indicator)
        if parsed.scheme in ['http', 'https', 'ftp', 'sftp'] and parsed.netloc:
            is_url = True; url_id = _get_vt_url_id(indicator)
            if not url_id: result['summary'] = 'Konnte URL ID nicht generieren.'; result['error_message'] = result['summary']; return result
    except ValueError: pass
    is_domain = False
    if not is_ip and not is_hash and not is_url:
         if re.fullmatch(r"^(?!(\d{1,3}\.){3}\d{1,3}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", indicator): is_domain = True

    if is_ip: endpoint = f"/ip_addresses/{indicator}"; effective_indicator_type = 'ip_address'; vt_gui_type = "ip-address"
    elif is_hash: endpoint = f"/files/{indicator}"; effective_indicator_type = 'file_hash'; vt_gui_type = "file"
    elif is_url and url_id: endpoint = f"/urls/{url_id}"; effective_indicator_type = 'url'; vt_gui_type = "url"
    elif is_domain: endpoint = f"/domains/{indicator}"; effective_indicator_type = 'domain'; vt_gui_type = "domain"

    if not endpoint:
        result['summary'] = 'Indikator-Typ nicht erkannt.'; result['error_message'] = result['summary']; result['status'] = 'info'; return result

    api_url = base_url + endpoint
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    logger.debug(f"{CONNECTOR_NAME}: Frage an: {api_url}")

    try:
        proxies_to_use = config.get('PROXIES')
        response = requests.get(api_url, headers=headers, proxies=proxies_to_use, timeout=20)

        gui_link = f"https://www.virustotal.com/gui/{vt_gui_type}/{quote_plus(indicator)}" if vt_gui_type != "search" else f"https://www.virustotal.com/gui/search/{quote_plus(indicator)}"
        result['link'] = gui_link

        if response.status_code == 200:
            data = response.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total_engines = sum(stats.values()) if stats else 0

            verdict_status = 'info'
            if total_engines > 0:
                if malicious > 0: verdict_status = 'malicious'
                elif suspicious > 0: verdict_status = 'suspicious'
                else: verdict_status = 'ok'
            else:
                reputation = data.get('reputation')
                if reputation is not None and reputation < 0: verdict_status = 'suspicious'

            result['status'] = verdict_status
            result['summary'] = f"{malicious}/{total_engines} Engines bösartig." if total_engines > 0 else "Keine Analyse-Stats."
            if verdict_status == 'suspicious' and stats.get('suspicious',0)>0: result['summary'] += f" ({stats['suspicious']} verdächtig)"

            result['details'] = {
                'score': data.get('reputation'),
                'tlp': None,
                'event_id': None, 'event_info': None, 'attribute_id': None,
                'attribute_type': effective_indicator_type,
                'labels': data.get('tags'),
                'raw_stats': stats if stats else None,
                'detection_ratio': f"{malicious}/{total_engines}" if total_engines > 0 else "N/A",
                'total_votes': data.get('total_votes'),
                'last_analysis_date': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(data.get('last_analysis_date'))) if data.get('last_analysis_date') else None,
            }
            result['details'] = {k: v for k, v in result['details'].items() if v is not None and v != {} and v != []}

            return result

        elif response.status_code == 404:
            result['status'] = 'not_found'; result['summary'] = 'Nicht in VirusTotal gefunden.'
            return result
        else:
            logger.error(f"{CONNECTOR_NAME}: API Fehler {response.status_code}: {response.text[:200]}")
            result['summary'] = f'API Fehler ({response.status_code}).'; result['error_message'] = response.text[:100]
            return result

    except requests.exceptions.Timeout:
        logger.error(f"{CONNECTOR_NAME}: Timeout bei Abfrage für {indicator}"); result['summary'] = 'Timeout bei API-Abfrage.'; result['error_message'] = 'Timeout'; return result
    except requests.exceptions.RequestException as e:
        logger.error(f"{CONNECTOR_NAME}: Netzwerkfehler bei Abfrage für {indicator}: {e}"); result['summary'] = f'Netzwerkfehler: {e}'; result['error_message'] = str(e); return result
    except Exception as e:
        logger.exception(f"{CONNECTOR_NAME}: Unerwarteter Fehler bei {indicator}: {e}"); result['summary'] = 'Interner Verarbeitungsfehler.'; result['error_message'] = str(e); return result