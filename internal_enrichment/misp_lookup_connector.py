import logging
import os
import json
try:
    from pymisp import PyMISP, PyMISPError
    import requests
    PYMISP_AVAILABLE = True
except ImportError:
    PYMISP_AVAILABLE = False
    requests = None

CONNECTOR_NAME = "MISP (Lookup)"
logger = logging.getLogger(__name__)

def analyze(indicator_value, indicator_type, config):
    """
    Sucht nach einem Attributwert in MISP via direktem POST Request
    und gibt standardisierte Details zurück.
    """
    result = {
        'connector_name': CONNECTOR_NAME, 'status': 'error',
        'summary': 'Connector Initial Error', 'details': None, 'link': None, 'error_message': None
    }

    if not PYMISP_AVAILABLE:
        result['summary'] = "PyMISP/requests Bibliothek nicht installiert."; result['error_message'] = result['summary']; logger.error(f"{CONNECTOR_NAME}: {result['summary']}"); return result

    misp_url = config.get('MISP_URL')
    misp_key = config.get('MISP_KEY')
    verify_ssl = config.get('MISP_VERIFY_SSL', False)
    proxies = config.get('PROXIES')

    if not misp_url or not misp_key:
        result['summary'] = 'MISP URL oder Key nicht konfiguriert.'; result['error_message'] = result['summary']; logger.error(f"{CONNECTOR_NAME}: {result['summary']}"); return result

    indicator = indicator_value.strip()
    if not indicator:
        result['summary'] = 'Leerer Indikatorwert.'; result['status'] = 'info'; return result

    if not misp_url.endswith('/'):
        misp_url += '/'

    search_url = misp_url + "attributes/restSearch"

    headers = {
        'Authorization': misp_key,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    payload = {
        'value': indicator,
        'includeContext': True,
        'includeEventInfo': True,
        'limit': 5
    }

    try:
        logger.info(f"{CONNECTOR_NAME}: Suche Attributwert '{indicator[:50]}...' via POST an {search_url}")
        logger.debug(f"{CONNECTOR_NAME}: Request Payload: {payload}")
        logger.debug(f"{CONNECTOR_NAME}: Request Proxies: {proxies}")

        response = requests.post(
            search_url,
            headers=headers,
            json=payload,
            verify=verify_ssl,
            proxies=proxies,
            timeout=30
        )

        logger.debug(f"{CONNECTOR_NAME}: Response Status Code: {response.status_code}")

        if response.status_code == 200:
            try:
                search_result = response.json()

                if isinstance(search_result, dict) and 'response' in search_result and isinstance(search_result['response'], dict):
                    attributes_found = search_result['response'].get('Attribute', [])

                    if not attributes_found:
                        logger.info(f"{CONNECTOR_NAME}: Indikator '{indicator}' nicht in MISP gefunden (leere Attributliste).")
                        result['status'] = 'not_found'
                        result['summary'] = 'Nicht in MISP gefunden.'
                        return result
                    else:
                        logger.info(f"{CONNECTOR_NAME}: Indikator '{indicator}' {len(attributes_found)} mal gefunden -> Status 'malicious'.")
                        first_hit = attributes_found[0]

                        event_id = first_hit.get('event_id', 'N/A')
                        attribute_id = first_hit.get('id', 'N/A')
                        event_data = first_hit.get('Event', {})
                        event_info = event_data.get('info', 'N/A') if event_data else 'N/A'
                        attribute_type = first_hit.get('type', 'N/A')

                        tlp_tag = None
                        tags = first_hit.get('Tag', [])
                        logger.debug(f"Gefundene Tags für Attribut {attribute_id}: {[t.get('name') for t in tags]}")
                        for tag_dict in tags:
                            tag_name = tag_dict.get('name', '')
                            if tag_name.lower().startswith('tlp:'):
                                tlp_tag = tag_name.upper(); break
                        if tlp_tag is None and event_data:
                            event_tags = event_data.get('Tag', [])
                            logger.debug(f"Kein TLP am Attribut, prüfe Event-Tags für Event {event_id}: {[t.get('name') for t in event_tags]}")
                            for tag_dict in event_tags:
                                tag_name = tag_dict.get('name', '')
                                if tag_name.lower().startswith('tlp:'):
                                    tlp_tag = tag_name.upper(); break

                        result['status'] = 'malicious'
                        result['summary'] = f"Gefunden in Event {event_id} ('{event_info[:50]}...')."
                        result['link'] = f"{misp_url}events/view/{event_id}"
                        result['details'] = {
                            'score': None, 'tlp': tlp_tag, 'event_id': event_id,
                            'event_info': event_info if event_info != 'N/A' else None,
                            'attribute_id': attribute_id,
                            'attribute_type': attribute_type if attribute_type != 'N/A' else None,
                            'labels': None, 'raw_stats': {'hit_count': len(attributes_found)}
                        }
                        result['details'] = {k: v for k, v in result['details'].items() if v is not None}
                        logger.debug(f"{CONNECTOR_NAME}: Final result being returned: {result}")
                        return result

                else:
                    logger.error(f"{CONNECTOR_NAME}: Unerwartete JSON-Struktur in MISP-Antwort: {str(search_result)[:500]}")
                    result['summary'] = "Unerwartete Antwortstruktur von MISP."
                    result['error_message'] = "Unexpected MISP response structure."
                    return result

            except json.JSONDecodeError as json_e:
                logger.error(f"{CONNECTOR_NAME}: Fehler beim Parsen der MISP JSON-Antwort: {json_e}", exc_info=True)
                result['summary'] = f"Fehler beim Parsen der MISP Antwort."
                result['error_message'] = "MISP JSON Decode Error."
                return result

        else:
            error_message = f"MISP API Fehler (Status: {response.status_code})."
            try:
                error_details = response.json()
                error_message = error_details.get('message', error_details.get('name', error_message))
                result['details'] = {'misp_error': error_details}
            except json.JSONDecodeError:
                 error_message = response.text[:200]
                 result['details'] = {'misp_error': error_message}

            logger.error(f"{CONNECTOR_NAME}: {error_message} (URL: {search_url})")
            result['summary'] = error_message
            result['error_message'] = error_message
            return result

    except requests.exceptions.RequestException as e:
        logger.error(f"{CONNECTOR_NAME}: Netzwerkfehler bei MISP-Suche nach '{indicator}': {e}", exc_info=True)
        result['summary'] = f"Netzwerkfehler: {e}"
        result['error_message'] = str(e)
    except Exception as e:
        logger.error(f"{CONNECTOR_NAME}: Allgemeiner Fehler bei MISP-Suche nach '{indicator}': {e}", exc_info=True)
        result['summary'] = f"Allgemeiner Fehler: {e}"
        result['error_message'] = str(e)

    result['status'] = 'error'
    return result