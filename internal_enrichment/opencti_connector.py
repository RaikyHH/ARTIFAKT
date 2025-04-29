import logging
import os
import ipaddress
from urllib.parse import quote_plus
from datetime import datetime, timezone

try:
    from pycti import OpenCTIApiClient
    PYCTI_AVAILABLE = True
except ImportError:
    PYCTI_AVAILABLE = False

CONNECTOR_NAME = "OpenCTI"
logger = logging.getLogger(__name__)

def _get_stix_lookup_info(api_client, internal_type, ioc_value):
    """Ermittelt Infos für die Observable/SDO Suche."""
    logger.debug(f"Mapping Typ '{internal_type}' für Lookup, Wert '{ioc_value[:50]}...'")
    is_observable = True
    handler = api_client.stix_cyber_observable
    list_method = 'list'
    filter_key = None
    stix_type = None

    if internal_type in ['ip-dst', 'ip-src']:
        try:
            ip = ipaddress.ip_address(ioc_value)
            stix_type = 'IPv4-Addr' if ip.version == 4 else 'IPv6-Addr'; filter_key = 'value'
        except ValueError: return None
    elif internal_type == 'domain': stix_type = 'Domain-Name'; filter_key = 'value'
    elif internal_type == 'url': stix_type = 'Url'; filter_key = 'value'
    elif internal_type == 'email': stix_type = 'Email-Addr'; filter_key = 'value'
    elif internal_type == 'md5': stix_type = 'File'; filter_key = 'hashes.MD5'
    elif internal_type == 'sha1': stix_type = 'File'; filter_key = 'hashes.SHA-1'
    elif internal_type == 'sha256': stix_type = 'File'; filter_key = 'hashes.SHA-256'
    elif internal_type == 'filename': stix_type = 'File'; filter_key = 'name'
    elif internal_type == 'regkey': stix_type = 'Windows-Registry-Key'; filter_key = 'attribute_key'
    elif internal_type == 'vulnerability':
        is_observable = False; stix_type = 'Vulnerability'; handler = api_client.vulnerability; filter_key = 'name'
    elif internal_type in ['comment', 'text']: return None
    else: logger.warning(f"Kein Mapping für Typ: {internal_type}"); return None

    if stix_type and filter_key:
        return handler, list_method, filter_key, stix_type, is_observable
    return None

def analyze(indicator_value, indicator_type, config):
    """
    Sucht nach einem Observable in OpenCTI und gibt standardisierte Details zurück,
    inklusive TLP-Level aus den Object Markings.
    """
    result = {'connector_name': CONNECTOR_NAME, 'status': 'error', 'summary': 'Initial Error', 'details': None, 'link': None, 'error_message': None}

    if not PYCTI_AVAILABLE:
        result['summary'] = "PyCTI Bibliothek nicht installiert."; result['error_message'] = result['summary']; logger.error(f"{CONNECTOR_NAME}: {result['summary']}"); return result
    opencti_url = config.get('OPENCTI_URL')
    opencti_token = config.get('OPENCTI_TOKEN')
    if not opencti_url or not opencti_token:
        result['summary'] = 'OpenCTI nicht konfiguriert.'; result['error_message'] = result['summary']; logger.error(f"{CONNECTOR_NAME}: {result['summary']}"); return result
    ioc_value = indicator_value.strip()
    if not ioc_value:
         result['summary'] = 'Leerer Indikatorwert.'; result['status'] = 'info'; return result

    try:
        logger.debug(f"{CONNECTOR_NAME}: Verbinde mit {opencti_url}")
        api_client = OpenCTIApiClient(opencti_url, opencti_token)
    except Exception as conn_e:
        logger.error(f"{CONNECTOR_NAME}: Fehler beim Verbinden: {conn_e}", exc_info=True)
        result['message'] = f"Verbindungsfehler: {conn_e}"; return result

    handling_info = _get_stix_lookup_info(api_client, indicator_type, ioc_value)
    if not handling_info:
        result['message'] = f"Typ '{indicator_type}' nicht für Suche unterstützt."
        result['status'] = 'info'
        logger.info(f"{CONNECTOR_NAME}: {result['message']}")
        return result

    api_handler, list_method_name, filter_key, stix_type_name, is_observable = handling_info

    try:
        logger.debug(f"{CONNECTOR_NAME}: Suche '{stix_type_name}' mit FilterKey '{filter_key}' = '{ioc_value[:50]}...'")
        list_method = getattr(api_handler, list_method_name)
        filters = {"mode": "and", "filters": [{"key": filter_key, "values": [ioc_value]}], "filterGroups": []}
        list_params = {'filters': filters, 'first': 1, 'getAll': True}

        found_list = list_method(**list_params)

        if not found_list:
            logger.info(f"{CONNECTOR_NAME}: Objekt '{stix_type_name}' mit Wert '{ioc_value[:50]}...' nicht gefunden.")
            result['status'] = 'not_found'
            result['summary'] = 'Nicht in OpenCTI gefunden.'
            result['link'] = f"{opencti_url}/dashboard/search/{quote_plus(ioc_value)}"
            return result
        else:
            found_object = found_list[0]
            logger.debug(f"Gefundenes OpenCTI Objekt Rohdaten (Auszug): { {k: v for k, v in found_object.items() if k in ['id', 'entity_type', 'x_opencti_score', 'labels', 'objectMarking']} }")
            obj_id = found_object.get('id')
            obj_type = found_object.get('entity_type', stix_type_name)
            obj_score = found_object.get('x_opencti_score')
            obj_labels = [label.get('value', '') for label in found_object.get('labels', [])]

            tlp_marking = None
            object_markings = found_object.get('objectMarking', [])
            if object_markings:
                 logger.debug(f"Prüfe {len(object_markings)} ObjectMarkings für TLP...")
                 for marking in object_markings:
                     if marking.get('definition_type', '').lower() == 'tlp':
                         tlp_value = marking.get('definition', '')
                         if tlp_value:
                             tlp_marking = tlp_value.upper()
                             logger.info(f"TLP Marking gefunden: {tlp_marking}")
                             break
            else:
                 logger.debug("Keine ObjectMarkings im gefundenen Objekt enthalten.")

            verdict_status = 'info'
            if obj_score is not None:
                if obj_score >= 80: verdict_status = 'malicious'
                elif obj_score >= 50: verdict_status = 'suspicious'
                elif obj_score > 0: verdict_status = 'info'
                else: verdict_status = 'ok'

            result['status'] = verdict_status
            result['summary'] = f"'{obj_type}' gefunden. Score: {obj_score if obj_score is not None else 'N/A'}."
            result['link'] = f"{opencti_url}/dashboard/id/{obj_id}"

            result['details'] = {
                'score': obj_score,
                'tlp': tlp_marking,
                'event_id': None,
                'event_info': None,
                'attribute_id': obj_id,
                'attribute_type': obj_type,
                'labels': obj_labels if obj_labels else None,
                'raw_stats': None
            }
            result['details'] = {k: v for k, v in result['details'].items() if v is not None}

            return result

    except Exception as e:
        logger.error(f"{CONNECTOR_NAME}: Allgemeiner Fehler bei Suche nach '{ioc_value}': {e}", exc_info=True)
        result['summary'] = f"Allgemeiner Fehler: {e}"
        result['error_message'] = str(e)
        result['status'] = 'error'

    return result