import logging
import os
import ipaddress
from urllib.parse import quote_plus

try:
    from pycti import OpenCTIApiClient
    PYCTI_AVAILABLE = True
except ImportError:
    PYCTI_AVAILABLE = False

CONNECTOR_NAME = "OpenCTI (Import - SimpleCreate)"
logger = logging.getLogger(__name__)

def _get_stix_simple_create_info(api_client, internal_type, ioc_value):
    """
    Ermittelt API-Handler, Filter-Schlüssel und Parameter für die Erstellung eines STIX Objekts.
    Gibt ein Tupel zurück: (api_handler, list_method_name, simple_key_string, filter_key, create_kwargs)
    oder None bei nicht unterstütztem Typ. create_kwargs ist None, wenn simple_key_string verwendet wird.
    """
    logger.debug(f"Mapping Typ '{internal_type}' für SimpleCreate, Wert '{ioc_value[:50]}...'")

    handler = api_client.stix_cyber_observable
    list_method = 'list'
    simple_key = None
    filter_key = None
    create_kwargs = None

    if internal_type in ['ip-dst', 'ip-src']:
        try:
            ip = ipaddress.ip_address(ioc_value)
            stix_type = 'IPv4-Addr' if ip.version == 4 else 'IPv6-Addr'
            simple_key = f"{stix_type}.value"
            filter_key = 'value'
        except ValueError: return None
    elif internal_type == 'domain':
        simple_key = 'Domain-Name.value'
        filter_key = 'value'
    elif internal_type == 'url':
        simple_key = 'Url.value'
        filter_key = 'value'
    elif internal_type == 'email':
        simple_key = 'Email-Addr.value'
        filter_key = 'value'

    hash_map = {'md5': 'MD5', 'sha1': 'SHA-1', 'sha256': 'SHA-256'}
    if internal_type in hash_map:
        stix_type = 'File'
        hash_type_stix = hash_map[internal_type]
        create_kwargs = {'hashes': {hash_type_stix: ioc_value}, 'type': stix_type}
        filter_key = f"hashes.{hash_type_stix}"
        return handler, list_method, None, filter_key, create_kwargs # Strukturierter Ansatz

    if internal_type == 'filename':
        simple_key = 'File.name'
        filter_key = 'name'

    if internal_type == 'regkey':
        stix_type = 'Windows-Registry-Key'
        create_kwargs = {'key': ioc_value, 'type': stix_type}
        filter_key = 'attribute_key'
        return handler, list_method, None, filter_key, create_kwargs # Strukturierter Ansatz

    if internal_type == 'vulnerability':
        handler = api_client.vulnerability
        create_kwargs = {'name': ioc_value}
        filter_key = 'name'
        return handler, list_method, None, filter_key, create_kwargs # Strukturierter Ansatz

    if simple_key and filter_key:
        return handler, list_method, simple_key, filter_key, None # Einfacher Ansatz

    logger.warning(f"Kein unterstütztes Mapping für Typ: {internal_type} gefunden.")
    return None

def import_indicator(ioc_value, ioc_type, config, source_info=None):
    """
    Fügt einen IoC als STIX Objekt zu OpenCTI hinzu. Prüft auf Existenz.
    Versucht 'simple_observable_key' wo möglich, sonst strukturierten Ansatz.
    """
    result = {'connector_name': CONNECTOR_NAME, 'success': False, 'message': 'Initial Error', 'details': None}
    source_info = source_info or {}

    if not PYCTI_AVAILABLE:
        result['message'] = "PyCTI Bibliothek nicht installiert."; logger.error(f"{CONNECTOR_NAME}: {result['message']}"); return result

    opencti_url = config.get('OPENCTI_URL')
    opencti_token = config.get('OPENCTI_TOKEN')
    if not opencti_url or not opencti_token:
        result['message'] = 'OpenCTI nicht konfiguriert.'; logger.error(f"{CONNECTOR_NAME}: {result['message']}"); return result

    ioc_value = ioc_value.strip()
    if not ioc_value:
        result['message'] = 'Leerer Indikatorwert.'; return result

    try:
        logger.debug(f"{CONNECTOR_NAME}: Verbinde mit {opencti_url}")
        api_client = OpenCTIApiClient(opencti_url, opencti_token)
    except Exception as conn_e:
        logger.error(f"{CONNECTOR_NAME}: Fehler beim Verbinden/Health Check: {conn_e}", exc_info=True)
        result['message'] = f"Verbindungsfehler: {conn_e}"; return result

    handling_info = _get_stix_simple_create_info(api_client, ioc_type, ioc_value)
    if not handling_info:
        result['message'] = f"Typ '{ioc_type}' nicht für Import unterstützt."
        result['success'] = True # Überspringen ist kein Fehler
        logger.info(f"{CONNECTOR_NAME}: {result['message']}"); return result

    api_handler, list_method_name, simple_key_string, filter_key, create_kwargs = handling_info
    stix_type_name = simple_key_string.split('.')[0] if simple_key_string else create_kwargs.get('type', 'Vulnerability' if api_handler == api_client.vulnerability else 'Unknown')

    try:
        logger.debug(f"{CONNECTOR_NAME}: Suche '{stix_type_name}' mit FilterKey '{filter_key}' = '{ioc_value[:50]}...'")
        list_method = getattr(api_handler, list_method_name)
        filters = {"mode": "and", "filters": [{"key": filter_key, "values": [ioc_value]}], "filterGroups": []}
        list_params = {'filters': filters, 'first': 1}
        if api_handler == api_client.stix_cyber_observable and stix_type_name != 'Unknown':
            list_params['type'] = stix_type_name

        existing_list = list_method(**list_params)

        if existing_list:
            existing_object = existing_list[0]
            octi_id = existing_object.get('id')
            logger.info(f"{CONNECTOR_NAME}: Objekt '{stix_type_name}' existiert bereits (ID: {octi_id}).")
            result['success'] = True
            result['message'] = f"Objekt existiert bereits in OpenCTI (ID: {octi_id})."
            result['details'] = {'opencti_id': octi_id, 'stix_type': stix_type_name, 'action': 'skipped_exists'}
            return result

        logger.info(f"{CONNECTOR_NAME}: Erstelle neues Objekt '{stix_type_name}' für Wert '{ioc_value[:50]}...'")

        common_create_params = {}
        description_parts = ["Added via ARTIFAKT"]
        if source_info.get('comment'): description_parts.append(f"Kommentar: {source_info['comment']}")
        if source_info.get('case_number'): description_parts.append(f"Case: {source_info['case_number']}")
        if source_info.get('source_system'): description_parts.append(f"Quelle: {source_info['source_system']}")
        common_create_params['description'] = " | ".join(description_parts)
        common_create_params['x_opencti_score'] = 50

        response = None
        create_method = getattr(api_handler, 'create')

        if simple_key_string:
            logger.debug(f"Versuche Create mit simple_observable_key='{simple_key_string}', simple_observable_value='{ioc_value[:50]}...'")
            response = create_method(
                simple_observable_key=simple_key_string,
                simple_observable_value=ioc_value,
                **common_create_params
            )
        elif create_kwargs:
            final_params = {**create_kwargs, **common_create_params}
            logger.debug(f"Versuche Create mit strukturierten Parametern: { {k:v for k,v in final_params.items() if k!='hashes'} }")
            response = create_method(**final_params)
        else:
             raise ValueError("Keine gültigen Parameter für Create gefunden.")

        logger.debug(f"Antwort von OpenCTI auf Create: {str(response)[:200]}{'...' if len(str(response))>200 else ''}")
        if response and isinstance(response, dict) and response.get('id'):
            octi_id = response.get('id')
            logger.info(f"{CONNECTOR_NAME}: Objekt '{stix_type_name}' erfolgreich erstellt (ID: {octi_id}).")
            result['success'] = True
            result['message'] = f"Erfolgreich in OpenCTI erstellt als '{stix_type_name}'."
            result['details'] = {'opencti_id': octi_id, 'stix_type': stix_type_name, 'action': 'created'}
        else:
            logger.error(f"{CONNECTOR_NAME}: Konnte Objekt '{stix_type_name}' nicht erstellen. Create Response: {response}")
            result['message'] = f"Konnte Objekt '{stix_type_name}' nicht erstellen (Response: {response}). Prüfe OpenCTI Logs & Berechtigungen."
            result['details'] = {'opencti_response': str(response)[:500]}

    except Exception as e:
        logger.error(f"{CONNECTOR_NAME}: Allgemeiner Fehler bei Import von '{ioc_value}': {e}", exc_info=True)
        result['message'] = f"Allgemeiner Fehler: {e}"
        result['details'] = {'exception': str(e)}

    return result