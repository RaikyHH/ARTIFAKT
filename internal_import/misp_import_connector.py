import logging
from pymisp import PyMISP, MISPAttribute, PyMISPError

CONNECTOR_NAME = "MISP (Import)"
logger = logging.getLogger(__name__)

TYPE_MAPPING = {
    'ip-dst': 'ip-dst',
    'ip-src': 'ip-src',
    'md5': 'md5',
    'sha1': 'sha1',
    'sha256': 'sha256',
    'vulnerability': 'vulnerability',
    'email': 'email',
    'email-src': 'email-src',
    'email-dst': 'email-dst',
    'url': 'url',
    'domain': 'domain',
    'regkey': 'regkey',
    'filename': 'filename',
    'comment': 'comment',
    'text': 'text',
}

def _map_type_to_misp(internal_type):
    """Mappt den intern erkannten Typ auf einen MISP Attribut-Typ."""
    misp_type = TYPE_MAPPING.get(internal_type, 'comment')
    if misp_type != 'comment' and internal_type not in TYPE_MAPPING:
        logger.warning(f"Kein spezifisches MISP-Mapping für internen Typ '{internal_type}' gefunden, verwende Fallback '{misp_type}'.")
    logger.debug(f"Mapping: Intern '{internal_type}' -> MISP '{misp_type}'")
    return misp_type

def import_indicator(ioc_value, ioc_type, config, source_info=None):
    """
    Fügt einen IoC als Attribut zu einem spezifischen MISP Event hinzu.

    Args:
        ioc_value (str): Der erkannte IoC-String.
        ioc_type (str): Der von app.py erkannte generische Typ.
        config (dict): Enthält MISP_URL, MISP_KEY, MISP_EVENTID_WRITE, MISP_VERIFY_SSL.
        source_info (dict, optional): Zusätzliche Kontextinfos (z.B. case_number, comment).

    Returns:
        dict: {'connector_name': str, 'success': bool, 'message': str, 'details': dict | None}
    """
    result = {
        'connector_name': CONNECTOR_NAME,
        'success': False,
        'message': 'Initial Error',
        'details': None
    }

    misp_url = config.get('MISP_URL')
    misp_key = config.get('MISP_KEY')
    misp_event_id = config.get('MISP_EVENTID_WRITE')
    verify_ssl = config.get('MISP_VERIFY_SSL', False)

    if not misp_url or not misp_key:
        result['message'] = 'MISP URL oder Key nicht konfiguriert.'
        logger.error(f"{CONNECTOR_NAME}: Konfiguration fehlt.")
        return result
    if not misp_event_id:
        result['message'] = 'MISP Event ID für Import nicht konfiguriert.'
        logger.error(f"{CONNECTOR_NAME}: MISP Event ID fehlt.")
        return result

    misp_attribute_type = _map_type_to_misp(ioc_type)
    if not misp_attribute_type:
        result['message'] = f"Konnte internen Typ '{ioc_type}' keinem MISP-Typ zuordnen."
        logger.error(f"{CONNECTOR_NAME}: {result['message']}")
        return result

    try:
        logger.debug(f"{CONNECTOR_NAME}: Verbinde mit {misp_url} (SSL Verify: {verify_ssl})")
        misp = PyMISP(misp_url, misp_key, ssl=verify_ssl)
        logger.info(f"{CONNECTOR_NAME}: Füge Attribut '{ioc_value}' (Typ: {misp_attribute_type}) zu Event {misp_event_id} hinzu.")

        attribute = MISPAttribute()
        attribute.type = misp_attribute_type
        attribute.value = ioc_value
        attribute.to_ids = False
        attribute.comment = "Added via ARTIFAKT"

        if source_info:
            case_num = source_info.get('case_number')
            src_sys = source_info.get('source_system')
            comment = source_info.get('comment')
            if case_num: attribute.comment += f" | Case: {case_num}"
            if src_sys: attribute.comment += f" | Source: {src_sys}"
            if comment: attribute.comment += f" | Note: {comment[:100]}{'...' if len(comment)>100 else ''}"

        attribute.add_tag("ARTIFAKT")

        response = misp.add_attribute(misp_event_id, attribute)

        if isinstance(response, dict) and response.get('Attribute'):
            created_attribute = response.get('Attribute')
            attr_id = created_attribute.get('id', 'N/A')
            logger.info(f"{CONNECTOR_NAME}: Attribut erfolgreich zu Event {misp_event_id} hinzugefügt (Attribut-ID: {attr_id}).")
            result['success'] = True
            result['message'] = f"Erfolgreich zu MISP Event {misp_event_id} hinzugefügt."
            result['details'] = {'misp_attribute_id': attr_id, 'misp_event_id': misp_event_id}
        elif isinstance(response, dict) and response.get('errors'):
             logger.error(f"{CONNECTOR_NAME}: MISP API Fehler beim Hinzufügen von Attribut zu Event {misp_event_id}: {response['errors']}")
             result['message'] = f"MISP API Fehler: {response['errors']}"
             result['details'] = {'misp_error': response['errors']}
        else:
             logger.warning(f"{CONNECTOR_NAME}: Unerwartete Antwort von misp.add_attribute für Event {misp_event_id}: {response}")
             result['message'] = "Unbekannte Antwort von MISP erhalten."
             result['details'] = {'misp_response': str(response)[:500]}

    except PyMISPError as e:
        logger.error(f"{CONNECTOR_NAME}: PyMISP Fehler für Event {misp_event_id}: {e}", exc_info=True)
        result['message'] = f"PyMISP Fehler: {e}"
    except Exception as e:
        logger.error(f"{CONNECTOR_NAME}: Allgemeiner Fehler beim Hinzufügen zu MISP Event {misp_event_id}: {e}", exc_info=True)
        result['message'] = f"Allgemeiner Fehler: {e}"

    return result