import logging

# --- Konfiguration ---
# Eindeutiger, menschenlesbarer Name für diesen Connector
CONNECTOR_NAME = "Template Connector"
# Logger für Ausgaben (besser als print)
logger = logging.getLogger(__name__)

# --- Hauptfunktion ---
def analyze(indicator_value, indicator_type, config):
    """
    Dies ist die Hauptfunktion, die von app.py aufgerufen wird.
    Sie MUSS exakt diese Signatur haben.

    Args:
        indicator_value (str): Der zu prüfende IoC-String (z.B. "8.8.8.8").
        indicator_type (str): Der von app.py erkannte Typ (z.B. "ip_address", "file_hash", "url").
                               Kann zur Optimierung genutzt werden, muss aber nicht.
        config (dict): Ein Dictionary mit Konfigurationen aus app.py.
                       Hier könnten API-Keys, URLs etc. drinstehen.
                       z.B. config.get('MY_CONNECTOR_API_KEY')

    Returns:
        dict: Ein Dictionary im standardisierten Format.
              MUSS 'connector_name' und 'status' enthalten.
              Andere Felder ('summary', 'details', 'link', 'error_message') sind optional.
              Mögliche Status: 'ok', 'suspicious', 'malicious', 'info', 'not_found', 'error'.
    """
    logger.debug(f"{CONNECTOR_NAME}: Analyze für '{indicator_value}' (Typ: {indicator_type}) gestartet.")

    # Standard-Rückgabewert initialisieren
    result = {
        'connector_name': CONNECTOR_NAME,
        'status': 'info', # Default-Status
        'summary': 'Analyse noch nicht implementiert.',
        'details': None,
        'link': None,
        'error_message': None
    }

    # --- Hier deine Logik einfügen ---
    # 1. Prüfe, ob der Connector für diesen indicator_type zuständig ist (optional).
    # 2. Hole benötigte Konfiguration aus dem `config`-Dictionary.
    #    api_key = config.get('MY_KEY')
    #    if not api_key:
    #        result['status'] = 'error'
    #        result['summary'] = 'API Key fehlt.'
    #        result['error_message'] = result['summary']
    #        return result
    # 3. Führe die eigentliche Analyse durch (z.B. API-Call).
    # 4. Verarbeite das Ergebnis.
    # 5. Fülle das `result`-Dictionary mit den entsprechenden Werten.
    #    Beispiel:
    #    try:
    #        api_response = make_api_call(indicator_value, api_key)
    #        if api_response['found']:
    #            result['status'] = 'suspicious' # Beispiel
    #            result['summary'] = f"Gefunden mit Score {api_response['score']}"
    #            result['details'] = api_response['raw_data']
    #            result['link'] = api_response['gui_link']
    #        else:
    #            result['status'] = 'not_found'
    #            result['summary'] = 'Nicht gefunden.'
    #    except Exception as e:
    #         logger.error(f"{CONNECTOR_NAME}: Fehler bei Analyse von '{indicator_value}': {e}", exc_info=True)
    #         result['status'] = 'error'
    #         result['summary'] = 'Fehler bei der Analyse.'
    #         result['error_message'] = str(e)

    logger.debug(f"{CONNECTOR_NAME}: Analyse für '{indicator_value}' beendet mit Status '{result['status']}'.")
    return result

# --- Optionale Hilfsfunktionen ---
# def make_api_call(indicator, key):
#    # ...
#    pass
