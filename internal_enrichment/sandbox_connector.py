import random
import logging

CONNECTOR_NAME = "Sandbox (Simulated)"
logger = logging.getLogger(__name__)

def analyze(indicator_value, indicator_type, config):
    """Simuliert eine Sandbox-Analyse für Datei-Hashes."""
    base_result = {
        'connector_name': CONNECTOR_NAME, 'status': 'info', 'summary': 'Nicht zutreffend.',
        'details': None, 'link': None, 'error_message': None
    }

    # Dieser Connector ist nur für Hashes sinnvoll
    # Alternativ könnte man auch den indicator_type von app.py prüfen
    is_hash = (len(indicator_value) == 32 or len(indicator_value) == 40 or len(indicator_value) == 64) and all(c in 'abcdefABCDEF0123456789' for c in indicator_value)

    if not is_hash:
         logger.debug(f"{CONNECTOR_NAME}: Übersprungen, da Indikator '{indicator_value[:10]}...' kein Hash ist.")
         base_result['summary'] = 'Nur für Datei-Hashes relevant.'
         return base_result

    file_hash = indicator_value
    logger.debug(f"{CONNECTOR_NAME}: Simuliere Analyse für Hash {file_hash[:10]}...")

    # --- Simulationslogik ---
    possible_stati = ['ok', 'suspicious', 'malicious']
    simulated_raw_status = random.choice(possible_stati)

    verdict_map = {'ok': 'Gutartig', 'suspicious': 'Verdächtig', 'malicious': 'Bösartig'}
    verdict_text = verdict_map.get(simulated_raw_status, 'Unbekannt')

    summary = f"Simulierte Analyse: {verdict_text}."
    details = {"simulation_engine": "RandomChooser v1.0", "notes": "Dies ist ein simuliertes Ergebnis."}

    # Ergebnis im Standardformat zurückgeben
    base_result['status'] = simulated_raw_status
    base_result['summary'] = summary
    base_result['details'] = details
    return base_result