# plugins/tls_basic.py
def analyze(session: dict) -> list:
    issues = []
    if 'TLS_RSA' in session.get('ciphersuite', ''):
        issues.append("Using RSA — susceptible to downgrade")
    if session.get('tls_version', '') == '0x0301':
        issues.append("Using TLS 1.0 — deprecated")
    return issues

