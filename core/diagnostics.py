# core/diagnostics.py
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64

def run_diagnostics(sessions, private_key_path=None):
    report = []
    for sess in sessions:
        entry = dict(sess)  # shallow copy
        entry['issues'] = []

        if not sess['tls_version']:
            entry['issues'].append("Missing TLS version")
        if not sess['ciphersuite']:
            entry['issues'].append("Missing Cipher Suite")
        if sess['alerts']:
            entry['issues'].extend([f"TLS Alert: {a}" for a in sess['alerts']])
        if sess['certificates']:
            try:
                cert_der = base64.b64decode(sess['certificates'][0])
                cert = x509.load_der_x509_certificate(cert_der, backend=default_backend())
                if cert.not_valid_after < datetime.utcnow():
                    entry['issues'].append("Expired certificate")
                if cert.issuer == cert.subject:
                    entry['issues'].append("Self-signed certificate")
            except Exception as e:
                entry['issues'].append(f"Certificate parse error: {e}")
        if 'TLS_ECDHE' in sess['ciphersuite'] or 'TLS_CHACHA' in sess['ciphersuite']:
            entry['issues'].append("Forward secrecy; cannot decrypt")
        elif private_key_path and sess['tls_version'] == '0x0303':
            entry['decryptable'] = True
        else:
            entry['decryptable'] = False

        report.append(entry)
    return report
