# Uses a small .pcap file (tls_sample.pcap) with simulated TLS 1.2 + 1.3 flows
# Mocks tshark_runner.extract_tls_records (so the test works even without actual TShark or PCAP)
# This test does not need an actual .pcap — it simulates parsed sessions. You can later drop a real PCAP under tests/data/tls_sample.pcap.
# tests/test_tls_basic.py
import pytest
from core.diagnostics import run_diagnostics
from core.report import print_report

def test_tls_diagnostics_basic(monkeypatch):
    sample_sessions = [
        {
            'stream_id': '1',
            'src': '10.0.0.1',
            'dst': '10.0.0.2',
            'tls_version': '0x0303',
            'ciphersuite': 'TLS_RSA_WITH_AES_256_CBC_SHA',
            'certificates': [],
            'alerts': [],
            'alpn': 'http/1.1'
        },
        {
            'stream_id': '2',
            'src': '10.0.0.1',
            'dst': '10.0.0.3',
            'tls_version': '0x0304',
            'ciphersuite': 'TLS_AES_128_GCM_SHA256',
            'certificates': [],
            'alerts': ['handshake_failure'],
            'alpn': 'h2'
        }
    ]

    report = run_diagnostics(sample_sessions)
    assert len(report) == 2
    assert report[1]['issues'][0] == "TLS Alert: handshake_failure"
    assert report[0]['decryptable'] is False

    print_report(report)
