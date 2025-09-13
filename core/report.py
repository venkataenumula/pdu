
# core/report.py
import json

def print_report(report, to_file=None):
    for r in report:
        print(f"\nStream {r['stream_id']} ({r['src']} → {r['dst']}):")
        print(f"  TLS Version: {r['tls_version']}")
        print(f"  Cipher Suite: {r['ciphersuite']}")
        print(f"  ALPN: {r.get('alpn', '-')}")
        if r['issues']:
            for i in r['issues']:
                print(f"  [!] {i}")
        else:
            print("  [✓] No issues detected")
        print(f"  Decryptable: {r.get('decryptable', False)}")

    if to_file:
        with open(to_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report written to {to_file}")
