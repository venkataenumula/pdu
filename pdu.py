# pdu.py
import argparse
from core.tshark_runner import extract_tls_records
from core.tls_parser import parse_tls_sessions
from core.diagnostics import run_diagnostics
from core.report import print_report

def main():
    parser = argparse.ArgumentParser(description="Packet Debug Utility (PDU) - TLS Analyzer")
    parser.add_argument("--pcap", required=True, help="Path to PCAP file")
    parser.add_argument("--key", help="Path to RSA private key (optional, for TLS 1.2 decryption)")
    parser.add_argument("--output", help="Write report to file (JSON)")
    args = parser.parse_args()

    print("[+] Extracting TLS records from PCAP...")
    records = extract_tls_records(args.pcap)

    print("[+] Parsing TLS sessions...")
    sessions = parse_tls_sessions(records)

    print("[+] Running diagnostics...")
    report = run_diagnostics(sessions, private_key_path=args.key)

    print("[+] Report Summary:")
    print_report(report, to_file=args.output)

if __name__ == "__main__":
    main()
