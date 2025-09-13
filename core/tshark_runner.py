# core/tshark_runner.py
import subprocess
import json

def extract_tls_records(pcap_file):
    fields = [
        "tls.record.version",
        "tls.handshake.type",
        "tls.handshake.extensions_server_name",
        "tls.handshake.ciphersuite",
        "tls.handshake.version",
        "tls.alert_message.desc",
        "tls.handshake.certificates",
        "ip.src",
        "ip.dst",
        "tcp.stream"
    ]

    cmd = [
        "tshark", "-r", pcap_file, "-Y", "tls", "-T", "json"
    ]
    for field in fields:
        cmd += ["-e", field]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print("[!] TShark execution failed")
        raise e
    except json.JSONDecodeError:
        print("[!] Failed to parse TShark JSON output")
        raise

