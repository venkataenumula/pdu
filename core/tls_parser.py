
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

# core/tls_parser.py
def parse_tls_sessions(records):
    sessions = {}
    for record in records:
        try:
            layers = record['_source']['layers']
            stream_id = layers.get('tcp.stream', ['unknown'])[0]
            session = sessions.setdefault(stream_id, {
                'stream_id': stream_id,
                'src': layers.get('ip.src', [''])[0],
                'dst': layers.get('ip.dst', [''])[0],
                'tls_version': '',
                'ciphersuite': '',
                'certificates': [],
                'alerts': [],
                'alpn': '',
            })

            if 'tls.handshake.version' in layers:
                session['tls_version'] = layers['tls.handshake.version'][0]
            if 'tls.handshake.ciphersuite' in layers:
                session['ciphersuite'] = layers['tls.handshake.ciphersuite'][0]
            if 'tls.alert_message.desc' in layers:
                session['alerts'].append(layers['tls.alert_message.desc'][0])
            if 'tls.handshake.certificates' in layers:
                session['certificates'] = layers['tls.handshake.certificates']
            if 'tls.handshake.extensions_alpn_str' in layers:
                session['alpn'] = layers['tls.handshake.extensions_alpn_str'][0]
        except Exception as e:
            print(f"[!] Failed to parse TLS record: {e}")
    return list(sessions.values())
