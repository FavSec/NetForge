#!/usr/bin/env python3
"""
NetForge backend — real pcap parsing
Supports: HTTP, HTTPS metadata, DNS, FTP, SMTP
Run with: python server.py
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import math
import io
import os
import tempfile
import collections
import struct

# Scapy — suppress startup warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, TCP, UDP, IP, IPv6, DNS, DNSQR, DNSRR, Raw

app = Flask(__name__)
CORS(app)  # Allow the GitHub Pages frontend to call this

# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())

def format_bytes(n: int) -> str:
    if n < 1024: return f"{n} B"
    if n < 1048576: return f"{n/1024:.1f} KB"
    return f"{n/1048576:.1f} MB"

def safe_decode(b: bytes) -> str:
    try:
        return b.decode("utf-8", errors="replace")
    except Exception:
        return repr(b)

# ─────────────────────────────────────────────
# TCP STREAM REASSEMBLY
# ─────────────────────────────────────────────

def reassemble_tcp_streams(packets):
    """
    Reassemble TCP streams from a list of Scapy packets.
    Returns a dict keyed by (src_ip, src_port, dst_ip, dst_port) → {"fwd": bytes, "rev": bytes}
    """
    streams = collections.defaultdict(lambda: {"fwd": {}, "rev": {}})

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        tcp = pkt[TCP]

        src = (ip.src, tcp.sport)
        dst = (ip.dst, tcp.dport)

        # Canonical key — lower tuple is always "fwd" side
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        rev_key = (ip.dst, tcp.dport, ip.src, tcp.sport)

        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw])
            seq = tcp.seq
            if key <= rev_key:
                streams[key]["fwd"][seq] = payload
            else:
                streams[rev_key]["rev"][seq] = payload

    # Concatenate in sequence order
    result = {}
    for key, dirs in streams.items():
        fwd_data = b"".join(v for _, v in sorted(dirs["fwd"].items()))
        rev_data = b"".join(v for _, v in sorted(dirs["rev"].items()))
        if fwd_data or rev_data:
            result[key] = {"fwd": fwd_data, "rev": rev_data}

    return result

# ─────────────────────────────────────────────
# PROTOCOL PARSERS
# ─────────────────────────────────────────────

def parse_http_request(data: bytes) -> dict | None:
    """Parse a raw HTTP request from reassembled bytes."""
    try:
        header_end = data.find(b"\r\n\r\n")
        header_bytes = data[:header_end] if header_end != -1 else data
        lines = header_bytes.split(b"\r\n")
        if not lines:
            return None

        request_line = safe_decode(lines[0]).split(" ")
        if len(request_line) < 2:
            return None

        method = request_line[0]
        if method not in ("GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS","CONNECT"):
            return None

        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                headers[safe_decode(k).strip()] = safe_decode(v).strip()

        body = data[header_end+4:] if header_end != -1 else b""

        return {
            "method": method,
            "uri": request_line[1] if len(request_line) > 1 else "/",
            "version": request_line[2] if len(request_line) > 2 else "HTTP/1.1",
            "headers": headers,
            "body": safe_decode(body[:2048]) if body else ""
        }
    except Exception:
        return None

def parse_http_response(data: bytes) -> dict | None:
    """Parse a raw HTTP response."""
    try:
        header_end = data.find(b"\r\n\r\n")
        header_bytes = data[:header_end] if header_end != -1 else data
        lines = header_bytes.split(b"\r\n")
        if not lines:
            return None

        status_line = safe_decode(lines[0]).split(" ", 2)
        if not status_line[0].startswith("HTTP"):
            return None

        status = int(status_line[1]) if len(status_line) > 1 else 0
        status_text = status_line[2] if len(status_line) > 2 else ""

        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                headers[safe_decode(k).strip()] = safe_decode(v).strip()

        body = data[header_end+4:] if header_end != -1 else b""

        return {
            "status": status,
            "statusText": status_text,
            "headers": headers,
            "body": safe_decode(body[:2048]) if body else ""
        }
    except Exception:
        return None

def detect_files_in_http(req: dict, res: dict, body: bytes) -> list:
    """Extract file metadata from HTTP responses."""
    files = []
    if not res:
        return files

    content_type = res["headers"].get("Content-Type", "")
    content_disp = res["headers"].get("Content-Disposition", "")
    content_len = res["headers"].get("Content-Length", "0")

    # Determine filename
    filename = None
    if "filename=" in content_disp:
        filename = content_disp.split("filename=")[-1].strip().strip('"')
    elif req and req.get("uri"):
        uri_path = req["uri"].split("?")[0]
        basename = uri_path.rstrip("/").split("/")[-1]
        if "." in basename:
            filename = basename

    if filename and content_type not in ("text/html", "text/css", "application/javascript"):
        size = int(content_len) if content_len.isdigit() else len(body)
        ent = entropy(body) if body else 0.0

        # Pick icon/color by mime
        icon_map = {
            "application/pdf": ("📄", "#e74c3c"),
            "text/csv": ("📊", "#2ecc71"),
            "application/zip": ("🗜️", "#f0a500"),
            "image/": ("🖼️", "#9b59b6"),
            "application/vnd.openxmlformats": ("📊", "#2ecc71"),
            "application/msword": ("📝", "#4f8ef7"),
            "application/octet-stream": ("⬛", "#7c8099"),
        }
        icon, color = "📎", "#7c8099"
        for mime_prefix, (i, c) in icon_map.items():
            if content_type.startswith(mime_prefix):
                icon, color = i, c
                break

        files.append({
            "name": filename,
            "mime": content_type,
            "size": size,
            "entropy": round(ent, 4),
            "md5": md5(body) if body else "",
            "sha256": sha256(body) if body else "",
            "icon": icon,
            "color": color,
        })

    return files

def detect_credentials(req: dict) -> list:
    """Scan request headers and body for credential patterns."""
    alerts = []
    if not req:
        return alerts

    headers = req.get("headers", {})
    body = req.get("body", "")

    # Authorization header
    auth = headers.get("Authorization", "")
    if auth.startswith("Basic "):
        import base64
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8", errors="replace")
            alerts.append({
                "sev": "high",
                "title": "Basic Auth credentials",
                "desc": f"Base64-decoded: {decoded}",
                "icon": "🔓"
            })
        except Exception:
            pass
    elif auth.startswith("Bearer "):
        token = auth[7:]
        if token.startswith("ghp_"):
            alerts.append({"sev":"high","title":"GitHub token","desc":f"ghp_*** in Authorization header","icon":"🔑"})
        else:
            alerts.append({"sev":"med","title":"Bearer token","desc":"Token in Authorization header","icon":"🔑"})

    # FTP/SMTP credentials in raw stream
    for keyword in ("PASS ", "AUTH PLAIN", "password=", "passwd=", "pwd="):
        if keyword.lower() in body.lower():
            alerts.append({"sev":"high","title":f"Credential keyword: {keyword.strip()}","desc":"Found in request body/stream","icon":"🔓"})

    return alerts

def parse_dns_packets(packets) -> list:
    """Extract DNS queries and responses from UDP packets."""
    dns_records = []
    seen = set()

    for pkt in packets:
        if not pkt.haslayer(DNS):
            continue
        dns = pkt[DNS]

        # Queries
        if dns.qr == 0 and dns.qdcount > 0:
            for i in range(dns.qdcount):
                try:
                    qr = dns.qd
                    for _ in range(i):
                        qr = qr.payload
                    name = qr.qname.decode("utf-8", errors="replace").rstrip(".")
                    qtype = {1:"A",2:"NS",5:"CNAME",12:"PTR",15:"MX",28:"AAAA",255:"ANY"}.get(qr.qtype, str(qr.qtype))
                    key = (name, qtype)
                    if key not in seen:
                        seen.add(key)
                        record = {"query": name, "type": qtype, "answer": None, "ttl": None}
                        dns_records.append(record)
                except Exception:
                    continue

        # Responses
        if dns.qr == 1 and dns.ancount > 0:
            try:
                rr = dns.an
                while rr and rr.type != 41:  # skip OPT
                    name = rr.rrname.decode("utf-8", errors="replace").rstrip(".")
                    qtype = {1:"A",2:"NS",5:"CNAME",12:"PTR",15:"MX",28:"AAAA"}.get(rr.type, str(rr.type))
                    answer = None
                    if hasattr(rr, "rdata"):
                        answer = str(rr.rdata)
                    elif hasattr(rr, "address"):
                        answer = str(rr.address)
                    # Update matching query record
                    for rec in dns_records:
                        if rec["query"] == name and rec["type"] == qtype and rec["answer"] is None:
                            rec["answer"] = answer
                            rec["ttl"] = rr.ttl
                            break
                    else:
                        dns_records.append({"query": name, "type": qtype, "answer": answer, "ttl": rr.ttl})
                    rr = rr.payload
            except Exception:
                pass

    return dns_records

def detect_dns_alerts(dns_records: list) -> list:
    """Flag suspicious DNS patterns."""
    alerts = []
    suspicious_tlds = {".ru", ".cn", ".tk", ".xyz", ".top", ".pw", ".cc"}
    tor_exits = {"185.220.101.", "185.220.102.", "185.107.47.", "198.96.155."}

    for rec in dns_records:
        name = rec.get("query", "")
        answer = rec.get("answer", "") or ""

        # High-entropy subdomain (possible DGA)
        parts = name.split(".")
        if parts:
            sub = parts[0]
            if len(sub) > 12 and entropy(sub.encode()) > 3.5:
                alerts.append({"sev":"high","title":"High-entropy subdomain","desc":f"Possible DGA: {name}","icon":"🚨"})

        # Suspicious TLD
        for tld in suspicious_tlds:
            if name.endswith(tld):
                alerts.append({"sev":"med","title":f"Suspicious TLD ({tld})","desc":f"Query: {name}","icon":"⚠️"})

        # Known Tor exit node
        for prefix in tor_exits:
            if answer.startswith(prefix):
                alerts.append({"sev":"high","title":"Tor exit node IP","desc":f"{answer} is a known Tor exit node","icon":"🕵️"})

    return alerts

def detect_tls(fwd_data: bytes) -> dict | None:
    """Detect TLS ClientHello and extract SNI."""
    if not fwd_data or len(fwd_data) < 6:
        return None
    # TLS record header: content_type=22 (handshake), version, length
    if fwd_data[0] != 0x16:
        return None
    try:
        version_byte = fwd_data[2]
        version_map = {0x01:"TLSv1.0", 0x02:"TLSv1.1", 0x03:"TLSv1.2", 0x04:"TLSv1.3"}
        # SNI lives in ClientHello extensions
        sni = None
        data = fwd_data[5:]  # skip TLS record header
        if len(data) > 40 and data[0] == 0x01:  # ClientHello
            # Walk to extensions (skip fixed fields: 1+3+2+32+1+session_len+2+cipher_len+1+comp_len)
            idx = 1 + 3 + 2 + 32  # handshake_type + length + version + random
            if idx < len(data):
                session_len = data[idx]
                idx += 1 + session_len
            if idx + 2 < len(data):
                cipher_len = struct.unpack("!H", data[idx:idx+2])[0]
                idx += 2 + cipher_len
            if idx < len(data):
                comp_len = data[idx]
                idx += 1 + comp_len
            if idx + 2 < len(data):
                ext_len = struct.unpack("!H", data[idx:idx+2])[0]
                idx += 2
                ext_end = idx + ext_len
                while idx + 4 < ext_end:
                    ext_type = struct.unpack("!H", data[idx:idx+2])[0]
                    ext_size = struct.unpack("!H", data[idx+2:idx+4])[0]
                    if ext_type == 0:  # SNI
                        sni_data = data[idx+4:idx+4+ext_size]
                        if len(sni_data) > 5:
                            name_len = struct.unpack("!H", sni_data[3:5])[0]
                            sni = sni_data[5:5+name_len].decode("utf-8", errors="replace")
                    idx += 4 + ext_size

        return {
            "version": version_map.get(version_byte, f"TLS 0x{version_byte:02x}"),
            "cipher": "Unknown (encrypted)",
            "sni": sni or "unknown",
            "cert": sni or "unknown"
        }
    except Exception:
        return None

def detect_ftp_smtp_creds(fwd_data: bytes) -> list:
    """Scan FTP/SMTP streams for cleartext credentials."""
    alerts = []
    text = safe_decode(fwd_data)
    lines = text.split("\r\n")

    import base64

    for line in lines:
        upper = line.upper()
        if upper.startswith("USER "):
            alerts.append({"sev":"med","title":"FTP/SMTP username","desc":line.strip(),"icon":"👤"})
        elif upper.startswith("PASS "):
            alerts.append({"sev":"high","title":"Cleartext password","desc":line.strip(),"icon":"🔓"})
        elif upper.startswith("AUTH PLAIN"):
            parts = line.split(" ")
            if len(parts) >= 3:
                try:
                    decoded = base64.b64decode(parts[2]).decode("utf-8", errors="replace")
                    creds = [x for x in decoded.split("\x00") if x]
                    alerts.append({"sev":"high","title":"SMTP AUTH PLAIN","desc":f"Decoded: {' / '.join(creds)}","icon":"🔓"})
                except Exception:
                    pass

    return alerts

# ─────────────────────────────────────────────
# MAIN ANALYSIS PIPELINE
# ─────────────────────────────────────────────

def analyze_pcap(filepath: str) -> dict:
    packets = rdpcap(filepath)
    sessions_out = []
    dns_packets = []
    sess_id = 0

    # Collect DNS packets separately (UDP)
    for pkt in packets:
        if pkt.haslayer(DNS):
            dns_packets.append(pkt)

    # Reassemble TCP streams
    streams = reassemble_tcp_streams(packets)

    for (src_ip, src_port, dst_ip, dst_port), data in streams.items():
        fwd = data["fwd"]
        rev = data["rev"]
        total_bytes = len(fwd) + len(rev)

        if total_bytes < 20:
            continue

        sess_id += 1
        sid = f"sess_{sess_id:03d}"
        ts = None
        for pkt in packets:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                if pkt[IP].src == src_ip and pkt[TCP].sport == src_port:
                    ts = int(pkt.time * 1000)
                    break
        if ts is None:
            import time
            ts = int(time.time() * 1000)

        # Detect protocol
        proto = "TCP"
        flags = []
        tls_info = None
        alerts = []
        files = []
        req_obj = {"method":"RAW","uri":f"{dst_ip}:{dst_port}","version":"TCP","headers":{},"body":""}
        res_obj = {"status":0,"statusText":"RAW","headers":{},"body":""}

        # HTTP detection (port 80 or parseable)
        if dst_port == 80 or (fwd and fwd[:4] in (b"GET ", b"POST", b"PUT ", b"DELE", b"HEAD", b"OPTI")):
            req = parse_http_request(fwd)
            res = parse_http_response(rev)
            if req:
                proto = "HTTP"
                req_obj = req
                if res:
                    res_obj = res
                    # Extract files
                    files = detect_files_in_http(req, res, rev)
                    if files:
                        flags.append("file")
                # Credentials
                cred_alerts = detect_credentials(req)
                alerts.extend(cred_alerts)
                if cred_alerts:
                    flags.append("creds")
                # Unencrypted HTTP alert
                alerts.append({"sev":"low","title":"Unencrypted HTTP","desc":f"Traffic to {dst_ip}:{dst_port} is cleartext","icon":"ℹ️"})

        # TLS/HTTPS detection
        elif dst_port == 443 or (fwd and len(fwd) > 0 and fwd[0] == 0x16):
            tls_info = detect_tls(fwd)
            if tls_info:
                proto = "HTTPS"
                flags.append("tls")
                req_obj = {"method":"CONNECT","uri":f"{tls_info['sni']}:443","version":"TLS","headers":{"SNI":tls_info["sni"],"TLS-Version":tls_info["version"]},"body":""}
                res_obj = {"status":200,"statusText":"Connection established","headers":{"Cipher":tls_info["cipher"]},"body":""}

        # FTP detection
        elif dst_port == 21 or src_port == 21:
            proto = "FTP"
            cred_alerts = detect_ftp_smtp_creds(fwd)
            alerts.extend(cred_alerts)
            if any(a["sev"]=="high" for a in cred_alerts):
                flags.append("creds")
            # Look for RETR/STOR
            text = safe_decode(fwd)
            for line in text.split("\r\n"):
                if line.upper().startswith("RETR ") or line.upper().startswith("STOR "):
                    filename = line.split(" ",1)[1].strip() if " " in line else "unknown"
                    ent = entropy(rev)
                    files.append({"name":filename,"mime":"application/octet-stream","size":len(rev),"entropy":round(ent,4),"md5":md5(rev),"sha256":sha256(rev),"icon":"📁","color":"#f0a500"})
                    flags.append("file")
                    alerts.append({"sev":"high","title":"File transfer over FTP","desc":f"Unencrypted: {filename} ({format_bytes(len(rev))})","icon":"🚨"})
            req_obj = {"method":"FTP","uri":safe_decode(fwd[:200]),"version":"FTP","headers":{},"body":""}
            res_obj = {"status":0,"statusText":safe_decode(rev[:200]),"headers":{},"body":""}

        # SMTP detection
        elif dst_port in (25, 587, 465) or src_port in (25, 587):
            proto = "SMTP"
            cred_alerts = detect_ftp_smtp_creds(fwd)
            alerts.extend(cred_alerts)
            if any(a["sev"]=="high" for a in cred_alerts):
                flags.append("creds")
            # Look for attachments in raw MIME
            text = safe_decode(fwd)
            if "Content-Disposition: attachment" in text:
                alerts.append({"sev":"high","title":"Email attachment detected","desc":"MIME attachment in SMTP stream","icon":"📎"})
                flags.append("file")
                files.append({"name":"email_attachment","mime":"application/octet-stream","size":len(fwd),"entropy":round(entropy(fwd),4),"md5":md5(fwd),"sha256":sha256(fwd),"icon":"📎","color":"#4f8ef7"})
            req_obj = {"method":"SMTP","uri":f"{dst_ip}:25","version":"SMTP","headers":{},"body":safe_decode(fwd[:1024])}
            res_obj = {"status":250,"statusText":safe_decode(rev[:200]),"headers":{},"body":""}

        # Build timeline
        timeline = []
        if tls_info:
            timeline.append({"type":"tls","time":ts,"label":f"TLS handshake","detail":f"{tls_info['sni']} • {tls_info['version']}"})
        if proto in ("HTTP","HTTPS"):
            timeline.append({"type":"req","time":ts+10,"label":f"{req_obj['method']} {req_obj['uri']}","detail":f"{req_obj['version']} • {format_bytes(len(fwd))}"})
            timeline.append({"type":"res","time":ts+50,"label":f"{res_obj['status']} {res_obj['statusText']}","detail":format_bytes(len(rev))})
        for f in files:
            timeline.append({"type":"file","time":ts+60,"label":f"File extracted: {f['name']}","detail":f"{format_bytes(f['size'])} • entropy {f['entropy']}"})

        # Try to get hostname from HTTP Host header
        src_host = src_ip
        dst_host = req_obj.get("headers",{}).get("Host", None) or (tls_info["sni"] if tls_info else dst_ip)

        sessions_out.append({
            "id": sid,
            "proto": proto,
            "ts": ts,
            "src": f"{src_ip}:{src_port}",
            "dst": f"{dst_ip}:{dst_port}",
            "srcHost": src_host,
            "dstHost": dst_host,
            "bytes": {"req": len(fwd), "res": len(rev)},
            "duration": 0,  # would need timestamp delta
            "state": "CLOSED",
            "flags": list(set(flags)),
            "request": req_obj,
            "response": res_obj,
            "files": files,
            "dns": [],
            "tls": tls_info,
            "alerts": alerts,
            "timeline": timeline,
        })

    # Attach DNS records to sessions or create standalone sessions
    dns_records = parse_dns_packets(dns_packets)
    dns_alerts = detect_dns_alerts(dns_records)

    if dns_records:
        import time
        sessions_out.append({
            "id": f"sess_{sess_id+1:03d}",
            "proto": "DNS",
            "ts": int(time.time()*1000),
            "src": "local:53",
            "dst": "resolver:53",
            "srcHost": "local",
            "dstHost": "dns-resolver",
            "bytes": {"req": 64, "res": 128},
            "duration": 10,
            "state": "CLOSED",
            "flags": ["dns"],
            "request": {"method":"QUERY","uri":"DNS","version":"DNS","headers":{},"body":""},
            "response": {"status":0,"statusText":"NOERROR","headers":{},"body":""},
            "files": [],
            "dns": dns_records,
            "tls": None,
            "alerts": dns_alerts,
            "timeline": [{"type":"dns","time":int(time.time()*1000),"label":f"{r['query']}","detail":f"{r['type']} → {r['answer']}"} for r in dns_records[:10]],
        })

    return {"sessions": sessions_out}

# ─────────────────────────────────────────────
# FLASK ROUTES
# ─────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})

@app.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    allowed = {".pcap", ".pcapng", ".cap"}
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in allowed:
        return jsonify({"error": f"Unsupported format: {ext}. Use {', '.join(allowed)}"}), 400

    # Save to temp file (Scapy needs a real path)
    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        f.save(tmp.name)
        tmp_path = tmp.name

    try:
        result = analyze_pcap(tmp_path)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        os.unlink(tmp_path)

if __name__ == "__main__":
    print("NetForge backend running at http://localhost:5050")
    print("Upload endpoint: POST http://localhost:5050/analyze")
    app.run(host="127.0.0.1", port=5050, debug=False)
