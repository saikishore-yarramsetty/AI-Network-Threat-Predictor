# sniff_packets.py
from scapy.all import sniff, TCP, UDP, IP, DNS, DNSQR, Raw, get_if_list
import pandas as pd
import joblib
from datetime import datetime
import os
import psutil
import socket
import re
import ssl
import struct
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "traffic_log.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model", "model.pkl")

# Config
ENABLE_CERT_LOOKUP = True
CERT_TIMEOUT = 1.2
FILTER_PACKETS = "ip"  # Only capture IP packets to reduce idle waiting

os.makedirs(LOG_DIR, exist_ok=True)
if not os.path.exists(LOG_FILE) or os.stat(LOG_FILE).st_size == 0:
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("timestamp,src_ip,src_port,dst_ip,dst_port,packet_length,proc_name,owner,prediction,domain,url_path\n")

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model not found at: {MODEL_PATH}")
model = joblib.load(MODEL_PATH)
print(f"✅ Model loaded from: {MODEL_PATH}")

# Local IPs
def get_local_ips():
    local_ips = set()
    for iface_addrs in psutil.net_if_addrs().values():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET:
                local_ips.add(addr.address)
    return local_ips

LOCAL_IPS = get_local_ips()

# Process lookup
def get_process_name(src_ip, src_port, dst_ip, dst_port, proto):
    try:
        for conn in psutil.net_connections(kind='inet'):
            laddr = getattr(conn, 'laddr', None)
            raddr = getattr(conn, 'raddr', None)
            if not laddr: continue
            try:
                l_ip, l_port = (laddr.ip, laddr.port) if hasattr(laddr, 'ip') else (laddr[0], laddr[1])
            except: continue
            try:
                r_ip, r_port = (raddr.ip, raddr.port) if raddr and hasattr(raddr, 'ip') else (raddr[0], raddr[1]) if raddr else (None, None)
            except:
                r_ip, r_port = (None, None)
            if proto == 'tcp' and conn.type != socket.SOCK_STREAM: continue
            if proto == 'udp' and conn.type != socket.SOCK_DGRAM: continue
            if (l_ip == src_ip and l_port == src_port) or (l_ip == dst_ip and l_port == dst_port) or (l_port == src_port) or (l_port == dst_port):
                try:
                    if conn.pid:
                        return psutil.Process(conn.pid).name()
                except:
                    return "Unknown"
        return "Unknown"
    except:
        return "Unknown"

# DNS cache
dns_cache = {}

# Regex HTTP host/path
HTTP_HOST_REGEX = re.compile(br"Host:\s*([^\r\n]+)", re.IGNORECASE)
HTTP_REQUEST_LINE = re.compile(br"^(GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+([^\s]+)\s+HTTP/", re.IGNORECASE)

def get_http_host_and_path(packet):
    try:
        if not packet.haslayer(Raw): return None, None
        payload = bytes(packet[Raw].load)
        m = HTTP_REQUEST_LINE.search(payload)
        path = m.group(2).decode(errors="ignore") if m else None
        mh = HTTP_HOST_REGEX.search(payload)
        host = mh.group(1).decode(errors="ignore") if mh else None
        return host, path
    except:
        return None, None

# Reverse DNS and TLS cache
_reverse_dns_cache = {}
_cert_cache = {}

def reverse_dns_lookup(ip):
    if not ip: return None
    if ip in _reverse_dns_cache: return _reverse_dns_cache[ip]
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        _reverse_dns_cache[ip] = name
        return name
    except:
        _reverse_dns_cache[ip] = None
        return None

def get_cert_common_name(ip, port=443, timeout=CERT_TIMEOUT):
    key = f"{ip}:{port}"
    if key in _cert_cache: return _cert_cache[key]
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        ctx = ssl.create_default_context()
        ss = ctx.wrap_socket(sock, server_hostname=None)
        cert = ss.getpeercert()
        ss.close()
        san = cert.get("subjectAltName", ())
        for typ, name in san:
            if typ.lower() == "dns":
                _cert_cache[key] = name
                return name
        subject = cert.get("subject", ())
        for item in subject:
            for k, v in item:
                if k.lower() in ("commonname", "cn"):
                    _cert_cache[key] = v
                    return v
    except:
        pass
    _cert_cache[key] = None
    return None

# TLS SNI extraction
def extract_sni_from_tls(packet):
    if not packet.haslayer(Raw): return None
    payload = bytes(packet[Raw].load)
    try:
        if payload[0] != 22: return None
        offset = 5 + 1 + 3
        offset += 2 + 32
        session_id_len = payload[offset]; offset += 1 + session_id_len
        cs_len = struct.unpack(">H", payload[offset:offset+2])[0]; offset += 2 + cs_len
        cm_len = payload[offset]; offset += 1 + cm_len
        ext_len = struct.unpack(">H", payload[offset:offset+2])[0]; offset += 2
        end = offset + ext_len
        while offset + 4 <= end:
            ext_type, ext_size = struct.unpack(">HH", payload[offset:offset+4]); offset += 4
            if ext_type == 0:
                sni_len = struct.unpack(">H", payload[offset:offset+2])[0]; offset += 2
                sni_type = payload[offset]
                if sni_type == 0:
                    host_len = struct.unpack(">H", payload[offset+1:offset+3])[0]
                    host = payload[offset+3:offset+3+host_len].decode(errors="ignore")
                    return host
            offset += ext_size
    except:
        return None
    return None

# Extract features + domain
def extract_features(packet):
    try:
        src_ip = packet[IP].src if packet.haslayer(IP) else ""
        dst_ip = packet[IP].dst if packet.haslayer(IP) else ""
        sport = int(packet.sport) if hasattr(packet, 'sport') else 0
        dport = int(packet.dport) if hasattr(packet, 'dport') else 0
        proto = 'tcp' if packet.haslayer(TCP) else ('udp' if packet.haslayer(UDP) else 'other')
        features = {
            'packet_length': len(packet),
            'tcp_flags': int(packet[TCP].flags) if packet.haslayer(TCP) else 0,
            'src_port': sport,
            'dst_port': dport,
            'packet_rate': 10
        }
        proc_name = get_process_name(src_ip, sport, dst_ip, dport, proto)
        owner = "Local" if (src_ip in LOCAL_IPS or dst_ip in LOCAL_IPS) else "Other_Device"
        domain = None; url_path = None

        host, path = get_http_host_and_path(packet)
        if host: domain = host
        if path: url_path = path

        if not domain and proto == 'tcp' and dport in (443, 8443):
            sni = extract_sni_from_tls(packet)
            if sni: domain = sni
            elif ENABLE_CERT_LOOKUP:
                cname = get_cert_common_name(dst_ip, port=dport)
                if cname: domain = cname

        if not domain and dst_ip in dns_cache: domain = dns_cache[dst_ip]
        if not domain and dst_ip:
            rd = reverse_dns_lookup(dst_ip)
            if rd and not rd.endswith(".in-addr.arpa"): domain = rd
        if not domain: domain = "Unknown"
        if not url_path: url_path = ""

        return pd.DataFrame([features]), src_ip, dst_ip, proc_name, owner, domain, url_path
    except Exception as e:
        print("Error extracting features:", e)
        return None, None, None, "Unknown", "Unknown", "Unknown", ""

def process_dns(packet):
    try:
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            qname = packet[DNSQR].qname.decode().rstrip('.')
            dst_ip = packet[IP].dst
            dns_cache[dst_ip] = qname
    except:
        pass

def predict_packet(packet):
    process_dns(packet)
    data, src_ip, dst_ip, proc_name, owner, domain, url_path = extract_features(packet)
    if data is not None:
        try: prediction = model.predict(data)[0]
        except: prediction = "Unknown"
        ts = datetime.now().isoformat()
        print(f"[{ts}] {owner} | {proc_name} | {src_ip}:{data['src_port'][0]} -> {dst_ip}:{data['dst_port'][0]} → {prediction} | domain: {domain} path: {url_path}")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(",".join(map(str, [ts, src_ip, data['src_port'][0], dst_ip, data['dst_port'][0], data['packet_length'][0], proc_name, owner, prediction, domain, url_path])) + "\n")
            f.flush()

# Detect active interface automatically
def detect_active_interface():
    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET and addr.address not in ("127.0.0.1",):
                return iface_name
    return get_if_list()[0]

iface = detect_active_interface()
print(f"Using interface: {iface}")
print("🚀 Starting real-time packet capture... (Press Ctrl+C to stop)")

# Main sniff loop
while True:
    try:
        sniff(prn=predict_packet, store=False, iface=iface, filter=FILTER_PACKETS)
    except KeyboardInterrupt:
        print("\n🛑 Packet capture stopped by user.")
        break
    except Exception as e:
        print(f"⚠️ Error occurred: {e}. Restarting sniff in 2s...")
        time.sleep(2)
