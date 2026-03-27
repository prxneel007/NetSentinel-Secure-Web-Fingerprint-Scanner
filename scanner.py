import socket
import threading
import time

# ──────────────────────────────────────────────
#  All well-known + registered port numbers
# ──────────────────────────────────────────────
SERVICES = {
    20:   "FTP-Data",
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP-Server",
    68:   "DHCP-Client",
    69:   "TFTP",
    80:   "HTTP",
    88:   "Kerberos",
    110:  "POP3",
    119:  "NNTP",
    123:  "NTP",
    135:  "MS-RPC",
    137:  "NetBIOS-NS",
    138:  "NetBIOS-DGM",
    139:  "NetBIOS-SSN",
    143:  "IMAP",
    161:  "SNMP",
    162:  "SNMP-Trap",
    179:  "BGP",
    194:  "IRC",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    500:  "IKE/IPSec",
    514:  "Syslog",
    515:  "LPD-Print",
    520:  "RIP",
    587:  "SMTP-Submission",
    631:  "IPP-Print",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1080: "SOCKS-Proxy",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle-DB",
    1723: "PPTP-VPN",
    2049: "NFS",
    2181: "Zookeeper",
    2375: "Docker",
    2376: "Docker-TLS",
    3000: "Dev-Server",
    3306: "MySQL",
    3389: "RDP",
    4369: "RabbitMQ",
    5000: "Flask/UPnP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5672: "RabbitMQ-AMQP",
    5900: "VNC",
    6379: "Redis",
    6443: "Kubernetes-API",
    7001: "WebLogic",
    7077: "Spark",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8088: "Hadoop",
    8443: "HTTPS-Alt",
    8888: "Jupyter",
    9000: "PHP-FPM/SonarQube",
    9042: "Cassandra",
    9090: "Prometheus",
    9092: "Kafka",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Cluster",
    10250:"Kubernetes-Kubelet",
    11211:"Memcached",
    15672:"RabbitMQ-Mgmt",
    27017:"MongoDB",
    27018:"MongoDB-Shard",
    50070:"Hadoop-HDFS",
}

PORTS = list(SERVICES.keys())

lock = threading.Lock()


# ──────────────────────────────────────────────
#  Detect server type from banner / host
# ──────────────────────────────────────────────
def detect_server(banner, host):
    banner = banner.lower()
    host   = host.lower()

    if "nginx"      in banner: return "Nginx"
    if "apache"     in banner: return "Apache"
    if "iis"        in banner: return "Microsoft IIS"
    if "cloudflare" in banner: return "Cloudflare"
    if "gws"        in banner: return "Google Web Server"
    if "lighttpd"   in banner: return "Lighttpd"
    if "caddy"      in banner: return "Caddy"
    if "openresty"  in banner: return "OpenResty (Nginx)"
    if "gunicorn"   in banner: return "Gunicorn (Python)"
    if "tornado"    in banner: return "Tornado (Python)"
    if "jetty"      in banner: return "Jetty (Java)"
    if "tomcat"     in banner: return "Apache Tomcat"
    if "werkzeug"   in banner: return "Werkzeug / Flask"
    if "express"    in banner: return "Express.js (Node)"
    if "fastapi"    in banner: return "FastAPI (Python)"
    if "google"     in host:   return "Google Web Server"
    if "amazon"     in host or "aws" in host: return "Amazon / AWS"
    if "microsoft"  in host:   return "Microsoft"
    return "Unknown"


# ──────────────────────────────────────────────
#  Scan a single port  (thread worker)
# ──────────────────────────────────────────────
def scan_port(host, port, open_ports):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        if result == 0:
            service = SERVICES.get(port, "Unknown")
            with lock:
                open_ports.append(f"Port {port:>5}  →  OPEN   ({service})")
        sock.close()
    except Exception:
        pass


# ──────────────────────────────────────────────
#  HTTP banner grab
# ──────────────────────────────────────────────
def grab_http_banner(host):
    status_code = "N/A"
    banner      = "hidden"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, 80))
        request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        sock.send(request.encode())
        response = sock.recv(4096).decode(errors="ignore")
        sock.close()

        lines = response.split("\r\n")
        if lines and "HTTP" in lines[0]:
            parts = lines[0].split(" ")
            if len(parts) >= 2:
                status_code = parts[1]

        for line in lines:
            if line.lower().startswith("server:"):
                banner = line.split(":", 1)[1].strip()
                break
    except Exception:
        pass
    return status_code, banner


# ──────────────────────────────────────────────
#  Main scan function  (called by server.py)
# ──────────────────────────────────────────────
def scan_server(host):

    # Validate / resolve hostname
    host = host.strip()
    if not host:
        return "Error: No hostname provided."

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return f"Error: Could not resolve hostname '{host}'."

    output     = []
    open_ports = []          # local list — thread-safe via lock

    output.append(f"Target     : {host}")
    output.append(f"IP Address : {ip}")
    output.append(f"Scan Time  : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    output.append("-" * 45)

    # Launch one thread per port
    threads = []
    for port in PORTS:
        t = threading.Thread(target=scan_port, args=(host, port, open_ports))
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=5)        # safety timeout per thread

    # Sort results by port number
    open_ports.sort(key=lambda x: int(x.split()[1]))

    if open_ports:
        output.extend(open_ports)
    else:
        output.append("No open ports found.")

    output.append("-" * 45)

    # HTTP fingerprint
    status_code, banner = grab_http_banner(host)
    detected = detect_server(banner, host)

    output.append(f"HTTP Status  : {status_code}")
    output.append(f"Server Banner: {banner}")
    output.append(f"Server Type  : {detected}")

    return "\n".join(output)