# NetSentinel — Secure Web Fingerprint Scanner

A TLS-encrypted, multi-threaded network port scanner with HTTP fingerprinting, RTT measurement, and concurrent client support. Clients authenticate over a secure SSL connection and remotely trigger scans against any target host. Results include open ports, service names, per-port round-trip times, average latency, scan throughput, HTTP status, and web server identification.

> **Disclaimer:** This tool is intended for authorized network analysis only. Always obtain explicit permission before scanning any host or network you do not own.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Setup](#setup)
- [Usage](#usage)
- [Sample Output](#sample-output)
- [Port Reference](#port-reference)
- [HTTP Server Detection](#http-server-detection)
- [Security Notes](#security-notes)


---

## Overview

NetSentinel is built around three core modules:

- **`scanner.py`** — Scan engine. Performs multi-threaded TCP port scanning across 80+ ports, measures per-port RTT, calculates average latency and throughput, and performs HTTP banner grabbing for server fingerprinting.
- **`server.py`** — TLS server. Accepts encrypted client connections, authenticates users, dispatches scan jobs, and tracks active client count in real time.
- **`client.py`** — TLS client. Connects to the server over SSL, authenticates, submits a target host, and streams the full scan result.

All modules use the Python standard library exclusively — no third-party packages are required.

---

## Architecture

```
CLIENT                                         SERVER
------                                         ------
client.py
  |
  |-- TLS Handshake ------------------------------> server.py
  |  <-------------- Auth Prompt ------------------|
  |-- Credentials --------------------------------->|
  |  <-------------- Auth OK ----------------------|
  |-- Target Host --------------------------------->|
  |                                                 |-- scanner.py
  |                                                 |     |-- Thread per port (80+ ports)
  |                                                 |     |-- TCP connect + RTT measurement
  |                                                 |     |-- Latency + throughput calculation
  |                                                 |     |-- HTTP banner grab (port 80)
  |                                                 |     |-- Server fingerprint detection
  |  <-------------- Scan Results + Active Clients -|
```

All client-server traffic is encrypted via TLS. The server executes the scan and streams results back once complete.

---

## Project Structure

```
netsentinel/
├── server.py          # TLS server — auth, client tracking, scan dispatch
├── client.py          # TLS client — connection, auth, result display
├── scanner.py         # Scan engine — port scanning, RTT, fingerprinting
├── cert.pem           # Server TLS certificate
├── key.pem            # Server private key
├── ca.pem             # Certificate Authority certificate
├── ca.key             # CA private key
├── ca.srl             # CA serial number file
├── client.crt         # Client certificate
├── client.csr         # Client certificate signing request
└── client.key         # Client private key
```

---

## Requirements

- Python 3.7 or higher
- OpenSSL (for certificate generation)
- No third-party packages — uses Python standard library only

Modules used: `socket`, `ssl`, `threading`, `time`

---

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/netsentinel.git
cd netsentinel
```

### 2. Generate TLS Certificates

Skip this step if certificate files are already present.

```bash
# Generate the Certificate Authority
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.pem -subj "/CN=NetSentinel-CA"

# Generate the server certificate signed by the CA
openssl genrsa -out key.pem 2048
openssl req -new -key key.pem -out cert.csr -subj "/CN=NetSentinel-Server"
openssl x509 -req -days 365 -in cert.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out cert.pem

# (Optional) Generate a client certificate
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=NetSentinel-Client"
openssl x509 -req -days 365 -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.crt
```

### 3. Configure the Server

Edit `server.py` to set the bind address and credentials:

```python
HOST = "127.0.0.1"   # Use 0.0.0.0 to accept on all interfaces
PORT = 8000

USERS = {
    "alice": "securepassword123",
    "admin": "adminpass456",
}
```

### 4. Configure the Client

Edit `client.py` to point to your server:

```python
HOST = "192.168.1.100"   # Replace with your server's IP
PORT = 8000
```

---

## Usage

### Start the Server

```bash
python server.py
```

```
[*] Secure Web Fingerprint Server running on 127.0.0.1:8000
[*] Waiting for connections ...
```

### Connect with the Client

```bash
python client.py
```

```
Username: alice
Password:
Authentication successful.
Enter website/IP to scan: scanme.nmap.org

Scanning ... please wait.
```

---

## Sample Output

```
==================================================
           SCAN RESULTS
==================================================
Target     : scanme.nmap.org
IP Address : 45.33.32.156
Scan Time  : 2025-06-01 14:32:10
---------------------------------------------
Port 22 -> OPEN (SSH) | RTT: 183.42 ms
Port 80 -> OPEN (HTTP) | RTT: 181.67 ms
---------------------------------------------
Average Latency : 3.84 ms
Throughput      : 14.22 ports/sec
HTTP Status  : 200
Server Banner: Apache/2.4.7
Server Type  : Apache

Active Clients: 1

Scan completed in 5.62 seconds.
==================================================
```

---

## Port Reference

The scanner checks 80+ ports across all major service categories.

**Web & Proxy**

| Port  | Service    | Port  | Service    |
|-------|------------|-------|------------|
| 80    | HTTP       | 8080  | HTTP-Proxy |
| 443   | HTTPS      | 8443  | HTTPS-Alt  |
| 8000  | HTTP-Alt   | 8888  | Jupyter    |

**Databases**

| Port  | Service    | Port  | Service    |
|-------|------------|-------|------------|
| 3306  | MySQL      | 5432  | PostgreSQL |
| 27017 | MongoDB    | 6379  | Redis      |
| 1433  | MSSQL      | 9042  | Cassandra  |
| 1521  | Oracle DB  | 11211 | Memcached  |

**Remote Access & VPN**

| Port  | Service  | Port  | Service  |
|-------|----------|-------|----------|
| 22    | SSH      | 3389  | RDP      |
| 23    | Telnet   | 5900  | VNC      |
| 1194  | OpenVPN  | 1723  | PPTP     |

**Infrastructure & DevOps**

| Port  | Service            | Port  | Service        |
|-------|--------------------|-------|----------------|
| 2375  | Docker             | 6443  | Kubernetes API |
| 9200  | Elasticsearch      | 9092  | Kafka          |
| 2181  | Zookeeper          | 5601  | Kibana         |
| 9090  | Prometheus         | 50070 | Hadoop HDFS    |

See `scanner.py` for the complete port list.

---

## HTTP Server Detection

The scanner sends a `HEAD /` request to port 80 and inspects the `Server` response header. Detected servers:

Nginx, Apache, Microsoft IIS, Cloudflare, Google Web Server, Lighttpd, Caddy, OpenResty, Gunicorn, Tornado, Jetty, Apache Tomcat, Werkzeug/Flask, Express.js, FastAPI, Amazon/AWS, Microsoft (hostname-based)

If the header is absent or unrecognized, the type is reported as `Unknown`.

---

## Security Notes

| Concern | Current Behavior | Recommended for Production |
|---|---|---|
| Certificate verification | Disabled on client (`CERT_NONE`) | Enable with trusted CA cert and `CERT_REQUIRED` |
| Credential storage | Plaintext dictionary in `server.py` | Hashed passwords (`bcrypt`) via environment variables |
| Access control | Single-factor username/password | Add IP allowlisting, rate limiting, or MFA |
| rtt_list thread safety | Relies on CPython GIL for list.append() | Add explicit lock for portability |
| Logging | stdout only | Structured logging with audit trail |

---

