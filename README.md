# NetSentinel — Secure Web Fingerprint Scanner

A TLS-encrypted, multi-threaded network port scanner with HTTP fingerprinting, built on a remote client-server architecture. Clients authenticate over a secure SSL connection and remotely trigger scans against any target host. Results include open ports, service names, HTTP status codes, and web server identification.



---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Setup](#setup)
- [Usage](#usage)
- [Port Reference](#port-reference)
- [HTTP Server Detection](#http-server-detection)
- [Security Notes](#security-notes)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

NetSentinel is built around three core modules:

- **`server.py`** — Listens for incoming TLS connections, handles authentication, and dispatches scan jobs.
- **`client.py`** — Connects to the server over TLS, authenticates, submits a target host, and displays the scan output.
- **`scanner.py`** — Performs multi-threaded port scanning across 80+ well-known ports and grabs HTTP banners for server fingerprinting.

---

## Architecture

```
CLIENT                                         SERVER
------                                         ------
client.py
  │
  ├── TLS Handshake ─────────────────────────► server.py
  │ ◄─────────────── Auth Prompt ─────────────────┤
  ├── Credentials ──────────────────────────────► │
  │ ◄─────────────── Auth OK ──────────────────── │
  ├── Target Host ──────────────────────────────► │
  │                                               ├── scanner.py
  │                                               │     ├── Thread per port (80+ ports)
  │                                               │     ├── TCP connect scan
  │                                               │     ├── HTTP banner grab
  │                                               │     └── Server fingerprint
  │ ◄─────────────── Scan Results ────────────────┤
```

All traffic between client and server is encrypted via TLS. The server performs the scan and streams results back to the client.

---

## Project Structure

```
netsentinel/
├── server.py          # TLS server — authentication and scan dispatch
├── client.py          # TLS client — connection, auth, and result display
├── scanner.py         # Scan engine — port scanning and HTTP fingerprinting
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
- No third-party packages — uses Python standard library only (`socket`, `ssl`, `threading`)

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

Edit `server.py` to set the bind address and user credentials:

```python
HOST = "127.0.0.1"   # Use 0.0.0.0 to accept connections on all interfaces
PORT = 8000

USERS = {
    "alice": "securepassword123",
    "admin": "adminpass456",
}
```

### 4. Configure the Client

Edit `client.py` to point to your server's IP address:

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

The client will prompt for credentials and a target host:

```
Username: alice
Password:
Authentication successful.
Enter website/IP to scan: scanme.nmap.org

Scanning ... please wait.
```

### Sample Output

```
==================================================
           SCAN RESULTS
==================================================
Target     : scanme.nmap.org
IP Address : 45.33.32.156
Scan Time  : 2025-06-01 14:32:10
---------------------------------------------
Port    22  ->  OPEN   (SSH)
Port    80  ->  OPEN   (HTTP)
---------------------------------------------
HTTP Status  : 200
Server Banner: Apache/2.4.7
Server Type  : Apache

Scan completed in 4.87 seconds.
==================================================
```



## HTTP Server Detection

The scanner sends a `HEAD /` HTTP request to port 80 and inspects the `Server` response header. The following servers are currently detected:

- Nginx
- Apache
- Microsoft IIS
- Cloudflare
- Google Web Server (GWS)
- Lighttpd
- Caddy
- OpenResty
- Gunicorn
- Tornado
- Jetty
- Apache Tomcat
- Werkzeug / Flask
- Express.js
- FastAPI

If the server header is absent or unrecognized, the type is reported as `Unknown`.

---

## Security Notes

This project is designed for learning and lab environments. Before deploying in any real network:

| Concern | Current Behavior | Recommended Action |
|---|---|---|
| Certificate verification | Disabled on client (`CERT_NONE`) | Enable and supply a trusted CA cert |
| Credential storage | Plaintext dictionary in `server.py` | Use hashed passwords (`bcrypt`) stored in env variables or a secrets manager |
| Access control | Single-factor username/password | Add IP allowlisting, rate limiting, or multi-factor authentication |
| Logging | Printed to stdout only | Implement structured logging with an audit trail |

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add your feature"`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

Please open an issue before starting significant changes.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
