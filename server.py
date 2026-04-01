import socket
import ssl
import threading
import time
from scanner import scan_server

HOST = "127.0.0.1"
PORT = 8000

# ──────────────────────────────────────────────
#  Simple user store  (extend as needed)
# ──────────────────────────────────────────────
USERS = {
    "pesu": "pesu1234",\
    "admin": "admin123",
}
client_count = 0   # 🔹 ADDED
lock = threading.Lock()   # 🔹 ADDED

# ──────────────────────────────────────────────
#  Handle one client connection
# ──────────────────────────────────────────────
def handle_client(conn, addr):
    
    global client_count   # 🔹 ADDED

    with lock:   # 🔹 ADDED
        client_count += 1
        print(f"[+] Client connected: {addr} | Total clients: {client_count}")

    try:
        # ── Authentication ──────────────────────
        conn.send(b"Username: ")
        username = conn.recv(1024).decode(errors="ignore").strip()

        conn.send(b"Password: ")
        password = conn.recv(1024).decode(errors="ignore").strip()

        if USERS.get(username) != password:
            conn.send(b"Authentication failed.\n")
            print(f"[-] Auth failed for '{username}' from {addr}")
            return

        conn.send(b"Authentication successful.\n")
        print(f"[+] Auth OK: '{username}' from {addr}")

        # ── Get target host ─────────────────────
        conn.send(b"Enter website/IP to scan: ")
        host = conn.recv(1024).decode(errors="ignore").strip()

        # Basic input validation
        if not host or len(host) > 253:
            conn.send(b"Error: Invalid hostname.\n")
            return

        print(f"[*] Scanning '{host}' for {addr} ...")
        start = time.time()

        result  = scan_server(host)
        result += f"\n\nActive Clients: {client_count}"   # 🔹 ADDED
        elapsed = time.time() - start

        result += f"\n\nScan completed in {elapsed:.2f} seconds."

        # ── Send result in chunks ───────────────
        data = result.encode()
        conn.sendall(data)

    except ConnectionResetError:
        print(f"[!] Client {addr} disconnected abruptly.")

    except ssl.SSLError as e:
        print(f"[!] SSL error with {addr}: {e}")

    except Exception as e:
        try:
            conn.send(f"Server error: {e}\n".encode())
        except Exception:
            pass
        print(f"[!] Error handling {addr}: {e}")

    finally:
        conn.close()
        print(f"[-] Client disconnected: {addr}")
        with lock:   # 🔹 ADDED
            client_count -= 1


# ──────────────────────────────────────────────
#  SSL setup
# ──────────────────────────────────────────────
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

# ──────────────────────────────────────────────
#  Start server
# ──────────────────────────────────────────────
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # reuse port quickly
server.bind((HOST, PORT))
server.listen(10)

secure_server = context.wrap_socket(server, server_side=True)

print(f"[*] Secure Web Fingerprint Server running on {HOST}:{PORT}")
print(f"[*] Waiting for connections ...\n")

while True:
    try:
        conn, addr = secure_server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()

    except ssl.SSLError as e:
        print(f"[!] SSL handshake failed: {e}")

    except KeyboardInterrupt:
        print("\n[*] Server shutting down.")
        secure_server.close()
        break
