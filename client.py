import socket
import ssl

HOST = "10.1.3.151"
PORT = 8000

# ──────────────────────────────────────────────
#  SSL context  (self-signed cert — local test)
# ──────────────────────────────────────────────
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode    = ssl.CERT_NONE

# ──────────────────────────────────────────────
#  Connect
# ──────────────────────────────────────────────
try:
    raw_sock    = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure_sock = context.wrap_socket(raw_sock, server_hostname=HOST)
    secure_sock.connect((HOST, PORT))

except ssl.SSLError as e:
    print(f"SSL error: {e}")
    exit(1)

except ConnectionRefusedError:
    print(f"Connection refused. Is the server running on {HOST}:{PORT}?")
    exit(1)

except Exception as e:
    print(f"Connection error: {e}")
    exit(1)

# ──────────────────────────────────────────────
#  Authentication
# ──────────────────────────────────────────────
try:
    # Username
    prompt = secure_sock.recv(1024).decode()
    print(prompt, end="")
    secure_sock.send(input().encode())

    # Password
    prompt = secure_sock.recv(1024).decode()
    print(prompt, end="")
    secure_sock.send(input().encode())

    # Auth result
    result = secure_sock.recv(1024).decode()
    print(result.strip())

    if "failed" in result.lower():
        secure_sock.close()
        exit(1)

    # ── Target host ─────────────────────────
    prompt = secure_sock.recv(1024).decode()
    print(prompt, end="")
    secure_sock.send(input().encode())

    # ── Receive full scan result ─────────────
    #    Loop until server closes connection
    print("\nScanning ... please wait.\n")
    data = b""
    while True:
        chunk = secure_sock.recv(4096)
        if not chunk:
            break
        data += chunk

    print("=" * 50)
    print("           SCAN RESULTS")
    print("=" * 50)
    print(data.decode(errors="ignore"))
    print("=" * 50)

except ConnectionResetError:
    print("Server closed the connection unexpectedly.")

except ssl.SSLError as e:
    print(f"SSL error during communication: {e}")

except Exception as e:
    print(f"Error: {e}")

finally:
    secure_sock.close()