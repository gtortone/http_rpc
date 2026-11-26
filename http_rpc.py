#!/usr/bin/env python3
"""
HTTP front-end for gpio_daemon.py (talks to /run/gpio.sock, never to the GPIOs).
Stdlib only. HTTP Basic authentication (user/password).

API (JSON replies; actions accept POST or GET):
  GET  /status                       outputs, enable, adc_mode, voltages
  GET  /output/<NAME|n>              state of one output (n = 1-based index)
  POST /output/<NAME|n>/on|off|toggle
  POST /all/on|off
  GET  /analog/<NAME>                one analog reading
  POST /reload                       re-read gpio_config.json

Users (PBKDF2-SHA256 hashes in USERS_FILE, mode 600):
  http_rpc.py --set-user <name>      create / change password
  http_rpc.py --del-user <name>
Restart S70http_rpc after changing users.
"""

import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_ADDR = os.environ.get("HTTP_RPC_ADDR", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("HTTP_RPC_PORT", "8080"))
SOCKET_PATH = "/run/gpio.sock"
CONFIG_FILE = "/etc/rpc/gpio_config.json"
USERS_FILE  = os.environ.get("HTTP_RPC_USERS", "/etc/rpc/http_users")
PBKDF2_ITER = 50000          # slow on RV1106; successful logins are cached in RAM

# The daemon serves one connection at a time (listen(1)): serialise requests.
_sock_lock = threading.Lock()

USERS = {}                   # user -> (salt, iterations, hash)
_auth_cache = set()


# -------------------------
# Password hashing
# -------------------------
def _pbkdf2(password, salt, it):
    try:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, it)
    except (AttributeError, ValueError):
        # Pure-Python fallback (Python >= 3.12 without OpenSSL lacks pbkdf2_hmac)
        key = password.encode()
        u = hmac.new(key, salt + b"\x00\x00\x00\x01", "sha256").digest()
        out = int.from_bytes(u, "big")
        for _ in range(it - 1):
            u = hmac.new(key, u, "sha256").digest()
            out ^= int.from_bytes(u, "big")
        return out.to_bytes(32, "big")


def load_users():
    users = {}
    try:
        with open(USERS_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    u, salt, it, h = line.split(":")
                    users[u] = (bytes.fromhex(salt), int(it), bytes.fromhex(h))
    except FileNotFoundError:
        pass
    return users


def save_users(users):
    tmp = USERS_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        for u, (salt, it, h) in users.items():
            f.write(f"{u}:{salt.hex()}:{it}:{h.hex()}\n")
    os.replace(tmp, USERS_FILE)


def check_auth(header):
    if not header.startswith("Basic "):
        return False
    key = hashlib.sha256(header.encode()).digest()
    if key in _auth_cache:
        return True
    try:
        user, _, pwd = base64.b64decode(header[6:]).decode().partition(":")
    except ValueError:
        return False
    rec = USERS.get(user)
    if rec is None:
        _pbkdf2(pwd, b"0123456789abcdef", PBKDF2_ITER)   # same timing as a real user
        return False
    salt, it, h = rec
    if hmac.compare_digest(_pbkdf2(pwd, salt, it), h):
        _auth_cache.add(key)
        return True
    return False


# -------------------------
# Daemon access
# -------------------------
class DaemonError(Exception):
    pass


def send_cmd(cmd):
    with _sock_lock:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(SOCKET_PATH)
            s.sendall(cmd.encode())
            chunks = []
            while True:                      # daemon closes after replying
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
            s.close()
        except OSError as e:
            raise DaemonError(f"gpio daemon unreachable: {e}")
    return b"".join(chunks).decode()


def output_names():
    """Active outputs in config order (same num_outputs rule as the daemon)."""
    with open(CONFIG_FILE) as f:
        raw = json.load(f)
    names = list(raw.get("outputs", {}))
    n = raw.get("num_outputs")
    return names[:n] if isinstance(n, int) and n >= 0 else names


def resolve_output(ref):
    names = output_names()
    if ref.isdigit() and 1 <= int(ref) <= len(names):
        return names[int(ref) - 1]
    return ref if ref in names else None


def reply_to_obj(resp):
    """Daemon reply -> (http_code, obj)."""
    if resp.startswith("OK"):
        return 200, {"result": resp}
    if resp.startswith("ERR"):
        code = 404 if "Unknown" in resp else 503 if "unavailable" in resp else 400
        return code, {"error": resp[4:]}
    try:
        return 200, json.loads(resp)
    except ValueError:
        return 502, {"error": f"unexpected daemon reply: {resp!r}"}


def output_state(name):
    code, obj = reply_to_obj(send_cmd(f"read {name}"))
    if code != 200:
        return code, obj
    return 200, {name: "on" if obj.get("value") else "off"}


# -------------------------
# HTTP
# -------------------------
R_OUTPUT = re.compile(r"^/output/([^/]+)(?:/(on|off|toggle))?/?$")
R_ALL    = re.compile(r"^/all/(on|off)/?$")
R_ANALOG = re.compile(r"^/analog/([^/]+)/?$")


class Handler(BaseHTTPRequestHandler):
    server_version = "rpc-http/1.0"

    def _send(self, code, obj, extra=None):
        body = (json.dumps(obj) + "\n").encode()
        self.send_response(code)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _route(self, path):
        if path in ("/", "/status"):
            return reply_to_obj(send_cmd("status"))

        if path == "/reload":
            return reply_to_obj(send_cmd("reload"))

        m = R_ALL.match(path)
        if m:
            code, obj = reply_to_obj(send_cmd(f"all {1 if m.group(1) == 'on' else 0}"))
            return (reply_to_obj(send_cmd("status")) if code == 200 else (code, obj))

        m = R_OUTPUT.match(path)
        if m:
            name = resolve_output(m.group(1))
            if name is None:
                return 404, {"error": f"unknown output '{m.group(1)}'"}
            action = m.group(2)
            if action:
                if action == "toggle":
                    code, obj = output_state(name)
                    if code != 200:
                        return code, obj
                    val = 0 if obj[name] == "on" else 1
                else:
                    val = 1 if action == "on" else 0
                code, obj = reply_to_obj(send_cmd(f"{name} {val}"))
                if code != 200:
                    return code, obj
            return output_state(name)

        m = R_ANALOG.match(path)
        if m:
            code, obj = reply_to_obj(send_cmd(f"read {m.group(1)}"))
            if code == 200 and obj.get("type") != "analog":
                return 404, {"error": f"'{m.group(1)}' is not an analog"}
            return code, ({obj["name"]: obj["value"]} if code == 200 else obj)

        return 404, {"error": "not found"}

    def _handle(self):
        if not check_auth(self.headers.get("Authorization", "")):
            return self._send(401, {"error": "unauthorized"},
                              {"WWW-Authenticate": 'Basic realm="RPC", charset="UTF-8"'})
        try:
            code, obj = self._route(self.path.split("?", 1)[0])
        except DaemonError as e:
            code, obj = 503, {"error": str(e)}
        except (OSError, ValueError) as e:
            code, obj = 500, {"error": str(e)}
        self._send(code, obj)

    do_GET = do_POST = _handle

    def log_message(self, fmt, *args):
        print(f"{self.client_address[0]} {fmt % args}", flush=True)


# -------------------------
# Main
# -------------------------
def manage_users(cmd, user):
    if ":" in user or not user:
        sys.exit("invalid user name")
    users = load_users()
    if cmd == "--set-user":
        pwd = getpass.getpass(f"password for {user}: ")
        if not pwd or pwd != getpass.getpass("repeat: "):
            sys.exit("empty or mismatching password")
        salt = secrets.token_bytes(16)
        users[user] = (salt, PBKDF2_ITER, _pbkdf2(pwd, salt, PBKDF2_ITER))
    elif cmd == "--del-user":
        users.pop(user, None)
    else:
        sys.exit(f"unknown command {cmd}")
    save_users(users)
    print(f"OK users: {', '.join(users) or 'none'} (restart S70http_rpc)")


def main():
    global USERS
    if len(sys.argv) == 3:
        return manage_users(sys.argv[1], sys.argv[2])
    USERS = load_users()
    if not USERS:
        sys.exit(f"no users in {USERS_FILE}: run '{sys.argv[0]} --set-user <name>'")
    print(f"HTTP RPC on {LISTEN_ADDR}:{LISTEN_PORT}, users: {', '.join(USERS)}", flush=True)
    ThreadingHTTPServer((LISTEN_ADDR, LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
