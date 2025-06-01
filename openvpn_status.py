#!/usr/bin/python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import json
import time

PORT = 7506
MAX_RETRIES = 3 
RETRY_DELAY_SECONDS = 1 
OPENVPN_MGMT_HOST = '127.0.0.1'
OPENVPN_MGMT_PORT = 7505
OPENVPN_CONNECT_TIMEOUT_SECONDS = 3
OPENVPN_OPERATION_TIMEOUT_SECONDS = 5

class StatusHandler(BaseHTTPRequestHandler):
    def _log(self, message):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)

    def get_openvpn_status(self):
        for attempt in range(MAX_RETRIES):
            sock = None
            try:
                self._log(f"Attempt {attempt + 1}/{MAX_RETRIES}: Connecting to OpenVPN management at {OPENVPN_MGMT_HOST}:{OPENVPN_MGMT_PORT}...")
                sock = socket.create_connection((OPENVPN_MGMT_HOST, OPENVPN_MGMT_PORT), timeout=OPENVPN_CONNECT_TIMEOUT_SECONDS)
                sock.settimeout(OPENVPN_OPERATION_TIMEOUT_SECONDS)
                self._log(f"Attempt {attempt + 1}: Connected. Receiving initial greeting...")

               
              
                initial_greeting = b""
                try:
                    while not initial_greeting.endswith(b"\n"):
                        chunk = sock.recv(1024)
                        if not chunk: 
                            self._log(f"Attempt {attempt + 1}: Connection closed while receiving greeting.")
                            raise socket.error("Connection closed prematurely during greeting")
                        initial_greeting += chunk
                    self._log(f"Attempt {attempt + 1}: Initial greeting received (len {len(initial_greeting)}).")
                except socket.timeout:
                    self._log(f"Attempt {attempt + 1}: Timeout receiving initial greeting. This might be okay if no greeting is sent.")
                    
                except Exception as e_greet:
                    self._log(f"Attempt {attempt + 1}: Error during greeting: {e_greet}")
                    

                self._log(f"Attempt {attempt + 1}: Sending 'status' command...")
                sock.sendall(b"status\n")
                
                data = b""
                self._log(f"Attempt {attempt + 1}: Receiving status data...")
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        self._log(f"Attempt {attempt + 1}: Connection closed by server after sending status. Data len: {len(data)}")
                        break 
                    data += chunk
                   
                    if data.strip().endswith(b"END"):
                        self._log(f"Attempt {attempt + 1}: END marker found. Total data length: {len(data)}.")
                        break
                
                sock.close()
                self._log(f"Attempt {attempt + 1}: Successfully fetched status data.")
                return data.decode('utf-8', errors='ignore')

            except (socket.timeout, ConnectionRefusedError, socket.error) as e_conn:
                self._log(f"Attempt {attempt + 1}/{MAX_RETRIES} FAILED: {type(e_conn).__name__} - {str(e_conn)}")
                if sock:
                    sock.close()
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY_SECONDS)
                else:
                    self._log(f"All {MAX_RETRIES} retries failed.")
            except Exception as e_general:
                self._log(f"An unexpected error occurred in get_openvpn_status (attempt {attempt+1}): {str(e_general)}")
                if sock:
                    sock.close()
                
                break 
        
        self._log("Returning empty string from get_openvpn_status after all attempts or critical error.")
        return ""

    def do_GET(self):
        try:
            self._log(f"GET request received from {self.client_address[0]}")
            data = self.get_openvpn_status()
            users = {}
            if data:
               
                lines = data.split("\n")
                client_list_started = False
                for line in lines:
                    if line.startswith("CLIENT_LIST"):
                        client_list_started = True
                        parts = line.split(",")
                        if len(parts) >= 7:
                            username = parts[1].strip()
                            if username: 
                                users.setdefault(username, {
                                    "active": 0,
                                    "bytes_received": 0,
                                    "bytes_sent": 0
                                })
                                users[username]["active"] += 1
                                try:
                                    users[username]["bytes_received"] += int(parts[5])
                                    users[username]["bytes_sent"] += int(parts[6])
                                except ValueError:
                                    self._log(f"Warning: Could not parse byte counts for user {username}. Parts: {parts}")
                        
                       
                    elif line.startswith("ROUTING_TABLE"):
                        client_list_started = False 
                        break 
                    elif line.startswith("GLOBAL_STATS"):
                        client_list_started = False
                        break
                    elif line.strip() == "END":
                        client_list_started = False
                        break
            
           
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(users).encode('utf-8'))
        except Exception as e:
            self._log(f"Error in do_GET: {str(e)}")
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Internal server error", "detail": str(e)}).encode('utf-8'))

def run_server():
    try:
        server = HTTPServer((('0.0.0.0', PORT)), StatusHandler)
        print(f"OpenVPN Status Server running on http://0.0.0.0:{PORT}", flush=True)
        server.serve_forever()
    except OSError as e:
         print(f"FATAL: Could not bind to port {PORT}. Is another instance running? Error: {e}", flush=True)
    except KeyboardInterrupt:
        print("\nShutting down OpenVPN Status Server...", flush=True)
        if 'server' in locals() and server:
            server.server_close()
    except Exception as e_run:
        print(f"FATAL: An unexpected error occurred while running the server: {e_run}", flush=True)


if __name__ == "__main__":
    run_server()