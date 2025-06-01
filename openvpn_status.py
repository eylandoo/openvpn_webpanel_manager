#!/usr/bin/python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import json
import time

PORT = 7506
MAX_RETRIES = 3 # تعداد تلاش برای اتصال به 7505
RETRY_DELAY_SECONDS = 1 # تاخیر بین هر تلاش
OPENVPN_MGMT_HOST = '127.0.0.1' # استفاده از 127.0.0.1 به جای localhost برای قطعیت
OPENVPN_MGMT_PORT = 7505
OPENVPN_CONNECT_TIMEOUT_SECONDS = 3 # زمان انتظار برای برقراری اتصال اولیه
OPENVPN_OPERATION_TIMEOUT_SECONDS = 5 # زمان انتظار برای خواندن/نوشتن روی سوکت پس از اتصال

class StatusHandler(BaseHTTPRequestHandler):
    def _log(self, message):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)

    def get_openvpn_status(self):
        for attempt in range(MAX_RETRIES):
            sock = None
            try:
                self._log(f"Attempt {attempt + 1}/{MAX_RETRIES}: Connecting to OpenVPN management at {OPENVPN_MGMT_HOST}:{OPENVPN_MGMT_PORT}...")
                sock = socket.create_connection((OPENVPN_MGMT_HOST, OPENVPN_MGMT_PORT), timeout=OPENVPN_CONNECT_TIMEOUT_SECONDS)
                sock.settimeout(OPENVPN_OPERATION_TIMEOUT_SECONDS) # تایم اوت برای خواندن/نوشتن
                self._log(f"Attempt {attempt + 1}: Connected. Receiving initial greeting...")

                # خواندن و دور ریختن پیام خوشامدگویی اولیه
                # رابط مدیریت معمولا با ">INFO:" یا مشابه شروع می‌شود و با خط جدید تمام می‌شود.
                initial_greeting = b""
                try:
                    while not initial_greeting.endswith(b"\n"):
                        chunk = sock.recv(1024)
                        if not chunk: # اگر اتصال قبل از دریافت کامل خوشامدگویی بسته شود
                            self._log(f"Attempt {attempt + 1}: Connection closed while receiving greeting.")
                            raise socket.error("Connection closed prematurely during greeting")
                        initial_greeting += chunk
                    self._log(f"Attempt {attempt + 1}: Initial greeting received (len {len(initial_greeting)}).")
                except socket.timeout:
                    self._log(f"Attempt {attempt + 1}: Timeout receiving initial greeting. This might be okay if no greeting is sent.")
                    # ادامه می‌دهیم چون برخی تنظیمات OpenVPN ممکن است خوشامدگویی نداشته باشند
                except Exception as e_greet:
                    self._log(f"Attempt {attempt + 1}: Error during greeting: {e_greet}")
                    # ادامه می‌دهیم، شاید بتوانیم status را بگیریم

                self._log(f"Attempt {attempt + 1}: Sending 'status' command...")
                sock.sendall(b"status\n") # استفاده از دستور status ساده
                
                data = b""
                self._log(f"Attempt {attempt + 1}: Receiving status data...")
                while True:
                    chunk = sock.recv(4096) # خواندن در تکه‌های کوچکتر
                    if not chunk: # اتصال بسته شده توسط سرور
                        self._log(f"Attempt {attempt + 1}: Connection closed by server after sending status. Data len: {len(data)}")
                        break 
                    data += chunk
                    # خروجی دستور status معمولا با END و سپس یک خط جدید (\r\n یا \n) تمام می‌شود.
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
            except Exception as e_general: # سایر خطاها
                self._log(f"An unexpected error occurred in get_openvpn_status (attempt {attempt+1}): {str(e_general)}")
                if sock:
                    sock.close()
                # برای خطاهای عمومی شاید بهتر باشد سریعتر از حلقه خارج شویم
                break # یا return ""
        
        self._log("Returning empty string from get_openvpn_status after all attempts or critical error.")
        return ""

    def do_GET(self):
        try:
            self._log(f"GET request received from {self.client_address[0]}")
            data = self.get_openvpn_status()
            users = {}
            if data:
                # self._log(f"Raw data received from OpenVPN:\n{data[:1000]}...") # برای دیباگ اگر لازم شد
                lines = data.split("\n")
                client_list_started = False
                for line in lines:
                    if line.startswith("CLIENT_LIST"):
                        client_list_started = True
                        parts = line.split(",")
                        if len(parts) >= 7:
                            username = parts[1].strip()
                            if username: # اطمینان از اینکه نام کاربری خالی نیست
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
                        # else: # برای دیباگ بیشتر می‌توان خطوط CLIENT_LIST با فرمت نادرست را لاگ کرد
                        #     if client_list_started: self._log(f"Warning: Malformed CLIENT_LIST line: {line}")
                    elif line.startswith("ROUTING_TABLE"):
                        client_list_started = False # پس از لیست کلاینت‌ها، بخش‌های دیگر شروع می‌شوند
                        break # دیگر نیازی به پردازش خطوط بعدی برای لیست کلاینت‌ها نیست
                    elif line.startswith("GLOBAL_STATS"):
                        client_list_started = False
                        break
                    elif line.strip() == "END":
                        client_list_started = False
                        break
            
            # self._log(f"Processed users: {users}") # برای دیباگ
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
        if 'server' in locals() and server: # بررسی وجود متغیر سرور قبل از بستن
            server.server_close()
    except Exception as e_run:
        print(f"FATAL: An unexpected error occurred while running the server: {e_run}", flush=True)


if __name__ == "__main__":
    run_server()