import network
import socket
import ujson
import ubinascii
import uhashlib
import os
import time
from machine import Pin

led_power = Pin(12, Pin.OUT)  
led_connected = Pin(25, Pin.OUT)  

from config import WIFI_SSID, WIFI_PASSWORD, DEVICE_PIN, SERVER_PORT

VAULT_FILE = "vault.json"
SESSION_VALID = False

ANALYTICS_FILE = "analytics.json"
START_TIME = time.time()

def load_analytics():
    try:
        with open(ANALYTICS_FILE, 'r') as f:
            return ujson.load(f)
    except:
        return {
            "total_logins": 0,
            "failed_logins": 0,
            "last_login": None,
            "total_passwords": 0,
            "passwords_added": 0,
            "passwords_updated": 0,
            "passwords_deleted": 0,
            "total_connections": 0,
            "password_views": 0
        }

def save_analytics(analytics):
    with open(ANALYTICS_FILE, 'w') as f:
        ujson.dump(analytics, f)

def get_uptime():
    uptime_seconds = int(time.time() - START_TIME)
    days = uptime_seconds // 86400
    hours = (uptime_seconds % 86400) // 3600
    minutes = (uptime_seconds % 3600) // 60
    return f"{days}d {hours}h {minutes}m"

def calculate_password_health():
    vault = load_vault()
    if len(vault) == 0:
        return {"score": 100, "weak": 0, "duplicates": 0, "avg_age": 0}
    
    weak_count = 0
    passwords_list = []
    
    for entry in vault:
        decrypted = decrypt_data(entry['password'])
        if decrypted and len(decrypted) < 8:
            weak_count += 1
        passwords_list.append(decrypted)
    
    duplicates = len(passwords_list) - len(set(passwords_list))
    
    score = 100
    score -= (weak_count * 10)
    score -= (duplicates * 15)
    score = max(0, min(100, score))
    
    return {
        "score": score,
        "weak": weak_count,
        "duplicates": duplicates,
        "total": len(vault)
    }

def encrypt_data(data, key=DEVICE_PIN):
    key_bytes = key.encode()
    data_bytes = data.encode()
    encrypted = bytearray()
    for i, byte in enumerate(data_bytes):
        encrypted.append(byte ^ key_bytes[i % len(key_bytes)])
    return ubinascii.b2a_base64(encrypted).decode().strip()

def decrypt_data(encrypted_data, key=DEVICE_PIN):
    try:
        key_bytes = key.encode()
        data_bytes = ubinascii.a2b_base64(encrypted_data)
        decrypted = bytearray()
        for i, byte in enumerate(data_bytes):
            decrypted.append(byte ^ key_bytes[i % len(key_bytes)])
        return decrypted.decode()
    except:
        return None

def load_vault():
    try:
        with open(VAULT_FILE, 'r') as f:
            return ujson.load(f)
    except:
        return []

def save_vault(vault):
    with open(VAULT_FILE, 'w') as f:
        ujson.dump(vault, f)

def create_ap():
    ap = network.WLAN(network.AP_IF)
    ap.active(True)
    ap.config(essid=WIFI_SSID, password=WIFI_PASSWORD, authmode=network.AUTH_WPA_WPA2_PSK)
    
    while not ap.active():
        time.sleep(0.1)
    
    print("=" * 40)
    print("ESP-Encrypt Password Manager")
    print("=" * 40)
    print(f"WiFi SSID: {WIFI_SSID}")
    print(f"WiFi Password: {WIFI_PASSWORD}")
    print(f"IP Address: {ap.ifconfig()[0]}")
    print(f"Access PIN: {DEVICE_PIN}")
    print("=" * 40)
    led_power.on()
    return ap

def load_file(filename):
    try:
        with open(filename, 'r') as f:
            return f.read()
    except:
        return "<html><body><h1>Error: File not found</h1></body></html>"

def handle_request(client_socket, request):
    global SESSION_VALID
    
    try:
        lines = request.decode().split('\r\n')
        if len(lines) < 1:
            return
        
        request_line = lines[0]
        method, path, _ = request_line.split(' ')
        
        body = ""
        if method == "POST":
            body = lines[-1]
        
        if path == "/" or path == "/login":
            response = load_file("web/login.html").replace("{{PIN}}", DEVICE_PIN)
            send_response(client_socket, response)
        
        elif path == "/verify-pin" and method == "POST":
            data = parse_json(body)
            analytics = load_analytics()
            
            if data and data.get("pin") == DEVICE_PIN:
                SESSION_VALID = True
                analytics["total_logins"] += 1
                analytics["last_login"] = time.time()
                save_analytics(analytics)
                send_json(client_socket, {"success": True})
            else:
                analytics["failed_logins"] += 1
                save_analytics(analytics)
                send_json(client_socket, {"success": False, "error": "Invalid PIN"})
        
        elif path == "/vault":
            if SESSION_VALID:
                response = load_file("web/index.html")
                send_response(client_socket, response)
            else:
                send_response(client_socket, "<html><body><h1>Unauthorized</h1></body></html>", 401)

        elif path == "/analytics":
            if SESSION_VALID:
                response = load_file("web/analytics.html")
                send_response(client_socket, response)
            else:
                send_response(client_socket, "<html><body><h1>Unauthorized</h1></body></html>", 401)

        elif path == "/api/analytics" and method == "GET":
            if SESSION_VALID:
                analytics = load_analytics()
                vault = load_vault()
                health = calculate_password_health()
                
                # Calculate last login time
                last_login = "Never"
                if analytics["last_login"]:
                    seconds_ago = int(time.time() - analytics["last_login"])
                    if seconds_ago < 60:
                        last_login = f"{seconds_ago}s ago"
                    elif seconds_ago < 3600:
                        last_login = f"{seconds_ago // 60}m ago"
                    else:
                        last_login = f"{seconds_ago // 3600}h ago"
                
                analytics_data = {
                    "total_logins": analytics["total_logins"],
                    "failed_logins": analytics["failed_logins"],
                    "last_login": last_login,
                    "total_passwords": len(vault),
                    "passwords_added": analytics["passwords_added"],
                    "passwords_updated": analytics["passwords_updated"],
                    "passwords_deleted": analytics["passwords_deleted"],
                    "total_connections": analytics["total_connections"],
                    "password_views": analytics["password_views"],
                    "uptime": get_uptime(),
                    "health_score": health["score"],
                    "weak_passwords": health["weak"],
                    "duplicate_passwords": health["duplicates"]
                }
                
                send_json(client_socket, analytics_data)
            else:
                send_json(client_socket, {"error": "Unauthorized"}, 401)
                
        elif path == "/api/passwords" and method == "GET":
            if SESSION_VALID:
                analytics = load_analytics()
                analytics["password_views"] += 1
                save_analytics(analytics)
                
                vault = load_vault()
                decrypted_vault = []
                for entry in vault:
                    decrypted_entry = entry.copy()
                    decrypted_entry['password'] = decrypt_data(entry['password'])
                    decrypted_vault.append(decrypted_entry)
                send_json(client_socket, decrypted_vault)
            else:
                send_json(client_socket, {"error": "Unauthorized"}, 401)
        
        elif path == "/api/passwords" and method == "POST":
            if SESSION_VALID:
                data = parse_json(body)
                vault = load_vault()
                analytics = load_analytics()
                
                new_entry = {
                    "id": len(vault) + 1,
                    "website": data.get("website", ""),
                    "username": data.get("username", ""),
                    "password": encrypt_data(data.get("password", "")),
                    "notes": data.get("notes", "")
                }
                vault.append(new_entry)
                save_vault(vault)
                
                analytics["passwords_added"] += 1
                analytics["total_passwords"] = len(vault)
                save_analytics(analytics)
                
                send_json(client_socket, {"success": True, "id": new_entry["id"]})
            else:
                send_json(client_socket, {"error": "Unauthorized"}, 401)
                
        elif path.startswith("/api/passwords/") and method == "PUT":
            if SESSION_VALID:
                entry_id = int(path.split("/")[-1])
                data = parse_json(body)
                vault = load_vault()
                analytics = load_analytics()
                
                for entry in vault:
                    if entry["id"] == entry_id:
                        entry["website"] = data.get("website", entry["website"])
                        entry["username"] = data.get("username", entry["username"])
                        if "password" in data:
                            entry["password"] = encrypt_data(data["password"])
                        entry["notes"] = data.get("notes", entry["notes"])
                        break
                
                save_vault(vault)
                analytics["passwords_updated"] += 1
                save_analytics(analytics)
                
                send_json(client_socket, {"success": True})
            else:
                send_json(client_socket, {"error": "Unauthorized"}, 401)
        
        elif path.startswith("/api/passwords/") and method == "DELETE":
            if SESSION_VALID:
                entry_id = int(path.split("/")[-1])
                vault = load_vault()
                analytics = load_analytics()
                
                vault = [entry for entry in vault if entry["id"] != entry_id]
                save_vault(vault)
                
                analytics["passwords_deleted"] += 1
                analytics["total_passwords"] = len(vault)
                save_analytics(analytics)
                
                send_json(client_socket, {"success": True})
            else:
                send_json(client_socket, {"error": "Unauthorized"}, 401)
    
    except Exception as e:
        print(f"Error handling request: {e}")
        send_response(client_socket, "<html><body><h1>500 Internal Server Error</h1></body></html>", 500)

def parse_json(body):
    try:
        return ujson.loads(body)
    except:
        return None

def send_response(client_socket, content, status_code=200):
    status_text = "OK" if status_code == 200 else "Error"
    response = f"HTTP/1.1 {status_code} {status_text}\r\n"
    response += "Content-Type: text/html\r\n"
    response += "Connection: close\r\n\r\n"
    response += content
    client_socket.send(response.encode())

def send_json(client_socket, data, status_code=200):
    status_text = "OK" if status_code == 200 else "Error"
    response = f"HTTP/1.1 {status_code} {status_text}\r\n"
    response += "Content-Type: application/json\r\n"
    response += "Connection: close\r\n\r\n"
    response += ujson.dumps(data)
    client_socket.send(response.encode())

def start_server():
    ap = create_ap()
    
    addr = socket.getaddrinfo('0.0.0.0', SERVER_PORT)[0][-1]
    server_socket = socket.socket()
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(addr)
    server_socket.listen(5)
    
    print(f"Server listening on port {SERVER_PORT}")
    print("Waiting for connections...")
    
    while True:
        try:
            client_socket, client_addr = server_socket.accept()
            print(f"Client connected from {client_addr}")
            
            analytics = load_analytics()
            analytics["total_connections"] += 1
            save_analytics(analytics)
            
            led_connected.on()
            
            request = client_socket.recv(2048)
            if request:
                handle_request(client_socket, request)
            
            client_socket.close()
            
            time.sleep(2)
            led_connected.off()
            
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    start_server()