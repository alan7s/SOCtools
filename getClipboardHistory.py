import sqlite3
import json
from datetime import datetime, timedelta, timezone
import base64
import os

# Replace with your username bellow
username = "username"
clipboard_base_path = fr'C:\Users\{username}\AppData\Local\ConnectedDevicesPlatform'
target_filename = 'ActivitiesCache.db'
clipboard_path = None

try:
    for root, dirs, files in os.walk(clipboard_base_path):
        if target_filename in files:
            clipboard_path = os.path.join(root, target_filename)
    
    if clipboard_path:
        print(f"History found: {clipboard_path}")
        conn = sqlite3.connect(clipboard_path)

        cursor = conn.cursor()
        cursor.execute('SELECT StartTime, ClipboardPayload, Payload FROM SmartLookup WHERE ClipboardPayload IS NOT NULL')
        resultados = cursor.fetchall()
        conn.close()

        print("----- Clipboard History -----")

        for StartTime, ClipboardPayload_bytes, Payload in resultados:
            clipboard_time_log = datetime.fromtimestamp(StartTime, tz=timezone.utc).astimezone(timezone(timedelta(hours=-3))).strftime('%Y-%m-%d %H:%M:%S')     
            try:
                clipboard_payload_str = ClipboardPayload_bytes.decode('utf-8')
                data = json.loads(clipboard_payload_str)
                    
                has_valid_content = False
                decoded_content_list = []
                    
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and 'content' in item:
                            try:
                                base64_bytes = item['content'].encode('ascii')
                                decoded_content = base64.b64decode(base64_bytes).decode('utf-8', errors='ignore')
                                decoded_content_list.append(decoded_content.strip())
                                has_valid_content = True
                            except:
                                continue

                if has_valid_content:
                    print(f"Timestamp: {clipboard_time_log}") 
                    print(f"Content: {decoded_content_list}")
                    print("-" * 100)                   
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                continue
    else:
        print("Clipboard History not found")
except Exception as e:
        print(e)
