import shutil
import sqlite3
import os
import tempfile

USERNAME = 'user'

browser_paths = {
    "Chrome": fr'C:\Users\{USERNAME}\AppData\Local\Google\Chrome\User Data\Default\History',
    "Edge"  : fr'C:\Users\{USERNAME}\AppData\Local\Microsoft\Edge\User Data\Default\History'
}
for browser, path in browser_paths.items():
    try:
        if not os.path.exists(path):
            continue

        temp_history_db = os.path.join(tempfile.gettempdir(), '{browser}_history_copy')
        shutil.copy(path, temp_history_db)

        conn = sqlite3.connect(temp_history_db)
        cursor = conn.cursor()

        cursor.execute('SELECT url FROM downloads_url_chains')

        for row in cursor.fetchall():
            print(f'{browser} URL: {row[0]}')

        conn.close()
    except Exception as e:
        print(e)
