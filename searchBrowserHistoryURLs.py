import shutil
import sqlite3
import os
import tempfile

USERNAME = 'user'
SEARCH = 'word'

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

        cursor.execute('SELECT url FROM urls')

        for row in cursor.fetchall():
            link = row[0]
            if SEARCH.lower() in link.lower():
                print(f'{browser} URL: {link}')

        conn.close()
    except Exception as e:
        print(e)
