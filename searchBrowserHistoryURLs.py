import shutil
import sqlite3
import os
import tempfile
import datetime

USERNAME = 'user'
SEARCH = 'word'
everyURL = []

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
        cursor.execute('SELECT url, last_visit_time FROM urls')

        for url, last_visit_time in cursor.fetchall():
            if SEARCH.lower() in url.lower():
                epoch = datetime.datetime(1601, 1, 1)
                browser_epoch = datetime.timedelta(microseconds=last_visit_time, hours=-3) #UTC-3
                acess_log = epoch + browser_epoch
                everyURL.append((browser, acess_log, url))

        conn.close()
    except Exception as e:
        print(e)

browsedURL = sorted(everyURL, key=lambda x: x[1])
for browser, acess_log, url in browsedURL:
    print(f'{browser} {acess_log}')
    print(url)
    print('---------------------')
