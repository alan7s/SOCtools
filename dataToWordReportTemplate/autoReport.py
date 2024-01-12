from docxtpl import DocxTemplate
from datetime import datetime
import pandas as pd
import requests
import time
# CSV to report template
# Version v0.1 by alan7s

def vtScan(domain):
    print(f'Scanning {domain}')
    
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'

    headers = {
        "accept": "application/json",
        "x-apikey": "YOUR-API-KEY"  # Virustotal API KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        last_analysis_stats = data['data']['attributes']['last_analysis_stats']

        # Sum analysis stats /y
        total = sum(last_analysis_stats.values())
        
        # Get malicious stats x/
        malicious = last_analysis_stats['malicious']
        
        if malicious >= 1:
            output = f'{malicious}/{total} VT' # VirusTotal scan: x/y
        else:
            output = "Não"
    else:
        output = "Não" ##teste##
        
    print('Waiting 15s before next scan')
    time.sleep(15) #api limit 4 request per minute
    return output

def urlTable(df):
    df = df.rename(columns={'URL (custom)':'url', 'Web Category (custom) (Unique Count)':'category', 'Count':'events' })
    df['url'] = df['url'].str.rstrip('/')
    df['events'] = df['events'].str.replace(',', '.').astype(float)
    df['ioc'] = df['url'].apply(lambda a: vtScan(a))
    url = []
    for index, row in df.iterrows():
        url.append({'url':row['url'],'category':row['category'],'events':row['events'],'ioc':row['ioc']})
    return url

doc = DocxTemplate("template_example.docx")

'''
CSV content format example: Top URLs blocked.csv

URL (custom) | Web Category (custom)(Unique Count) | Count
-----------------------------------------------------------
example1.com |     computer-and-internet-info      | 105,338
example2.com |     computer-and-internet-info      | 98,731
example...   |              ...                    |    ...
'''

urlblocked_df = pd.read_csv('Top URLs blocked.csv')
urlallowed_df = pd.read_csv('Top URLs allowed.csv')

start_date = "01/01/2024"
end_date = "07/01/2024"
today_date = datetime.today().strftime("%d/%m/%Y")
urlblocked = urlTable(urlblocked_df)
urlallowed = urlTable(urlallowed_df)

context = {
    'start_date': start_date, 
    'end_date': end_date, 
    'today_date': today_date,
    'urlblocked': urlblocked,
    'urlallowed': urlallowed
}

doc.render(context)
doc.save("report.docx")