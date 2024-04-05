import requests
import time
from pandas import json_normalize
from urllib.parse import quote
import os
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
import ipaddress
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Version v0.3 by alan7s

def cortexCheck(ip, api, id, fqdn):
    headers = {
        "x-xdr-auth-id": str(id), # Cortex API KEY ID
        "Authorization": api # Cortex API KEY
    }
    parameters = { "request_data": {
        "filters": [
            {
                "field": "ip_list",
                "value": [ip],
                "operator": "in"
            }
        ]
    } }
    res = requests.post(url=f'https://api-{fqdn}.xdr.us.paloaltonetworks.com/public_api/v1/endpoints/get_endpoint/', # Set domain name
						headers=headers,
						json=parameters)
    cortex = res.json()
    try:
        endpoint = cortex['reply']['endpoints'][0]
        lastseen = endpoint['last_seen']
        date = timestamp = lastseen / 1000.0
        date = datetime.fromtimestamp(timestamp, timezone.utc)
        date = date - timedelta(hours=3)
        format_date = '%b %d, %Y, %I:%M %p'
        lastseen = date.strftime(format_date)
        output = f'Cortex Checker:\n\n. Name: {endpoint['endpoint_name']}\n\n. Type: {endpoint['endpoint_type']}\n\n. Status: {endpoint['endpoint_status']}\n\n. User: {endpoint['users']}\n\n. OS: {endpoint['os_type']}\n\n. Agent version: {endpoint['endpoint_version']}\n\n. IP address: {endpoint['ip']}\n\n. Last seen: {lastseen}'
    except IndexError:
        output = f'Cortex Checker:\n\n{ip} not found'
    encoded_output = quote(output)
    return encoded_output

def add_comment(qradar_url_base,qradar_header,offense_id,comment):
    URL = qradar_url_base + '/siem/offenses/' + str(offense_id) + f'/notes?note_text={comment}'
    response = requests.post(URL, headers=qradar_header, verify=False)
    if response.status_code == 201:
        print('Offense ID: ' + str(offense_id) + ' comment added')
        return response.json()
    else:
        print('Error at add comment ' + str(offense_id) + '. Error: ' + str(response.status_code))
        return None

def get_offenses(qradar_url,qradar_header):
    response = requests.get(qradar_url, headers=qradar_header, verify=False)
    if response.status_code == 200:
        print('Success to get offenses')
        return response.json()
    else:
        print('Error: ' + str(response.status_code))
        return None
    
def notes_len(qradar_url_base,qradar_header, id):
    qradar_url = qradar_url_base + f'/siem/offenses/{id}/notes'
    response = requests.get(qradar_url, headers=qradar_header, verify=False).json()
    return len(response)
    
def main():
    load_dotenv(override=True)
    tenant = input("Tenant: ")
    cortex_api = os.getenv(f"cortex_api_{tenant}")
    cortex_id = os.getenv(f"cortex_id_{tenant}")
    cortex_fqdn = os.getenv(f"cortex_fqdn_{tenant}")
    qradar_sec_token = os.getenv("qradar_sec_token")
    qradar_url_base = os.getenv("qradar_url_base")

    qradar_url_suffix='/siem/offenses?filter=status%3Dopen'
    qradar_url = qradar_url_base + qradar_url_suffix
    qradar_header = {
        'SEC':qradar_sec_token,
        'Content-Type':'application/json',
        'accept':'application/json'
    }

    offenses = get_offenses(qradar_url,qradar_header)
    offenses = json_normalize(offenses)
    print("All open offenses:")
    #for i in range(len(offenses)):
    #    print(offenses.iloc[i]['id'])
    print(offenses['offense_source'])
    
    for i in range(len(offenses)):
        if offenses.iloc[i]['status'] == 'OPEN':
            ip = offenses.iloc[i]['offense_source']
            try:
                if notes_len(qradar_url_base,qradar_header, offenses.iloc[i]['id']) == 0 and ipaddress.ip_address(ip).is_private:
                    add_comment(qradar_url_base,qradar_header,offenses.iloc[i]['id'],cortexCheck(ip, cortex_api, cortex_id, cortex_fqdn))
            except ValueError:
                print(f"{ip} não representa um endereço IP válido.")

if __name__ == "__main__":
    main()
