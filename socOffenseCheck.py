import requests
import shodan
from pandas import json_normalize
from urllib.parse import quote
import os
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
import ipaddress
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Version v0.4 by alan7s

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

def vtScan(ip,inpt, api):
    if inpt:
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    else:
        url = f'https://www.virustotal.com/api/v3/domains/{ip}'

    headers = {
        "accept": "application/json",
        "x-apikey": api  # Virustotal API KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        last_analysis_stats = data['data']['attributes']['last_analysis_stats']

        # Sum analysis stats /y
        total = sum(last_analysis_stats.values())
        
        # Get malicious stats x/
        malicious = last_analysis_stats['malicious']
        if inpt:
            output = f'VirusTotal Checker:\n\n{malicious}/{total} security vendors flagged {ip}. See https://www.virustotal.com/gui/ip-address/{ip}' # VirusTotal scan: x/y
        else:
            output = f'VirusTotal Checker:\n\n{malicious}/{total} security vendors flagged {ip}. See https://www.virustotal.com/gui/domain/{ip}'         
    else:
         output = f"VirusTotal Error: Failed to fetch data. Status Code: {response.status_code}"
    encoded_output = quote(output)
    return encoded_output

def shodanScan(target, api):
    api_key = api #Shodan API KEY
    api = shodan.Shodan(api_key)
    try:
        results = api.host(target)

        str_result = f"Organization: {results.get('org', 'N/A')}"

        domains = results.get('domains', [])
        if domains:
            str_domains = f"Domains: {', '.join(map(str, domains))}"
        else:
            str_domains = f"Domains: N/A"

        ports = results.get('ports', [])
        if ports:
            str_ports = f". Ports: {', '.join(map(str, ports))}"
        else:
            str_ports = f". Ports: N/A"

        vulnerabilities = results.get('vulns', [])
        if vulnerabilities:
            str_vulnerabilities = f". Vulnerabilities: {', '.join(map(str, vulnerabilities))}"
        else:
            str_vulnerabilities = f". Vulnerabilities: N/A"
        str_source = f'. Source https://www.shodan.io/host/{target}'
        output = f'Shodan Checker:\n\n{str_result}\n\n{str_domains}\n\n{str_ports}\n\n{str_vulnerabilities}\n\n{str_source}'
    except shodan.APIError as e:
       output = f"Shodan Error: {e}"
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
    virustotal_api = os.getenv("virustotal_api")
    shodan_api = os.getenv("shodan_api")

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
                if notes_len(qradar_url_base,qradar_header, offenses.iloc[i]['id']) == 0:
                    if ipaddress.ip_address(ip).is_private:
                        add_comment(qradar_url_base,qradar_header,offenses.iloc[i]['id'],cortexCheck(ip, cortex_api, cortex_id, cortex_fqdn))
                    else:
                        add_comment(qradar_url_base,qradar_header,offenses.iloc[i]['id'],vtScan(ip,True,virustotal_api))
                        add_comment(qradar_url_base,qradar_header,offenses.iloc[i]['id'],shodanScan(ip,shodan_api))
            except ValueError:
                print(f"{ip} não representa um endereço IP válido.")

if __name__ == "__main__":
    main()
