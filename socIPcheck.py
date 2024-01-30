import requests
import shodan
import argparse
from datetime import datetime, timezone, timedelta
import os
from dotenv import load_dotenv
# Version v0.6 by alan7s

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
    print("VirusTotal scan:")
    if response.status_code == 200:
        data = response.json()
        last_analysis_stats = data['data']['attributes']['last_analysis_stats']

        # Sum analysis stats /y
        total = sum(last_analysis_stats.values())
        
        # Get malicious stats x/
        malicious = last_analysis_stats['malicious']
        if inpt:
            print(f'. {malicious}/{total} security vendors flagged {ip}. See https://www.virustotal.com/gui/ip-address/{ip}') # VirusTotal scan: x/y
        else:
            print(f'. {malicious}/{total} security vendors flagged {ip}. See https://www.virustotal.com/gui/domain/{ip}')
            

    else:
         print(f"Failed to fetch data. Status Code: {response.status_code}")

def shodanScan(target, api):
    api_key = api #Shodan API KEY
    api = shodan.Shodan(api_key)
    print()
    print("Shodan scan: ")
    try:
        results = api.host(target)

        print(f". Organization: {results.get('org', 'N/A')}")

        domains = results.get('domains', [])
        if domains:
            print(f". Domains: {', '.join(map(str, domains))}")
        else:
            print(". Domains: N/A")

        ports = results.get('ports', [])
        if ports:
            print(f". Ports: {', '.join(map(str, ports))}")
        else:
            print(". Ports: N/A")

        vulnerabilities = results.get('vulns', [])
        if vulnerabilities:
            print(f". Vulnerabilities: {', '.join(map(str, vulnerabilities))}")
        else:
            print(". Vulnerabilities: N/A")
        print(f'. Source https://www.shodan.io/host/{target}')
        print()
    except shodan.APIError as e:
       print(f"Error: {e}")

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
    print("Cortex endpoint: ")
    try:
        endpoint = cortex['reply']['endpoints'][0]
        lastseen = endpoint['last_seen']
        date = timestamp = lastseen / 1000.0
        date = datetime.fromtimestamp(timestamp, timezone.utc)
        date = date - timedelta(hours=3)
        format_date = '%b %d, %Y, %I:%M %p'
        lastseen = date.strftime(format_date)
        print(f'. Name: {endpoint['endpoint_name']}')
        print(f'. Type: {endpoint['endpoint_type']}')
        print(f'. Status: {endpoint['endpoint_status']}')
        print(f'. User: {endpoint['users']}')
        print(f'. OS: {endpoint['os_type']}')
        print(f'. Agent version: {endpoint['endpoint_version']}')
        print(f'. IP address: {endpoint['ip']}')
        print(f'. Last seen: {lastseen}')
        print()
        print(f'Machine {endpoint['endpoint_name']} with Cortex {endpoint['endpoint_status']} last seen in {lastseen}')
    except IndexError:
        print(f'{ip} not found')

def main():
    parser = argparse.ArgumentParser(description='Scan IP address using VirusTotal, Shodan and Cortex XDR.')
    parser.add_argument('-r', '--remote', dest='remote_ip', required=False, help='Remote IP address to scan')
    parser.add_argument('-l', '--local', dest='local_ip', required=False, help='Local IP address to check')
    parser.add_argument('-d', '--domain', dest='domain_scan', required=False, help='Domain address to scan')

    args = parser.parse_args()
    print("================")
    print("   socIPcheck   ")
    print("================")

    # Carregando as variáveis de ambiente do arquivo .env
    load_dotenv(override=True)
    '''.env file content example:
    virustotal_api = "API_KEY"
    shodan_api = "API_KEY"
    cortex_api = "API_KEY"
    cortex_id = "ID"
    cortex_fqdn = "fqdn"
    '''
    virustotal_api = os.getenv("virustotal_api")
    shodan_api = os.getenv("shodan_api")
    cortex_api = os.getenv("cortex_api")
    cortex_id = os.getenv("cortex_id")
    cortex_fqdn = os.getenv("cortex_fqdn")

    if args.remote_ip:
        vtScan(args.remote_ip, True, virustotal_api)
        shodanScan(args.remote_ip, shodan_api)
    if args.local_ip:
        cortexCheck(args.local_ip, cortex_api, cortex_id, cortex_fqdn)
    if args.domain_scan:
        vtScan(args.domain_scan, False, virustotal_api)

if __name__ == "__main__":
    main()
