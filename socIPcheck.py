import requests
import shodan
import argparse
from datetime import datetime, timezone, timedelta
import ipaddress
# Version v0.4 by alan7s

def vtScan(ip,inpt):
    if inpt:
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    else:
        url = f'https://www.virustotal.com/api/v3/domains/{ip}'

    headers = {
        "accept": "application/json",
        "x-apikey": "YOUR_API_KEY"  # Virustotal API KEY
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
        
        print(f'. {malicious}/{total} security vendors flagged {ip}') # VirusTotal scan: x/y
    else:
         print(f"Failed to fetch data. Status Code: {response.status_code}")

def shodanScan(target):
    api_key = 'YOUR_API_KEY' #Shodan API KEY
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
        print()
    except shodan.APIError as e:
       print(f"Error: {e}")

def cortexCheck(ip):
    headers = {
        "x-xdr-auth-id": str(0), # Cortex API KEY ID
        "Authorization": "YOUR_API_KEY" # Cortex API KEY
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
    res = requests.post(url="https://api-domain.xdr.us.paloaltonetworks.com/public_api/v1/endpoints/get_endpoint/", # Set domain name
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

def cidrexpander(ip):
    ip_list = []
    for i in ipaddress.IPv4Network(ip):
        ip_list.append(str(i))
    with open(r'IPcidrExpander.txt', 'w') as fp:
        fp.write('[' + ','.join(ip_list) + ']')
    print('File IPcidrExpander.txt saved in this directory')

def main():
    parser = argparse.ArgumentParser(description='Scan IP address using VirusTotal, Shodan and Cortex XDR.')
    parser.add_argument('-r', '--remote', dest='remote_ip', required=False, help='Remote IP address to scan')
    parser.add_argument('-l', '--local', dest='local_ip', required=False, help='Local IP address to check')
    parser.add_argument('-e', '--expander', dest='expander_ip', required=False, help='IP CIDR expander')
    parser.add_argument('-d', '--domain', dest='remote_domain', required=False, help='Domain address to scan')

    args = parser.parse_args()
    print("================")
    print("   socIPcheck   ")
    print("================")
    
    if args.remote_ip:
        vtScan(args.remote_ip, True)
        shodanScan(args.remote_ip)
    if args.local_ip:
        cortexCheck(args.local_ip)
    if args.expander_ip:
        cidrexpander(args.expander_ip)
    if args.remote_domain:
        vtScan(args.remote_domain, False)

if __name__ == "__main__":
    main()
