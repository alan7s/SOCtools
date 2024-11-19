import socket
import requests
import shodan
import argparse
from datetime import datetime, timezone, timedelta
import os
from dotenv import load_dotenv
import time
import re
import xml.etree.ElementTree as ET
# Version v1.5 by alan7s

def wildfire(url,api_key):
    url_api = f'https://wildfire.paloaltonetworks.com/publicapi/get/verdict'
    data = {
        'apikey': api_key,
        'url': url
    }
    response = requests.post(url_api, data=data)
    print("\n[+] Wildfire scan:\n")
    if response.status_code == 200:
        # Parse do XML
        root = ET.fromstring(response.text)
        url = root.find(".//url").text
        verdict = int(root.find(".//verdict").text)
        
        verdict_map = {
            0: "benign",
            1: "malware",
            2: "grayware",
            4: "phishing",
            5: "C2"
        }
        
        verdict_text = verdict_map.get(verdict, "unknown")
        print(f"\t. {url} flagged as {verdict_text} by Wildfire")
    else:
        print(f"\tFailed to fetch verdict. Status code: {response.status_code}")


def abuseIPDB(ip, api_key):
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90'
    headers = {
        "Accept": "application/json",
        "Key": api_key  # AbuseIPDB API Key
    }
    response = requests.get(url, headers=headers)
    print("\n[+] AbuseIPDB scan:\n")
    if response.status_code == 200:
        data = response.json()
        abuse_confidence_score = data['data']['abuseConfidenceScore']
        if abuse_confidence_score > 0:
            print(f'\t. {ip} has an abuse confidence score of {abuse_confidence_score}/100. See https://www.abuseipdb.com/check/{ip}')
        else:
            print(f'\t. No abusive activity found for {ip}. See https://www.abuseipdb.com/check/{ip}')
    else:
        print(f"\tFailed to fetch data. Status Code: {response.status_code}")

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
    print(f"\n[+] VirusTotal {'IP' if inpt else "Domain"} scan:\n")
    if response.status_code == 200:
        data = response.json()
        last_analysis_stats = data['data']['attributes']['last_analysis_stats']

        # Sum analysis stats /y
        total = sum(last_analysis_stats.values())
        
        # Get malicious stats x/
        malicious = last_analysis_stats['malicious']
        if inpt:
            print(f'\t. {malicious}/{total} security vendors flagged {ip}. See https://www.virustotal.com/gui/ip-address/{ip}') # VirusTotal scan: x/y
        else:
            print(f'\t. {malicious}/{total} security vendors flagged {ip}. See https://www.virustotal.com/gui/domain/{ip}')
    else:
         print(f"Failed to fetch data. Status Code: {response.status_code}")

def shodanScan(target, api_key):
    api = shodan.Shodan(api_key)
    try:
        results = api.host(target)
        print("\n[+] Shodan scan:\n")
        print(f"\t. Organization: {results.get('org', 'N/A')}")
        domains = results.get('domains', [])
        print(f"\t. Domains: {', '.join(map(str,domains)) if domains else 'Domains: N/A'}")
        ports = results.get('ports', [])
        print(f"\t. Ports: {', '.join(map(str,ports)) if ports else 'Ports: N/A'}")
        vulnerabilities = results.get('vulns', [])
        print(f"\t. Vulnerabilities: {', '.join(map(str,vulnerabilities)) if vulnerabilities else 'Vulnerabilities: N/A'}")
        print(f'\t. Source https://www.shodan.io/host/{target}\n')
        return 1
    except shodan.APIError as e:
       return 0
    
def shodanFreeScan(target):
    print("\n[+] Shodan scan:\n")
    try:
        results = requests.get(f"https://internetdb.shodan.io/{target}").json()
        print(f"\t. Hostnames: {', '.join(map(str, results['hostnames'])) if results['hostnames'] else 'Hostnames: N/A'}")
        print(f"\t. Ports: {', '.join(map(str,results['ports'])) if results['ports'] else 'Ports: N/A'}")
        print(f"\t. Vulnerabilities: {', '.join(map(str, results['vulns'])) if results['vulns'] else 'Vulnerabilities: N/A'}")
        print(f'\t. Source https://www.shodan.io/host/{target}\n')
        return 1
    except Exception as e:
       print(f"\tError: {e}\n")
       return 0

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

    print("\n[+] Cortex endpoint:\n")
    if res.status_code == 401:
        print(f"Cortex API: Unauthorized. Status Code: {res.status_code}")
        return 0
    elif res.status_code != 200:
        print(f"Cortex API: Error. Status Code: {res.status_code}")
        return 0
    cortex = res.json()
    try:
        endpoint = cortex['reply']['endpoints'][0]
        lastseen = endpoint['last_seen']
        date = timestamp = lastseen / 1000.0
        date = datetime.fromtimestamp(timestamp, timezone.utc)
        date = date - timedelta(hours=3)
        format_date = '%b %d, %Y, %I:%M %p'
        lastseen = date.strftime(format_date)
        print(f"\t. Name: {endpoint['endpoint_name']}")
        print(f"\t. Type: {endpoint['endpoint_type']}")
        print(f"\t. Status: {endpoint['endpoint_status']}")
        print(f"\t. User: {', '.join(endpoint['users'])}")
        print(f"\t. OS: {endpoint['os_type']}")
        print(f"\t. Agent version: {endpoint['endpoint_version']}")
        print(f"\t. IP address: {', '.join(endpoint['ip'])}")
        print(f"\t. Last seen: {lastseen}\n")
        print(f"Machine {endpoint['endpoint_name']} is with Cortex {endpoint['endpoint_status']} last seen in {lastseen}")
        return 1
    except IndexError:
        print(f"\t .{ip} not found\n")

def cortexMalwareScan(api, id, fqdn, ip):
    headers = {
        "x-xdr-auth-id": str(id), # Cortex API KEY ID --> Role: Privileged Responder | Security Level: Standard
        "Authorization": api, # Cortex API KEY
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    payload = { "request_data": {
        "filters": [
            {
                "field": "ip_list",
                "value": [ip],
                "operator": "in"
            }
        ]
    } }
    url=f"https://api-{fqdn}.xdr.us.paloaltonetworks.com/public_api/v1/endpoints/scan"
    response = requests.post(url, json=payload, headers=headers)
    print(response.json())

def resolvDNS(ip):
    try:
        dnsRevolv = socket.gethostbyaddr(ip)[0]
        print(f"[+] Address: {dnsRevolv} ({ip}).")
    except:
        print(f"[+] {ip} didn't resolve name.")    

def banner():
    print("""
             ,-----------------------------,      
        ,------------------------------------,    
      ,"                                   ,"|    
     +------------------------------------+  |
     |  .------------------------------.  |  |
     |  |┌──(alan7s㉿PC-666)-[SOCtools]|  |  |
     |  |└─$ ./socIPcheck.py           |  |  |
     |  | ┌─┐┌─┐┌─┐╦╔═╗┌─┐┬ ┬┌─┐┌─┐┬┌─ |  |  |
     |  | └─┐│ ││  ║╠═╝│  ├─┤├┤ │  ├┴┐ |  |  |
     |  | └─┘└─┘└─┘╩╩  └─┘┴ ┴└─┘└─┘┴ ┴ |  |  |
     |  |           ...                |  |  |/----
     |  |┌──(alan7s㉿PC-666)-[SOCtools]|  |  |   ,/
     |  |└─$                           |  |  |  //
     |  `------------------------------'  |," .;
     +------------------------------------+  ;;
        /_)___________________________(_/  //'
       ___________________________/___
      /  oooooooooooooooo  .o.  oooo /,
     / ==ooooooooooooooo==.o.  ooo= //
    /_==__==========__==_ooo__ooo=_/'
    `-----------------------------'""")

def main():
    parser = argparse.ArgumentParser(description='Scan IP address using VirusTotal, Shodan and Cortex XDR.')
    parser.add_argument('-r', '--remote', dest='remote_ip', required=False, help='Remote IP address to scan')
    parser.add_argument('-l', '--local', dest='local_ip', required=False, help='Local IP address to check')
    parser.add_argument('-d', '--domain', dest='domain_scan', required=False, help='Domain address to scan')
    parser.add_argument('-t', '--tenant', dest='tenant', required=False, help='API tenant')
    parser.add_argument('-s', '--scan', dest='scan_ip', required=False, action='store_true', help='Initiate local malware scan')
    parser.add_argument('-b', '--bulk', dest='bulk_scan', required=False, action='store_true', help='Bulk scan')

    args = parser.parse_args()

    banner()
    
    # Carregando as variáveis de ambiente do arquivo .env
    load_dotenv(override=True)
    #.env file content example:
    #   virustotal_api = "API_KEY"
    #   shodan_api = "API_KEY"
    #   abuseipdb_api = "API_KEY"
    #   cortex_api_tenant = "API_KEY"
    #   cortex_id_tenant = "ID"
    #   cortex_fqdn_tenant = "fqdn"

    virustotal_api = os.getenv("virustotal_api")
    shodan_api = os.getenv("shodan_api")
    abuseipdb_api = os.getenv("abuseipdb_api")
    wildfire_api = os.getenv("wildfire_api")

    ip_pattern = r'^(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.(?!$)|$)){4}$'

    if args.local_ip:
        if args.tenant:
            cortex_api = os.getenv(f"cortex_api_{args.tenant}")
            cortex_id = os.getenv(f"cortex_id_{args.tenant}")
            cortex_fqdn = os.getenv(f"cortex_fqdn_{args.tenant}")
            cortexScan = cortexCheck(args.local_ip, cortex_api, cortex_id, cortex_fqdn)
            if cortexScan:
                if args.scan_ip:
                    cortex_responder_id =  os.getenv(f"cortex_responder_id_{args.tenant}")
                    cortex_responder_api =  os.getenv(f"cortex_responder_api_{args.tenant}")
                    cortexMalwareScan(cortex_responder_api, cortex_responder_id, cortex_fqdn, args.local_ip)
            else:
                resolvDNS(args.local_ip)
        else:
            print("You need specified a tenant")
    if args.domain_scan and not args.bulk_scan:
        vtScan(args.domain_scan, False, virustotal_api)
        wildfire(args.domain_scan,wildfire_api)
    if args.remote_ip and not args.bulk_scan:
        vtScan(args.remote_ip, True, virustotal_api)
        abuseIPDB(args.remote_ip, abuseipdb_api)
        if not shodanScan(args.remote_ip, shodan_api):
            shodanFreeScan(args.remote_ip)
    if args.bulk_scan:
        bulk = []
        print("\n\nInsert a domain or remote IP (or press Enter to leave): ")
        while True:
            data = input()
            if data:
                bulk.append(data)
            else:
                break
        print(*bulk, sep=", ")
        for data in bulk:
            if re.match(ip_pattern, data):
                vtScan(data, True, virustotal_api)
                abuseIPDB(data, abuseipdb_api)
                shodanScan(data, shodan_api)
            else:
                vtScan(data,False,virustotal_api)
            time.sleep(15) #api limit 4 request per minute

if __name__ == "__main__":
    main()
