import requests
import os
from dotenv import load_dotenv
import argparse
import pandas as pd

# Upload LUMU IOCs to Cortex XDR Blocklist
# Version v0.7 by alan7s

def cortexCheck(api, id, fqdn, blocklist, comment):
    headers = {
        "x-xdr-auth-id": str(id), # Cortex API KEY ID --> Role: Responder | Security Level: Standard
        "Authorization": api, # Cortex API KEY
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    payload = { "request_data": {
        "hash_list": blocklist,
        "comment": comment,
    } }
    url=f"https://api-{fqdn}.xdr.us.paloaltonetworks.com/public_api/v1/hash_exceptions/blocklist"
    response = requests.post(url, json=payload, headers=headers)
    print(response.json())

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

def chunks(lista, n):
    for i in range(0, len(lista), n):
        yield lista[i:i + n]

def getLumuFiles(id,api): #Need LUMU Defender
    url = f'https://defender.lumu.io/api/incidents/{id}/context?key={api}&hash=sha256'
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        try:
            return data['related_files']
        except:
            return []
    else:
        print("Request failed:", response.status_code)
        return []
    
def getAllLumuINC(api): #not implemented yet
    url = f'https://defender.lumu.io/api/incidents/all?key={api}&page=1&items=50'
    headers = {'Content-Type': 'application/json'}
    data = {
        "status": ["open"],
    }

    response = requests.post(url, headers=headers, json=data)
    openinc = response.json()['items']
    return openinc

def logHash(filename, hashes, description):
    with open(filename, 'a') as outfile:
        outfile.writelines('#'+description+'\n')
        outfile.writelines((str(i)+'\n' for i in hashes))

def main():
    load_dotenv(override=True)

    parser = argparse.ArgumentParser(description='Block hash files or binaries with IOC in Cortex XDR.')
    parser.add_argument('-t', '--tenant', dest='tenant', required=True, help='Cortex and Lumu API tenant')
    parser.add_argument('-i', '--incident', dest='incident', required=False, help='Incident ID (LUMU Defender required)')
    parser.add_argument('-s', '--scan', dest='scan_ip', required=False, help='Initializes Malware Scan on the IP.')
    parser.add_argument('-f', '--file', dest='file_path', required=True, help='Path to csv file.')
    parser.add_argument('-c', '--comment', dest='comment', required=True, help='Hash description.')

    args = parser.parse_args()
    tenant = args.tenant
    idLUMU = args.incident
    ipSCAN = args.scan_ip

    cortex_api = os.getenv(f"cortex_responder_api_{tenant}")
    cortex_id = os.getenv(f"cortex_responder_id_{tenant}")
    cortex_fqdn = os.getenv(f"cortex_fqdn_{tenant}")
    lumu_api = os.getenv(f"lumu_defender_api_{tenant}")

    if idLUMU:
        related_files = getLumuFiles(idLUMU,lumu_api)
    else:
        file_path = args.file_path
        try:
            df = pd.read_csv(file_path)
            related_files = df[' sha256'].tolist()
        except:
            related_files = []

    listofblocklist = list(chunks(related_files, 100))

    if len(listofblocklist) > 0:
        print(f'IOCs: {len(related_files)}')
        print(f'Sublists: {len(listofblocklist)}')
        description = args.comment
        comment = "LUMU IOC "+ description
        print(comment)
        logHash('hashes.txt', related_files, description)
        for i in range(len(listofblocklist)):      
            cortexCheck(cortex_api, cortex_id, cortex_fqdn, listofblocklist[i], comment)
    if ipSCAN:
        cortexMalwareScan(cortex_api, cortex_id, cortex_fqdn, ipSCAN)

if __name__ == "__main__":
    main()
