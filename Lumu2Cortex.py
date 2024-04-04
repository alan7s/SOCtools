import requests
import os
from dotenv import load_dotenv
import argparse
import pandas as pd

# Upload LUMU IOCs to Cortex XDR Blocklist
# Version v0.5 by alan7s

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
        "x-xdr-auth-id": str(id), # Cortex API KEY ID --> Role: Responder | Security Level: Standard
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

def getLumuFiles(id,api): #depende do tipo de licença
    url = f'https://defender.lumu.io/api/incidents/{id}/context?key={api}&hash=sha256'
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        try:
            return data['related_files']
        except:
            return []
    else:
        print("Falha na requisição:", response.status_code)
        return []
    
def getAllLumuINC(api): #não implementado ainda
    url = f'https://defender.lumu.io/api/incidents/all?key={api}&page=1&items=50'
    headers = {'Content-Type': 'application/json'}
    data = {
        "status": ["open"],
    }

    response = requests.post(url, headers=headers, json=data)
    openinc = response.json()['items']
    return openinc


def main():
    # Carregando as variáveis de ambiente do arquivo .env
    load_dotenv(override=True)

    parser = argparse.ArgumentParser(description='Load LUMU incident related files hash into Cortex XDR.')
    parser.add_argument('-t', '--tenant', dest='tenant', required=True, help='Cortex and Lumu API tenant')
    parser.add_argument('-i', '--incident', dest='incident', required=False, help='Incident ID')
    parser.add_argument('-s', '--scan', dest='scan_ip', required=False, help='Initiate Malware Scan for an IP')

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
        df = pd.read_csv('lumuiocs.csv') #set your lumu.csv path
        try:
            related_files = df[' sha256'].tolist()
        except:
            related_files = []

    listofblocklist = list(chunks(related_files, 100))
    if len(listofblocklist) > 0:
        print(f'IOCs: {len(related_files)}')
        print(f'Sublistas: {len(listofblocklist)}')
        comment = input("Add general description: ")
        comment = "LUMU IOC "+ comment
        for i in range(len(listofblocklist)):      
            cortexCheck(cortex_api, cortex_id, cortex_fqdn, listofblocklist[i], comment)
    if ipSCAN:
        cortexMalwareScan(cortex_api, cortex_id, cortex_fqdn, ipSCAN)

if __name__ == "__main__":
    main()
