import requests
import os
from dotenv import load_dotenv

# Upload LUMU IOCs to Cortex XDR Blocklist
# Version v0.3 by alan7s

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

def chunks(lista, n):
    for i in range(0, len(lista), n):
        yield lista[i:i + n]

def getLUMU(id,api):
    url = f'https://defender.lumu.io/api/incidents/{id}/context?key={api}&hash=sha256'
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data['related_files']
    else:
        print("Falha na requisição:", response.status_code)
        return []

def main():
    # Carregando as variáveis de ambiente do arquivo .env
    load_dotenv(override=True)

    tenant = input("Tenant: ")

    cortex_api = os.getenv(f"cortex_responder_api_{tenant}")
    cortex_id = os.getenv(f"cortex_responder_id_{tenant}")
    cortex_fqdn = os.getenv(f"cortex_fqdn_{tenant}")
    lumu_api = os.getenv(f"lumu_defender_api_{tenant}")

    idLUMU = input("Incident ID: ")
    related_files = getLUMU(idLUMU,lumu_api)
    listofblocklist = list(chunks(related_files, 100))
    if len(listofblocklist) > 0:
        print(f'IOCs: {len(related_files)}')
        print(f'Sublistas: {len(listofblocklist)}')
        comment = input("Add comment: ")
        for i in range(len(listofblocklist)):      
            cortexCheck(cortex_api, cortex_id, cortex_fqdn, listofblocklist[i], comment)

if __name__ == "__main__":
    main()
