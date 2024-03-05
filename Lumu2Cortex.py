import requests
import os
from dotenv import load_dotenv
import pandas as pd
import time

# Upload LUMU IOCs to Cortex XDR Blocklist
# Version v0.2 by alan7s

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

def main():
    # Carregando as variáveis de ambiente do arquivo .env
    load_dotenv(override=True)
    '''.env file content example:
        cortex_api = "API_KEY"
        cortex_id = "ID"
        cortex_fqdn = "fqdn"
    '''
    cortex_api = os.getenv("cortex_responder_api")
    cortex_id = os.getenv("cortex_responder_id")
    cortex_fqdn = os.getenv("cortex_fqdn")
        
    df = pd.read_csv('lumuiocs.csv') #set your lumu.csv path
    #print(df)
    blocklist = df[' sha256'].tolist()
    print("IOCs loaded")
    listofblocklist = list(chunks(blocklist, 100))
    print(f'IOCs: {len(blocklist)}')
    print(f'Sublistas: {len(listofblocklist)}')
    comment = input("Add comment: ")
    for i in range(len(listofblocklist)):      
        cortexCheck(cortex_api, cortex_id, cortex_fqdn, listofblocklist[i], comment)
        time.sleep(5)

if __name__ == "__main__":
    main()
