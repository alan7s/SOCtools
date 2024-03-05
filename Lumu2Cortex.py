import requests
import os
from dotenv import load_dotenv
import pandas as pd

# Upload LUMU Related Files IOCs to Cortex XDR Blocklist
# Version v0.1 by alan7s

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

def main():
    try:
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
        blocklist = df[' sha256'].tolist()
        print(blocklist)
        print("IOCs loaded")
        comment = input("Add comment: ")
        cortexCheck(cortex_api, cortex_id, cortex_fqdn, blocklist, comment)
    except:
        print('An exception occurred')

if __name__ == "__main__":
    main()
