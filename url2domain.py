import tldextract

def url2domain(arquivo_entrada, arquivo_saida):
    try:
        with open(arquivo_entrada, 'r') as entrada:
            urls = entrada.readlines()
        domains = set()
        for url in urls:
            url = url.strip()
            parsed_url = tldextract.extract(url)
            domains.add(parsed_url.registered_domain)

        with open(arquivo_saida, 'w') as saida:
            for domain in domains:
                if domain:
                    print(domain)
                    saida.write(domain + '\n')
        print(f"Domínios extraídos com sucesso e salvos em {arquivo_saida}")
    except FileNotFoundError:
        print(f"Arquivo {arquivo_entrada} não encontrado.")
    

def main():
    input = 'listURL.txt' 
    output = 'listDomain.txt' 
    url2domain(input, output)

if __name__ == "__main__":
    main()
