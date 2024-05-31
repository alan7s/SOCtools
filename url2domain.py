import tldextract

def url2domain(arquivo_entrada, arquivo_saida):
    try:
        with open(arquivo_entrada, 'r') as entrada:
            urls = entrada.readlines()
        domains = []
        for url in urls:
            url = url.strip()
            parsed_url = tldextract.extract(url)
            domains.append(parsed_url.registered_domain)
            print(parsed_url.registered_domain)

        with open(arquivo_saida, 'w') as saida:
            for domain in domains:
                saida.write(domain + '\n')
        print(f"Domínios extraídos com sucesso e salvos em {arquivo_saida}")
    except FileNotFoundError:
        print(f"Arquivo {arquivo_entrada} não encontrado.")
    

def main():
    input = 'urlList.txt' 
    output = 'domainList.txt' 
    url2domain(input, output)

if __name__ == "__main__":
    main()