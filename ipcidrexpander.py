import argparse
import ipaddress
def cidrexpander(ip):
    ip_list = []
    for i in ipaddress.IPv4Network(ip):
        ip_list.append(str(i))
    with open(r'IPcidrExpander.txt', 'w') as fp:
        fp.write('[' + ','.join(ip_list) + ']')
    print('File IPcidrExpander.txt saved in this directory')

def main():
    parser = argparse.ArgumentParser(description='Expand IP address')
    parser.add_argument('-e', '--expander', dest='expander_ip', required=False, help='IP CIDR expander')
    args = parser.parse_args()

    if args.expander_ip:
        try:
            cidrexpander(args.expander_ip)
        except Exception as e:
            print(f"Erro: {e}")

if __name__ == "__main__":
    main()