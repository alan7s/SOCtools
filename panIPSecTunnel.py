from skilletlib import Panos, exceptions
import getpass
import argparse

#PAN IPSec Tunnel
#Implemented commands:
#show vpn ike-sa gateway {name}
#test vpn ipsec-sa tunnel {name}
#Version v0.1 by alan7s

def sendCMD(name, action, protocol, target, device):
    cli_cmd = f'<{action}><vpn><{protocol}><{target}>{name}</{target}></{protocol}></vpn></{action}>'
    try:
        print("Sending command:")
        print(f'{action} vpn {protocol} {target} {name}')
        response = device.execute_op(cmd_str=cli_cmd, cmd_xml=False)
        print("Response:")
        print(response)
    except Exception as e:
        print(f'Error: {e}')


def fwcli(target_ip, target_port, target_username, target_password, name, target, action):
    print(f"Generating {target_ip} firewall's API key.\n")
    device = Panos(api_username=target_username,
                   api_password=target_password,
                   hostname=target_ip,
                   api_port=target_port)
    if target == 'gateway':
        sendCMD(name,action,'ike-sa',target,device)
    if target == 'tunnel':
        sendCMD(name,action,'ipsec-sa',target,device)

def callFW(name, target, action):
    fwip = input("Enter your firewall IP: ")
    fwport = input("Enter your firewall port: ")
    username = input("Enter your firewall username: ")
    password = getpass.getpass("Enter your firewall password: ")
    fwcli(fwip,fwport,username,password,name, target, action)

def main():
    parser = argparse.ArgumentParser(description='Email Threat Analysis')
    parser.add_argument('-g', '--gateway', dest='gateway', required=False, help='Select ike-sa gateway')
    parser.add_argument('-t', '--tunnel', dest='tunnel', required=False, help='Select ipsec-sa tunnel')
    parser.add_argument('-r', '--restart', dest='restart', required=False, action='store_true', help='Restart selected target')
    parser.add_argument('-s', '--show', dest='show', required=False, action='store_true', help='Show selected target')

    args = parser.parse_args()

    target = None
    action = None

    if not (args.restart or args.show):
        parser.error('One of the options -r or -s must be provided.')
        
    if args.restart:
        action = 'test'
    if args.show:
        action = 'show'

    if action:
        if args.gateway:
            target = 'gateway'
            callFW(args.gateway, target, action)
        if args.tunnel:
            target = 'tunnel'
            callFW(args.tunnel, target, action)
    else:
        parser.error('One of the options -s or -r must be provided along with -g or -t')

if __name__ == "__main__":
    main()
