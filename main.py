# -*- coding: utf-8 -*-
#Imports
from argparse import ArgumentParser, FileType, HelpFormatter
from sys import argv, exit
from socket import create_connection, socket, AF_INET, SOCK_DGRAM, getservbyport

# Override "help" message
class CustomFormatter(HelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None:
            prefix = '\033[1;36m❰\033[1;33m!\033[1;36m❱ \033[1;97mUsage\033[0;0m: '
        return super(CustomFormatter, self).add_usage(usage, actions, groups, prefix)

# Override error messages
class ArgumentParser(ArgumentParser):
    def error(self, message):
        self.exit(2, f'\033[1;36m❰\033[38:5:9m!\033[1;36m❱ \033[1;97mError\033[0;0m: {message}\n')

# Parse arguments
argparse = ArgumentParser(prog="Netscan", usage=f"{argv[0]} <host>.",
        description="A simple port scanner.",
        formatter_class=CustomFormatter)
argparse._positionals.title = 'Positional arguments'
argparse._optionals.title = 'Optional arguments'
argparse.add_argument("host", help="Host to scan", type=str)
argparse.add_argument("--udp", help="Scan using UDP protocol", action="store_false", dest="udp", default=True)
argparse.add_argument("--range", help="Scanner range", action="store", dest="range", default=100, type=int)
args = argparse.parse_args()

def portscan(host, protocol, prange):
    scanned = []
    if protocol:
        for port in range(0, prange+1):
            try:
                with create_connection((host, port)) as connection:
                    connection.send('HEAD / HTTP/1.1'.encode())
                    scanned.append({'port':port, 'service':getservbyport(port, "tcp"), 'banner':connection.recv(1024).decode(errors='ignore'), 'protocol':'TCP'})
            except ConnectionRefusedError:
                continue
    else:
        for port in range(prange):
            try:
                with socket(AF_INET, SOCK_DGRAM) as connection:
                    connection.sendto('HEAD / HTTP/1.1'.encode())
                    scanned.append({'port':port, 'service':getservbyport(port, "udp"), 'banner':connection.recvfrom(1024)[0].decode(errors='ignore'), 'protocol':'UDP'})
            except ConnectionRefusedError:
                continue
    return scanned

if(args.range > 65535):
    exit(1, f'\033[1;36m❰\033[38:5:9m!\033[1;36m❱ \033[1;97mError\033[0;0m: invalid range to scan\n')

print(f'\n\r \033[38:5:15m╭─────────────────────> \033[38:5:29mNetscan \033[38:5:15m<─────────────────────╮\n')
for service in portscan(args.host, args.udp, prange=args.range):
    print(f'\r   \033[38:5:6m┌[ \033[38:5:3m{service["port"]}:\n'
     f'\r   \033[38:5:6m└─┬[ \033[38:5:15mService: \033[38:5:228m{service["service"]}\n'
     f'\r   \033[38:5:6m  ├[ \033[38:5:15mBanner: \033[38:5:228m{service["banner"]}\n'
     f'\r  \033[38:5:6m   └[ \033[38:5:15mProtocol: \033[38:5:228m{service["protocol"]}\033[38:5:15m\n')
print(f' ╰───────────────────────────────────────────────────────╯')
