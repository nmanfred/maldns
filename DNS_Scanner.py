import pyshark
import netifaces
import sys

interface = ''
with open('interface.conf', 'r', newline='') as f:
    interface = f.read().strip()

if interface not in netifaces.interfaces():
    print("Bad interface. Check interface.conf")
    sys.exit(1)

cap = pyshark.LiveCapture(interface=interface, bpf_filter='udp port 53')

def print_dns_info(pkt):
    with open('domains.txt', 'a+', newline='') as d:
        if pkt.dns.qry_name:
            print('{}'.format(pkt.dns.qry_name))
            d.write('{}\n'.format(pkt.dns.qry_name))

cap.apply_on_packets(print_dns_info, timeout=100) 












