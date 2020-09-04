# Aharon Samet
# Find all people who sent SYN and did not send ACK
from scapy.layers.inet import TCP, IP
from scapy.utils import rdpcap

pcap_File = rdpcap("SynFloodSample.pcap")

dicts = {}
for pkt in pcap_File:
    if TCP in pkt and (pkt[TCP].flags == 'S'):
        ip = str(pkt[IP].src)
        if ip in dicts:
            adding = dicts.get(ip) + 1
            dicts[ip] = adding
        else:
            d = {ip: 1}
            dicts.update(d)


for pkt in pcap_File:
    if TCP in pkt and (pkt[TCP].flags == 'A'):
        ip = str(pkt[IP].src)
        if ip in dicts:
            minus = dicts.get(ip) - 1
            d = {ip: minus}
            dicts.update(d)


for kye, val in sorted(dicts.items()):
    if val > 0:
        with open("syn.txt", 'ab') as file:
            val = str(val)
            kye = str(kye)
            file.write((kye + '::' + val).encode())
            file.write('\n'.encode())
        print("{} {} {}".format(str(kye), '::', str(val)))
