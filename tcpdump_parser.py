from scapy.all import *
import json
from Configuration import *

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('pcap/test4.pcap')
ip = []
# Let's iterate through every packet
for packet in packets:
    print(packet.summary())
    print(type(packet.summary()))
    try:
        splitted = packet.summary().split()
        for i in ((splitted[5].split(':'))[0]).split('.'):
            ip.append(i)
        for j in ((splitted[7].split(':'))[0]).split('.'):
            ip.append(j)
    except Exception as e:
        print(e)

ip=list(dict.fromkeys(ip))
print(repr(ip))
# filename = 'configuration.json'
# with open(filename) as f:
#     datastore = json.load(f)
# conf = Configuration()
# conf.get_conf_from_file(filename)
# print(conf)

