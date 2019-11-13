from scapy.all import *
import json
from Configuration import *

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('pcap/test4.pcap')
sum = 0
# Let's iterate through every packet
for packet in packets:
    print(packet.summary())
    print(type(packet.summary()))
    sum += 1
print(sum)

with open('configuration.json') as f:
    datastore = json.load(f)

print(datastore['conditions'])
print('\n')
print(datastore['parameters'][0]['value'])
print('\n')
filename = 'configuration.json'
conf = Configuration()
conf.get_conf_from_file(filename)
print(conf)