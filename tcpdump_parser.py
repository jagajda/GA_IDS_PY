from scapy.all import *
import json
from Configuration import *

# # rdpcap comes from scapy and loads in our pcap file
# packets = rdpcap('pcap/test4.pcap')
# sum = 0
# transport = []
# network = []
# # Let's iterate through every packet
# for packet in packets:
#     print(packet.summary())
#     print(type(packet.summary()))
#     try:
#         splitted = packet.summary().split()
#         transport.append(splitted[4])
#         network.append(splitted[2])
#     except Exception as e:
#         print(e)
#     sum += 1
# print(sum)
# network=list(dict.fromkeys(network))
# transport=list(dict.fromkeys(transport))
# print(repr(transport))
# print(repr(network))
filename = 'configuration.json'
with open(filename) as f:
    datastore = json.load(f)
conf = Configuration()
conf.get_conf_from_file(filename)
print(conf)