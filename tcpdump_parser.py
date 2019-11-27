from scapy.all import *
import json
from Configuration import *

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('pcap/test4.pcap')
src_ip1 = []
src_ip2 = []
src_ip3 = []
src_ip4 = []
dst_ip1 = []
dst_ip2 = []
dst_ip3 = []
dst_ip4 = []
# Let's iterate through every packet
for packet in packets:
    print(packet.summary())
    print(type(packet.summary()))
    try:
        splitted = packet.summary().split()
        src = (splitted[5].split(':'))[0].split('.')
        src_ip1.append(src[0])
        src_ip2.append(src[1])
        src_ip3.append(src[2])
        src_ip4.append(src[3])
        dst = (splitted[7].split(':'))[0].split('.')
        dst_ip1.append(dst[0])
        dst_ip2.append(dst[1])
        dst_ip3.append(dst[2])
        dst_ip4.append(dst[3])
    except Exception as e:
        print(e)

src_ip1=list(dict.fromkeys(src_ip1))
print(repr(src_ip1))
src_ip2=list(dict.fromkeys(src_ip2))
print(repr(src_ip2))
src_ip3=list(dict.fromkeys(src_ip3))
print(repr(src_ip3))
src_ip4=list(dict.fromkeys(src_ip4))
print(repr(src_ip4))

dst_ip1=list(dict.fromkeys(dst_ip1))
print(repr(dst_ip1))
dst_ip2=list(dict.fromkeys(dst_ip2))
print(repr(dst_ip2))
dst_ip3=list(dict.fromkeys(dst_ip3))
print(repr(dst_ip3))
dst_ip4=list(dict.fromkeys(dst_ip4))

# print(repr(dst_ip4))
# filename = 'configuration.json'
# with open(filename) as f:
#     datastore = json.load(f)
# conf = Configuration()
# conf.get_conf_from_file(filename)
# print(conf)

