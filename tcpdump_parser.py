from scapy.all import *

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('test4.pcap')
sum = 0;
# Let's iterate through every packet
for packet in packets:
    print(packet.summary())
    sum += 1
print(sum)