from scapy.all import *

input_fpath = 'pcap/test4.pcap'
output_fpath = 'packets.log'

def main():
    try:
        packets = rdpcap(input_fpath)
    except Exception as e:
        print(e)
    with open(output_fpath, 'w+') as f:
        for packet in packets:
            str = packet.summary()
            if len(str.split()) >= 9:
                f.write(packet.summary() + '\n')

if __name__ == '__main__':
    main()