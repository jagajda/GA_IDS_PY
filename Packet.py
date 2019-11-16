from Rule import *

class Packet:

    def __init__(self, ip_src = '', ip_dest = '', network = '', transport = '', src_port = '', dest_port = '', attack = False):
        self._ip_src = ip_src
        self._ip_dest = ip_dest
        self._network = network
        self._transport = transport
        self._src_port = src_port
        self._dest_port = dest_port
        self._attack = attack

    def __str__(self):
        return self._ip_src + '\t' + self._ip_dest + '\t' + self._network + '\t' + \
               self._transport + '\t' + self._src_port + '\t' + self._dest_port + '\t' + \
               self._attack +'\n'

    def __eq__(self, other):
        if self._ip_src != other._ip_src:
            return False
        elif self._ip_dest != other._ip_dest:
            return False
        elif self._transport != other._transport:
            return False
        elif self._network != other._network:
            return False
        elif self._src_port != other._src_port:
            return False
        elif self._dest_port != other._dest_port:
            return False
        else:
            return True

    def get_value(self, detected, rule):
        if detected == True and self._attack == True:
            rule._true_positive += 1
            return 10
        elif detected == True and self._attack == False:
            rule._false_positive += 1
            return -5
        elif detected == False and self._attack == True:
            rule._false_negative += 1
            return -10
        else:
            rule._true_negative += 1
            return 5

def get_packets_from_file(packet_filename):
    packet_list =[]
    with open(packet_filename, 'r+') as f:
        for line in f:
            try:
                splitted = line.split()
                ip_src = (splitted[5].split(':'))[0]
                ip_dest = (splitted[7].split(':'))[0]
                network = splitted[2]
                transport = splitted [4]
                src_port = (splitted[5].split(':'))[1]
                dest_port = (splitted[7].split(':'))[1]
                if len(splitted >= 8):
                    packet_list.append(Packet(ip_src, ip_dest, network, transport, src_port, dest_port))
            except Exception as e:
                print(e)
    return packet_list

def update_attacks(packet_list, packets_from_conf_file):
    for attack in packets_from_conf_file:
        for p in packet_list:
            if p == attack:
                p._attack = True
            else:
                p._attack = False