import random
from Packet import *
import copy

ip_addr_set = [str(i) for i in range(1, 255)]
ip_addr_set += ['*' for i in range(255,510)]

transport_set = ['TCP', 'UDP', 'ICMP' '*', '-']
port_set = ['microsoft_ds', '48448', 'https', '50195', '60278', '55592', '35065', 'http', '50111', '52243', '53479', \
            'ssh', '36991', '56748', '64103', '34229', '33972', 'netbios_ssn', '53540', '51153', '56703', '49766', \
            '56566', '19756', '19704', '36522', '51947', '44032', '14135', '34746', '44257', '14134', '40870', \
            '34641', '49187', '5024', '3306', '50849', '33962', '36663', '41390', '64863', '38013', '56396', '41448', \
            '56543', '60483', '50239', '51880', '8000', '46192', '52807', '58227', '37515', '39989', '49767', '40077', \
            '35613', '60769', '56976', '45022', '47457', '50969', '55344', '39070', '60279', '49188', '41033', '40820', \
            '52717', 'isakmp', '39872', '35558', '50196', '55382', '59256', '34498', '43162', '43761', '34208', '36807', \
            '60980', '60544', '60929', '43491', '57233', '52133', '54529', '49768', '61617', '48739', '41906', '33703', \
            '51689', '60444', '60484', '15592', '51220', '57478', '43684', '54130', '37046', '46097', '38265', '44414', \
            '60934', '50197', '49769', '60280', '54500', '47174', '54369', '51215', '62742', '9200', '34026', '52236', \
            '64104', '50198', '50447', '40311', '46980', '49770', '60485', '48094', '47170', '40210', '57573', '52446', \
            '44422', '50199', '57612', '60281', '49189', '62737', '55554', '59816', '41697', '49771', '56709', '50503', \
            '40002', '39992', '55245', '45877', '20029', '60486', '55713', '50200', '47259', '20028', '18382', '19992', \
            '20026', '58233', '41606', '20027', '49772', '60282', '50947', '40459', '49348', '64105', '50666', '56410', \
            '50201', '36845', '60487', '55558', '55559', '45844', '48861', '23715', '50819', '59736', '49283', '60283', \
            '58241', '59788', '49773', '37477', '50202', '49190', '45848', '50822', '60488', '60284', '33816', '49774', \
            '50203', '35930', '5218', '44118', '60489', '55610', '55560', '60285', '20036', '36909', '64106', '49775', \
            '50204', '58202', '14136', '5938', '14131', '54165', '55556', '55555', '60286', '40747', '60490', '50205', \
            '49191', '56544', '14119', '62023', '49776', '49345', '8443', '23644', '56545', '62024', '58186', '59157', \
            '18245', '60491', '58236', '56546', '60287', '49777', '50206', '58203', '54485', '54635', '64107', '55557', \
            '45500', '62743', '60492', '60288', '60592', '53127', '62744', '49778', '50207', '56547', '49192', '49779', \
            '60289', '60493', '58180', '53068', '53708', '53528', '50208', '62745', '20037', '60290', '20038', '60494', \
            '49780', '56537', '19757', '19705', '*', '-']

network_set = ['IP', '*', '-']

class Rule:
    def __init__(self, ip_src='', ip_dest='', transport='', src_port='', dest_port='', network = ''):
        self._ip_src = ip_src
        self._ip_dest = ip_dest
        self._transport = transport
        self._src_port = src_port
        self._dest_port = dest_port
        self._network = network
        self._value = 0
        self._true_positive = 0 #rule matched attack
        self._true_negative = 0 #rule matched normal traffic
        self._false_positive = 0 #rule omitted normal traffic
        self._false_negative = 0 #rule omitted attack

    def __eq__(self, other):
        if self._ip_src != other._ip_src:
            return False
        elif self._ip_dest != other._ip_dest:
            return False
        elif self._dest_port != other._dest_port:
            return False
        elif self._src_port != other._src_port:
            return False
        elif self._transport != other._transport:
            return False
        elif self._network != other._network:
            return False
        else:
            return True

    def validate(self, packet_list):
        detected = False
        for p in packet_list:
            for i,j in zip(self._ip_src.split('.'), p._ip_src.split('.')):
                if i == j or i == '*':
                    detected = True
                    self.value += p.get_value(detected, self)
                    continue
                else:
                    detected = False
            for i,j in zip(self._ip_dest.split('.'), p._ip_dest.split('.')):
                if i == j or i == '*':
                    detected = True
                    self.value += p.get_value(detected, self)
                    continue
                else:
                    detected = False
            if self._src_port == '*' or p._src_port == self._src_port or self._dest_port == '*' or self._dest_port == p._dest_port:
                detected = True
                self.value += p.get_value(detected, self)
                continue
            elif self._src_port == '-' or self._dest_port == '-':
                detected = False
            else:
                detected = False
            if self._network == '*' or self._network == p._network:
                detected = True
                self.value += p.get_value(detected, self)
                continue
            elif self._network == '-':
                detected = False
            else:
                detected = False
            if self._transport == '*' or self._transport == p._transport:
                detected = True
                self.value += p.get_value(detected, self)
                continue
            elif self._transport == '-':
                detected = False
            else:
                detected = False
            self.value += p.get_value(detected, self)

    def evaluate_parameters(self):
        self._fpr = self._false_positive/(self._false_positive + self._true_negative)
        self._fnr = self._false_negative/(self._false_negative + self._true_positive)
        self._tpr = self._true_positive/(self._true_positive + self._false_negative)
        self._tnr = self._true_negative/(self._true_negative + self._false_positive)
        self._accuracy = (self._true_positive + self._true_negative) / (self._true_positive + self._true_negative  + self._false_positive + self._false_negative)
        self._precision = self._true_positive / (self._true_positive + self._false_positive)

    def mutation(self, type):
        if type == 1:
            ip_src = self._ip_src.split('.')
            if ip_src[3] == '*':
                ip_src[2] = '*'
            elif ip_src[2] == '*':
                ip_src[1] = '*'
            elif ip_src[1] == '*':
                ip_src[0] = '*'
            self._ip_src = ip_src[3] + '.' + ip_src[2] + '.' + ip_src[1] + '.' + ip_src[0]
        elif type == 2:
            ip_dest = self._ip_dest.split('.')
            if ip_dest[3] == '*':
                ip_dest[2] = '*'
            elif ip_dest[2] == '*':
                ip_dest[1] = '*'
            elif ip_dest[1] == '*':
                ip_dest[0] = '*'
            self._ip_dest = ip_dest[3] + '.' + ip_dest[2] + '.' + ip_dest[1] + '.' + ip_dest[0]
        elif type == 3:
            self._dest_port = random.choice([self._dest_port, '*', '-'])
            self._src_port = random.choice([self._src_port, '*', '-'])

    def crossover(self, other, type):
        first = copy.deepcopy(self)
        second = copy.deepcopy(self)
        if 1 <= type <= 7:
            ip_src1 = self._ip_src.split('.')
            ip_src2 = other._ip_src.split('.')
            tmp = ip_src1
            ip_src1[2] = ip_src2[2]
            ip_src1[3] = ip_src2[3]
            ip_src2[2] = tmp[2]
            ip_src2[3] = tmp[3]
            ip_dest1 = self._ip_dest.split('.')
            ip_dest2 = other._ip_dest.split('.')
            tmp = ip_src1
            ip_dest1[2] = ip_src2[2]
            ip_dest1[3] = ip_src2[3]
            ip_dest2[2] = tmp[2]
            ip_dest2[3] = tmp[3]
            if (ip_src1[0] == '*'):
                ip_src1[1] = '*'
                ip_src1[2] = '*'
                ip_src1[3] = '*'
            if (ip_src1[1] == '*'):
                ip_src1[2] = '*'
                ip_src1[3] = '*'
            if (ip_src1[2] == '*'):
                ip_src1[3] = '*'
            if (ip_src2[0] == '*'):
                ip_src2[1] = '*'
                ip_src2[2] = '*'
                ip_src2[3] = '*'
            if (ip_src2[1] == '*'):
                ip_src2[2] = '*'
                ip_src2[3] = '*'
            if (ip_src2[2] == '*'):
                ip_src2[3] = '*'
            if (ip_dest1[0] == '*'):
                ip_dest1[1] = '*'
                ip_dest1[2] = '*'
                ip_dest1[3] = '*'
            if (ip_dest1[1] == '*'):
                ip_dest1[2] = '*'
                ip_dest1[3] = '*'
            if (ip_dest1[2] == '*'):
                ip_dest1[3] = '*'
            if (ip_dest2[0] == '*'):
                ip_dest2[1] = '*'
                ip_dest2[2] = '*'
                ip_dest2[3] = '*'
            if (ip_dest2[1] == '*'):
                ip_dest2[2] = '*'
                ip_dest2[3] = '*'
            if (ip_dest2[2] == '*'):
                ip_dest2[3] = '*'
            first._ip_src = ip_src1[0] + '.' + ip_src1[1] + '.' + ip_src1[2] + '.' + ip_src1[3]
            first._ip_dest = ip_dest1[0] + '.' + ip_dest1[1] + '.' + ip_dest1[2] + '.' + ip_dest1[3]
            second._ip_src = ip_src2[0] + '.' + ip_src2[1] + '.' + ip_src2[2] + '.' + ip_src2[3]
            second._ip_dest = ip_dest1[0] + '.' + ip_dest2[1] + '.' + ip_dest2[2] + '.' + ip_dest2[3]
            return [first, second]
        else:
            first = copy.deepcopy(self)
            second = copy.deepcopy(other)
            tmp_src_port = first._src_port
            tmp_dest_port = first._dest_port
            first._src_port = second._src_port
            first._dest_port = second._dest_port
            second._src_port = tmp_src_port
            second._dest_port = tmp_dest_port
            return [first, second]

def get_max(list):
    max = list[0]
    for r in list:
        if r._value > max:
            max = r
    return max


def generate_initial_rules(self, population_size):
    act_num_of_rules = 0
    population = []
    while (act_num_of_rules <= population_size):
        ip_first = ''
        ip_second = ''
        ip_third = ''
        ip_fourth = ''
        ip_first = random.choice(ip_addr_set)
        if(ip_first == '*'):
            ip_second = '*'
            ip_third = '*'
            ip_fourth = '*'
        else:
            ip_second = random.choice(ip_addr_set)
        if(ip_second == '*'):
            ip_third = '*'
            ip_fourth = '*'
        else:
            ip_third = random.choice(ip_addr_set)
        if(ip_third == '*'):
            ip_fourth = '*'
        else:
            ip_fourth = random.choice(ip_addr_set)
        _ip_src = ip_first + '.' + ip_second + '.' + ip_third + '.' + ip_fourth
        ip_first = ''
        ip_second = ''
        ip_third = ''
        ip_fourth = ''
        ip_first = random.choice(ip_addr_set)
        if(ip_first == '*'):
            ip_second = '*'
            ip_third = '*'
            ip_fourth = '*'
        else:
            ip_second = random.choice(ip_addr_set)
        if(ip_second == '*'):
            ip_third = '*'
            ip_fourth = '*'
        else:
            ip_third = random.choice(ip_addr_set)
        if(ip_third == '*'):
            ip_fourth = '*'
        else:
            ip_fourth = random.choice(ip_addr_set)
        _ip_dest = ip_first + '.' + ip_second + '.' + ip_third + '.' + ip_fourth
        new_rule = Rule(ip_src=_ip_src, ip_dest= _ip_dest, \
                        dest_port= random.choice(port_set), \
                        src_port=random.choice(port_set), \
                        transport=random.choice(transport_set), \
                        network=random.choice(network_set))
        for prev_rule in population:
            if prev_rule == new_rule:
                del new_rule
            else:
                population.append(new_rule)
                act_num_of_rules += 1
    return population