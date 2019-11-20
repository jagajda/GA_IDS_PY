from Configuration import *
from Packet import  *
from Rule import *
from Population import *

conf_filename = 'configuration.json'
input_filename = 'packets.log'

def main():
    packets = []
    #parsing configuration file
    try:
        _configuration = Configuration()
        _configuration.get_conf_from_file(conf_filename)
    except Exception as e:
        print(e)
    print(_configuration)
    #reading input logs
    try:
        packets = get_packets_from_file(input_filename)
        update_attacks(packets, _configuration._attacks)
    except Exception as e:
        print(e)
    #initializing first population
    _population = Population()
    _population._rule_list = generate_initial_rules(_configuration._population_size)
    _population.print_rule_list()

if __name__ == '__main__':
    main()
