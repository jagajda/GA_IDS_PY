from Configuration import *
from Packet import  *
from Rule import *
from Population import *

conf_filename = 'configuration.json'
input_filename = 'packets.log'

def main():
    # parsing configuration file
    try:
        _configuration = Configuration()
        _configuration.get_conf_from_file(conf_filename)
    except Exception as e:
        print(e)
    # print(_configuration)
    # reading input logs
    try:
        packets = get_packets_from_file(input_filename)
        update_attacks(packets, _configuration._attacks)
    except Exception as e:
        print(e)
    print('Packets number= ' + str(len(packets)) + '\n')
    # initializing first population
    _population = Population()
    _population._rule_list = generate_initial_rules(_configuration._population_size)
    _population.validate(packets)
    print(str(len(_population._rule_list)))
    _population.cross_selection(_configuration)
    print(str(len(_population._rule_list)))
    _population.mutation_selection(_configuration)
    print(str(len(_population._rule_list)))
    _population.preserve_elite(_configuration)
    print(str(len(_population._rule_list)))
    _population.crossover(_configuration)
    print(str(len(_population._rule_list)))
    _population.mutation()
    print(str(len(_population._rule_list)))
    _population.update_current_population(_configuration)
    print(str(len(_population._rule_list)))
    #_population.remove_duplicates()
    _population.clear_values()
    print(str(len(_population._rule_list)))
    _population.validate(packets)
    print(str(len(_population._rule_list)))
    _population.sort_rules()
    _population.print_rule_list()
    _population.print_best_rule()

if __name__ == '__main__':
    main()
