from Configuration import *
from Packet import  *
from Rule import *
from Population import *

conf_filename = 'configuration.json'
input_filename = 'packets.log'

def main():
    # parsing configuration file
    iter = 0
    best_rules = []
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
    print('Attacks number= ' + str(get_attacks_num(packets)) + '\n')
    _population = Population()
    _population._rule_list = generate_initial_rules(_configuration._population_size)
    _population.validate(packets)
    while(_configuration.calculate_conditions(iterations=iter, diff_between_solutions=0, length_between_solutions=0)):
        _population.cross_selection(_configuration)
        _population.mutation_selection(_configuration)
        _population.preserve_elite(_configuration)
        _population.crossover(_configuration)
        _population.mutation()
        _population.update_current_population(_configuration)
        _population.clear_values()
        _population.validate(packets)
        _population.print_best_rule()
        best_rules.append(_population.get_best_rule())
        iter += 1
    # _population.sort_rules()
    # # _population.print_rule_list()
    # _population.print_best_rule()
    create_graphs(best_rules)
if __name__ == '__main__':
    main()
