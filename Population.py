import random, copy
import numpy as np
import matplotlib.pyplot as plt
from Rule import *

class Population:
    def __init__(self, rule_list = []):
        self._rule_list = rule_list
        self._cross_list = []
        self._mutation_list = []
        self._next_generation = []

    def __str__(self):
        _str = ''
        _str += 'Rule list size: '
        _str += str(len(self._rule_list)) + '\n'
        _str += 'Cross list size: '
        _str += str(len(self._cross_list)) + '\n'
        _str += 'Mutation list size: '
        _str += str(len(self._mutation_list)) + '\n'
        _str += 'Next generation list size: '
        _str += str(len(self._next_generation)) + '\n'
        return _str

    def validate(self, packet_list):
        for r in self._rule_list:
            r.validate(packet_list)

    def cross_selection(self, configuration):
        number_of_crossover = int(configuration._population_size * (configuration._crossover_percentage/100))
        act_num = 0
        while(act_num < number_of_crossover):
            tournament_list = []
            for i in range(0, configuration._tournament_size):
                already_on_list = False
                chosen = copy.deepcopy(random.choice(self._rule_list))
                for r in tournament_list:
                    if r == chosen:
                        already_on_list = True
                if not already_on_list:
                    tournament_list.append(chosen)
            self._cross_list.append(get_max(tournament_list))
            act_num += 1

    def mutation_selection(self, configuration):
        number_of_mutation = int(configuration._population_size * (configuration._mutation_percentage/100))
        act_num = 0
        while(act_num < number_of_mutation):
            chosen = copy.deepcopy(random.choice(self._rule_list))
            self._mutation_list.append(chosen)
            act_num += 1

    def crossover(self, configuration):
        [a, b] = np.array_split(self._cross_list, 2)
        number_of_crossover = int(configuration._population_size * (configuration._crossover_percentage / 100))
        act_num = 0
        while(act_num < number_of_crossover):
            first = random.choice(a)
            second = random.choice(b)
            result = first.crossover(second, random.randint(1, 10))
            self._next_generation.append(result[0])
            self._next_generation.append(result[1])
            act_num += 1


    def mutation(self):
        for r in self._mutation_list:
            cp = copy.deepcopy(r)
            self._next_generation.append(cp.mutation(random.randint(1,3)))

    def preserve_elite(self, configuration):
        elite_size = int(configuration._population_size * (configuration._mutation_percentage/100))
        self._rule_list.sort(key=lambda x: x._value, reverse=True)
        self._next_generation = self._rule_list[:elite_size]

    def update_current_population(self, configuration):
        self._rule_list = self._next_generation[:configuration._population_size]
        self._rule_list.sort(key=lambda x: x._value, reverse=True)

    def get_best_rule(self):
        cp = copy.deepcopy(self._rule_list)
        cp.sort(key=lambda x: x._value, reverse=True)
        return cp[0]

    def generate_initial_population(self, rule_list):
        self._rule_list = rule_list

    def sort_rules(self):
        self._rule_list.sort(key=lambda  x: x._value, reverse=True)

    def print_best_rule(self):
        cp =copy.deepcopy(self._rule_list)
        cp.sort(key= lambda x: x._value, reverse= True)
        print(cp[0])

    def print_rule_list(self):
        for r in self._rule_list:
            print(r)

    def clear_values(self):
        for r in self._rule_list:
            r.clear_values()

    def remove_duplicates(self):
        self._rule_list = list(set(self._rule_list))

def create_graphs(best_rule_list):
    value_list = []
    tp_list = []
    tn_list = []
    fp_list = []
    fn_list = []
    acc_list = []
    prec_list =[]
    for r in best_rule_list:
        r.evaluate_parameters()
        value_list.append(r._value)
        tp_list.append(r._tpr)
        tn_list.append(r._tnr)
        fn_list.append(r._fnr)
        fp_list.append(r._fpr)
        acc_list.append(r._accuracy)
        prec_list.append(r._precision)
    iterations = [i for i in range(0, len(best_rule_list))]
    plt.figure(1)
    plt.plot(iterations, value_list)
    plt.show()
    plt.figure(2)
    plt.plot(iterations, tp_list)
    plt.show()
    plt.figure(3)
    plt.plot(iterations, tn_list)
    plt.show()
    plt.figure(4)
    plt.plot(iterations, fp_list)
    plt.show()
    plt.figure(5)
    plt.plot(iterations, fn_list)
    plt.show()
    plt.figure(6)
    plt.plot(iterations, prec_list)
    plt.show()
    plt.figure(7)
    plt.plot(iterations, acc_list)
    plt.show()