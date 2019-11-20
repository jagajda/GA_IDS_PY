import random, copy
from Rule import *

class Population:
    def __init__(self, rule_list = []):
        self._rule_list = rule_list
        self._cross_list = []
        self._mutation_list = []
        self._next_generation = []

    def cross_selection(self, configuration):
        number_of_crossover = int(configuration._population_size * configuration._crossover_percentage/100)
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
        number_of_mutation = int(configuration._population_size * configuration._mutation_percentage/100)
        act_num = 0
        while(act_num < number_of_mutation):
            chosen = copy.deepcopy(random.choice(self._rule_list))
            self._mutation_list.append(chosen)

    def crossover(self, configuration):
        [a, b] = split(self._cross_list, 2)
        number_of_crossover = int(configuration._population_size * configuration._crossover_percentage / 100)
        act_num = 0
        while(act_num < number_of_crossover):
            first = random.choice(a)
            second = random.choice(b)
            result = first.Rule.crossover(second)
            self._next_generation.append(result[0])
            self._next_generation.append(result[1])
            act_num += 1


    def mutation(self):
        for r in self._mutation_list:
            r.Rule.mutation()
            self._next_generation.append(r)

    def preserve_elite(self, configuration):
        elite_size = int(configuration._population_size * configuration._mutation_percentage/100)
        self._rule_list.sort(key=lambda x: x._value, reverse=True)
        self._next_generation = self._rule_list[:elite_size]

    def update_current_population(self):
        self._rule_list.clear()
        self._rule_list = self._next_generation
        self._next_generation.clear()

    def get_best_rule(self):
        self._rule_list.sort(key=lambda  x: x._value, reverse=True)
        return self._rule_list[0]

    def generate_initial_population(self, rule_list):
        self._rule_list = rule_list

def split(l, n):
    n = max(1, n)
    return (l[i:i+n] for i in range(0, len(l), n))