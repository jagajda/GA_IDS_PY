import json
from Condition import *
from Rule import *

class Configuration:
    def __init__(self, conditions_vec = [], population_size = 0, max_lifetime = 0,\
                 crossover_percentage = 0, mutation_percentage = 0 ,tournament_size = 0,\
                 elite_percentage = 0, attacks = []):
        self._conditions = conditions_vec
        self._population_size = population_size
        self._max_lifetime = max_lifetime
        self._elite_percentage = elite_percentage
        self._crossover_percentage = crossover_percentage
        self._mutation_percentage = mutation_percentage
        self._tournament_size  = tournament_size
        self._attacks = attacks

    def __str__(self):
        _str = ''
        for i in self._conditions:
            _str += i.get_str()
        for r in self._attacks:
            _str += r.get_str()
        _str += str(self._population_size) + '\n'
        _str += str(self._max_lifetime) + '\n'
        _str += str(self._crossover_percentage) + '\n'
        _str += str(self._mutation_percentage) + '\n'
        _str += str(self._tournament_size) + '\n'
        _str += str(self._elite_percentage) + '\n'
        return _str


    def get_conf_from_file(self, conf_filename):
        with open(conf_filename) as f:
            data = json.load(f)
        for i in data['conditions']:
            self._conditions.append(Condition(i['name'], i['valid'], float(i['value'])))
        for r in data['attacks']:
            self._attacks.append(Packet(r['ip_src'], r['ip_dest'], r['network'], r['transport'], r['src_port'], r['dest_port'], True))
        self._population_size = int(data['parameters'][0]['value'])
        self._max_lifetime = int(data['parameters'][1]['value'])
        self._crossover_percentage = int(data['parameters'][2]['value'])
        self._mutation_percentage = int(data['parameters'][3]['value'])
        self._tournament_size = int(data['parameters'][4]['value'])
        self._elite_percentage = int(data['parameters'][5]['value'])


    def calculate_conditions(self, iterations, diff_between_solutions, length_between_solutions):
        for i in self._conditions:
            if i._name == 'number of iterations':
                if i._valid == 'True':
                    if iterations > i._value:
                        return False
            if i._name == 'diff':
                if i._valid == 'True':
                    if diff_between_solutions < i._value:
                        return False
            if i._name == 'Length':
                if i._valid == 'True':
                    if length_between_solutions < i._value:
                        return False
            return True
