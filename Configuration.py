import json
from Condition import *

class Configuration:
    def __init__(self, conditions_vec = [], population_size = 0, max_lifetime = 0):
        self._conditions = conditions_vec
        self._population_size = population_size
        self._max_lifetime = max_lifetime

    def __str__(self):
        _str = ''
        for i in self._conditions:
            _str += i.get_str()
        _str += str(self._population_size) + '\n'
        _str += str(self._max_lifetime) + '\n'
        return _str


    def get_conf_from_file(self, conf_filename):
        with open(conf_filename) as f:
            data = json.load(f)
        for i in data['conditions']:
            self._conditions.append(Condition(i['name'], i['valid'], float(i['value'])))
        self._population_size = int(data['parameters'][0]['value'])
        self._max_lifetime = int(data['parameters'][1]['value'])
        self._crossover_percentage = int(data['parameters'][2]['value'])
        self._mutation_percentage = int(data['parameters'][3]['value'])


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
