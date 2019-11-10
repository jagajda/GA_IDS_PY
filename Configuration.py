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
        self._max_lifetime = int(data['parameters'][0]['value'])

