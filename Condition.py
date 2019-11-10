class Condition:
    def __init__(self, name = 'def_condtion', valid = 'No validity spec', value = '0.0'):
        self._name = name
        self._valid = valid
        self._value = value

    def get_str(self):
        _str = ''
        _str += self._name + '\n'
        _str += self._valid + '\n'
        _str += str(self._value) + '\n'
        return _str