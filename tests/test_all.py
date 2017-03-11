#! /usr/bin/env python

# These non-regression tests should be OK from python2.4 to python3.x
# elfesteem does not work for python2.3 and older, e.g. because 'sorted' or
# 'reversed' don't exist, neither the type 'set', etc.

# How to import by name, compatible with python2 and python3
import os, imp
__dir__ = os.path.dirname(__file__)
def import_by_name(name):
    fp, pathname, description = imp.find_module(name, [__dir__])
    try:
        module = imp.load_module(name, fp, pathname, description)
    finally:
        if fp is not None: fp.close()
    return module

class print_colored(object): # Namespace
    end = '\033[0m'
    def bold(self, txt):
        print('\033[1m'+txt+self.end)
    bold = classmethod(bold)
    def boldred(self, txt):
        print('\033[91;1m'+txt+self.end)
    boldred = classmethod(boldred)
    def boldgreen(self, txt):
        print('\033[92;1m'+txt+self.end)
    boldgreen = classmethod(boldgreen)

for name in (
        'visual_studio_mangling',
        'pe_manipulation',
        'elf_manipulation',
        'rprc_manipulation',
        ):
    module = import_by_name('test_' + name)
    print_colored.bold(name)
    ko = module.run_test()
    if ko:
        for k in ko:
            print_colored.boldred('Non-regression failure %r'%k)
    else:
        print_colored.boldgreen('OK')
