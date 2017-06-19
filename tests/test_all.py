#! /usr/bin/env python

# These non-regression tests should be OK from python2.3 to python3.x

# How to import by name, compatible with python2 and python3
import sys, os, imp
__dir__ = os.path.dirname(__file__)
def import_by_name(name):
    fp, pathname, description = imp.find_module(name, [__dir__])
    try:
        module = imp.load_module(name, fp, pathname, description)
    finally:
        if fp is not None: fp.close()
    return module

try:
    import hashlib
except ImportError:
    # Python 2.4 does not have hashlib
    # but 'md5' is deprecated since python2.5
    import md5 as oldpy_md5
    class hashlib(object):
        def md5(self, data):
            return oldpy_md5.new(data)
        md5 = classmethod(md5)

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

def assertion(target, value, message, status_ptr):
    if target != value:
        print_colored.boldred('Non-regression failure for %r' % message)
        status_ptr[0] = False

def run_tests(run_test):
    status_ptr = [True]
    run_test(lambda target, value, msg, status_ptr=status_ptr:
        assertion(target, value, msg, status_ptr))
    if status_ptr[0]:
        print_colored.boldgreen('OK')
    return status_ptr[0]

if __name__ == "__main__":
    exit_value = 0
    for name in (
            'visual_studio_mangling',
            'pe_manipulation',
            'elf_manipulation',
            'macho_manipulation',
            'rprc_manipulation',
            'minidump_manipulation',
            'intervals',
            ):
        module = import_by_name('test_' + name)
        print_colored.bold(name)
        if not run_tests(module.run_test):
            exit_value = 1
    sys.exit(exit_value)
