#! /usr/bin/env python
# Generic container for all binary types known by elfesteem,
# with auto-recognition of the binary type.

import sys, os
sys.path.insert(1, os.path.abspath(sys.path[0]+'/..'))

from elfesteem.elf_init import ELF
from elfesteem.pe_init import PE, COFF
from elfesteem.minidump_init import Minidump
from elfesteem.macho import MACHO
from elfesteem.rprc import RPRC

class UnknownFormat(object):
    def __init__(self, raw):
        self.raw = raw
    architecture = 'UNKNOWN'
    entrypoint = -1
    sections   = ()
    symbols    = ()
    dynsyms    = ()
    class virt_stub(object):
        max_addr = lambda _:-1
    virt = virt_stub()

class BINARY(object):
    def __init__(self, raw):
        for container in ELF, PE, Minidump, MACHO, RPRC, COFF:
            try:
                self.e = container(raw)
                break
            except ValueError:
                pass
            except AssertionError:
                pass
        else:
            self.e = UnknownFormat(raw)
    container    = property(lambda _:_.e.__class__.__name__)
    architecture = property(lambda _:_.e.architecture)
    entrypoint   = property(lambda _:_.e.entrypoint)
    max_addr     = property(lambda _:_.e.virt.max_addr())
    sections     = property(lambda _:_.e.sections)
    symbols      = property(lambda _:_.e.symbols)
    dynsyms      = property(lambda _:_.e.dynsyms)

if __name__ == "__main__":
    for file in sys.argv[1:]:
        print("File: %s"%file)
        fd = open(file, 'rb')
        try:
            raw = fd.read()
        finally:
            fd.close()
        e = BINARY(raw)
        print("  container    %s" % e.container)
        print("  architecture %s" % e.architecture)
        print("  entrypoint   %#x" % e.entrypoint)
        print("  max address  %#x" % e.max_addr)
        print("  %d sections:" % len(e.sections))
        for sect in e.sections:
            print("    %s" % sect)
        print("  %d symbols:" % len(e.symbols))
        for symbol in e.symbols:
            print("    %s" % symbol)
        print("  %d dynamic symbols:" % len(e.dynsyms))
        for symbol in e.dynsyms:
            print("    %s" % symbol)
