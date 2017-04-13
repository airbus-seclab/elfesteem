#! /usr/bin/env python

import os
__dir__ = os.path.dirname(__file__)

from test_all import run_tests, hashlib
from elfesteem.rprc import RPRC

def run_test():
    ko = []
    def assertion(target, value, message):
        if target != value: ko.append(message)
    import struct
    assertion('f71dbe52628a3f83a77ab494817525c6',
              hashlib.md5(struct.pack('BBBB',116,111,116,111)).hexdigest(),
              'MD5')
    e = RPRC()
    d = e.pack()
    assertion('865001a37fa24754bd17012e85d2bfff',
              hashlib.md5(d).hexdigest(),
              'Creation of a standard empty RPRC')
    d = RPRC(d).pack()
    assertion('865001a37fa24754bd17012e85d2bfff',
              hashlib.md5(d).hexdigest(),
              'Creation of a standard empty RPRC; fix point')
    rprc_m3 = open(__dir__+'/binary_input/ducati-m3_p768.bin', 'rb').read()
    assertion('d31c5887b98b37f949da3570b8688983',
              hashlib.md5(rprc_m3).hexdigest(),
              'Reading ducati-m3_p768.bin')
    e = RPRC(rprc_m3)
    d = e.pack()
    assertion('d31c5887b98b37f949da3570b8688983',
              hashlib.md5(d).hexdigest(),
              'Packing after reading ducati-m3_p768.bin')
    # Packed file is identical :-)
    d = e.display().encode('latin1')
    assertion('c691ff75fffede7701086f6b3c981b3b',
              hashlib.md5(d).hexdigest(),
              'Display RPRC file content')
    d = e.getsectionbyvad(0x00004000).pack()
    assertion('c77c8edf39114343b16b284ffddd2dff',
              hashlib.md5(d).hexdigest(),
              'Get existing section by address')
    d = e.getsectionbyvad(0x00400000)
    assertion(None, d, 'Get non-existing section by address')
    d = e.content[0x100:0x120]
    assertion('604e845109bba89a3dfa00da8c65cbd1',
              hashlib.md5(d).hexdigest(),
              'Extract chunk from raw data')
    d = e.virt[0x00004000]
    assertion('6b31bdfa7f9bfece263381ffa91bd6a9',
              hashlib.md5(d).hexdigest(),
              'Extract byte from mapped memory')
    d = e.virt[0x00004000:0x00004020]
    assertion('4b22b71399e1e0a6820c769456ce7483',
              hashlib.md5(d).hexdigest(),
              'Extract chunk from mapped memory')
    d = e.virt[0x00003ff0:0x00004020]
    assertion('ff2e5ba4b1c82e231f477c01ec805e06',
              hashlib.md5(d).hexdigest(),
              'Extract chunk from mapped and unmapped memory')
    e.virt[0x00004000:0x00004100] = e.virt[0x00004000:0x00004100]
    d = e.pack()
    assertion('d31c5887b98b37f949da3570b8688983',
              hashlib.md5(d).hexdigest(),
              'Writing in memory (interval)')
    e.virt[0x00004000] = e.virt[0x00004000:0x00004100]
    d = e.pack()
    assertion('d31c5887b98b37f949da3570b8688983',
              hashlib.md5(d).hexdigest(),
              'Writing in memory (address)')
    try:
        e.virt[0x00040000] = e.virt[0x00004000:0x00004100]
        ko.append('Writing in non-mapped memory')
    except ValueError:
        pass
    try:
        e.virt[0x00003ff0:0x00004020] = e.virt[0x00003ff0:0x00004020]
        ko.append('Writing in partially non-mapped memory')
    except ValueError:
        pass
    try:
        e = RPRC(open(__dir__+'/binary_input/README.txt', 'rb').read())
        ko.append('Not an RPRC')
    except ValueError:
        pass
    return ko

if __name__ == "__main__":
    run_tests(run_test)
