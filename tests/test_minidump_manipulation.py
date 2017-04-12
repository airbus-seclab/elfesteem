#! /usr/bin/env python

import os
__dir__ = os.path.dirname(__file__)

from test_all import run_tests, hashlib
from elfesteem.minidump_init import Minidump

def run_test():
    ko = []
    def assertion(target, value, message):
        if target != value: ko.append(message)
    import struct
    assertion('f71dbe52628a3f83a77ab494817525c6',
              hashlib.md5(struct.pack('BBBB',116,111,116,111)).hexdigest(),
              'MD5')
    md_windows = open(__dir__+'/binary_input/windows.dmp', 'rb').read()
    assertion('82a09a9d801bddd1dc94dfb9ba6eddf0',
              hashlib.md5(md_windows).hexdigest(),
              'Reading windows.dmp')
    e = Minidump(md_windows)
    d = e.dump().encode('latin1')
    assertion('48cae6cc782305b611f6e8b82049b9a0',
              hashlib.md5(d).hexdigest(),
              'Displaying the content of windows.dmp')
    # NB: the two other files, minidump-i386.dmp and minidump-x86_64.dmp,
    # are not well analyzed by the minidump implementation; the result of
    # parsing these files is very different from the result using
    # https://chromium.googlesource.com/breakpad/breakpad
    # and some investigations are needed to find why.
    return ko

if __name__ == "__main__":
    run_tests(run_test)
