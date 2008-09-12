#! /usr/bin/env python

import pe
from pe_init import PE
import rlcompleter,readline,pdb, sys
from pprint import pprint as pp
readline.parse_and_bind("tab: complete")
import shlex

f = open('my_dump.txt', 'r')

for i in xrange(27):
    f.readline()

state = 0
funcs = []
dll = ""

#parse imprec output
new_dll = []
while True:
    l = f.readline()
    if not l:
        break
    l = l.strip()
    if state == 0 and l.startswith("FThunk"):
        t = [r for r in shlex.shlex(l)]
        ad = int(t[2], 16)
        state = 1
        continue
    if state == 1:
        t = [r for r in shlex.shlex(l)]
        if not len(t):
            new_dll.append(({"name":dll,
             "firstthunk":ad},funcs[:] ))
            dll = ""
            funcs, state = [], 0
        else:
            dll = t[2]
            funcs.append(t[6])            
        continue


pp(new_dll)

data = open('DUMP_00401000-00479000', 'rb').read()

e = PE()
e.DirImport.add_dlldesc(new_dll)
s_text = e.SHList.add_section(name = "text", addr = 0x1000, data = data)
s_myimp = e.SHList.add_section(name = "myimp", rawsize = len(e.DirImport))
e.DirImport.set_rva(s_myimp.addr)

e.Opthdr.Opthdr.AddressOfEntryPoint = s_text.addr

open('uu.bin', 'wb').write(str(e))
    
