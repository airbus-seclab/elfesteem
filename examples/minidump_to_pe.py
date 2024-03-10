#! /usr/bin/env python
"""Minidump to PE example"""
import sys
from elfesteem.minidump_init import Minidump
from elfesteem.pe_init import PE

fd = open(sys.argv[1])
try:
    raw = fd.read()
finally:
    fd.close()
minidump = Minidump(raw)

pe = PE()
for i, memory in enumerate(sorted(minidump.memory.itervalues(),
                                  key=lambda x:x.address)):
    # Get section name
    name = str(memory.name)
    if not name:
        name = "s_%02d" % i
    else:
        name = name.split('\\')[-1]

    # Get section protection
    protect = memory.pretty_protect
    protect_mask = 0x20
    if protect == "UNKNOWN":
        protect_mask |= 0xe0000000
    else:
        if "EXECUTE" in protect:
            protect_mask |= 1 << 29
        if "READ" in protect:
            protect_mask |= 1 << 30
        if "WRITE" in protect:
            protect_mask |= 1 << 31

    # Add the section
    pe.SHList.add_section(name=name, addr=memory.address, rawsize=memory.size,
                          data=memory.content, flags=protect_mask)

# Find entry point
entry_point = minidump.threads.Threads[0].ThreadContext.Eip[0]
pe.Opthdr.AddressOfEntryPoint = entry_point

fd = open("out_pe.bin", "w")
try:
    fd.write(str(pe))
finally:
    fd.close()
