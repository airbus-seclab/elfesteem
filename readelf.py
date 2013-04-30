#! /usr/bin/env python
import getopt, sys

if sys.version_info[0] == 2 and sys.version_info[1] < 5:
    print >> sys.stderr, "python version older than 2.5 is not supported"
    exit(1)

from elfesteem import elf_init, elf

def display_reloc(e, sh):
    # Output format similar to readelf -r
    if not 'rel' in dir(sh):
        return
    print "\nRelocation section %r at offset 0x%x contains %d entries:" % (sh.sh.name, sh.sh.offset, len(sh.reltab))
    if e.size == 32:
        header = " Offset     Info    Type            Sym.Value  Sym. Name"
        format = "%08x  %08x %-16s  %08x   %s"
    elif e.size == 64:
        header = "  Offset          Info           Type           Sym. Value     Sym. Name"
        format = "%012x  %012x %-16s  %016x  %s"
    if sh.sht == elf.SHT_RELA:
        header = header + " + Addend"
    elif sh.sht == elf.SHT_REL:
        pass
    else:
        Fail
    print header
    for r in sh.reltab:
        name = r.sym
        if name == '': name = "."
        output = format%(r.offset, r.info, names['reloc_names'][e.Ehdr.machine][r.type], r.value, name)
        if sh.sht == elf.SHT_RELA:
            output = output + " + %x"%r.addend
        print output

def display_symbols(e, table_name):
    # Output format similar to readelf -s or readelf --dyn-syms
    if not table_name in e.sh.__dict__:
        print "Symbol table '.%s' missing" % table_name
        return
    table = e.sh.__dict__[table_name]
    print "Symbol table '.%s' contains %d entries:" % (table_name, len(table.symtab))
    if e.size == 32:
        header = "   Num:    Value  Size Type    Bind   Vis      Ndx Name"
        format = "%6d: %08x  %4d %-7s %-6s %-7s  %-3s %s"
    elif e.size == 64:
        header = "   Num:    Value          Size Type    Bind   Vis      Ndx Name"
        format = "%6d: %016x  %4d %-7s %-6s %-7s  %-3s %s"
    print header
    for i, value in enumerate(table.symtab):
        type = names['sym_type'][value.info&0xf]
        bind = names['sym_bind'][value.info>>4]
        if value.shndx>999:  ndx = "ABS"
        elif value.shndx==0: ndx = "UND"
        else:                ndx = "%3d"%value.shndx
        print format%(i, value.value, value.size, type, bind, "DEFAULT", ndx, value.name)



options = {}
opts, args = getopt.getopt(sys.argv[1:], "hrsd", ["help", "Relocation sections", "Symbol Table", "Dynamic symbols"])
for opt, arg in opts:
    if opt == '-h':
        print >> sys.stderr, "Usage: readelf.py [-hrs] elf-file(s)"
        sys.exit(1)
    elif opt == '-r':
        options['reltab'] = True
    elif opt == '-s':
        options['symtab'] = True
    elif opt == '-d':
        options['dynsym'] = True

names = elf_init.compute_elf_constant_names()
for file in args:
    if len(args) > 1:
        print "\nFile: %s" % file
    raw = open(file, 'rb').read()
    e = elf_init.ELF(raw)
    if 'reltab' in options:
        for sh in e.sh:
            display_reloc(e, sh)
    if 'symtab' in options:
        display_symbols(e, 'symtab')
    if 'dynsym' in options:
        display_symbols(e, 'dynsym')
