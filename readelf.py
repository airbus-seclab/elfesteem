#! /usr/bin/env python
import sys

if sys.version_info[0] == 2 and sys.version_info[1] < 5:
    sys.stderr.write("python version older than 2.5 is not supported\n")
    exit(1)

from elfesteem import elf_init, elf

def display_program_headers(e):
    # Output format similar to readelf -l
    if len(e.ph.phlist) == 0:
        print("\nThere are no program headers in this file.")
        return
    print("\nElf file type is", elf.constants['ET'][e.Ehdr.type])
    print("Entry point 0x%x" % e.Ehdr.entry)
    print("There are %d program headers, starting at offset %d" % (e.Ehdr.phnum, e.Ehdr.phoff))
    print("\nProgram Headers:")
    if e.wsize == 32:
        header = " Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align"
        format = " %-14s 0x%06x 0x%08x 0x%08x 0x%05x 0x%05x %-3s 0x%x"
    elif e.wsize == 64:
        header = " Type           Offset             VirtAddr           PhysAddr\n                FileSiz            MemSiz              Flags  Align"
        format = " %-14s 0x%016x 0x%016x 0x%016x\n                0x%016x 0x%016x  %-3s    %x"
    print(header)
    for p in e.ph:
        flags = [' ', ' ', ' ']
        if p.ph.flags & 4: flags[0] = 'R'
        if p.ph.flags & 2: flags[1] = 'W'
        if p.ph.flags & 1: flags[2] = 'E'
        print(format%(elf.constants['PT'][p.ph.type],
                         p.ph.offset, p.ph.vaddr, p.ph.paddr,
                         p.ph.filesz, p.ph.memsz, ''.join(flags),
                         p.ph.align))
        if p.ph.type == elf.PT_INTERP:
            s = p.shlist[0]
            print('     [Requesting program interpreter: %s]' % e[s.sh.offset:s.sh.offset+s.sh.size])
    if len(e.sh.shlist) == 0:
        return
    print("\nSection to Segment mapping:")
    print(" Segment Sections...")
    for i, p in enumerate(e.ph):
        res = "  %02d    " % i
        for s in p.shlist:
            res += s.sh.name
        print(res)

def display_reloc(e, sh):
    # Output format similar to readelf -r
    if not 'rel' in dir(sh):
        return
    print("\nRelocation section %r at offset 0x%x contains %d entries:" % (sh.sh.name, sh.sh.offset, len(sh.reltab)))
    if e.wsize == 32:
        header = " Offset     Info    Type            Sym.Value  Sym. Name"
        format = "%08x  %08x %-16s  %08x   %s"
    elif e.wsize == 64:
        header = "  Offset          Info           Type           Sym. Value     Sym. Name"
        format = "%012x  %012x %-16s  %016x  %s"
    if sh.sht == elf.SHT_RELA:
        header = header + " + Addend"
    elif sh.sht == elf.SHT_REL:
        pass
    else:
        Fail
    print(header)
    for r in sh.reltab:
        name = r.sym
        if name == '':
            name = e.sh[r.shndx].sh.name
        machine = elf.constants['EM'][e.Ehdr.machine]
        if machine == 'SPARC32PLUS': machine = 'SPARC'
        if machine == 'SPARCV9':     machine = 'SPARC'
        if hasattr(r, 'type1'):
            # MIPS64
            type = 'R_%s_%s' % (machine, elf.constants['R'][machine][r.type1])
        else:
            type = 'R_%s_%s' % (machine, elf.constants['R'][machine][r.type])
        output = format%(r.offset, r.info, type, r.value, name)
        if sh.sht == elf.SHT_RELA:
            if r.addend < 0: output = output + " - %x"%-r.addend
            else:            output = output + " + %x"%r.addend
        print(output)
        if hasattr(r, 'type1'):
            type = 'R_%s_%s' % (machine, elf.constants['R'][machine][r.type2])
            print("                    Type2: %-16s" % type)
            type = 'R_%s_%s' % (machine, elf.constants['R'][machine][r.type3])
            print("                    Type3: %-16s" % type)

def display_sections(e):
    if e.wsize == 32:
        header = "  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al"
        format = "  [%2d] %-17s %-15s %08x %06x %06x %02x %3s %2d  %2d %2d"
    elif e.wsize == 64:
        header = "  [Nr] Name              Type             Address           Offset\n       Size              EntSize          Flags  Link  Info  Align"
        format = "  [%2d] %-17s %-15s  %016x  %08x\n       %016x  %016x %3s      %2d    %2d    %2d"
    print(header)
    m = elf.constants['EM'][e.Ehdr.machine]
    for i, sh in enumerate(e.sh):
        flags = ""
        if sh.sh.flags & elf.SHF_WRITE:            flags += "W"
        if sh.sh.flags & elf.SHF_ALLOC:            flags += "A"
        if sh.sh.flags & elf.SHF_EXECINSTR:        flags += "X"
        if sh.sh.flags & elf.SHF_MERGE:            flags += "M"
        if sh.sh.flags & elf.SHF_STRINGS:          flags += "S"
        if sh.sh.flags & elf.SHF_INFO_LINK:        flags += "I"
        if sh.sh.flags & elf.SHF_LINK_ORDER:       flags += "L"
        if sh.sh.flags & elf.SHF_OS_NONCONFORMING: flags += "O"
        if sh.sh.flags & elf.SHF_GROUP:            flags += "G"
        if sh.sh.flags & elf.SHF_TLS:              flags += "T"
        if sh.sh.flags & elf.SHF_EXCLUDE:          flags += "E"
        if m in elf.constants['SHT'] and sh.sh.type in elf.constants['SHT'][m]:
            type = m+'_'+elf.constants['SHT'][m][sh.sh.type]
        elif sh.sh.type in elf.constants['SHT']:
            type = elf.constants['SHT'][sh.sh.type]
        elif elf.SHT_LOOS <= sh.sh.type <= elf.SHT_HIOS:
            type = "LOOS+%x"%(sh.sh.type - elf.SHT_LOOS)
        elif elf.SHT_LOPROC <= sh.sh.type <= elf.SHT_HIPROC:
            type = "LOPROC+%x"%(sh.sh.type - elf.SHT_LOPROC)
        elif elf.SHT_LOUSER <= sh.sh.type <= elf.SHT_HIUSER:
            type = "LOUSER+%x"%(sh.sh.type - elf.SHT_LOUSER)
        else:
            type = "Unknown%#x"%sh.sh.type
        if type == 'GNU_verdef':   type = 'VERDEF'
        if type == 'GNU_verneed':  type = 'VERNEED'
        if type == 'GNU_versym':   type = 'VERSYM'
        print(format%(i, sh.sh.name, type,
                         sh.sh.addr, sh.sh.offset,
                         sh.sh.size, sh.sh.entsize, flags,
                         sh.sh.link, sh.sh.info, sh.sh.addralign))

def display_groups(e):
    for i, sh in enumerate(e.sh):
        if sh.sh.type == elf.SHT_GROUP:
            if sh.flags == elf.GRP_COMDAT: flags = 'COMDAT'
            else: flags = ''
            symbol = e.sh[sh.sh.link]
            if not symbol.sh.type == elf.SHT_SYMTAB:
                print("readelf: Error: Bad sh_link in group section `%s'"%sh.sh.name)
                continue
            symbol = symbol[sh.sh.info].name
            print("%s group section [%4d] `%s' [%s] contains %d sections:"%(
                flags,i,sh.sh.name,symbol,len(sh.sections)))
            format = "   [%5s]   %s"
            print(format%('Index',' Name'))
            for s in sh.sections:
                print(format%(s,e.sh[s].sh.name))
                if not (e.sh[s].sh.flags & elf.SHF_GROUP):
                    print("No SHF_GROUP in %s"%e.sh[s].sh.name)

def display_symbols(e, table_name):
    # Output format similar to readelf -s or readelf --dyn-syms
    if not table_name in e.sh.__dict__:
        print("Symbol table '.%s' missing" % table_name)
        return
    table = e.sh.__dict__[table_name]
    print("Symbol table '.%s' contains %d entries:" % (table_name, len(table.symtab)))
    if e.wsize == 32:
        header = "   Num:    Value  Size Type    Bind   Vis      Ndx Name"
        format = "%6d: %08x  %4d %-7s %-6s %-7s  %-3s %s"
    elif e.wsize == 64:
        header = "   Num:    Value          Size Type    Bind   Vis      Ndx Name"
        format = "%6d: %016x  %4d %-7s %-6s %-7s  %-3s %s"
    print(header)
    for i, value in enumerate(table.symtab):
        type = elf.constants['STT'][value.info&0xf]
        bind = elf.constants['STB'][value.info>>4]
        visibility = elf.constants['STV'][value.other]
        if value.shndx>999:  ndx = "ABS"
        elif value.shndx==0: ndx = "UND"
        else:                ndx = "%3d"%value.shndx
        print(format%(i, value.value, value.size, type, bind, visibility, ndx, value.name))



if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-S', dest='options', action='append_const', const='sections', help='Sections')
    parser.add_argument('-r', dest='options', action='append_const', const='reltab',   help='Relocation sections')
    parser.add_argument('-s', dest='options', action='append_const', const='symtab',   help='Symbol table')
    parser.add_argument('-d', dest='options', action='append_const', const='dynsym',   help='Dynamic symbols')
    parser.add_argument('-l', dest='options', action='append_const', const='program',   help='Program headers')
    parser.add_argument('-g', dest='options', action='append_const', const='groups',   help='Section groups')
    parser.add_argument('file', nargs='+', help='ELF file(s)')
    args = parser.parse_args()
    if args.options == None:
        args.options = []

    for file in args.file:
        if len(args.file) > 1:
            print("\nFile: %s" % file)
        raw = open(file, 'rb').read()
        e = elf_init.ELF(raw)
        if 'sections' in args.options:
            display_sections(e)
        if 'reltab' in args.options:
            for sh in e.sh:
                display_reloc(e, sh)
        if 'symtab' in args.options:
            display_symbols(e, 'symtab')
        if 'dynsym' in args.options:
            display_symbols(e, 'dynsym')
        if 'program' in args.options:
            display_program_headers(e)
        if 'groups' in args.options:
            display_groups(e)
