#! /usr/bin/env python
import sys, os

if sys.version_info[0] == 2 and sys.version_info[1] < 5:
    sys.stderr.write("python version older than 2.5 is not supported\n")
    exit(1)

sys.path.insert(1, os.path.abspath(sys.path[0]+'/..'))
from elfesteem import elf_init, elf

et_strings = {
    elf.ET_REL: 'REL (Relocatable file)',
    elf.ET_EXEC: 'EXEC (Executable file)',
    elf.ET_DYN: 'DYN (Shared object file)',
    elf.ET_CORE: 'CORE (Core file)',
    }
def expand_code(table, val):
    if val in table: return table[val]
    return '<unknown>: %#x' % val

def display_headers(e):
    print("ELF Header:")
    import struct
    ident = struct.unpack('16B', e.Ehdr.ident)
    print("  Magic:   %s"%' '.join(['%02x'%_ for _ in ident]))
    print("  Class:                             %s"%expand_code({
        elf.ELFCLASS32: 'ELF32',
        elf.ELFCLASS64: 'ELF64',
        }, ident[elf.EI_CLASS]))
    print("  Data:                              %s"%expand_code({
        elf.ELFDATA2LSB: "2's complement, little endian",
        elf.ELFDATA2MSB: "2's complement, big endian",
        }, ident[elf.EI_DATA]))
    print("  Version:                           %s"%expand_code({
        1: '1 (current)',
        }, ident[elf.EI_VERSION]))
    print("  OS/ABI:                            %s"%expand_code({
        0: 'UNIX - System V',
        }, ident[elf.EI_OSABI]))
    print("  ABI Version:                       %d"%ident[elf.EI_ABIVERSION])
    print("  Type:                              %s"%expand_code(et_strings, e.Ehdr.type))
    machine_code = dict(elf.constants['EM'])
    # Same textual output as readelf, from readelf.c
    machine_code[elf.EM_M32]            = 'ME32100'
    machine_code[elf.EM_SPARC]          = 'Sparc'
    machine_code[elf.EM_386]            = 'Intel 80386'
    machine_code[elf.EM_68K]            = 'MC68000'
    machine_code[elf.EM_88K]            = 'MC88000'
    machine_code[elf.EM_486]            = 'Intel 80486'
    machine_code[elf.EM_860]            = 'Intel 80860'
    machine_code[elf.EM_MIPS]           = 'MIPS R3000'
    machine_code[elf.EM_S370]           = 'IBM System/370'
    machine_code[elf.EM_MIPS_RS3_LE]    = 'MIPS R4000 big-endian'
    machine_code[elf.EM_PARISC]         = 'HPPA'
    machine_code[elf.EM_SPARC32PLUS]    = 'Sparc v8+'
    machine_code[elf.EM_960]            = 'Intel 80960'
    machine_code[elf.EM_PPC]            = 'PowerPC'
    machine_code[elf.EM_PPC64]          = 'PowerPC64'
    machine_code[elf.EM_V800]           = 'NEC V800'
    machine_code[elf.EM_FR20]           = 'Fujitsu FR20'
    machine_code[elf.EM_RH32]           = 'TRW RH32'
    machine_code[elf.EM_ARM]            = 'ARM'
    machine_code[elf.EM_FAKE_ALPHA]     = 'Digital Alpha (old)'
    machine_code[elf.EM_SH]             = 'Renesas / SuperH SH'
    machine_code[elf.EM_SPARCV9]        = 'Sparc v9'
    machine_code[elf.EM_TRICORE]        = 'Siemens Tricore'
    machine_code[elf.EM_ARC]            = 'ARC'
    machine_code[elf.EM_H8_300]         = 'Renesas H8/300'
    machine_code[elf.EM_H8_300H]        = 'Renesas H8/300H'
    machine_code[elf.EM_H8S]            = 'Renesas H8S'
    machine_code[elf.EM_H8_500]         = 'Renesas H8/500'
    machine_code[elf.EM_IA_64]          = 'Intel IA-64'
    machine_code[elf.EM_MIPS_X]         = 'Stanford MIPS-X'
    machine_code[elf.EM_COLDFIRE]       = 'Motorola Coldfire'
    print("  Machine:                           %s"%expand_code(machine_code, e.Ehdr.machine))
    """
    TO BE CONTINUED
                ("version","u32"),
                ("entry","ptr"),
                ("phoff","ptr"),
                ("shoff","ptr"),
                ("flags","u32"),
                ("ehsize","u16"),
                ("phentsize","u16"),
                ("phnum","u16"),
                ("shentsize","u16"),
                ("shnum","u16"),
                ("shstrndx","u16") ]
    """

def display_program_headers(e):
    # Output format similar to readelf -l
    if len(e.ph.phlist) == 0:
        print("\nThere are no program headers in this file.")
        return
    print("\nElf file type is %s" % expand_code(et_strings, e.Ehdr.type))
    print("Entry point 0x%x" % e.Ehdr.entry)
    print("There are %d program headers, starting at offset %d" % (e.Ehdr.phnum, e.Ehdr.phoff))
    print("\nProgram Headers:")
    if e.wsize == 32:
        header = "  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align"
        format = "  %-14s 0x%06x 0x%08x 0x%08x 0x%05x 0x%05x %-3s 0x%x"
    elif e.wsize == 64:
        header = "  Type           Offset             VirtAddr           PhysAddr\n                FileSiz            MemSiz              Flags  Align"
        format = "  %-14s 0x%016x 0x%016x 0x%016x\n                0x%016x 0x%016x  %-3s    %x"
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
            print('      [Requesting program interpreter: %s]' % e[s.sh.offset:s.sh.offset+s.sh.size].strip('\0'))
    if len(e.sh.shlist) == 0:
        return
    print("\n Section to Segment mapping:")
    print("  Segment Sections...")
    for i, p in enumerate(e.ph):
        res = "   %02d     " % i
        for s in p.shlist:
            res += s.sh.name + " "
        print(res)

def display_dynamic(e):
    machine = elf.constants['EM'][e.Ehdr.machine]
    for i, sh in enumerate(e.sh):
        if sh.sh.type != elf.SHT_DYNAMIC:
            continue
        if e.wsize == 32:
            header = "  Tag        Type                         Name/Value"
            format = "%#010x %-28s  %s"
            dyntab = sh.dyntab[:-2]
        elif e.wsize == 64:
            header = "  Tag        Type                         Name/Value"
            format = "%#018x %-20s  %s"
            dyntab = sh.dyntab[:-1]
        print("\nDynamic section at offset %#x contains %d entries:" % (sh.sh.offset, len(dyntab)))
        print(header)
        for d in dyntab:
            type = elf.constants['DT'].get(machine, {}).get(d.type, None)
            if type is None: type = elf.constants['DT'].get(d.type, None)
            else: type = machine + '_' + type
            if type in ('NEEDED',):
                name = 'Shared library: [%s]' % d.name
            elif type in ('STRSZ','SYMENT','RELSZ','RELENT','PLTRELSZ','RELASZ'):
                name = '%d (bytes)' % d.name
            elif type in ('PLTGOT','HASH','STRTAB','SYMTAB','INIT','FINI','REL',
                          'JMPREL','DEBUG','RELA',
                          'CHECKSUM','VERNEED',
                          'GNU_HASH',
                          'MIPS_BASE_ADDRESS','MIPS_LIBLIST','MIPS_GOTSYM',
                          'MIPS_HIDDEN_GOTIDX','MIPS_PROTECTED_GOTIDX',
                          'MIPS_LOCAL_GOTIDX','MIPS_LOCALPAGE_GOTIDX',
                          'MIPS_SYMBOL_LIB','MIPS_MSYM','MIPS_CONFLICT',
                          'MIPS_RLD_MAP','MIPS_OPTIONS',
                          'MIPS_INTERFACE','MIPS_INTERFACE_SIZE'):
                name = '%#x' % d.name
            elif type == 'PLTREL':
                name = elf.constants['DT'].get(d.name, d.name)
            elif type == 'MIPS_FLAGS':
                if d.name == 0:
                    name = 'NONE'
                else:
                    flags = ('QUICKSTART', 'NOTPOT', 'NO_LIBRARY_REPLACEMENT',
                             'NO_MOVE', 'SGI_ONLY', 'GUARANTEE_INIT',
                             'DELTA_C_PLUS_PLUS', 'GUARANTEE_START_INIT',
                             'PIXIE', 'DEFAULT_DELAY_LOAD', 'REQUICKSTART',
                             'REQUICKSTARTED', 'CORD', 'NO_UNRES_UNDEF',
                             'RLD_ORDER_SAFE')
                    name = ' '.join([ f for (f,b)
                                        in zip(flags,reversed(bin(d.name)[2:]))
                                        if b == '1' ])
            else:
                name = d.name
            output = format%(d.type, '(%s)'%type, name)
            print(output)


def display_symbols(e, table_name):
    # Output format similar to readelf -s or readelf --dyn-syms
    if not table_name in e.sh.__dict__:
        print("Symbol table '.%s' missing" % table_name)
        return
    print(e.sh.__dict__[table_name].readelf_display())



if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', dest='options', action='append_const', const='headers',  help='Headers')
    parser.add_argument('-S', dest='options', action='append_const', const='sections', help='Sections')
    parser.add_argument('-r', dest='options', action='append_const', const='reltab',   help='Relocation sections')
    parser.add_argument('-s', dest='options', action='append_const', const='symtab',   help='Symbol table')
    parser.add_argument('-D', dest='options', action='append_const', const='dynsym',   help='Dynamic symbols')
    parser.add_argument('-d', dest='options', action='append_const', const='dynamic',  help='Dynamic section')
    parser.add_argument('-l', dest='options', action='append_const', const='program',  help='Program headers')
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
        if 'headers' in args.options:
            display_headers(e)
        if 'sections' in args.options:
            print(e.sh.readelf_display())
        if 'reltab' in args.options:
            # Same output as readelf -r
            for sh in e.sh:
                if not 'rel' in dir(sh): continue
                print("\n" + sh.readelf_display())
        if 'symtab' in args.options:
            # Same output as readelf -s
            display_symbols(e, 'symtab')
        if 'dynsym' in args.options:
            # Same output as readelf --dyn-syms
            display_symbols(e, 'dynsym')
        if 'dynamic' in args.options:
            display_dynamic(e)
        if 'program' in args.options:
            display_program_headers(e)
        if 'groups' in args.options:
            for sh in e.sh:
                if not sh.sh.type == elf.SHT_GROUP: continue
                print(sh.readelf_display())
