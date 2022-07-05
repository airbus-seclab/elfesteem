#! /usr/bin/env python

import sys, os
import time
import platform

sys.path.insert(1, os.path.abspath(sys.path[0]+'/..'))
from elfesteem import macho_init, macho
from elfesteem.cstruct import data_null, CBase

def print_header(e, **fargs):
    print("Mach header")
    print("      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags")
    print(" 0x%08x %7d %10d  0x%02x  %10u %5u %10u 0x%08x" %(e.Mhdr.magic,e.Mhdr.cputype ,e.Mhdr.cpusubtype & (0xffffffff ^ macho.CPU_SUBTYPE_MASK),(e.Mhdr.cpusubtype & macho.CPU_SUBTYPE_MASK) >> 24,e.Mhdr.filetype,e.Mhdr.ncmds,e.Mhdr.sizeofcmds,e.Mhdr.flags))

import subprocess
def popen_read_out_err(cmd):
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    p.stdin.close()
    return p.stdout.read() + p.stderr.read()

import re
def get_otool_version():
    otool_v = popen_read_out_err(["otool", "--version"])
    if type(otool_v) != str: otool_v = str(otool_v, encoding='latin1')
    r = re.search(r' LLVM version (\d+)', otool_v)
    if r:
        return int(r.groups()[0])
    else:
        sys.stderr.write("Could not detect otool version\n")
        sys.stderr.write(otool_v)
        return None

def split_integer(v, nbits, ndigits, truncate=None):
    mask = (1<<nbits)-1
    res = []
    while ndigits > 0:
        res.insert(0, v & mask)
        v = v >> nbits
        ndigits -= 1
    res[0] += v << nbits
    if truncate is not None:
        while len(res) > truncate and res[-1] == 0:
            res = res[:-1]
    return ".".join(["%u"%_ for _ in res])

def print_lc(e, llvm=False, **fargs):
    for i, lc in enumerate(e.load):
        print("Load command %u" %i)
        print("\n".join(lc.otool(llvm=llvm)))



def print_symbols(e, **fargs):
    for sect in e.sect:
        if type(sect) != macho_init.SymbolTable:
            continue
        print("%-35s %-15s %-4s %-10s %s"%("Symbol","Section","Type","Value","Description"))
        for symbol in sect.symbols:
            print(symbol.otool())

def print_dysym(e, **fargs):
    # Display indirect symbol tables
    for sect in e.sect:
        if getattr(sect, 'type', None) is None:
            continue
        elif sect.type == 'indirectsym':
            print("Indirect symbols [%d entries]"%len(sect))
            print("%5s %s"%("index","name"))
            for entry in sect:
                entry = entry.index
                if   entry == macho.INDIRECT_SYMBOL_LOCAL:
                    print("%5s" % "LOCAL")
                elif entry == macho.INDIRECT_SYMBOL_ABS:
                    print("%5s" % "ABSOLUTE")
                elif 0 <= entry < len(e.symbols.symbols):
                    print("%5s %s" % (entry,e.symbols.symbols[entry].name))
                else:
                    print("INVALID(%d)" % entry)
        elif sect.type == 'locrel':
            print("Local relocations [%d entries]"%len(sect))
            for entry in sect:
                print(repr(entry))
        elif sect.type == 'extrel':
            print("External relocations [%d entries]"%len(sect))
            for entry in sect:
                print(repr(entry))

def print_indirect(e, **fargs):
    # Find section with indirect symbols and indirect symbols table
    indirectsym_table = None
    indirectsym_section = []
    for s in e.sect:
        if getattr(s, 'type', None) == 'indirectsym':
            if indirectsym_table is not None:
                raise ValueError("Only one IndirectSymbolTable per Mach-O file")
            indirectsym_table = s
        if not hasattr(s, 'sh'): continue
        if s.sh.type in [
                macho.S_SYMBOL_STUBS,
                macho.S_LAZY_SYMBOL_POINTERS,
                macho.S_NON_LAZY_SYMBOL_POINTERS,
                macho.S_LAZY_DYLIB_SYMBOL_POINTERS,
                ]:
            indirectsym_section.append(s)
    # Display
    verbose = False # Exactly the same output as 'otool -Iv'
    import struct
    idx = 0
    for s in indirectsym_section:
        print("Indirect symbols for (%s,%s) %u entries"
           % (s.sh.segname, s.sh.sectname, len(s)))
        if e.wsize == 64:
            header = "%-18s %5s"
            format = "0x%016x %5s"
            valfmt = e.sex+"Q"
        if e.wsize == 32:
            header = "%-10s %5s"
            format = "0x%08x %5s"
            valfmt = e.sex+"I"
        if s.sh.type == macho.S_SYMBOL_STUBS:
            # First two bytes are 0xff 0x25
            valfmt = e.sex+"HI"
        address = s.addr
        data = [ "address", "index", " name" ]
        if verbose:
            # The value read in the table is not output by otool
            # it may be useless ???
            header += "%-20s "
            format += "%-20s "
            data += "value"
        header += "%s"
        format += "%s"
        print(header % tuple(data))
        for entry in s:
            if verbose: content = struct.unpack(valfmt,entry.content)[-1]
            index = indirectsym_table.entries[idx].index
            name = ''
            if   index == macho.INDIRECT_SYMBOL_LOCAL: index = "LOCAL"
            elif index == macho.INDIRECT_SYMBOL_ABS:   index = "ABSOLUTE"
            else:  name = ' '+e.symbols.symbols[index].name
            data = [ address, index, name ]
            if verbose: data.append(content)
            print(format % tuple(data))
            idx += 1
            address += entry.bytelen

def print_relocs(e, **fargs):
    for s in e.sect:
        if not hasattr(s, 'reloclist'): continue
        print("Relocation information (%s,%s) %u entries"
           % (s.sh.segname, s.sh.sectname, s.sh.nreloc))
        print("address  pcrel length extern type    scattered symbolnum/value")
        for x in s.reloclist:
            if x.scattered: xt, xn = 'n/a', '0x%08x' % x.symbolNumOrValue
            else:           xt, xn = x.extern, '%u' % x.symbolNumOrValue
            print("%08x %-5u %-6u %-6s %-7d %-9d %s" %
                (x.address, x.pcrel, x.length, xt, x.type, x.scattered, xn))

def print_opcodes(e, **fargs):
    messages_and_values = (
        ('rebase_', macho.REBASE_OPCODE_DONE,
         'rebase opcodes:', 'no compressed rebase info'),
        ('bind_', macho.BIND_OPCODE_DONE,
         'binding opcodes:', 'no compressed binding info'),
        ('weak_bind_', macho.BIND_OPCODE_DONE,
         'weak binding opcodes:', 'no compressed weak binding info'),
        ('lazy_bind_', -1,
         'lazy binding opcodes:', 'no compressed lazy binding info'),
        )
    for t, v, ok, ko in messages_and_values:
        s_list = [ _ for _ in e.sect if getattr(_, 'type', None) == t ]
        if len(s_list) == 0:
            print(ko)
            continue
        if len(s_list) > 1:
            print("ERROR: many sections with %s"%t[:-1])
        for s in s_list:
            print(ok)
            for x in s._array:
                print(x)
                if x.opcode == v:
                    break

def print_rebase(e, **fargs):
    for s in e.sect:
        if getattr(s, 'type', None) != 'rebase_': continue
        print("rebase information (from compressed dyld info):")
        print("segment section          address     type")
        for x in s.info: print(x)

def print_bind(e, **fargs):
    for s in e.sect:
        if getattr(s, 'type', None) != 'bind_': continue
        print("bind information:")
        print("segment section          address        type    addend dylib            symbol")
        for x in s.info: print(x)
        break
    else:
        print("no compressed binding info")

def print_weak_bind(e, **fargs):
    for s in e.sect:
        if getattr(s, 'type', None) != 'weak_bind_': continue
        print("weak binding information:")
        print("segment section          address       type     addend symbol")
        for x in s.info: print(x)
        break
    else:
        print("no weak binding")

def print_lazy_bind(e, **fargs):
    for s in e.sect:
        if getattr(s, 'type', None) != 'lazy_bind_': continue
        print("lazy binding information (from lazy_bind part of dyld info):")
        print("segment section          address    index  dylib            symbol")
        for x in s.info: print(x)
        break
    else:
        print("no compressed lazy binding info")

def print_export(e, **fargs):
    for s in e.sect:
        if getattr(s, 'type', None) != 'export_': continue
        print("export information (from trie):")
        for x in sorted(s.info, key=lambda _:_.addr): print(x)
        break
    else:
        print("no compressed export info")

archi = {
    (macho.CPU_TYPE_MC680x0,   macho.CPU_SUBTYPE_MC680x0_ALL):  'm68k',
    (macho.CPU_TYPE_MC680x0,   macho.CPU_SUBTYPE_MC68030_ONLY): 'm68030',
    (macho.CPU_TYPE_MC680x0,   macho.CPU_SUBTYPE_MC68040):      'm68040',
    (macho.CPU_TYPE_MC88000,   macho.CPU_SUBTYPE_MC88000_ALL):  'm88k',
    (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_I386_ALL):     'i386',
    (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_486):          'i486',
    (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_486SX):        'i486SX',
    (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_PENT):         'pentium',
    (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_PENTPRO):      'pentpro',
    #macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_PENTIUM_4):    'pentium4',
    (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_PENTII_M3):    'pentIIm3',
    (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_PENTII_M5):    'pentIIm5',
    (macho.CPU_TYPE_X86_64,    macho.CPU_SUBTYPE_X86_64_ALL):   'x86_64',
    (macho.CPU_TYPE_X86_64,    macho.CPU_SUBTYPE_X86_64_H):     'x86_64h',
    (macho.CPU_TYPE_I860,      macho.CPU_SUBTYPE_I860_ALL):     'i860',
    (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_ALL):  'ppc',
    (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_601):  'ppc601',
    (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_603):  'ppc602',
    (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_603):  'ppc603',
    (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_603e): 'ppc603e',
    (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_603ev):'ppc603ev',
    (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_604):  'ppc604',
    (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_604e): 'ppc604e',
    (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_620):  'ppc620',
    (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_750):  'ppc750',
    (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_7400): 'ppc7400',
    (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_7450): 'ppc7450',
    (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_970):  'ppc970',
    (macho.CPU_TYPE_POWERPC64, macho.CPU_SUBTYPE_POWERPC64_ALL):'ppc64',
    (macho.CPU_TYPE_POWERPC64, macho.CPU_SUBTYPE_POWERPC_970):  'ppc970-64',
    (macho.CPU_TYPE_VEO,       macho.CPU_SUBTYPE_VEO_ALL):      'veo',
    (macho.CPU_TYPE_VEO,       macho.CPU_SUBTYPE_VEO_1):        'veo1',
    (macho.CPU_TYPE_VEO,       macho.CPU_SUBTYPE_VEO_2):        'veo2',
    (macho.CPU_TYPE_VEO,       macho.CPU_SUBTYPE_VEO_3):        'veo3',
    (macho.CPU_TYPE_VEO,       macho.CPU_SUBTYPE_VEO_4):        'veo4',
    (macho.CPU_TYPE_HPPA,      macho.CPU_SUBTYPE_HPPA_ALL):     'hppa',
    (macho.CPU_TYPE_HPPA,      macho.CPU_SUBTYPE_HPPA_7100LC):  'hppa7100LC',
    (macho.CPU_TYPE_SPARC,     macho.CPU_SUBTYPE_SPARC_ALL):    'sparc',
    (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_ALL):      'arm',
    (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_V4T):      'armv4t',
    (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_V5TEJ):    'armv5',
    (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_XSCALE):   'xscale',
    (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_V6):       'armv6',
    (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_V6M):      'armv6m',
    (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_V7):       'armv7',
    (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_V7F):      'armv7f',
    (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_V7S):      'armv7s',
    (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_V7K):      'armv7k',
    (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_V7M):      'armv7m',
    (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_V7EM):     'armv7em',
    (macho.CPU_TYPE_ARM64,     macho.CPU_SUBTYPE_ARM64_ALL):    'arm64',
    (macho.CPU_TYPE_ARM64,     macho.CPU_SUBTYPE_ARM64_V8):     'arm64v8',
    }

def arch_name(e):
    return archi[(e.Mhdr.cputype,
        e.Mhdr.cpusubtype & (0xffffffff ^ macho.CPU_SUBTYPE_MASK))]

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    # Simulates 'otool'
    parser.add_argument('-arch', dest='arch_type', action='append', help='select architecture')
    parser.add_argument('-h', dest='options', action='append_const', const='header', help='print the mach header')
    parser.add_argument('-l', dest='options', action='append_const', const='load', help='print the load commands')
    parser.add_argument('--symbols', dest='options', action='append_const', const='symbols', help='print the symbols')
    parser.add_argument('--dysym', dest='options', action='append_const', const='dysym', help='print dynamic symbols')
    parser.add_argument('-r', dest='options', action='append_const', const='reloc', help='Display the relocation entries')
    parser.add_argument('-I', dest='options', action='append_const', const='indirect', help='Display the indirect symbol table')
    parser.add_argument('--llvm', dest='llvm_version', action='append', help='Simulate the output of a given version of llvm-otool')
    # Simulates 'dyldinfo'
    parser.add_argument('-opcodes', dest='options', action='append_const', const='opcodes', help='opcodes used to generate the rebase and binding information')
    parser.add_argument('-rebase', dest='options', action='append_const', const='rebase', help='addresses dyld will adjust if file not loaded at preferred address')
    parser.add_argument('-bind', dest='options', action='append_const', const='bind', help='addresses dyld will set based on symbolic lookups')
    parser.add_argument('-weak_bind', dest='options', action='append_const', const='weak_bind', help='symbols which dyld must coalesce')
    parser.add_argument('-lazy_bind', dest='options', action='append_const', const='lazy_bind', help='addresses dyld will lazily set on first use')
    parser.add_argument('-export', dest='options', action='append_const', const='export', help='addresses of all symbols this file exports')
    parser.add_argument('file', nargs='*', help='object file')
    args = parser.parse_args()
    if args.options == None:
        args.options = []
    if len(args.file) == 0:
        parser.print_help()
    functions = []
    fargs = {}
    dyldinfo_simulation = False
    if args.llvm_version:
        # Hypothesis: the major number of the version of Xcode is sufficient
        # to determine what the output format of llvm-otool is.
        for llvm in args.llvm_version:
            if 'native' in llvm:
                fargs['llvm'] = get_otool_version()
            else:
                fargs['llvm'] = int(llvm)
    if 'header' in args.options:
        functions.append(print_header)
    if 'load' in args.options:
        if fargs.get('llvm',8) in (8, 9, 10, 11) and not 'header' in args.options:
            functions.append(print_header)
        functions.append(print_lc)
    if 'symbols' in args.options:
        functions.append(print_symbols)
    if 'dysym' in args.options:
        functions.append(print_dysym)
    if 'reloc' in args.options:
        functions.append(print_relocs)
    if 'indirect' in args.options:
        functions.append(print_indirect)
    if 'rebase' in args.options:
        functions.append(print_rebase)
        dyldinfo_simulation = True
    if 'bind' in args.options:
        functions.append(print_bind)
        dyldinfo_simulation = True
    if 'weak_bind' in args.options:
        functions.append(print_weak_bind)
        dyldinfo_simulation = True
    if 'lazy_bind' in args.options:
        functions.append(print_lazy_bind)
        dyldinfo_simulation = True
    if 'export' in args.options:
        functions.append(print_export)
        dyldinfo_simulation = True
    if 'opcodes' in args.options:
        functions.append(print_opcodes)
        dyldinfo_simulation = True

    for file in args.file:
        raw = open(file, 'rb').read()
        filesize = os.path.getsize(file)
        try:
            e = macho_init.MACHO(raw,
                parseSymbols = False)
        except ValueError as err:
            print("%s:" %file)
            print("    %s" % err)
            continue
        if args.arch_type is None:
            if hasattr(e, 'Fhdr'):
                # Select the current architecture, if present
                current = platform.machine()
                for _ in e.arch:
                    if current == arch_name(_):
                        e = _
                        break
                else:
                    # Display all architectures
                    e = [ _ for _ in e.arch ]
        elif 'all' in args.arch_type:
            if hasattr(e, 'Fhdr'):
                # Display all architectures
                e = [ _ for _ in e.arch ]
        elif len(args.arch_type) == 1:
            if hasattr(e, 'Fhdr'):
                # Display one architecture
                current = args.arch_type[0]
                for _ in e.arch:
                    if current == arch_name(_):
                        e = _
                        break
                else:
                    sys.stderr.write("error: otool: file: %s does not contain architecture: %s\n" % (file, current))
                    e = []
            else:
                # Display if it is the architecture
                current = args.arch_type[0]
                if current != arch_name(e):
                    e = []
        else:
            if hasattr(e, 'Fhdr'):
                # Display some architectures, in the order appearing in the args
                f = []
                for current in args.arch_type:
                    for _ in e.arch:
                        if current == arch_name(_):
                            f.append(_)
                            break
                    else:
                        sys.stderr.write("error: otool: file: %s does not contain architecture: %s\n" % (file, current))
                e = f
            else:
                # Display if one is the architecture
                for current in args.arch_type:
                    if current == arch_name(e):
                        break
                else:
                    e = []

        if dyldinfo_simulation and len(args.file) > 1:
            print("\n%s:" %file)
        if hasattr(e, 'Mhdr'):
            if not dyldinfo_simulation and functions != [ print_header ]:
                print("%s:" %file)
            for f in functions:
                f(e, **fargs)
        else:
            for _ in e:
                t0 = _.Mhdr.cputype
                t1 = _.Mhdr.cpusubtype & (0xffffffff ^ macho.CPU_SUBTYPE_MASK)
                if dyldinfo_simulation:
                    print("for arch %s:" % arch_name(_))
                else:
                    if functions != [ print_header ]:
                        print("%s (architecture %s):" %(file, arch_name(_)))
                for f in functions:
                    f(_, **fargs)
