#! /usr/bin/env python

from optparse import OptionParser
from elfesteem import macho_init, macho, intervals
import os.path
import time
import platform
import sys

parser = OptionParser(usage = "usage: %prog [options] file")
parser.add_option('-l', "--loadcommands", action="store_true",dest="loadcommands",default=False,help="print the load commands")
parser.add_option('-H', "--header", action="store_true", dest="header", default=False, help="print the mach header")
parser.add_option('-b', "--symbols", action="store_true", dest="symbols", default=False, help="print the symbols")
parser.add_option('-A', "--arch", dest="architectures", help="enable the choice of a fat architecture")
(options, args) = parser.parse_args()

def print_header(e):
    print("Mach header")
    print("      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags")
    print(" 0x%08x %7d %10d  0x%02x %10u %5u %10u 0x%08x" %(e.Mhdr.magic,e.Mhdr.cputype ,e.Mhdr.cpusubtype & macho.CPU_SUBTYPE_MASK,(e.Mhdr.cpusubtype & macho.CPU_CAPS_MASK) >> 24,e.Mhdr.filetype,e.Mhdr.ncmds,e.Mhdr.sizeofcmds,e.Mhdr.flags))

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

def print_lc(e):
    for i,lc in enumerate(e.lh.lhlist):
        print("Load command %u" %i)
        lc_value = [
            ("cmd",     "LC_%s" %macho.constants['LC'][lc.cmd]),
            ("cmdsize", lc.cmdsize),
            ]
        shift = 1
        for name, _ in getattr(lc.lhc, '_fields', []):
            value = getattr(lc, name)
            if name in ["vmaddr", "vmsize"]:
                if lc.cmd == macho.LC_SEGMENT_64: value = "0x%016x" % value
                else:                             value = "0x%08x" % value
            elif name in ["maxprot", "initprot", "cksum"]:
                value = "0x%08x" % value
            elif name == "flags":
                value = "0x%x" % value
            elif name == "stroffset":
                name = "        name"
                value = "%s (offset %u)" %(lc.name, value)
            elif name == "timestamp":
                name = "time stamp"
                value = "%u %s" %(value, time.ctime(value))
            elif name in ["current_version", "compatibility_version"]:
                shift = 0
                name = name[:-8]
                value = "version " + split_integer(value, 8, 3)
            elif lc.cmd == macho.LC_VERSION_MIN_MACOSX:
                shift = 2
                value = split_integer(value, 8, 3, truncate=1)
            elif lc.cmd == macho.LC_VERSION_MIN_IPHONEOS:
                shift = 2
                value = split_integer(value, 8, 3, truncate=2)
            elif lc.cmd == macho.LC_SOURCE_VERSION:
                shift = 2
                value = split_integer(value, 10, 5, truncate=2)
            elif lc.cmd == macho.LC_UNIXTHREAD:
                shift = 4
                break
            lc_value.append((name, value))
        if lc.cmd == macho.LC_UUID:
            lc_value.append(("uuid", "%.8X-%.4X-%.4X-%.4X-%.4X%.8X" % lc.uuid))

        # otool displays lc_value with a nice alignment
        name_max_len = 0
        for name, _ in lc_value:
            if name_max_len < len(name):
                name_max_len = len(name)
        format = "%%%ds %%s" % (name_max_len+shift)
        for pair in lc_value:
            print format % pair
        # for some load command, additional information is displayed

        if lc.cmd == macho.LC_SEGMENT or lc.cmd == macho.LC_SEGMENT_64:
            if hasattr(lc,'sectionsToAdd'):
                for s in lc.sectionsToAdd(e):
                    if not hasattr(s, 'reloclist') :
                        #PRINT SECTION
                        print("Section")
                        print("  sectname %.16s" %s.sh.sectname)
                        print("   segname %.16s" %s.sh.segname)
                        if lc.cmd == macho.LC_SEGMENT_64:
                            print("      addr 0x%016x" %s.sh.addr)
                            print("      size 0x%016x" %s.sh.size)
                        else:
                            print("      addr 0x%08x" %s.sh.addr)
                            print("      size 0x%08x" %s.sh.size)
                        print("    offset %u" %s.sh.offset)
                        print("     align 2^%u (%d)" %(s.sh.align, 1 << s.sh.align))
                        print("    reloff %u" %s.sh.reloff)
                        print("    nreloc %u" %s.sh.nreloc)
                        print("     flags 0x%08x" %s.sh.all_flags)
                        comment1 = ""
                        if s.sh.type == macho.S_SYMBOL_STUBS or s.sh.type == macho.S_LAZY_SYMBOL_POINTERS or s.sh.type == macho.S_NON_LAZY_SYMBOL_POINTERS :
                            comment1 = " (index into indirect symbol table)"
                        print(" reserved1 %u%s" %(s.sh.reserved1,comment1))
                        comment2 = ""
                        if s.sh.type == macho.S_SYMBOL_STUBS:
                            comment2 = " (size of stubs)"
                        print(" reserved2 %u%s" %(s.sh.reserved2,comment2))

        elif lc.cmd == macho.LC_UNIXTHREAD:
            if e.Mhdr.cputype == macho.CPU_TYPE_POWERPC:
                print("     flavor PPC_THREAD_STATE")
                print("      count PPC_THREAD_STATE_COUNT")
                print("    r0  0x%08x r1  0x%08x r2  0x%08x r3   0x%08x r4   0x%08x" %(lc.data[2], lc.data[3], lc.data[4], lc.data[5], lc.data[6]))
                print("    r5  0x%08x r6  0x%08x r7  0x%08x r8   0x%08x r9   0x%08x" %(lc.data[7], lc.data[8], lc.data[9], lc.data[10], lc.data[11]))
                print("    r10 0x%08x r11 0x%08x r12 0x%08x r13  0x%08x r14  0x%08x" %(lc.data[12], lc.data[13], lc.data[14], lc.data[15], lc.data[16]))
                print("    r15 0x%08x r16 0x%08x r17 0x%08x r18  0x%08x r19  0x%08x" %(lc.data[17], lc.data[18], lc.data[19], lc.data[20], lc.data[21]))
                print("    r20 0x%08x r21 0x%08x r22 0x%08x r23  0x%08x r24  0x%08x" %(lc.data[22], lc.data[23], lc.data[24], lc.data[25], lc.data[26]))
                print("    r25 0x%08x r26 0x%08x r27 0x%08x r28  0x%08x r29  0x%08x" %(lc.data[27], lc.data[28], lc.data[29], lc.data[30], lc.data[31]))
                print("    r30 0x%08x r31 0x%08x cr  0x%08x xer  0x%08x lr   0x%08x" %(lc.data[32], lc.data[33], lc.data[34], lc.data[35], lc.data[36]))
                print("    ctr 0x%08x mq  0x%08x vrsave 0x%08x srr0 0x%08x srr1 0x%08x" %(lc.data[37], lc.data[38], lc.data[39], lc.data[0], lc.data[1]))
            elif e.Mhdr.cputype == macho.CPU_TYPE_POWERPC64:
                print("     flavor PPC_THREAD_STATE64")
                print("      count PPC_THREAD_STATE64_COUNT")
                print("    r0  0x%016x r1  0x%016x r2   0x%016x" %(lc.data[2], lc.data[3],lc.data[4]))
                print("    r3  0x%016x r4  0x%016x r5   0x%016x" %(lc.data[5], lc.data[6], lc.data[7]))
                print("    r6  0x%016x r7  0x%016x r8   0x%016x" %(lc.data[8], lc.data[9], lc.data[10]))
                print("    r9  0x%016x r10 0x%016x r11  0x%016x" %(lc.data[11], lc.data[12], lc.data[13]))
                print("   r12  0x%016x r13 0x%016x r14  0x%016x" %(lc.data[14], lc.data[15], lc.data[16]))
                print("   r15  0x%016x r16 0x%016x r17  0x%016x" %(lc.data[17], lc.data[18], lc.data[19]))
                print("   r18  0x%016x r19 0x%016x r20  0x%016x" %(lc.data[20], lc.data[21], lc.data[22]))
                print("   r21  0x%016x r22 0x%016x r23  0x%016x" %(lc.data[23], lc.data[24], lc.data[25]))
                print("   r24  0x%016x r25 0x%016x r26  0x%016x" %(lc.data[26], lc.data[27], lc.data[28]))
                print("   r27  0x%016x r28 0x%016x r29  0x%016x" %(lc.data[29], lc.data[30], lc.data[31]))
                print("   r30  0x%016x r31 0x%016x cr   0x%08x" %(lc.data[32], lc.data[33], lc.data[34]))
                print("   xer  0x%016x lr  0x%016x ctr  0x%016x" %(lc.data[35], lc.data[36], lc.data[37]))
                print("vrsave  0x%08x        srr0 0x%016x srr1 0x%016x" %(lc.data[38], lc.data[0], lc.data[1]))
            elif e.Mhdr.cputype == macho.CPU_TYPE_I386:
                print("     flavor i386_THREAD_STATE")
                print("      count i386_THREAD_STATE_COUNT")
                print("\t    eax 0x%08x ebx    0x%08x ecx 0x%08x edx 0x%08x" %(lc.data[0], lc.data[1],lc.data[2], lc.data[3]))
                print("\t    edi 0x%08x esi    0x%08x ebp 0x%08x esp 0x%08x" %(lc.data[4], lc.data[5],lc.data[6], lc.data[7]))
                print("\t    ss  0x%08x eflags 0x%08x eip 0x%08x cs  0x%08x" %(lc.data[8], lc.data[9],lc.data[10], lc.data[11]))
                print("\t    ds  0x%08x es     0x%08x fs  0x%08x gs  0x%08x" %(lc.data[12], lc.data[13],lc.data[14], lc.data[15]))
            elif e.Mhdr.cputype == macho.CPU_TYPE_X86_64:
                print("     flavor x86_THREAD_STATE64")
                print("      count x86_THREAD_STATE64_COUNT")
                print("   rax  0x%016x rbx 0x%016x rcx  0x%016x" %(lc.data[0], lc.data[1],lc.data[2]))
                print("   rdx  0x%016x rdi 0x%016x rsi  0x%016x" %(lc.data[3], lc.data[4],lc.data[5]))
                print("   rbp  0x%016x rsp 0x%016x r8   0x%016x" %(lc.data[6], lc.data[7],lc.data[8]))
                print("    r9  0x%016x r10 0x%016x r11  0x%016x" %(lc.data[9], lc.data[10],lc.data[11]))
                print("   r12  0x%016x r13 0x%016x r14  0x%016x" %(lc.data[12], lc.data[13],lc.data[14]))
                print("   r15  0x%016x rip 0x%016x" %(lc.data[15], lc.data[16]))
                print("rflags  0x%016x cs  0x%016x fs   0x%016x" %(lc.data[17], lc.data[18],lc.data[19]))
                print("    gs  0x%016x" %(lc.data[20]))
            elif e.Mhdr.cputype == macho.CPU_TYPE_ARM:
                print("     flavor ARM_THREAD_STATE")
                print("      count ARM_THREAD_STATE_COUNT")
                print("\t    r0  0x%08x r1     0x%08x r2  0x%08x r3  0x%08x" %(lc.data[0], lc.data[1],lc.data[2],lc.data[3]))
                print("\t    r4  0x%08x r5     0x%08x r6  0x%08x r7  0x%08x" %(lc.data[4], lc.data[5],lc.data[6],lc.data[7]))
                print("\t    r8  0x%08x r9     0x%08x r10 0x%08x r11 0x%08x" %(lc.data[8], lc.data[9],lc.data[10],lc.data[11]))
                print("\t    r12 0x%08x sp     0x%08x lr  0x%08x pc  0x%08x" %(lc.data[12], lc.data[13],lc.data[14],lc.data[15]))
                print("\t   cpsr 0x%08x" %lc.data[16])

        elif lc.cmd == macho.LC_LINKER_OPTION:
            for i, s in enumerate(lc.strings):
                print("  string #%d %s" % (i+1, s))



def print_symbols(e):
    for sect in e.sect.sect:
        if type(sect) != macho_init.SymbolTable:
            continue
        print("%-35s %-15s %-4s %-10s %s"%("Symbol","Section","Type","Value","Description"))
        for value in sect.symbols:
            n_type = {
                macho.N_UNDF: 'U',
                macho.N_ABS : 'A',
                macho.N_SECT: 'S',
                macho.N_PBUD: 'P',
                macho.N_INDR: 'I',
                }[value.type & macho.N_TYPE]
            n_type += [ ' ', 'X' ] [value.type & macho.N_EXT]
            n_type += [ ' ', 'X' ] [(value.type & macho.N_PEXT)>>4]
            if value.type & macho.N_STAB:
                n_type += 'D'
            desc = value.description
            if value.sectionindex == 0:
                section = "NO_SECT"
            else:
                section = e.sect.sect[value.sectionindex-1]
                section = "%s,%s"%(section.sh.segname,section.sh.sectname)
            print("%-35s %-15s %-4s 0x%08x %04x"%(value.name,section,n_type,value.value,desc))



if not args:
    parser.print_help()
    sys.exit(0)
    
archi = {(macho.CPU_TYPE_X86_64,    macho.CPU_SUBTYPE_X86_64_ALL): 'x86_64',
         (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_ALL): 'ppc',
         (macho.CPU_TYPE_POWERPC64, macho.CPU_SUBTYPE_POWERPC_ALL): 'ppc64',
         (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_I386_ALL): 'i386',
         (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_ALL): 'arm',
         (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_601): 'ppc601',
         (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_603): 'ppc603',
         (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_603e): 'ppc603e',
         (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_603ev): 'ppc603ev',
         (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_604): 'ppc604',
         (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_604e): 'ppc604e',
         (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_750): 'ppc750',
         (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_7400): 'ppc7400',
         (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_7450): 'ppc7450',
         (macho.CPU_TYPE_POWERPC,   macho.CPU_SUBTYPE_POWERPC_970): 'ppc970',
         (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_486): 'i486',
         (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_486SX): 'i486SX',
         (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_PENT): 'pentium',
         (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_586): 'i586',
         (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_PENTPRO): 'pentpro',
         (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_PENTPRO): 'i686',
         (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_PENTII_M3): 'pentIIm3',
         (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_PENTII_M5): 'pentIIm5',
         (macho.CPU_TYPE_I386,      macho.CPU_SUBTYPE_PENTIUM_4): 'pentium4',
         (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_V4T): 'armv4t',
         (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_V5TEJ): 'armv5',
         (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_XSCALE): 'xscale',
         (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_V6): 'armv6',
         (macho.CPU_TYPE_ARM,       macho.CPU_SUBTYPE_ARM_V7): 'armv7'}

for file in args:
    raw = open(file, 'rb').read()
    filesize = os.path.getsize(file)
    e = macho_init.MACHO(raw, interval=intervals.Intervals().add(0,filesize), parseSymbols = False)
    architectures = options.architectures

    if architectures == None and hasattr(e, 'Fhdr'):
        architectures = platform.machine()
    if architectures != None:
        for (cputype, cpusubtype), arch in archi.items():
            if arch == architectures:
                break
        else:
            cputype, cpusubtype = None, None

        if cputype == macho.CPU_TYPE_ARM:
            for mac in e.arch:
                if mac.Mhdr.cpusubtype & macho.CPU_SUBTYPE_MASK == cpusubtype:
                    e = mac
        else:
            for mac in e.arch:
                if mac.Mhdr.cputype == cputype:
                    e = mac
                    break
            else:
                pass
                #raise ValueError("Cannot find architecture in FAT file")

    functions = []

    if options.header:
        functions.append(print_header)
    if options.loadcommands:
        functions.append(print_lc)
    if options.symbols:
        functions.append(print_symbols)

    if hasattr(e, 'Fhdr'):
        for mach in e.arch:
            print("%s (architecture %s):" %(file, archi[(mach.Mhdr.cputype, mach.Mhdr.cpusubtype & macho.CPU_SUBTYPE_MASK)]))
            for f in functions:
                f(mach)
    else :
        print("%s:" %file)
        for f in functions:
            f(e)

