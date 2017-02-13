#! /usr/bin/env python
import sys

if sys.version_info[0] == 2 and sys.version_info[1] < 5:
    sys.stderr.write("python version older than 2.5 is not supported\n")
    exit(1)

from elfesteem import pe_init, pe
import pprint, struct

def test_rebuild(e):
    bin = str(e)
    if bin != raw:
        print("ERROR: PE file is not reconstructed identical")
        f = pe_init.PE(bin)
        bin2 = str(f)
        if bin != bin2:
            print("ERROR: PE does not even have a fixpoint")

def print_petype(e):
    if hasattr(e, 'COFFhdr'): COFFhdr = e.COFFhdr
    else:                     COFFhdr = e.Coffhdr
    machine = pe.constants['IMAGE_FILE_MACHINE'].get(COFFhdr.machine,
        "UNKNOWN(%#x)" % COFFhdr.machine)
    if hasattr(e, 'NThdr'):
        print("PE for %s"%machine)
    else:
        print("COFF for %s"%machine)
    print("COFF: %d sections, %d symbols; flags %#x; szopthdr %#x" % (
        COFFhdr.numberofsections,
        COFFhdr.numberofsymbols,
        COFFhdr.characteristics,
        COFFhdr.sizeofoptionalheader,
        ))
    if COFFhdr.sizeofoptionalheader:
        if hasattr(e.Opthdr, 'majorlinkerversion'):
            vstamp = '%d.%d' % ( e.Opthdr.majorlinkerversion,
                                 e.Opthdr.minorlinkerversion )
        else:
            # Sometimes, the doc does not say how vstamp is splitted in
            # major / minor
            vstamp = '%#x' % e.Opthdr.vstamp
        magic = pe.constants['IMAGE_OPTIONAL_HDR_MAGIC'].get(e.Opthdr.magic,
            "UNKNOWN(%#x)" % e.Opthdr.magic)
        print("OPThdr magic: %s; version %s; Entry: %#10x" % (
            magic, vstamp, e.Opthdr.entry))
    if COFFhdr.pointertosymboltable:
        strtab_off = COFFhdr.pointertosymboltable + 18 * COFFhdr.numberofsymbols
        print("SymbolTable: %#x; %d symbols; strtab of len %d bytes" % (
            COFFhdr.pointertosymboltable,
            COFFhdr.numberofsymbols,
            len(e.content) - strtab_off,
            ))
    print("MaxAddr %#x" % e.virt.max_addr())
    if hasattr(e, 'NThdr'):
        print("NThdr: Sig %#x OSver %d.%d IMGver %d.%d subsystem %s v%d.%d" % (
            e.NTsig.signature,
            e.NThdr.majoroperatingsystemversion,
            e.NThdr.minoroperatingsystemversion,
            e.NThdr.MajorImageVersion,
            e.NThdr.MinorImageVersion,
            pe.constants['IMAGE_SUBSYSTEM'].get(e.NThdr.subsystem,
                'unk%d'%e.NThdr.subsystem),
            e.NThdr.majorsubsystemversion,
            e.NThdr.minorsubsystemversion,
            ))
        print("  ImageBase %#x s_align %#x f_align %#x sz_img %#x sz_hdr %#x" % (
            e.NThdr.ImageBase,
            e.NThdr.sectionalignment,
            e.NThdr.filealignment,
            e.NThdr.sizeofimage,
            e.NThdr.sizeofheaders,
            ))

def print_sections(e):
    print("\nSECTIONS")
    print("No               Name     offset      rsize  vsize/paddr    vaddr      flags")
    for i, s in enumerate(e.SHList):
        print("%2d %18s %#10x %#10x %#10x %#10x %#10x" %(i,
               s.name.strip('\0'),
               s.scnptr, s.rsize,
               s.paddr, s.vaddr,
               s.flags))
    if hasattr(e, 'NThdr'):
        print("\nNT HEADERS")
        print("No          Name         addr      memsz")
        for i, s in enumerate(e.NThdr.optentries):
            n = e.getsectionbyrva(s.rva)
            if n is None:
                class NoSection(object):
                    name = '<no section>'
                n = NoSection()
            print("%2d %15s %#10x %#10x %12s" %(i,
                   pe.constants['DIRECTORY_ENTRY'][i],
                   s.rva, s.size,
                   '' if s.size == 0 else n.name.strip('\0')
                   ))

from operator import itemgetter
def print_layout(e, filesz):
    if filesz == 0:
        print("\nEMPTY FILE")
        return
    layout = []
    of = 0
    if hasattr(e, 'COFFhdr'): COFFhdr = e.COFFhdr
    else:                     COFFhdr = e.Coffhdr
    if hasattr(e, 'NThdr'): # PE
        if hasattr(e, 'DOShdr'):  DOShdr = e.DOShdr
        else:                     DOShdr = e.Doshdr
        layout.append((0, e.NThdr.sizeofheaders, 'Headers'))
        layout.append((0, len(DOShdr.pack()), 'DOS header'))
        of += DOShdr.lfanew
        layout.append((of, len(e.NTsig.pack()), 'NT sig'))
        of += len(e.NTsig.pack())
    layout.append((of, len(COFFhdr.pack()), 'COFF header'))
    of += len(COFFhdr.pack())
    if COFFhdr.sizeofoptionalheader > 0:
        layout.append((of, len(e.Opthdr.pack()), 'Optional headers'))
    if hasattr(e, 'NThdr'): # PE
        layout.append((of + len(e.Opthdr.pack()), len(e.NThdr.pack()), 'NT header'))
        layout.append((of, COFFhdr.sizeofoptionalheader, 'NT + Optional headers'))
    of += COFFhdr.sizeofoptionalheader
    layout.append((of, len(e.SHList.pack()), 'List of Sections'))
    of += len(e.SHList.pack())
    if hasattr(e, 'NThdr'):
        layout.append((DOShdr.lfanew, of-DOShdr.lfanew, 'PE header'))
    for i, s in enumerate(e.SHList):
        if s.rsize == 0:
            # Empty section, not in the file!
            continue
        if s.flags & (pe.STYP_BSS|pe.STYP_SBSS|pe.STYP_DSECT):
            # bss/dummy section, not in the file!
            continue
        if i == 0 and s.name.startswith('$'):
            # '$build.attributes' dummy section is seen in TI COFF sample file
            # PECOFF reference documentation 4.2 explains the special
            # interpretation of $ in section names, which is compatible
            # with ignoring sections starting with $
            continue
        layout.append((s.scnptr, s.rsize,
                        'Section '+s.name.strip('\0')))
        if s.nreloc:
            layout.append((s.relptr, s.nreloc*10,
                            'Relocs  '+s.name.strip('\0')))
        if s.nlnno:
            nlnno = s.nlnno
            if s.lnnoptr+s.nlnno*6 > filesz:
                nlnno = (filesz-s.lnnoptr)//6
                print("LINENO for section %s is %d and should probably be %s" % (s.name.strip('\0'), s.nlnno, nlnno))
            layout.append((s.lnnoptr, nlnno*6,
                            'LineNo  '+s.name.strip('\0')))

    if COFFhdr.pointertosymboltable != 0 and COFFhdr.numberofsymbols != 0:
        layout.append((COFFhdr.pointertosymboltable,
                       18 * COFFhdr.numberofsymbols,
                       'COFF Symbols'))
        layout.append((COFFhdr.pointertosymboltable +
                       18 * COFFhdr.numberofsymbols,
                       len(e.SymbolStrings.pack()),
                       'COFF SymbolStrings'))

    if hasattr(e, 'NThdr'):
        for i, s in enumerate(e.NThdr.optentries):
            if s.rva != 0 and s.size != 0:
                if i == pe.DIRECTORY_ENTRY_SECURITY:
                    # SECURITY vaddr is an offset, not a RVA!
                    of = s.rva
                else:
                    of = e.rva2off(s.rva)
                layout.append((of, s.size,
                                'DirEnt '+pe.constants['DIRECTORY_ENTRY'][i]))
    print("\nFILE CONTENT LAYOUT")
    def section_extract(x):
        s = x[2].split()[0]
        o = ['Section', 'DirEnt']
        if s in o: return (o.index(s), x)
        else: return (len(o), x)
    layout.sort(key=section_extract)
    layout.sort(key=itemgetter(1), reverse=True)
    layout.sort(key=itemgetter(0))
    format = "%#10x-%#010x %s%s"
    context = [(0, filesz)]
    for l in [l for l in layout if l[0] != None]:
        if context[-1][0] <= l[0] and l[0]+l[1] <= context[-1][1]:
            if context[-1][0] < l[0]:
                b, f = context[-1][0], l[0]
                print(format % (b, f, ". " * (len(context)-1),
                        '(unknown, %d bytes)' % (f-b)))
        else:
            while l[0] >= context[-1][1]:
                b, f = context[-1][1], min(l[0], context[-2][1])
                if f > b:
                    print(format % (b, f, ". " * (len(context)-2),
                        '(unknown; %d bytes)' % (f-b)))
                context.pop()
        context.append((l[0],l[0]+l[1]))
        print(format % (l[0], l[0]+l[1], ". " * (len(context)-2),
            ' '.join(l[2:])))
    if True:
            # If we did not reach the end of the file
            l = (filesz,)
            while len(context) > 1 and l[0] >= context[-1][1]:
                b, f = context[-1][1], min(l[0], context[-2][1])
                if f > b:
                    print(format % (b, f, ". " * (len(context)-2),
                        '(unknown; %d bytes)' % (f-b)))
                context.pop()
            if context[-1][1] > filesz:
                print(format % (context[-1][1], filesz, "", "(went after EOF!)"))
    for l in [l for l in layout if l[0] == None]:
        print("Not in a section: %s" % (' '.join(l[2:])))

def pe_dir_display(e):
    print(repr(e.DirImport))
    print(repr(e.DirExport))
    print(repr(e.DirDelay))

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', dest='options', action='append_const', const='headers',  help='Headers')
    parser.add_argument('-S', dest='options', action='append_const', const='sections', help='Sections')
    parser.add_argument('-D', dest='options', action='append_const', const='directories',   help='Directories')
    #parser.add_argument('-d', dest='options', action='append_const', const='dynsym',   help='Dynamic symbols')
    #parser.add_argument('-r', dest='options', action='append_const', const='reltab',   help='Relocation sections')
    parser.add_argument('-s', dest='options', action='append_const', const='symtab',   help='Symbol table')
    #parser.add_argument('-d', dest='options', action='append_const', const='dynsym',   help='Dynamic symbols')
    parser.add_argument('-l', dest='options', action='append_const', const='layout',   help='File content layout')
    parser.add_argument('file', nargs='+', help='ELF file(s)')
    args = parser.parse_args()
    if args.options == None:
        args.options = []

    for file in args.file:
        if len(args.file) > 1:
            print("\nFile: %s" % file)
        raw = open(file, 'rb').read()
        if raw[:2] == struct.pack("2B", 0x4d,0x5a):
            e = pe_init.PE(raw)
            if e.NTsig.signature != 0x4550:
                print('Not a valid PE')
                continue
        else:
            try:
                e = pe_init.Coff(raw)
            except ValueError:
                print('Not a valid COFF')
                continue
        #test_rebuild(e)
        if 'headers' in args.options:
            print_petype(e)
        if 'sections' in args.options:
            print_sections(e)
        if 'symtab' in args.options:
            if hasattr(e, 'Symbols'):
                for s in e.Symbols.symbols:
                    print("%r"%s)
        if 'layout' in args.options:
            print_layout(e,len(raw))
        if 'directories' in args.options:
            pe_dir_display(e)

# http://media.blackhat.com/bh-us-11/Vuksan/BH_US_11_VuksanPericin_PECOFF_Slides.pdf
