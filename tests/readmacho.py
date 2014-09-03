#! /usr/bin/env python
import getopt, sys, os.path, struct

if sys.version_info[0] == 2 and sys.version_info[1] < 5:
    sys.stderr.write("python version older than 2.5 is not supported\n")
    exit(1)

from elfesteem import macho_init, macho, intervals

options = {}
opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])
for opt, arg in opts:
    if opt == '-h':
        sys.stderr.write("Usage: readelf.py [-hSrsd] elf-file(s)\n")
        sys.exit(1)

def display_file_content(e):
    if hasattr(e,'lh'):
        print "Load Commands"
        for lc in e.lh.lhlist:
            print "LC cmd", lc.__class__.__name__
            if (hasattr(lc,'fileoff')):
                print "LC offset", lc.fileoff
                for sh in lc.sh:
                    print "SH", sh.segname, sh.sectname, sh.offset, sh.size
    if hasattr(e,'sect'):
        print "Sections"
        for s in e.sect.sect:
            if hasattr(s, 'sh'):
                print "S", s.__class__.__name__, s.offset, len(str(s)), repr(s.sh)
            else:
                print "S", s.__class__.__name__, s.offset, len(str(s))
    if hasattr(e,'fh'):
        print "--------FAT FILE--------"
        for i, f in enumerate(e.arch):
            print "-------MACHO ARCH------- %x" % e.fh.farchlist[i].cputype
            for lc in f.lh.lhlist:
                print "LC cmd", lc.__class__.__name__
                if (hasattr(lc,'fileoff')):
                    print "LC offset", lc.fileoff
                    for sh in lc.sh:
                        print "SH", sh.segname, sh.sectname, sh.offset, sh.size
            print "Sections"
            for s in f.sect.sect:
                if hasattr(s, 'sh'):
                    print "S", s.__class__.__name__, s.offset, len(str(s)), repr(s.sh)
                else:
                    print "S", s.__class__.__name__, s.offset, len(str(s))

def changeMainToUnixThread(e):
    # cputype peut etre deduit de e
    #lh = macho_init.LoaderUnixthread({'cputype':macho.CPU_TYPE_X86_64}, 1, 64)
    #lh = macho_init.LoaderUnixthread({'cputype':macho.CPU_TYPE_I386}, 1, 32)
    lh = macho_init.LoaderUnixthread({'cputype':e.Mhdr.cputype}, 1, 32)
    main_pos, = e.lh.getpos(macho.LC_MAIN)
    sign_pos, = e.lh.getpos(macho.LC_DYLIB_CODE_SIGN_DRS)
    #print repr(e.lh.lhlist[sign_pos].sect[0])
    #print repr(e.sect.sect)
    sectsign_pos, = e.sect.getpos(e.lh.lhlist[sign_pos].sect[0])
    print "sectsign_pos", sectsign_pos
    # a calculer a partir de LC_MAIN
    for lc in e.lh.lhlist :
        if lc.lht == macho.LC_MAIN :
            lh.entrypoint = lc.entryoff - 0x40 + getVaddr(e)
            #lh.entrypoint = 0xff6 + 0x1000
            mainasmpos = lc.entryoff - 0x40
    #lh.entrypoint = 0x0000000100000EB0
    e.lh.append(lh)
    e.lh.removepos(sign_pos)
    e.lh.removepos(main_pos)
    e.sect.removepos(sectsign_pos)
    #e.Mhdr.sizeofcmds -= len(str(e.lh.lhlist[sign_pos]))
    #e.lh.lhlist.remove(e.lh.lhlist[sign_pos])
    #e.Mhdr.ncmds-=1
    #e.Mhdr.sizeofcmds -= len(str(e.lh.lhlist[main_pos]))
    #e.lh.lhlist.remove(e.lh.lhlist[main_pos])
    #e.Mhdr.ncmds-=1
    data = e[mainasmpos:mainasmpos+64]
    call_offset, = struct.unpack("<I", data[0x31:0x35])
    print "OFFSET %x" % call_offset
    call_offset = mainasmpos + 0x40 - (0xff6 + 0x35)
    data = data[:0x31] + struct.pack("<i", call_offset) + data[0x35:]
    call_offset, = struct.unpack("<I", data[0x31:0x35])
    print "OFFSET %x" % call_offset
    #data = macho_init.SectionHeader(e.sex, e.wsize, content=data, segment="__TEXT", sectname="__text")
    ##print mainasmpos
    ##print repr(e[mainasmpos:mainasmpos+64])
    #e.add(data)
    """
    print "---------", repr(e.lh.lhlist[1].sh[0])
    print "---------", repr(e.lh.lhlist[1].sh)
    taille = len(str(e.lh.lhlist[1].sh[0]))
    e.lh.lhlist[1].nsects -= 1
    e.lh.lhlist[1].filesize -= taille
    e.lh.lhlist[1].vmsize -= taille
    e.lh.lhlist[1].cmdsize -= taille
    e.lh.lhlist[1].sh.remove(e.lh.lhlist[1].sh[0])
    print "--------- APRES ----------", repr(e.lh.lhlist[1].sh)
    """
def getVaddr(e):
    if hasattr(e,'lh'):
        for lc in e.lh.lhlist:
            if (hasattr(lc,'vmaddr')):
                if not lc.vmaddr == 0:
                    return lc.vmaddr - lc.fileoff
    return "No Vaddr Found"

def tests():
    if not macho_init.MACHO('\xce\xfa\xed\xfe').__class__.__name__ == 'MACHO':
        print "BUG: cannot create a MachO with only Magic Number"
    if not len(macho_init.MACHO(struct.pack("<IIIII",macho.MH_MAGIC,0,0,0,1)).lh.lhlist)>0:
        print "BUG: cannot append lhlist"
    if not macho_init.Loader(None,1,32,"").__class__.__name__ == 'Loader':
        print "BUG: cannot create a Loader"
    if not macho_init.Loader(None,1,32,struct.pack("<II",1,0)).__class__.__name__ == 'LoaderSegment':
        print "BUG: cannot create a LoaderSegment"
    if not macho_init.Loader(None,1,32,struct.pack("<II",123456789,0)).__class__.__name__ == 'Loader':
        print "BUG: cannot create a loader command with an unknown lht"
    a=macho_init.Loader(None,1,32,struct.pack("<II",1,0))
    a.nsects = 2
    if not a.nsects == 2 :
        print "BUG: cannot modify the section number of a Loader"
    if not macho_init.Section(1,32).__class__.__name__ == 'Section':
        print "BUG: Cannot create a Section Header"

for file in args:
    if len(args) > 1:
        print "\nFile: %s" % file
    raw = open(file, 'rb').read()
    filesize = os.path.getsize(file)
    e = macho_init.MACHO(raw, interval=intervals.Intervals().add(0,filesize))
    """
    if hasattr(e,'lh'):
        for lc in e.lh.lhlist:
            if hasattr(lc,'segname'):
                print "LC WITH SEGNAME", lc, repr(lc.sect)
    for lc in e.lh.lhlist:
        if hasattr(lc,'segname'):
            if lc.segname == "__DATA" :
                e.lh.extendSegment(lc, 0x1000)
    """
    for s in e.sect.sect:
        if hasattr(s, 'sh') :
            if s.sh.type == macho.S_SYMBOL_STUBS:
                symbol_stub = s
                break
    """
    print "len_stub", s.sh.reserved2
    for sy in s.list:
        print "symbol stub ", repr(sy.content), "offset", hex(sy.offset)
    """
    #changeMainToUnixThread(e)
    #print(getVaddr(e))
    #e.changeStart()
    #print "AVANT"
    #e.lh.append(e.lh.lhlist[8])
    #e.Mhdr.sizeofcmds -= len(str(e.lh.lhlist[10]))
    #e.lh.lhlist.remove(e.lh.lhlist[10])
    #e.Mhdr.ncmds-=1

    #e.lh.lhlist[11:13] = [e.lh.lhlist[12], e.lh.lhlist[11]]
    #lhtemp = e.lh.lhlist[11]
    #e.lh.lhlist[11] = e.lh.lhlist[4]
    #e.lh.lhlist[4] = lhtemp
    #display_file_content(e)
    # Non regression test
    #errors = e.checkParsedCompleted() # print all non-zero not parsed
    errors = e.checkParsedCompleted(detect_nop=True) # deal with nop at end of __text
    #errors = e.checkParsedCompleted(add_rawdata=True) # deal with all non-zero not parsed
    if not errors == None :
        for pos, data in errors:
            print "problem at position %d with byte %r" % (pos, data)
    str_e = str(e)
    f = macho_init.MACHO(str_e, interval=intervals.Intervals().add(0,filesize))
    #"""
    for s in e.sect.sect:
        if hasattr(s,'sh'):
            if s.sh.type == macho.S_SYMBOL_STUBS:
                (s.list[0].content,s.list[1].content)=(s.list[1].content,s.list[0].content)
    #"""
    #display_file_content(f)
    #sys.exit(0)
    open(file+".dump", 'wb').write(str_e)
    import os
    os.chmod(file+".dump", 0755)
    #@@@@tests()
    #errors = f.checkParsedCompleted() # print all non-zero not parsed
    errors = f.checkParsedCompleted(detect_nop=True) # deal with nop at end of __text
    #errors = f.checkParsedCompleted(add_rawdata=True) # deal with all non-zero not parsed
    if not errors == None :
        for pos, data in errors:
            print "problem at position %d with byte %r" % (pos, data)
    if str_e != str(f):
        print "BUG: str(e) is not a fixpoint"
        sys.exit(1)
    if str_e != raw:
        print "BUG: str(e) is not raw"
        sys.exit(1)
    #print repr(e.virt[0x2000:0x2020])
    #e.virt[0x2000]="HelloWorld"
    #   data = data-object(load-command)
    if hasattr(e,'fh'):
        #by default for FAT files, add to first architecture
        f = e.arch.macholist[0]
    else:
        f = e
    #*****!!!!!!!          data = macho_init.SectionHeader(f.sex, f.wsize, content='sdklkldl')
    # data = Section(content='sdklkldl', segment='__TEXT')
    #for i in range(100):
    #*****!!!!!!!          f.add(data)
    #lc = macho_init.Loader(parent=None,sex='<',wsize=32, content=struct.pack("<II",0x26,0))
    #print "------------ add lc", repr(lc)
    #print "------------ lc class name", lc.__class__.__name__
    #f.add(lc)
    #e.changeUUID("2A0405CF8B1F3502A605695A54C407BB")
    #print "APRES"
    #display_file_content(e)
    #e.lh.lhlist[8:10] = [e.lh.lhlist[9], e.lh.lhlist[8]]
    open(file+".dump", 'wb').write(str(e))
    import os
    os.chmod(file+".dump", 0755)
"""
    print "Representation of Mhdr", repr(e.Mhdr)
    print "0x%x" % e.Mhdr.magic
    # printf("0x%x\n", e.Ehdr.magic)
    for lc in e.lh:
        print repr(lc)
    for lc in e.lh:
        if isinstance(lc, macho_init.LoaderSegment):
            for sh in lc.sh:
                print "Section %s at %d size %d" % (sh.sectname, sh.offset, sh.size)
"""
