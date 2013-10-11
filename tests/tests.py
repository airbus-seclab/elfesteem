#! /usr/bin/env python
import getopt, sys, os, os.path, struct, subprocess
sys.path[0:0] = ['..']

if sys.version_info[0] == 2 and sys.version_info[1] < 5:
    print >> sys.stderr, "python version older than 2.5 is not supported"
    exit(1)

from elfesteem import macho_init, macho, intervals

# binary code for the _start function, taken from crt0.o by gcc
start_32bit = 'j\x00\x89\xe5\x83\xe4\xf0\x83\xec\x10\x8b]\x04\x89\x1c$\x8dM\x08\x89L$\x04\x83\xc3\x01\xc1\xe3\x02\x01\xcb\x89\\$\x08\x8b\x03\x83\xc3\x04\x85\xc0u\xf7\x89\\$\x0c\xe8\x0b\xdf\xff\xff\x89\x04$\xe83\xdf\xff\xff\xf4\x90\x90U\x89\xe5\x83\xec\x18\xe8\x00\x00\x00\x00X\x89\xe1\x8d\x80Q\x00\x00\x00\x89\x01\xe8\x1b\x00\x00\x00\xc7E\xf8\x00\x00\x00\x00\x8bE\xf8\x89E\xfc\x8bE\xfc\x83\xc4\x18]\xc3'
start_64bit = 'j\x00H\x89\xe5H\x83\xe4\xf0H\x8b}\x08H\x8du\x10\x89\xfa\x83\xc2\x01\xc1\xe2\x03H\x01\xf2H\x89\xd1\xeb\x04H\x83\xc1\x08H\x839\x00u\xf6H\x83\xc1\x08\xe8\xbc\xde\xff\xff\x89\xc7\xe8\xe5\xde\xff\xff\xf4\x90\x90\x90\x90UH\x89\xe5H\x83\xec\x100\xc0H\x8d\rO\x00\x00\x00H\x89\xcf\xe8\x1d\x00\x00\x00\xc7E\xf8\x00\x00\x00\x00\x8bE\xf8\x89E\xfc\x8bE\xfcH\x83\xc4\x10]\xc3'

def changeMainToUnixThread(e ,**kargs):
    decal = 0
    if 'off' in kargs:
        off = kargs['off']
        #content = kargs['content']
    lh = macho_init.LoaderUnixthread(parent={'cputype':e.Mhdr.cputype}, sex='<', wsize=32)
    main_pos, = e.lh.getpos(macho.LC_MAIN)
    sign_pos, = e.lh.getpos(macho.LC_DYLIB_CODE_SIGN_DRS)
    sectsign_pos, = e.sect.getpos(e.lh.lhlist[sign_pos].sect[0])
    delta_from_start_to_main = 0x40
    offset_of_call_main = {32: 0x30, 64: 0x2F}[e.wsize]
    offset_of_call_exit = {32: 0x38, 64: 0x36}[e.wsize]
    content = {32: start_32bit, 64: start_64bit}[e.wsize]
    call_offset = {32: 0x0b, 64: 0x0c}[e.wsize]
    exit_offset = {32: 0x33, 64: 0x35}[e.wsize]
    for lc in e.lh.lhlist :
        if lc.lht == macho.LC_MAIN :
            if 'off' not in kargs:
                lh.entrypoint = lc.entryoff - delta_from_start_to_main + getVaddr(e)
            else :
                lh.entrypoint = off + getVaddr(e)
            mainasmpos = lc.entryoff - delta_from_start_to_main
    e.lh.append(lh)
    e.lh.removepos(sign_pos)
    e.lh.removepos(main_pos)
    e.sect.removepos(sectsign_pos)
    if 'off' in kargs:
        call = mainasmpos + call_offset - off
        exit = mainasmpos + exit_offset - off
        content = content[:offset_of_call_main+1] + struct.pack("<i", call) + content[offset_of_call_main+5:offset_of_call_exit+1] + struct.pack("<i", exit) + content[offset_of_call_exit+5:]
        e.sect.sect[-1].content = content
    
def getVaddr(e):
    if hasattr(e,'lh'):
        for lc in e.lh.lhlist:
            if (hasattr(lc,'vmaddr')):
                if not lc.vmaddr == 0:
                    return lc.vmaddr - lc.fileoff
    return "No Vaddr Found"

def initTests():
    if not macho_init.MACHO('\xce\xfa\xed\xfe').__class__.__name__ == 'MACHO':
        print "BUG: cannot create a MachO with only Magic Number"
    if not len(macho_init.MACHO(struct.pack("<IIIII",macho.MH_MAGIC,0,0,0,1)).lh.lhlist)>0:
        print "BUG: cannot append lhlist"
    if not macho_init.Loader(parent=None,sex='<',wsize=32,content="").__class__.__name__ == 'Loader':
        print "BUG: cannot create a Loader"
    if not macho_init.Loader(parent=None,sex='<',wsize=32, content=struct.pack("<II",1,0)).__class__.__name__ == 'LoaderSegment':
        print "BUG: cannot create a LoaderSegment"
    if not macho_init.Loader(parent=None,sex='<',wsize=32,content=struct.pack("<II",123456789,0)).__class__.__name__ == 'Loader':
        print "BUG: cannot create a loader command with an unknown lht"
    a=macho_init.Loader(parent=None,sex='<',wsize=32,content=struct.pack("<II",1,0))
    a.nsects = 2
    if not a.nsects == 2 :
        print "BUG: cannot modify the section number of a Loader"
    if not macho_init.Section(parent=None,sex='<',wsize=32).__class__.__name__ == 'Section':
        print "BUG: Cannot create a Section Header"

def test(file, **kargs):
    content_start = None
    content_start_64 = None
    dep = 0
    dep_64 = 0
    raw = open(file, 'rb').read()
    filesize = os.path.getsize(file)
    if 'parseSymbols' in kargs and not kargs['parseSymbols']:
        e = macho_init.MACHO(raw, interval=intervals.Intervals().add(0,filesize), parseSymbols = False)
    else:
        e = macho_init.MACHO(raw, interval=intervals.Intervals().add(0,filesize))
    
    if 'extendSegment' in kargs and kargs['extendSegment']:
        for lc in e.lh.lhlist:
            if hasattr(lc,'segname'):
                if lc.segname == "__LINKEDIT" :
                    e.lh.extendSegment(lc, 0x1000)

    if 'chgmaintounxthrd' in kargs and kargs['chgmaintounxthrd']:
        changeMainToUnixThread(e)

    #errors = e.checkParsedCompleted() # print all non-zero not parsed
    errors = e.checkParsedCompleted(detect_nop=True) # deal with nop at end of __text
    #errors = e.checkParsedCompleted(add_rawdata=True) # deal with all non-zero not parsed
    if not errors == [] :
        for pos, data in errors:
            #print "problem at position %x with byte %r" % (pos, data)
            pass
        print file, "--", "Some data is not parsed. To enable creating .dump with this data, use checkParsedCompleted(detect_nop=True)."
        return
    str_e = str(e)
    open(file+".dump", 'wb').write(str_e)
    os.chmod(file+".dump", 0755)
    if 'parseSymbols' in kargs and not kargs['parseSymbols']:
        f = macho_init.MACHO(str_e, interval=intervals.Intervals().add(0,len(str_e)), parseSymbols = False)
    else:
        f = macho_init.MACHO(str_e, interval=intervals.Intervals().add(0,len(str_e)))
    #errors = f.checkParsedCompleted() # print all non-zero not parsed
    errors = f.checkParsedCompleted(detect_nop=True) # deal with nop at end of __text
    #errors = f.checkParsedCompleted(add_rawdata=True) # deal with all non-zero not parsed
    if not errors == None :
        for pos, data in errors:
            print "problem at position %x with byte %r" % (pos, data)

    if str_e != str(f):
        print file, "--","BUG: str(e) is not a fixpoint"
        sys.exit(1)

    if str_e != raw:
        if 'chgmaintounxthrd' in kargs and kargs['chgmaintounxthrd'] or 'extendSegment' in kargs and kargs['extendSegment']:
            pass
        else :
            print file, "--","BUG: str(e) is not raw"
            sys.exit(1)

    if 'virt' in kargs and kargs['virt']:
        if 'bits' in kargs :
            if kargs['bits'] == 32:
                print repr(e.virt[0x2000:0x2020])
            if kargs['bits'] == 64:
                print repr(e.virt[0x100001000:0x100001020])

    if 'virt' in kargs and kargs['virt']=='write':
        if 'bits' in kargs :
            if kargs['bits'] == 32:
                f.virt[0x1F9C]="Virt HelloWorld !"
            if kargs['bits'] == 64:
                f.virt[0x100000F50]="Virt HelloWorld !"

    if 'addsection' in kargs and kargs['addsection']:
        if hasattr(e,'fh'):
            #by default for FAT files, add to first architecture
            f = e.arch.macholist[0]
        else:
            f = e
        data = macho_init.Section(parent=None, sex=f.sex, wsize=f.wsize, content='sdklkldl')
        f.add(data)

    if 'addcommand' in kargs and kargs['addcommand']:
        if hasattr(e,'fh'):
            #by default for FAT files, add to first architecture
            f = e.arch.macholist[0]
        else:
            f = e
        lc = macho_init.Loader(parent=None,sex='<',wsize=32, content=struct.pack("<II",0x26,0))
        f.add(lc)
        f.add(type=macho_init.LoaderSegment, segname='__NEWTEXT', initprot=macho.SEGMENT_READ|macho.SEGMENT_EXECUTE, content='some binary data')

    if 'addcommand64' in kargs and kargs['addcommand64']:
        if hasattr(e,'fh'):
            #by default for FAT files, add to first architecture
            f = e.arch.macholist[0]
        else:
            f = e
        lc = macho_init.Loader(parent=None,sex='<',wsize=64, content=struct.pack("<II",0x26,0))
        f.add(lc)
        f.add(type=macho_init.LoaderSegment_64, segname='__NEWTEXT', initprot=macho.SEGMENT_READ|macho.SEGMENT_EXECUTE, content='some binary data')

    if 'chgmaintounxthrd_command' in kargs and kargs['chgmaintounxthrd_command']:
        if hasattr(e,'fh'):
            #by default for FAT files, add to first architecture
            f = e.arch.macholist[0]
        else:
            f = e
        content = {32: start_32bit, 64: start_64bit}[f.wsize]
        """
        for s in f.sect.sect:
            if s.content[0:4]=='\x6a\x00\x89\xe5':
                content_start = str(s.content)
                dep = s.offset
        """
        f.add(type=macho_init.LoaderSegment, segname='__NEWTEXT', initprot=macho.SEGMENT_READ|macho.SEGMENT_EXECUTE, content=content)
        off = f.sect.sect[-1].offset
        changeMainToUnixThread(f, off=off)

    if 'chgmaintounxthrd_command_64' in kargs and kargs['chgmaintounxthrd_command_64']:
        if hasattr(e,'fh'):
            #by default for FAT files, add to first architecture
            f = e.arch.macholist[0]
        else:
            f = e
        """
        for s in f.sect.sect:
            if s.content[0:4]=='\x6a\x00\x48\x89':
                content_start_64 = str(s.content)
                dep_64 = s.offset
        """
        content = {32: start_32bit, 64: start_64bit}[f.wsize]
        f.add(type=macho_init.LoaderSegment_64, segname='__NEWTEXT', initprot=macho.SEGMENT_READ|macho.SEGMENT_EXECUTE, content=content)
        off = f.sect.sect[-1].offset
        changeMainToUnixThread(f, off=off)

    if 'changeUUID' in kargs and kargs['changeUUID']:
        e.changeUUID("2A0405CF8B1F3502A605695A54C407BB")
        for lc in e.lh.lhlist:
            if hasattr(lc,'uuid'):
                if not lc.uuid == (704906703, 35615, 13570, 42501, 26970, 1422133179):
                    print "BUG: UUID change failed"

    if 'invertLoaders' in kargs and kargs['invertLoaders']:
        cmd_8 = e.lh.lhlist[8].cmd
        cmd_9 = e.lh.lhlist[9].cmd
        e.lh.lhlist[8:10] = [e.lh.lhlist[9], e.lh.lhlist[8]]
        if not (e.lh.lhlist[8].cmd == cmd_9 or e.lh.lhlist[9].cmd == cmd_8):
            print "BUG: load commands are not inverted"

    newFile = file+".dump"
    open(newFile, 'wb').write(str(f))
    os.chmod(newFile, 0755)

    if not ('noPrint' in kargs and kargs['noPrint']):
        proc = subprocess.Popen(["./" + file], stdout=subprocess.PIPE, shell=True)
        (out_file, err_file) = proc.communicate()
        #print "(out_file, err_file)", (out_file, err_file)
        newProc = subprocess.Popen(["./" + newFile], stdout=subprocess.PIPE, shell=True)
        (out_newFile, err_newFile) = newProc.communicate()
        #print "(out_newFile, err_newFile)", (out_newFile, err_newFile)
        if 'virt' in kargs and kargs['virt']=='write':
            if not out_newFile == 'Virt HelloWorld !':
                print out_newFile
                print "BUG: output expected from %s file is 'Virt HelloWorld'" % newFile
        else :
            if not (out_file, err_file) == (out_newFile, err_newFile):
                print "BUG: output expected from %s file is 'structure definie'" % newFile

def nonRegressionTests():
    initTests()
    test('testelf32')
    #print "test('testelf32') OK"
    test('testelf')
    #print "test('testelf') OK"
    test('testelf32.o')
    #print "test('testelf32.o') OK"
    test('testelf.o')
    #print "test('testelf.o') OK"
    test('fattestelf')
    #print "test('fattestelf') OK"
    test('testelf32', virt = True, bits=32)
    #print "test('testelf32', virt = True, bits=32) OK"
    test('testelf', virt = True, bits=64)
    #print "test('testelf', virt = True, bits=64)"
    test('testelf32', virt = 'write', bits=32)
    #print "test('testelf32', virt = 'write', bits=32) OK"
    test('testelf', virt = 'write', bits=64)
    #print "test('testelf', virt = 'write', bits=64) OK"
    test('testelf32', addsection = True)
    #print "test('testelf32', addsection = True) OK"
    test('testelf',addsection = True)
    #print "test('testelf',addsection = True) OK"
    test('fattestelf',addsection = True)
    #print "test('fattestelf',addsection = True) OK"
    test('testelf32', addcommand = True)
    #print "test('testelf32', addsection = True) OK"
    test('testelf',addcommand64 = True)
    #print "test('testelf',addsection = True) OK"
    test('fattestelf',addcommand = True)
    #print "test('fattestelf',addsection = True) OK"
    test('testelf32', chgmaintounxthrd = True)
    #print "test('testelf32', chgmaintounxthrd = True) OK"
    test('testelf', chgmaintounxthrd = True)
    #print "test('testelf', chgmaintounxthrd = True) OK"
    test('testelf32', chgmaintounxthrd_command = True)
    #print "test('testelf32', chgmaintounxthrd_commnand = True) OK"
    test('testelf',chgmaintounxthrd_command_64 = True)
    #print "test('testelf',chgmaintounxthrd_commnand_64 = True) OK"
    test('testelf32', changeUUID = True)
    #print "test('testelf32', changeUUID = True) OK"
    test('testelf', changeUUID = True)
    #print "test('testelf', changeUUID = True) OK"
    test('testelf32', invertLoaders = True)
    #print "test('testelf32', invertLoaders = True) OK"
    test('testelf', invertLoaders = True)
    #print "test('testelf', invertLoaders = True) OK"
    test('testelf32', extendSegment = True)
    #print "test('testelf32', extendSegment = True) OK"
    test('testelf', extendSegment = True)
    #print "test('testelf', extendSegment = True) OK"
    test('AppleGVAHW')
    #print "test('AppleGVAHW') OK"
    test('Cyberduck')
    #print "test('Cyberduck') OK"
    test('libPrintServiceQuota.1.dylib')
    #print "test('libPrintServiceQuota.1.dylib') OK"
    test('Decibels')
    #print "test('Decibels') OK"
    test('Finder', noPrint = True)
    #print "test('Finder') OK"
    test('ArCHMock', noPrint = True)
    #print "test('ArCHMock') OK"
    test('PTBlender')
    #print "test('PTBlender') OK"
    test('OmniOutlinerProfessional')
    #print "test('OmniOutlinerProfessional') OK"
    test('Calculator',chgmaintounxthrd_command_64 = True)
    #print "test of calculator OK"
    test('wxHexEditor', parseSymbols = False)
    #print "test('wxHexEditor') OK"
    print "end of tests"
nonRegressionTests()