#! /usr/bin/env python

import os
__dir__ = os.path.dirname(__file__)
__dir__ += '/binary_input/macho/'

try:
    import hashlib
except ImportError:
    # Python 2.4 does not have hashlib
    # but 'md5' is deprecated since python2.5
    import md5 as oldpy_md5
    class hashlib(object):
        def md5(self, data):
            return oldpy_md5.new(data)
        md5 = classmethod(md5)

import struct
from elfesteem.macho import MACHO, log
from elfesteem import macho

def run_test():
    ko = []
    def assertion(target, value, message):
        if target != value: ko.append(message)
    def assertion_warn(target, value, message):
        if target != value: log.warn(message)
    assertion('f71dbe52628a3f83a77ab494817525c6',
              hashlib.md5(struct.pack('BBBB',116,111,116,111)).hexdigest(),
              'MD5')
    # Remove warnings
    import logging
    log.setLevel(logging.ERROR)
    # Locale setting is used by otool to display time stamps.
    # For non-regression tests, we need to negate the effet of the locale.
    import os
    os.environ['TZ'] = ''
    # Simple tests of object creation
    e = MACHO(struct.pack("<I",macho.MH_MAGIC))
    d = e.pack()
    assertion('37b830a1776346543c72ff53fbbe2b4a',
              hashlib.md5(d).hexdigest(),
              'Parsing a minimal data, with Mach-O magic number only')
    f = struct.pack("<IIIIIIIII",macho.MH_MAGIC,0,0,0,1,0,0,0,8)
    e = MACHO(f)
    assertion(1, len(e.load),
              'Parsing data, with one empty loader (lhlist length)')
    d = e.pack()
    assertion(f, d,
              'Parsing data, with one empty loader (pack)')
    log.setLevel(logging.WARN)
    l = macho.LoadCommand(sex='<',wsize=32,cmd=0)
    assertion(macho.LoadCommand, l.__class__,
              'Creation of an empty load command')
    l = macho.LoadCommand(sex='<',wsize=32,cmd=macho.LC_SEGMENT)
    assertion(macho.segment_command, l.__class__,
              'Creation of an empty LC_SEGMENT')
    l = macho.LoadCommand(sex='<',wsize=32,cmd=123456789)
    assertion(macho.LoadCommand, l.__class__,
              'Creation of a load command with an unknown type')
    l = macho.Section(parent=macho.sectionHeader(parent=None,sex='<',wsize=32))
    assertion(macho.Section, l.__class__,
              'Creation of an empty Section Header')
    # Parsing and modifying files
    macho_32 = open(__dir__+'macho_32.o', 'rb').read()
    macho_32_hash = hashlib.md5(macho_32).hexdigest()
    e = MACHO(macho_32, interval=True)
    d = e.pack()
    assertion(macho_32_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading 32-bit Mach-O object')
    for s in e.sect.sect:
        if not hasattr(s, 'reloclist'): continue
        d = s.reloclist[0].pack()
        assertion('a8f95e95126c45ff26d5c838300443bc',
              hashlib.md5(d).hexdigest(),
              'Not scattered relocation in a 32-bit Mach-O object')
        d = s.reloclist[2].pack()
        assertion('4f66fe3447267f2bf90da8108ef10ba6',
              hashlib.md5(d).hexdigest(),
              'Scattered relocation in a 32-bit Mach-O object')
        break
    macho_32 = open(__dir__+'macho_32.out', 'rb').read()
    macho_32_hash = hashlib.md5(macho_32).hexdigest()
    e = MACHO(macho_32, interval=True)
    d = e.pack()
    assertion(macho_32_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading 32-bit Mach-O object')
    macho_64 = open(__dir__+'macho_64.o', 'rb').read()
    macho_64_hash = hashlib.md5(macho_64).hexdigest()
    e = MACHO(macho_64, interval=True)
    d = e.pack()
    assertion(macho_64_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading 64-bit Mach-O')
    macho_64 = open(__dir__+'macho_64.out', 'rb').read()
    macho_64_hash = hashlib.md5(macho_64).hexdigest()
    e = MACHO(macho_64, interval=True)
    d = e.pack()
    assertion(macho_64_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading 64-bit Mach-O')
    macho_fat = open(__dir__+'macho_fat.out', 'rb').read()
    macho_fat_hash = hashlib.md5(macho_fat).hexdigest()
    e = MACHO(macho_fat, interval=True)
    d = e.pack()
    assertion(macho_fat_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading fat Mach-O')
    macho_32 = open(__dir__+'macho_32.out', 'rb').read()
    e = MACHO(macho_32)
    d = e.virt[0x1f9c:0x1fae]
    assertion('structure definie\0',
              d.decode('latin1'),
              'Extract chunk from mapped memory, in a section (32 bits)')
    e.virt[0x1f9c] = 'Hello World\0'.encode('latin1')
    d = e.pack()
    assertion('16db05dfe60b5ac86c45d8324ef5cfc6',
              hashlib.md5(d).hexdigest(),
              'Writing in memory (address) (32 bits)')
    e.virt[0x1f9c:0x1fa8] = 'Hello World\0'.encode('latin1')
    d = e.pack()
    assertion('16db05dfe60b5ac86c45d8324ef5cfc6',
              hashlib.md5(d).hexdigest(),
              'Writing in memory (interval) (32 bits)')
    e.add(macho.Section(parent=macho.sectionHeader(parent=e.load),
                        content='arbitrary content'.encode('latin1')))
    d = e.pack()
    assertion('b61b686819bd3c94e765b220ef708353',
              hashlib.md5(d).hexdigest(),
              'Adding a section (32 bits)')
    macho_lib = open(__dir__+'libdns_services.dylib', 'rb').read()
    e = MACHO(macho_lib)
    macho_lib_hash = hashlib.md5(macho_lib).hexdigest()
    d = e.pack()
    assertion(macho_lib_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading DNS library')
    d = ('\n'.join([_ for l in e.load for _ in l.otool()])).encode('latin1')
    assertion('2d6194feedf82da26124d3128473a949',
              hashlib.md5(d).hexdigest(),
              'Otool-like output including LC_SOURCE_VERSION')
    macho_lib = open(__dir__+'libecpg.6.5.dylib', 'rb').read()
    e = MACHO(macho_lib)
    macho_lib_hash = hashlib.md5(macho_lib).hexdigest()
    d = e.pack()
    assertion(macho_lib_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading postgresql library')
    d = ('\n'.join([_ for l in e.load for _ in l.otool()])).encode('latin1')
    assertion('df729c8806748bba93ef960787036d37',
              hashlib.md5(d).hexdigest(),
              'Otool-like output including section size "past end of file"')
    d = ('\n'.join([_ for l in e.load for _ in l.otool(llvm=7)])).encode('latin1')
    assertion('7038d70ea2d7caf8b4a2adc3c9c01ef9',
              hashlib.md5(d).hexdigest(),
              'Otool-like output including section size "past end of file", llvm version 7')
    macho_lib = open(__dir__+'libATCommandStudioDynamic.dylib', 'rb').read()
    e = MACHO(macho_lib)
    macho_lib_hash = hashlib.md5(macho_lib).hexdigest()
    d = e.pack()
    assertion(macho_lib_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading libATCommandStudioDynamic')
    bind_s = [ _ for _ in e.sect if getattr(_, 'type', None)
               in ('bind_','weak_bind_','lazy_bind_','rebase_','export_') ]
    d = ('\n'.join([str(_) for s in bind_s for _ in s.info])).encode('latin1')
    assertion('28aea32ae0bd5060345b51800163b9f4',
              hashlib.md5(d).hexdigest(),
              'dyldinfo-like output for all binding types (libATCommand...)')
    bind_s = [ _ for _ in e.sect if getattr(_, 'type', None)
               in ('bind_','weak_bind_','lazy_bind_','rebase_') ]
    d = ('\n'.join([str(_) for s in bind_s for _ in s])).encode('latin1')
    assertion('66bb196759c094c0c08d8159cf61d67f',
              hashlib.md5(d).hexdigest(),
              'dyldinfo-like output for dyld opcodes (libATCommand...)')
    macho_lib = open(__dir__+'libSystem.B.dylib', 'rb').read()
    e = MACHO(macho_lib)
    macho_lib_hash = hashlib.md5(macho_lib).hexdigest()
    d = e.pack()
    assertion(macho_lib_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading libSystem')
    bind_s = [ _ for a in e.arch for _ in a.sect if getattr(_, 'type', None)
               in ('rebase_','export_') ]
    d = ('\n'.join([str(_) for s in bind_s for _ in s.info])).encode('latin1')
    assertion('81bc735570cb8f78099579fcf6a29f65',
              hashlib.md5(d).hexdigest(),
              'dyldinfo-like output for rebase and export (libSystem)')
    bind_s = [ _ for a in e.arch for _ in a.sect if getattr(_, 'type', None)
               == 'rebase_' ]
    d = ('\n'.join([str(_) for s in bind_s for _ in s])).encode('latin1')
    assertion('c71cebc604ba70bfd348a3e08f7ea20c',
              hashlib.md5(d).hexdigest(),
              'dyldinfo-like output for rebase opcodes (libSystem)')
    macho_lib = open(__dir__+'libcoretls.dylib', 'rb').read()
    e = MACHO(macho_lib)
    macho_lib_hash = hashlib.md5(macho_lib).hexdigest()
    d = e.pack()
    assertion(macho_lib_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading libcoretls')
    bind_s = [ _ for a in e.arch for _ in a.sect if getattr(_, 'type', None)
               in ('rebase_','export_') ]
    d = ('\n'.join([str(_) for s in bind_s for _ in s.info])).encode('latin1')
    assertion('d7983c780f70e8c81d277ee0f7f8a27d',
              hashlib.md5(d).hexdigest(),
              'dyldinfo-like output for rebase and export (libcoretls)')
    # print('HASH', hashlib.md5(d).hexdigest())

    macho_app = open(__dir__+'OSXII', 'rb').read()
    log.setLevel(logging.ERROR)
    e = MACHO(macho_app)
    log.setLevel(logging.WARN)
    macho_app_hash = hashlib.md5(macho_app).hexdigest()
    d = e.pack()
    assertion(macho_app_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading OSXII app')
    d = ('\n'.join([_ for a in e.arch for l in a.load for _ in l.otool(llvm=7)])).encode('latin1')
    assertion('8b926db115b4cae5146774ef589674be',
              hashlib.md5(d).hexdigest(),
              'Otool-like output including ppc & i386 register state')
    macho_app = open(__dir__+'MacTheRipper', 'rb').read()
    log.setLevel(logging.ERROR)
    e = MACHO(macho_app)
    log.setLevel(logging.WARN)
    macho_app_hash = hashlib.md5(macho_app).hexdigest()
    d = e.pack()
    assertion(macho_app_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading MacTheRipper app')
    d = ('\n'.join([_ for l in e.load for _ in l.otool()])).encode('latin1')
    assertion('b10cd006c10906db3329e0dccd0babbe',
              hashlib.md5(d).hexdigest(),
              'Otool-like output including LC_PREBOUND_DYLIB')
    macho_app = open(__dir__+'SweetHome3D', 'rb').read()
    log.setLevel(logging.ERROR)
    e = MACHO(macho_app)
    log.setLevel(logging.WARN)
    macho_app_hash = hashlib.md5(macho_app).hexdigest()
    d = e.pack()
    assertion(macho_app_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading SweetHome3D app')
    d = ('\n'.join([_ for a in e.arch for l in a.load for _ in l.otool()])).encode('latin1')
    assertion('4bf0088471bd2161baf4a42dbb09dc5b',
              hashlib.md5(d).hexdigest(),
              'Otool-like output including ppc, i386 & x86_64register state')
    macho_32be = open(__dir__+'libPrintServiceQuota.1.dylib', 'rb').read()
    log.setLevel(logging.ERROR)
    e = MACHO(macho_32be)
    log.setLevel(logging.WARN)
    macho_32be_hash = hashlib.md5(macho_32be).hexdigest()
    d = e.pack()
    assertion(macho_32be_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading 32-bit big-endian Mach-O shared library')
    d = ('\n'.join([_ for l in e.load for _ in l.otool()])).encode('latin1')
    assertion('cabaf4f4368c094bbb0c09f278510006',
              hashlib.md5(d).hexdigest(),
              'Otool-like output for LC in 32-bit big-endian Mach-O shared library')
    macho_ios = open(__dir__+'Decibels', 'rb').read()
    log.setLevel(logging.ERROR)
    e = MACHO(macho_ios)
    log.setLevel(logging.WARN)
    macho_ios_hash = hashlib.md5(macho_ios).hexdigest()
    d = e.pack()
    assertion(macho_ios_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading iOS application Decibels')
    d = ('\n'.join([_ for a in e.arch for l in a.load for _ in l.otool()])).encode('latin1')
    assertion('0d3281e546fd6e41306dbf38e5fbd0b6',
              hashlib.md5(d).hexdigest(),
              'Otool-like output for LC in iOS application')
    macho_ios = open(__dir__+'LyonMetro', 'rb').read()
    log.setLevel(logging.ERROR)
    e = MACHO(macho_ios)
    log.setLevel(logging.WARN)
    macho_ios_hash = hashlib.md5(macho_ios).hexdigest()
    d = e.pack()
    assertion(macho_ios_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading iOS application LyonMetro')
    d = ('\n'.join([_ for l in e.load for _ in l.otool()])).encode('latin1')
    assertion('7bac82cc00b5cce2cb96344d678508e5',
              hashlib.md5(d).hexdigest(),
              'Otool-like output including LC_VERSION_MIN_IPHONEOS')
    macho_linkopt = open(__dir__+'TelephonyUtil.o', 'rb').read()
    e = MACHO(macho_linkopt)
    macho_linkopt_hash = hashlib.md5(macho_linkopt).hexdigest()
    d = e.pack()
    assertion_warn(macho_linkopt_hash,
              hashlib.md5(d).hexdigest(),
              "Packing after reading object file with LC_LINKER_OPTION does not return the same value, because there is some nop padding at the end of __TEXT,__text; this is a bug in the way 'intervals' are updated")
    e = MACHO(d)
    macho_linkopt_hash = hashlib.md5(d).hexdigest()
    d = e.pack()
    assertion(macho_linkopt_hash,
              hashlib.md5(d).hexdigest(),
              'Fixed-point for object file with LC_LINKER_OPTION')
    d = ('\n'.join([_ for l in e.load for _ in l.otool()])).encode('latin1')
    assertion('984bf38084c14e435f30eebe36944b47',
              hashlib.md5(d).hexdigest(),
              'Otool-like output for LC in object file with LC_LINKER_OPTION')
    e = MACHO(macho_32)
    e.add(macho.LoadCommand(sex='<',wsize=32,cmd=0))
    d = e.pack()
    assertion('6fefeaf7b4de67f8270d3425942d7a97',
              hashlib.md5(d).hexdigest(),
              'Adding an empty command (32 bits)')
    f = struct.pack("<III",macho.LC_ROUTINES_64,12,0)
    log.setLevel(logging.ERROR)
    l = macho.prebind_cksum_command(parent=None, sex='<', wsize=32, content=f)
    log.setLevel(logging.WARN)
    assertion(f, l.pack(),
              'Creating a LC_PREBIND_CKSUM (with content and incoherent subclass)')
    f = struct.pack("<III",macho.LC_PREBIND_CKSUM,12,0)
    l = macho.prebind_cksum_command(parent=None, sex='<', wsize=32, content=f)
    assertion(f, l.pack(),
              'Creating a LC_PREBIND_CKSUM (with content and subclass)')
    l = macho.LoadCommand(parent=None, sex='<', wsize=32, content=f)
    assertion(f, l.pack(),
              'Creating a LC_PREBIND_CKSUM (from "content")')
    l = macho.LoadCommand(sex='<',wsize=32,cmd=macho.LC_PREBIND_CKSUM)
    assertion(f, l.pack(),
              'Creating a LC_PREBIND_CKSUM (from "cmd")')
    e = MACHO(macho_32)
    e.add(l)
    d = e.pack()
    assertion('d7a33133a04126527eb6d270990092fa',
              hashlib.md5(d).hexdigest(),
              'Adding a LC_PREBIND_CKSUM command')
    e = MACHO(macho_32)
    e.add(type=macho.LC_SEGMENT, segname='__NEWTEXT',
        initprot=macho.VM_PROT_READ|macho.VM_PROT_EXECUTE,
        content='some binary data'.encode('latin1'))
    d = e.pack()
    assertion('c4ad6da5422642cb15b91ccd3a09f592',
              hashlib.md5(d).hexdigest(),
              'Adding a segment (32 bits)')
    macho_64 = open(__dir__+'macho_64.out', 'rb').read()
    e = MACHO(macho_64)
    d = e.virt[0x100000f50:0x100000f62]
    assertion('structure definie\0',
              d.decode('latin1'),
              'Extract chunk from mapped memory, in a section (64 bits)')
    e.virt[0x100000f50:0x100000f5c] = 'Hello World\0'.encode('latin1')
    d = e.pack()
    assertion('b29fe575093a6f68a54131e59138e1d8',
              hashlib.md5(d).hexdigest(),
              'Writing in memory (interval) (64 bits)')
    e.virt[0x100000f50] = 'Hello World\0'.encode('latin1')
    d = e.pack()
    assertion('b29fe575093a6f68a54131e59138e1d8',
              hashlib.md5(d).hexdigest(),
              'Writing in memory (address) (64 bits)')
    e.add(macho.Section(parent=macho.sectionHeader(parent=e.load),
                        content='arbitrary content'.encode('latin1')))
    d = e.pack()
    assertion('be836b2b8adcff60bcc7ca1d712a92a9',
              hashlib.md5(d).hexdigest(),
              'Adding a section (64 bits)')
    e = MACHO(macho_64)
    e.add(type=macho.LC_SEGMENT_64, segname='__NEWTEXT',
        initprot=macho.VM_PROT_READ|macho.VM_PROT_EXECUTE,
        content='some binary data'.encode('latin1'))
    d = e.pack()
    assertion('b4ad381503c51b6dc9dc3d79fb8ca568',
              hashlib.md5(d).hexdigest(),
              'Adding a segment (64 bits)')
    # The function changeMainToUnixThread migrates a Mach-O binary for
    # recent MacOSX (using a LC_MAIN loader) to a Mac-O binary for older
    # versions of MacOSX (10.7 and older, using a LC_UNIXTHREAD loader).
    e = MACHO(macho_32)
    changeMainToUnixThread(e)
    d = e.pack()
    assertion('1aa73a50d1b941c560f08c20926f9a05',
              hashlib.md5(d).hexdigest(),
              'Migrating from LC_MAIN to LC_UNIXTHREAD (32 bits)')
    insert_start_function(e)
    d = e.pack()
    assertion('14e8007a3b5b5070c56ea2a43b6b888e',
              hashlib.md5(d).hexdigest(),
              'Migrating from LC_MAIN to LC_UNIXTHREAD with new segment (32 bits)')
    e = MACHO(macho_64)
    changeMainToUnixThread(e)
    d = e.pack()
    assertion('a77d64572857d5414ae414852b930370',
              hashlib.md5(d).hexdigest(),
              'Migrating from LC_MAIN to LC_UNIXTHREAD (64 bits)')
    insert_start_function(e)
    d = e.pack()
    assertion('16b63a2d3cdb3549fe9870b805eb80f5',
              hashlib.md5(d).hexdigest(),
              'Migrating from LC_MAIN to LC_UNIXTHREAD with new segment (64 bits)')
    e = MACHO(macho_64)
    e.changeUUID("2A0405CF8B1F3502A605695A54C407BB")
    uuid_pos, = e.load.getpos(macho.LC_UUID)
    lh = e.load[uuid_pos]
    assertion((704906703, 35615, 13570, 42501, 26970, 1422133179),
              lh.uuid,
              'UUID change')
    d = e.pack()
    assertion('f86802506fb24de2ac2bebd9101326e9',
              hashlib.md5(d).hexdigest(),
              'UUID change (pack)')
    e = MACHO(macho_64)
    for l in e.load:
        if getattr(l,'segname',None) == "__LINKEDIT": break
    e.load.extendSegment(l, 0x1000)
    d = e.pack()
    assertion('405962fd8a4fe751c0ea4fe1a9d02c1e',
              hashlib.md5(d).hexdigest(),
              'Extend segment')
    return ko

def changeMainToUnixThread(e, **kargs):
    main_pos, = e.load.getpos(macho.LC_MAIN)
    sign_pos, = e.load.getpos(macho.LC_DYLIB_CODE_SIGN_DRS)
    sectsign_pos, = e.sect.getpos(e.load[sign_pos].sect[0])
    delta_from_start_to_main = 0x40
    lc_main = e.load[main_pos]
    mainasmpos = lc_main.entryoff - delta_from_start_to_main
    # At some point, we would like to create a load command with:
    #lh = macho.LoadCommand(sex='<', wsize=32, cmd=macho.LC_UNIXTHREAD,
    #    cputype=e.Mhdr.cputype)
    largs = { 'parent':{'cputype':e.Mhdr.cputype}, 'sex':'<', 'wsize': e.wsize}
    if e.wsize == 32:
        c = (macho.LC_UNIXTHREAD, 80, 1, 16,
             0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0xcafebabe, 0, 0, 0, 0, 0)
    elif e.wsize == 64:
        c = (macho.LC_UNIXTHREAD, 184, 4, 42,
             0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
             0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
             0xbabecafe,1, 0,0, 0,0, 0,0, 0,0)
    largs['content'] = struct.pack("<%dI"%len(c), *c)
    lh = macho.LoadCommand(**largs)
    lh.entrypoint = e.off2ad(mainasmpos)
    e.load.append(lh)
    e.load.removepos(sign_pos)
    e.load.removepos(main_pos)
    e.sect.removepos(sectsign_pos)

def insert_start_function(e):
    unix_pos, = e.load.getpos(macho.LC_UNIXTHREAD)
    lh = e.load[unix_pos]
    if e.wsize == 32:
        segtype = macho.LC_SEGMENT
        # binary code for the _start function, taken from crt0.o by gcc
        content = (
            106, 0,                  # pushl $0
            137, 229,                # movl %esp, %ebp
            131, 228, 240,           # andl $-16, %esp
            131, 236, 16,            # subl $16, %esp
            139, 93, 4,              # movl 4(%ebp), %ebx
            137, 28, 36,             # movl %ebx, (%esp)
            141, 77, 8,              # leal 8(%ebp), %ecx
            137, 76, 36, 4,          # movl %ecx, 4(%esp)
            131, 195, 1,             # addl $1, %ebx
            193, 227, 2,             # shll $2, %ebx
            1, 203,                  # addl %ecx, %ebx
            137, 92, 36, 8,          # movl %ebx, 8(%esp)
            139, 3,                  # movl (%ebx), %eax
            131, 195, 4,             # addl $4, %ebx
            133, 192,                # testl %eax, %eax
            117, 247,                # jne .-7
            137, 92, 36, 12,         # movl %ebx, 12(%esp)
            232, 0, 0, 0, 0,        ## call main
            137, 4, 36,              # movl %eax, (%esp)
            232, 0, 0, 0, 0,        ## call exit
            )
        call_offset = 0x0b
        exit_offset = 0x33
        offset_of_call_main = 0x30
        offset_of_call_exit = 0x38
    elif e.wsize == 64:
        segtype = macho.LC_SEGMENT_64
        # binary code for the _start function
        content = (
            106, 0,                  # pushq $0
            72, 137, 229,            # movq %rsp, %rbp
            72, 131, 228, 240,       # andq $-16, %rsp
            72, 139, 125, 8,         # movq 8(%rbp), %rdi
            72, 141, 117, 16,        # movq 16(%rbp), %rsi
            137, 250,                # movl %edi, %edx
            131, 194, 1,             # addl $1, %edx
            193, 226, 3,             # shll $3, %edx
            72, 1, 242,              # addq %rsi, %rdx
            72, 137, 209,            # movq %rdx, %rcx
            235, 4,                  # jmp .+4
            72, 131, 193, 8,         # addq $8, %rcx
            72, 131, 57, 0,          # cmpq $0, (%rcx)
            117, 246,                # jne .-8
            72, 131, 193, 8,         # addq $0, %rcx
            232, 0, 0, 0, 0,        ## call main
            137, 199,                # movl %eax, %edi
            232, 0, 0, 0, 0,        ## call exit
            )
        call_offset = 0x0c
        exit_offset = 0x35
        offset_of_call_main = 0x2f
        offset_of_call_exit = 0x36
    content = struct.pack('%dB'%len(content), *content)
    e.add(type=segtype, segname='__NEWTEXT',
        initprot=macho.VM_PROT_READ|macho.VM_PROT_EXECUTE, content=content)
    off = e.sect.sect[-1].offset
    mainasmpos = e.ad2off(lh.entrypoint)
    lh.entrypoint = e.off2ad(off)
    call = mainasmpos + call_offset - off
    exit = mainasmpos + exit_offset - off
    e.sect.sect[-1].content = content[:offset_of_call_main+1] + struct.pack("<i", call) + content[offset_of_call_main+5:offset_of_call_exit+1] + struct.pack("<i", exit) + content[offset_of_call_exit+5:]

if __name__ == "__main__":
    ko = run_test()
    if ko:
        for k in ko:
            print('Non-regression failure for %r'%k)
    else:
        print('OK')

