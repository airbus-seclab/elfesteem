#! /usr/bin/env python

import os
__dir__ = os.path.dirname(__file__)

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
from elfesteem.macho_init import MACHO
from elfesteem import macho, macho_init

def run_test():
    ko = []
    def assertion(target, value, message):
        if target != value: ko.append(message)
    assertion('f71dbe52628a3f83a77ab494817525c6',
              hashlib.md5(struct.pack('BBBB',116,111,116,111)).hexdigest(),
              'MD5')
    # Simple tests of object creation
    e = MACHO(struct.pack("<I",macho.MH_MAGIC))
    d = e.pack()
    assertion('37b830a1776346543c72ff53fbbe2b4a',
              hashlib.md5(d).hexdigest(),
              'Parsing a minimal data, with Mach-O magic number only')
    e = MACHO(struct.pack("<IIIII",macho.MH_MAGIC,0,0,0,1))
    assertion(1, len(e.lh.lhlist),
              'Parsing data, with one empty loader (lhlist length)')
    d = e.pack()
    assertion('9f3d0a34357e9a81ba87726c812997f2',
              hashlib.md5(d).hexdigest(),
              'Parsing data, with one empty loader (pack)')
    l = macho_init.Loader.create(parent=None,sex='<',wsize=32,
        content=struct.pack(""))
    assertion(macho_init.Loader, l.__class__,
              'Creation of an empty Loader')
    l = macho_init.Loader.create(parent=None,sex='<',wsize=32,
        content=struct.pack("<II",1,0))
    assertion(macho_init.LoaderSegment, l.__class__,
              'Creation of an empty LoaderSegment')
    l.nsects = 2
    assertion(2, l.nsects,
              'Modification of the section number of a loader')
    l = macho_init.Loader.create(parent=None,sex='<',wsize=32,
        content=struct.pack("<II",123456789,0))
    assertion(macho_init.Loader, l.__class__,
              'Creation of a loader command with an unknown lht')
    l = macho_init.Section(parent=None,sex='<',wsize=32)
    assertion(macho_init.Section, l.__class__,
              'Creation of a Section Header')
    # Parsing and modifying files
    macho_32 = open(__dir__+'/binary_input/macho_32.o', 'rb').read()
    macho_32_hash = hashlib.md5(macho_32).hexdigest()
    e = MACHO(macho_32, interval=True)
    d = e.pack()
    assertion(macho_32_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading 32-bit Mach-O object')
    macho_32 = open(__dir__+'/binary_input/macho_32.out', 'rb').read()
    macho_32_hash = hashlib.md5(macho_32).hexdigest()
    e = MACHO(macho_32, interval=True)
    d = e.pack()
    assertion(macho_32_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading 32-bit Mach-O object')
    macho_64 = open(__dir__+'/binary_input/macho_64.o', 'rb').read()
    macho_64_hash = hashlib.md5(macho_64).hexdigest()
    e = MACHO(macho_64, interval=True)
    d = e.pack()
    assertion(macho_64_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading 64-bit Mach-O')
    macho_64 = open(__dir__+'/binary_input/macho_64.out', 'rb').read()
    macho_64_hash = hashlib.md5(macho_64).hexdigest()
    e = MACHO(macho_64, interval=True)
    d = e.pack()
    assertion(macho_64_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading 64-bit Mach-O')
    macho_fat = open(__dir__+'/binary_input/macho_fat.out', 'rb').read()
    macho_fat_hash = hashlib.md5(macho_fat).hexdigest()
    e = MACHO(macho_fat, interval=True)
    d = e.pack()
    assertion(macho_fat_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading fat Mach-O')
    macho_32 = open(__dir__+'/binary_input/macho_32.out', 'rb').read()
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
    e.add(macho_init.Section(parent=None, sex=e.sex, wsize=e.wsize, content='arbitrary content'.encode('latin1')))
    d = e.pack()
    assertion('b61b686819bd3c94e765b220ef708353',
              hashlib.md5(d).hexdigest(),
              'Adding a section (32 bits)')
    e = MACHO(macho_32)
    e.add(macho_init.Loader(parent=None,sex='<',wsize=32,
        content=struct.pack("<II",0x26,0)))
    e.add(type=macho_init.LoaderSegment, segname='__NEWTEXT',
        initprot=macho.SEGMENT_READ|macho.SEGMENT_EXECUTE,
        content='some binary data'.encode('latin1'))
    d = e.pack()
    assertion('4c35f05c0df43a3252f079d99e58b4fc',
              hashlib.md5(d).hexdigest(),
              'Adding a command (32 bits)')
    macho_64 = open(__dir__+'/binary_input/macho_64.out', 'rb').read()
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
    e.add(macho_init.Section(parent=None, sex=e.sex, wsize=e.wsize, content='arbitrary content'.encode('latin1')))
    d = e.pack()
    assertion('be836b2b8adcff60bcc7ca1d712a92a9',
              hashlib.md5(d).hexdigest(),
              'Adding a section (64 bits)')
    e = MACHO(macho_64)
    e.add(macho_init.Loader(parent=None,sex='<',wsize=64,
        content=struct.pack("<II",0x26,0)))
    e.add(type=macho_init.LoaderSegment_64, segname='__NEWTEXT',
        initprot=macho.SEGMENT_READ|macho.SEGMENT_EXECUTE,
        content='some binary data'.encode('latin1'))
    d = e.pack()
    assertion('a946eb818aaf9f38938d0c12fb76ef6e',
              hashlib.md5(d).hexdigest(),
              'Adding a command (64 bits)')
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
    e.changeUUID("2A0405CF8B1F3502A605695A54C407BB")
    uuid_pos, = e.lh.getpos(macho.LC_UUID)
    lh = e.lh.lhlist[uuid_pos]
    assertion((704906703, 35615, 13570, 42501, 26970, 1422133179),
              lh.uuid,
              'UUID change')
    d = e.pack()
    assertion('e600164b4154d5bde8b691c4439e4535',
              hashlib.md5(d).hexdigest(),
              'UUID change (pack)')
    e = MACHO(macho_64)
    for l in e.lh.lhlist:
        if getattr(l,'segname',None) == "__LINKEDIT": break
    e.lh.extendSegment(l, 0x1000)
    d = e.pack()
    assertion('405962fd8a4fe751c0ea4fe1a9d02c1e',
              hashlib.md5(d).hexdigest(),
              'Extend segment')
    return ko

def changeMainToUnixThread(e, **kargs):
    main_pos, = e.lh.getpos(macho.LC_MAIN)
    sign_pos, = e.lh.getpos(macho.LC_DYLIB_CODE_SIGN_DRS)
    sectsign_pos, = e.sect.getpos(e.lh.lhlist[sign_pos].sect[0])
    delta_from_start_to_main = 0x40
    lc_main = e.lh.lhlist[main_pos]
    mainasmpos = lc_main.entryoff - delta_from_start_to_main
    largs = { 'parent': {'cputype':e.Mhdr.cputype}, 'sex': '<', 'wsize': 32,
              'content': struct.pack("<II",macho.LC_UNIXTHREAD,8), }
    lh = macho_init.Loader.create(**largs)
    lh.parse_content(**largs)
    lh.entrypoint = e.off2ad(mainasmpos)
    e.lh.append(lh)
    e.lh.removepos(sign_pos)
    e.lh.removepos(main_pos)
    e.sect.removepos(sectsign_pos)

def insert_start_function(e):
    unix_pos, = e.lh.getpos(macho.LC_UNIXTHREAD)
    lh = e.lh.lhlist[unix_pos]
    if e.wsize == 32:
        segtype = macho_init.LoaderSegment
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
        segtype = macho_init.LoaderSegment_64
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
        initprot=macho.SEGMENT_READ|macho.SEGMENT_EXECUTE, content=content)
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

