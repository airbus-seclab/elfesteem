#! /usr/bin/env python

import os
__dir__ = os.path.dirname(__file__)
__dir__ += '/binary_input/macho/'

from test_all import run_tests, assertion, hashlib, open_read
import struct
from elfesteem.macho import MACHO, log
from elfesteem import macho

# We want to be able to verify warnings in non-regression test
log_history = []
log.warning = lambda *args, **kargs: log_history.append(('warn',args,kargs))
log.error = lambda *args, **kargs: log_history.append(('error',args,kargs))

def test_MACHO_xleb128(assertion):
    # Testing some internals
    from elfesteem.macho import Uleb128, Sleb128
    f = struct.pack("B", 0x0)
    v = Uleb128(parent=None,content=f)
    assertion(v.value, 0x0, 'Reading Uleb128 %#x' % v.value)
    assertion(v.pack(), f, 'Packing Uleb128 %#x' % v.value)
    v = Sleb128(parent=None,content=f)
    assertion(v.value, 0x0, 'Reading Sleb128 %#x' % v.value)
    assertion(v.pack(), f, 'Packing Sleb128 %#x' % v.value)
    f = struct.pack("B", 0x20)
    v = Uleb128(parent=None,content=f)
    assertion(v.value, 0x20, 'Reading Uleb128 %#x' % v.value)
    assertion(v.pack(), f, 'Packing Uleb128 %#x' % v.value)
    v = Sleb128(parent=None,content=f)
    assertion(v.value, 0x20, 'Reading Sleb128 %#x' % v.value)
    assertion(v.pack(), f, 'Packing Sleb128 %#x' % v.value)
    f = struct.pack("B", 0x40)
    v = Uleb128(parent=None,content=f)
    assertion(v.value, 0x40, 'Reading Uleb128 %#x' % v.value)
    assertion(v.pack(), f, 'Packing Uleb128 %#x' % v.value)
    v = Sleb128(parent=None,content=f)
    assertion(v.value, -0x40, 'Reading Sleb128 %#x' % v.value)
    assertion(v.pack(), f, 'Packing Sleb128 %#x' % v.value)
    f = struct.pack("B", 0x60)
    v = Uleb128(parent=None,content=f)
    assertion(v.value, 0x60, 'Reading Uleb128 %#x' % v.value)
    assertion(v.pack(), f, 'Packing Uleb128 %#x' % v.value)
    v = Sleb128(parent=None,content=f)
    assertion(v.value, -0x20, 'Reading Sleb128 %#x' % v.value)
    assertion(v.pack(), f, 'Packing Sleb128 %#x' % v.value)
    f = struct.pack("BB", 0x80, 0x01)
    v = Uleb128(parent=None,content=f)
    assertion(v.value, 0x80, 'Reading Uleb128 %#x' % v.value)
    assertion(v.pack(), f, 'Packing Uleb128 %#x' % v.value)
    v = Sleb128(parent=None,content=f)
    assertion(v.value, 0x80, 'Reading Sleb128 %#x' % v.value)
    assertion(v.pack(), f, 'Packing Sleb128 %#x' % v.value)
    f = struct.pack("BBB", 0x80, 0xff, 0x41)
    v = Uleb128(parent=None,content=f)
    assertion(v.value, 0x107f80, 'Reading Uleb128 %#x' % v.value)
    assertion(v.pack(), f, 'Packing Uleb128 %#x' % v.value)
    v = Sleb128(parent=None,content=f)
    assertion(v.value, -0xf8080, 'Reading Sleb128 %#x' % v.value)
    assertion(v.pack(), f, 'Packing Sleb128 %#x' % v.value)

# Locale setting is used by otool to display time stamps.
# For non-regression tests, we need to negate the effet of the locale.
os.environ['TZ'] = ''

def test_MACHO_minimal(assertion):
    global log_history
    # Simple tests of object creation
    e = MACHO(struct.pack("<I",macho.MH_MAGIC))
    assertion([('warn', ('parse_dynamic_symbols() can only be used with x86 architectures, not %s', 0), {})],
              log_history,
              'Parsing a minimal data, with Mach-O magic number only (logs)')
    log_history = []
    assertion(e.entrypoint, -1,
              'No entrypoint in a truncated Mach-O header')
    assertion([('error', ('Not a unique loader with entrypoint: []',), {})],
              log_history,
              'No entrypoint in a truncated Mach-O header (logs)')
    log_history = []
    d = e.pack()
    assertion('37b830a1776346543c72ff53fbbe2b4a',
              hashlib.md5(d).hexdigest(),
              'Parsing a minimal data, with Mach-O magic number only')

def test_MACHO_zero_cmds(assertion):
    global log_history
    f = struct.pack("<IIIIIIIII",macho.MH_MAGIC,macho.CPU_TYPE_I386,0,0,1,0,0,0,8)
    e = MACHO(f)
    assertion([('error', ('Too many load command: %d commands cannot fit in %d bytes', 1, 0), {}),
               ('warn', ('Part of the file was not parsed: %d bytes', 1), {})],
              log_history,
              'Parsing a invalid output with zero sizeofcmds (logs)')
    log_history = []

def test_MACHO_toolarge_cmds(assertion):
    global log_history
    f = struct.pack("<IIIIIIIII",macho.MH_MAGIC,macho.CPU_TYPE_I386,0,0,1,0xffff,0,0,8)
    e = MACHO(f)
    assertion([('error', ('LoadCommands longer than file length',), {}),
               ('warn', ('Part of the file was not parsed: %d bytes', 1), {})],
              log_history,
              'Parsing a invalid output with big sizeofcmds (logs)')
    log_history = []

def test_MACHO_one_loader(assertion):
    global log_history
    f = struct.pack("<IIIIIIIIII",macho.MH_MAGIC,macho.CPU_TYPE_I386,0,0,1,12,0,macho.LC_PREBIND_CKSUM,12,0)
    e = MACHO(f)
    d = e.pack()
    assertion(f, d,
              'Parsing data, with one LC_PREBIND_CKSU loader')

def test_MACHO_one_loader_padding(assertion):
    global log_history
    f = struct.pack("<IIIIIIIIIII",macho.MH_MAGIC,macho.CPU_TYPE_I386,0,0,1,16,0,macho.LC_PREBIND_CKSUM,16,0,0)
    e = MACHO(f)
    assertion([('warn', ('%s has %d bytes of additional padding', 'prebind_cksum_command', 4), {})],
              log_history,
              'Parsing invalid data, with one LC_PREBIND_CKSU loader with padding (logs)')
    log_history = []

def test_MACHO_one_loader_too_short(assertion):
    global log_history
    f = struct.pack("<IIIIIIIIIII",macho.MH_MAGIC,macho.CPU_TYPE_I386,0,0,1,8,0,macho.LC_PREBIND_CKSUM,8,0,0)
    e = MACHO(f)
    assertion([('warn', ('%s is %d bytes too short', 'prebind_cksum_command', 4), {})],
              log_history,
              'Parsing invalid data, with one LC_PREBIND_CKSU loader, too short (logs)')
    log_history = []

def test_MACHO_additional_padding(assertion):
    global log_history
    f = struct.pack("<IIIIIIIIIII",macho.MH_MAGIC,macho.CPU_TYPE_I386,0,0,1,16,0,macho.LC_PREBIND_CKSUM,12,0,0)
    e = MACHO(f)
    assertion([('warn', ('LoadCommands have %d bytes of additional padding', 4), {})],
              log_history,
              'Parsing invalid data, with padding after load commands (logs)')
    log_history = []

def test_MACHO_empty_loader(assertion):
    f = struct.pack("<IIIIIIIII",macho.MH_MAGIC,macho.CPU_TYPE_I386,0,0,1,8,0,0,8)
    e = MACHO(f)
    assertion(1, len(e.load),
              'Parsing data, with one empty loader (lhlist length)')
    d = e.pack()
    assertion(f, d,
              'Parsing data, with one empty loader (pack)')

def test_MACHO_load_commands(assertion):
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

def test_MACHO_macho32_obj(assertion):
    global log_history
    # Parsing and modifying files
    macho_32 = open_read(__dir__+'macho_32.o')
    macho_32_hash = hashlib.md5(macho_32).hexdigest()
    e = MACHO(macho_32)
    d = e.pack()
    assertion(macho_32_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading 32-bit Mach-O object')
    assertion(e.entrypoint, -1,
              'No entrypoint in a Mach-O object')
    assertion([('error', ('Not a unique loader with entrypoint: []',), {})],
              log_history,
              'No entrypoint in a Mach-O object (logs)')
    assertion(len(e.symbols), 3,
              'Number of symbols in a Mach-O object')
    d = ("\n".join([_.otool() for _ in e.symbols])).encode('latin1')
    assertion('9543b68138927d012139e526f159846c',
              hashlib.md5(d).hexdigest(),
              'Display symbols')
    assertion(e.symbols['_printf'].otool(),
              '_printf                             NO_SECT         UX   0x00000000 0000',
              'Find symbol by name')
    assertion('SymbolNotFound', e.symbols[10].__class__.__name__,
              'Find symbol by invalid index')
    e.symbols[0].sectionindex = 5
    assertion(e.symbols[0].otool(),
              '_a                                  INVALID(5)      SX   0x00000000 0000',
              'Display symbol with invalid section')
    e.symbols[0].sectionindex = 0xff
    assertion(e.symbols[0].otool(),
              '_a                                  INVALID(255)    SX   0x00000000 0000',
              'Display symbol with too big section index')
    log_history = []
    e.entrypoint = 0
    assertion([('error', ('Not a unique loader with entrypoint: []',), {})],
              log_history,
              'Cannot set entrypoint in a Mach-O object (logs)')
    log_history = []
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

def test_MACHO_macho32_exe(assertion):
    global log_history
    macho_32 = open_read(__dir__+'macho_32.out')
    macho_32_hash = hashlib.md5(macho_32).hexdigest()
    e = MACHO(macho_32)
    d = e.pack()
    assertion(macho_32_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading 32-bit Mach-O executable')
    assertion(e.entrypoint, 8000,
              'entrypoint in a 32-bit Mach-O executable')
    assertion(e.virt.max_addr(), 16384,
              'Maximum address in a 32-bit Mach-O executable')
    e.entrypoint = 8010
    assertion(e.entrypoint, 8010,
              'Changing entrypoint in a 32-bit Mach-O executable')
    e.entrypoint = 9000
    assertion(e.entrypoint, 8010,
              'Changing entrypoint with an invalid address')
    assertion([('error', ('Address %#x not mapped in memory', 9000), {})],
              log_history,
              'Changing entrypoint with an invalid address (logs)')
    log_history = []

def test_MACHO_macho64_obj(assertion):
    macho_64 = open_read(__dir__+'macho_64.o')
    macho_64_hash = hashlib.md5(macho_64).hexdigest()
    e = MACHO(macho_64)
    d = e.pack()
    assertion(macho_64_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading 64-bit Mach-O object')

def test_MACHO_macho64_exe(assertion):
    macho_64 = open_read(__dir__+'macho_64.out')
    macho_64_hash = hashlib.md5(macho_64).hexdigest()
    e = MACHO(macho_64)
    d = e.pack()
    assertion(macho_64_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading 64-bit Mach-O executable')

def test_MACHO_fat(assertion):
    global log_history
    macho_fat = open_read(__dir__+'macho_fat.out')
    macho_fat_hash = hashlib.md5(macho_fat).hexdigest()
    e = MACHO(macho_fat)
    d = e.pack()
    assertion(macho_fat_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading fat Mach-O')
    assertion(e.virt.max_addr(), -1,
              'No unique maximum address in a Mach-O fat')
    assertion([('error', ('Not a unique memory mapping in Mach-O fat',), {})],
              log_history,
              'No unique maximum address in a Mach-O fat (logs)')
    log_history = []
    assertion(e.entrypoint, -1,
              'Many entrypoints in a fat Mach-O')
    assertion([('error', ('Not a unique entrypoint in Mach-O fat',), {})],
              log_history,
              'Many entrypoints in a fat Mach-O (logs)')
    log_history = []
    e.entrypoint = 0
    assertion([('error', ('Not a unique entrypoint in Mach-O fat',), {})],
              log_history,
              'Cannot set entrypoint directly in a fat Mach-O (logs)')
    log_history = []

def test_MACHO_virt(assertion):
    macho_32 = open_read(__dir__+'macho_32.out')
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

def test_MACHO_bin_sh(assertion):
    macho_bin = open_read(__dir__+'sh')
    e = MACHO(macho_bin)
    macho_bin_hash = hashlib.md5(macho_bin).hexdigest()
    d = e.pack()
    assertion(macho_bin_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading /bin/sh')

def test_MACHO_lib_dns(assertion):
    global log_history
    macho_lib = open_read(__dir__+'libdns_services.dylib')
    e = MACHO(macho_lib)
    assertion(e.entrypoint, -1,
              'No entrypoint in a Mach-O library')
    assertion([('error', ('Not a unique loader with entrypoint: []',), {})],
              log_history,
              'No entrypoint in a Mach-O library (logs)')
    log_history = []
    macho_lib_hash = hashlib.md5(macho_lib).hexdigest()
    d = e.pack()
    assertion(macho_lib_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading DNS library')
    d = ('\n'.join([_ for l in e.load for _ in l.otool()])).encode('latin1')
    assertion('2d6194feedf82da26124d3128473a949',
              hashlib.md5(d).hexdigest(),
              'Otool-like output including LC_SOURCE_VERSION')

def test_MACHO_lib_ecpg(assertion):
    macho_lib = open_read(__dir__+'libecpg.6.5.dylib')
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
    assertion(e.symbols[1].otool(),
              'execute.c                           NO_SECT         0x4  D 0x00000000 0000',
              'Display symbol with N_STAB type')

def test_MACHO_lib_ATcommand(assertion):
    macho_lib = open_read(__dir__+'libATCommandStudioDynamic.dylib')
    e = MACHO(macho_lib)
    macho_lib_hash = hashlib.md5(macho_lib).hexdigest()
    d = e.pack()
    assertion(macho_lib_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading libATCommandStudioDynamic')
    bind_s = [ _ for _ in e.sect if getattr(_, 'type', None)
               in ('bind_','weak_bind_','lazy_bind_','rebase_','export_') ]
    d = ('\n'.join([str(_) for s in bind_s for _ in s.info])).encode('latin1')
    assertion('8b29446352613fdb6c4a6142c7c476c3',
              hashlib.md5(d).hexdigest(),
              'dyldinfo-like output for all binding types (libATCommand...)')
    bind_s = [ _ for _ in e.sect if getattr(_, 'type', None)
               in ('bind_','weak_bind_','lazy_bind_','rebase_') ]
    d = ('\n'.join([str(_) for s in bind_s for _ in s])).encode('latin1')
    assertion('66bb196759c094c0c08d8159cf61d67f',
              hashlib.md5(d).hexdigest(),
              'dyldinfo-like output for dyld opcodes (libATCommand...)')

def test_MACHO_lib_system(assertion):
    macho_lib = open_read(__dir__+'libSystem.B.dylib')
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

def test_MACHO_lib_tls(assertion):
    macho_lib = open_read(__dir__+'libcoretls.dylib')
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

def test_MACHO_app_OSXII(assertion):
    global log_history
    macho_app = open_read(__dir__+'OSXII')
    e = MACHO(macho_app)
    assertion([('warn', ('parse_dynamic_symbols() can only be used with x86 architectures, not %s', 18), {})],
              log_history,
              'Parsing OSXII app (logs)')
    log_history = []
    macho_app_hash = hashlib.md5(macho_app).hexdigest()
    d = e.pack()
    assertion(macho_app_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading OSXII app')
    d = ('\n'.join([_ for a in e.arch for l in a.load for _ in l.otool(llvm=7)])).encode('latin1')
    assertion('8b926db115b4cae5146774ef589674be',
              hashlib.md5(d).hexdigest(),
              'Otool-like output including ppc & i386 register state')

def test_MACHO_app_MTR(assertion):
    global log_history
    macho_app = open_read(__dir__+'MacTheRipper')
    e = MACHO(macho_app)
    assertion([('warn', ('parse_dynamic_symbols() can only be used with x86 architectures, not %s', 18), {})],
              log_history,
              'Parsing MacTheRipper app (logs)')
    log_history = []
    macho_app_hash = hashlib.md5(macho_app).hexdigest()
    d = e.pack()
    assertion(macho_app_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading MacTheRipper app')
    assertion(e.entrypoint, 0xa760,
              'Entrypoint in MacTheRipper app')
    d = ('\n'.join([_ for l in e.load for _ in l.otool()])).encode('latin1')
    assertion('b10cd006c10906db3329e0dccd0babbe',
              hashlib.md5(d).hexdigest(),
              'Otool-like output including LC_PREBOUND_DYLIB')

def test_MACHO_exe_SH3D(assertion):
    global log_history
    macho_app = open_read(__dir__+'SweetHome3D')
    e = MACHO(macho_app)
    assertion([('warn', ('parse_dynamic_symbols() can only be used with x86 architectures, not %s', 18), {})],
              log_history,
              'Parsing SweetHome3D app (logs)')
    log_history = []
    macho_app_hash = hashlib.md5(macho_app).hexdigest()
    d = e.pack()
    assertion(macho_app_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading SweetHome3D app')
    d = ('\n'.join([_ for a in e.arch for l in a.load for _ in l.otool()])).encode('latin1')
    assertion('4bf0088471bd2161baf4a42dbb09dc5b',
              hashlib.md5(d).hexdigest(),
              'Otool-like output including ppc, i386 & x86_64register state')

def test_MACHO_lib_print(assertion):
    global log_history
    macho_32be = open_read(__dir__+'libPrintServiceQuota.1.dylib')
    e = MACHO(macho_32be)
    assertion([('warn', ('parse_dynamic_symbols() can only be used with x86 architectures, not %s', 18), {})],
              log_history,
              'Parsing libPrintServiceQuota (logs)')
    log_history = []
    macho_32be_hash = hashlib.md5(macho_32be).hexdigest()
    d = e.pack()
    assertion(macho_32be_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading 32-bit big-endian Mach-O shared library')
    d = ('\n'.join([_ for l in e.load for _ in l.otool()])).encode('latin1')
    assertion('cabaf4f4368c094bbb0c09f278510006',
              hashlib.md5(d).hexdigest(),
              'Otool-like output for LC in 32-bit big-endian Mach-O shared library')

def test_MACHO_ios_decibels(assertion):
    global log_history
    macho_ios = open_read(__dir__+'Decibels')
    e = MACHO(macho_ios)
    assertion([('warn', ('Some encrypted text is not parsed with the section headers of LC_SEGMENT(__TEXT)',), {}),
               ('warn', ('parse_dynamic_symbols() can only be used with x86 architectures, not %s', 12), {}),
               ('warn', ('Part of the file was not parsed: %d bytes', 2499), {}),
               ('warn', ('Some encrypted text is not parsed with the section headers of LC_SEGMENT(__TEXT)',), {}),
               ('warn', ('parse_dynamic_symbols() can only be used with x86 architectures, not %s', 12), {}),
               ('warn', ('Part of the file was not parsed: %d bytes', 2495), {})],
              log_history,
              'Parsing Decibels iOS app (logs)')
    log_history = []
    macho_ios_hash = hashlib.md5(macho_ios).hexdigest()
    d = e.pack()
    assertion(macho_ios_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading iOS application Decibels')
    d = ('\n'.join([_ for a in e.arch for l in a.load for _ in l.otool()])).encode('latin1')
    assertion('0d3281e546fd6e41306dbf38e5fbd0b6',
              hashlib.md5(d).hexdigest(),
              'Otool-like output for LC in iOS application')

def test_MACHO_ios_lyonmetro(assertion):
    global log_history
    macho_ios = open_read(__dir__+'LyonMetro')
    e = MACHO(macho_ios)
    assertion([('warn', ('Some encrypted text is not parsed with the section headers of LC_SEGMENT(__TEXT)',), {}),
               ('warn', ('parse_dynamic_symbols() can only be used with x86 architectures, not %s', 12), {}),
               ('warn', ('Part of the file was not parsed: %d bytes', 3908), {})],
              log_history,
              'Parsing LyonMetro iOS app (logs)')
    log_history = []
    macho_ios_hash = hashlib.md5(macho_ios).hexdigest()
    d = e.pack()
    assertion(macho_ios_hash,
              hashlib.md5(d).hexdigest(),
              'Packing after reading iOS application LyonMetro')
    assertion(e.entrypoint, 0x2f50,
              'Entrypoint in iOS application LyonMetro')
    d = ('\n'.join([_ for l in e.load for _ in l.otool()])).encode('latin1')
    assertion('7bac82cc00b5cce2cb96344d678508e5',
              hashlib.md5(d).hexdigest(),
              'Otool-like output including LC_VERSION_MIN_IPHONEOS')

def test_MACHO_obj_telephony(assertion):
    global log_history
    macho_linkopt = open_read(__dir__+'TelephonyUtil.o')
    macho_linkopt_hash = hashlib.md5(macho_linkopt).hexdigest()
    e = MACHO(macho_linkopt)
    assertion([('warn', ('Part of the file was not parsed: %d bytes', 6), {})],
              log_history,
              'Parsing TelephonyUtil.o (logs)')
    log_history = []
    d = e.pack()
    assertion(macho_linkopt_hash,
              hashlib.md5(d).hexdigest(),
              "Packing after reading object file with LC_LINKER_OPTION, 'interval' option is needed because there is some nop padding at the end of __TEXT,__text")
    d = ('\n'.join([_ for l in e.load for _ in l.otool()])).encode('latin1')
    assertion('984bf38084c14e435f30eebe36944b47',
              hashlib.md5(d).hexdigest(),
              'Otool-like output for LC in object file with LC_LINKER_OPTION')

def test_MACHO_loader_lc_build_version(assertion):
    global log_history
    macho_lcbuild = open_read(__dir__+'macho_lcbuild.out')
    macho_lcbuild_hash = hashlib.md5(macho_lcbuild).hexdigest()
    e = MACHO(macho_lcbuild)
    d = e.pack()
    assertion(macho_lcbuild_hash,
              hashlib.md5(d).hexdigest(),
              "Packing after reading executable with LC_BUILD_VERSION")
    d = ('\n'.join([_ for l in e.load for _ in l.otool()])).encode('latin1')
    assertion('6dd985753ccf51b0d5c7470126d43a6c',
              hashlib.md5(d).hexdigest(),
              'Otool-like output for LC in executable with LC_BUILD_VERSION')

def test_MACHO_prebind_32(assertion):
    global log_history
    macho_32 = open_read(__dir__+'macho_32.out')
    e = MACHO(macho_32)
    e.add(macho.LoadCommand(sex='<',wsize=32,cmd=0))
    d = e.pack()
    assertion('6fefeaf7b4de67f8270d3425942d7a97',
              hashlib.md5(d).hexdigest(),
              'Adding an empty command (32 bits)')
    f = struct.pack("<III",macho.LC_ROUTINES_64,12,0)
    l = macho.prebind_cksum_command(parent=None, sex='<', wsize=32, content=f)
    assertion([('warn', ('Incoherent input cmd=%#x for %s', 26, 'prebind_cksum_command'), {})],
              log_history,
              'Parsing incoherent load command prebind_cksum_command with LC_ROUTINES_64 tag (logs)')
    log_history = []
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

def test_MACHO_prebind_64(assertion):
    global log_history
    macho_64 = open_read(__dir__+'macho_64.out')
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

def test_MACHO_unixthread_32(assertion):
    # The function changeMainToUnixThread migrates a Mach-O binary for
    # recent MacOSX (using a LC_MAIN loader) to a Mac-O binary for older
    # versions of MacOSX (10.7 and older, using a LC_UNIXTHREAD loader).
    macho_32 = open_read(__dir__+'macho_32.out')
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

def test_MACHO_unixthread_64(assertion):
    macho_64 = open_read(__dir__+'macho_64.out')
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

def test_MACHO_changeUUID(assertion):
    macho_64 = open_read(__dir__+'macho_64.out')
    e = MACHO(macho_64)
    e.changeUUID("2A0405CF8B1F3502A605695A54C407BB")
    uuid_pos, = e.load.getpos(macho.LC_UUID)
    lh = e.load[uuid_pos]
    assertion((0x2A0405CF, 0x8B1F, 0x3502, 0xA605, 0x695A, 0x54C407BB),
              lh.uuid,
              'UUID change')
    assertion('<LC_UUID 2A0405CF-8B1F-3502-A605-695A54C407BB>',
              repr(lh),
              'UUID change (repr)')
    d = e.pack()
    assertion('f86802506fb24de2ac2bebd9101326e9',
              hashlib.md5(d).hexdigest(),
              'UUID change (pack)')
    lh.uuid = (0,0xAAAA,0,0,0,0x11111111)
    assertion((0,0xAAAA,0,0,0,0x11111111),
              lh.uuid,
              'set UUID')
    d = e.pack()
    assertion('c8457df239deb4c51c316bd6670a445e',
              hashlib.md5(d).hexdigest(),
              'set UUID (pack)')

def test_MACHO_extend_segment(assertion):
    macho_64 = open_read(__dir__+'macho_64.out')
    e = MACHO(macho_64)
    for l in e.load:
        if getattr(l,'segname',None) == "__LINKEDIT": break
    e.load.extendSegment(l, 0x1000)
    d = e.pack()
    assertion('405962fd8a4fe751c0ea4fe1a9d02c1e',
              hashlib.md5(d).hexdigest(),
              'Extend segment')
    assertion([],
              log_history,
              'No non-regression test created unwanted log messages')



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
             0, 0, macho.FAT_MAGIC, 0, 0, 0, 0, 0)
    elif e.wsize == 64:
        FAT_MAGIC_SWAPPED = macho.FAT_MAGIC>>16 + (macho.FAT_MAGIC&0xffff)<<16
        c = (macho.LC_UNIXTHREAD, 184, 4, 42,
             0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
             0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
             FAT_MAGIC_SWAPPED,1, 0,0, 0,0, 0,0, 0,0)
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
    else:
        raise ValueError("Wordsize %s is not possible", e.wsize)
    content = struct.pack('%dB'%len(content), *content)
    e.add(type=segtype, segname='__NEWTEXT',
        initprot=macho.VM_PROT_READ|macho.VM_PROT_EXECUTE, content=content)
    off = e.sect.sect[-1].offset
    mainasmpos = e.ad2off(lh.entrypoint)
    lh.entrypoint = e.off2ad(off)
    call = mainasmpos + call_offset - off
    exit = mainasmpos + exit_offset - off
    e.sect.sect[-1].content = content[:offset_of_call_main+1] + struct.pack("<i", call) + content[offset_of_call_main+5:offset_of_call_exit+1] + struct.pack("<i", exit) + content[offset_of_call_exit+5:]

def run_test(assertion):
    for name, value in dict(globals()).items():
        if name.startswith('test_'):
            value(assertion)

if __name__ == "__main__":
    run_tests(run_test)
