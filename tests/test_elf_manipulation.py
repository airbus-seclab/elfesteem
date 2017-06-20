#! /usr/bin/env python

import os
__dir__ = os.path.dirname(__file__)

from test_all import run_tests, assertion, hashlib
from elfesteem.strpatchwork import StrPatchwork
from elfesteem.elf_init import ELF, log
from elfesteem import elf

import struct

# We want to be able to verify warnings in non-regression test
log_history = []
log.warning = lambda *args, **kargs: log_history.append(('warn',args,kargs))
log.error = lambda *args, **kargs: log_history.append(('error',args,kargs))

def test_ELF_empty(assertion):
    e = ELF()
    d = e.pack()
    assertion('0ddf18391c150850c72257b3f3caa67b',
              hashlib.md5(d).hexdigest(),
              'Creation of a standard empty ELF')
    assertion(0,
              len(e.symbols),
              'Empty ELF has no symbols')
    d = ELF(d).pack()
    assertion('0ddf18391c150850c72257b3f3caa67b',
              hashlib.md5(d).hexdigest(),
              'Creation of a standard empty ELF; fix point')
    assertion(True,
              e.has_relocatable_sections(),
              'Standard empty ELF is relocatable')

def test_ELF_invalid(assertion):
    try:
        e = ELF(open(__dir__+'/binary_input/README.txt', 'rb').read())
        assertion(0,1, 'Not an ELF')
    except ValueError:
        pass

def test_ELF_creation(assertion):
    e = ELF(
        e_type    = elf.ET_REL, # Default value
        e_machine = elf.EM_386, # Default value
        sections = ['.text', '.text.startup', '.group',
                    '.data', '.rodata.str1.4', '.rodata.cst4',
                    '.bss', '.eh_frame', '.comment', '.note.GNU-stack',
                    ],
        relocs = ['.text'], # These sections will have relocs
        )
    d = e.pack()
    assertion('dc3f17080d002ba0bfb3aec9f3bec8b2',
              hashlib.md5(d).hexdigest(),
              'Creation of an ELF with a given list of sections')

def test_ELF_small32(assertion):
    global log_history
    elf_small = open(__dir__+'/binary_input/elf_small.out', 'rb').read()
    assertion('d5284d5f438e25ef5502a0c1de97d84f',
              hashlib.md5(elf_small).hexdigest(),
              'Reading elf_small.out')
    e = ELF(elf_small)
    d = e.pack()
    assertion('d5284d5f438e25ef5502a0c1de97d84f',
              hashlib.md5(d).hexdigest(),
              'Packing after reading elf_small.out')
    # Packed file is identical :-)
    d = repr(e.ph).encode('latin1')
    assertion('ab4b1e52e7532789592878872910a2a1',
              hashlib.md5(d).hexdigest(),
              'Display Program Headers')
    d = repr(e.sh).encode('latin1')
    assertion('ddf01165114eb70bd27910e4c5b03c09',
              hashlib.md5(d).hexdigest(),
              'Display Section Headers (repr)')
    d = e.sh.readelf_display().encode('latin1')
    assertion('08da11fa164d7013561db398c068ac71',
              hashlib.md5(d).hexdigest(),
              'Display Section Headers (readelf)')
    d = e.getsectionbyname('.symtab').readelf_display().encode('latin1')
    assertion('943434f4cde658b1659b7d8db39d9e60',
              hashlib.md5(d).hexdigest(),
              'Display Symbol Table')
    assertion('    49: 0804a01c     0 NOTYPE  GLOBAL DEFAULT  ABS _edata',
              e.getsectionbyname('.symtab')['_edata'].readelf_display(),
              'Get symbol by name, found')
    assertion('     2: 00000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail',
              e.getsectionbyname('.dynsym')[2].readelf_display(),
              'Get symbol by index, found')
    d = e.getsectionbytype(elf.SHT_SYMTAB).pack()
    assertion('4ed5a808faff1ca7c6a766ae45ebf377',
              hashlib.md5(d).hexdigest(),
              'Get existing section by type')
    d = e.getsectionbyname('.text').pack()
    assertion('7149c6e4b8baaab8beebfeb818585638',
              hashlib.md5(d).hexdigest(),
              'Get existing section by name')
    d = e.getsectionbyvad(0x080483d0+0x100).pack()
    assertion('7149c6e4b8baaab8beebfeb818585638',
              hashlib.md5(d).hexdigest(),
              'Get existing section by address')
    d = e.getsectionbyname('no_sect')
    assertion(None, d, 'Get non-existing section by name')
    d = e.getsectionbyvad(0x1000)
    assertion(None, d, 'Get non-existing section by address')
    d = e[0x100:0x120]
    assertion('5e94f899265a799826a46ec86a293e16',
              hashlib.md5(d).hexdigest(),
              'Extract chunk from raw data')
    assertion(e[0x100:0x120],
              e._content[0x100:0x120],
              'Extract chunk from raw data, deprecated API')
    assertion(True,
              e.virt.is_addr_in(0x080483d0),
              'Address in mapped virtual memory')
    assertion(False,
              e.virt.is_addr_in(0x08048000),
              'Address not in mapped virtual memory')
    d = e.virt[0x080483d0:0x080483e0]
    assertion('9d225ebfd0f9562b74b17c5a4653dc6f',
              hashlib.md5(d).hexdigest(),
              'Extract chunk from mapped memory, in a section')
    try:
        d = e.virt[0x08040000:0x08040020]
        assertion(0,1, 'Extract chunk from non-mapped memory')
    except ValueError:
        pass
    assertion(e.virt[0x080483d0:0x080483e0],
              e.virt(0x080483d0,0x080483e0),
              'Extract chunk from mapped memory, old API')
    e.virt[0x080483d0:0x080483e0] = e.virt[0x080483d0:0x080483e0]
    d = e.pack()
    assertion('d5284d5f438e25ef5502a0c1de97d84f',
              hashlib.md5(d).hexdigest(),
              'Writing in memory (interval)')
    e.virt[0x080483d0] = e.virt[0x080483d0:0x080483e0]
    d = e.pack()
    assertion('d5284d5f438e25ef5502a0c1de97d84f',
              hashlib.md5(d).hexdigest(),
              'Writing in memory (address)')
    assertion(0x804a028, len(e.virt), 'Max virtual address')
    assertion([('warn', ('__len__ deprecated',), {})],
              log_history,
              '__len__ deprecated (logs)')
    log_history = []
    # Find leave; ret
    assertion(0x8048481,
              e.virt.find(struct.pack('BB', 0xc9, 0xc3)),
              'Find pattern (existing)')
    assertion(-1,
              e.virt.find(struct.pack('BBBB', 1,2,3,4)),
              'Find pattern (not existing)')

def test_ELF_small64(assertion):
    elf64_small = open(__dir__+'/binary_input/elf64_small.out', 'rb').read()
    assertion('dc21d928bb6a3a0fa59b17fafe803d50',
              hashlib.md5(elf64_small).hexdigest(),
              'Reading elf64_small.out')
    e = ELF(elf64_small)
    d = e.pack()
    assertion('dc21d928bb6a3a0fa59b17fafe803d50',
              hashlib.md5(d).hexdigest(),
              'Packing after reading elf64_small.out')
    # Packed file is identical :-)
    d = e.sh.readelf_display().encode('latin1')
    assertion('6d4aa86afdbf612430cb699987bc22b9',
              hashlib.md5(d).hexdigest(),
              'Display Section Headers (readelf, 64bit)')
    d = e.getsectionbyname('.symtab').readelf_display().encode('latin1')
    assertion('452e64fb0f2dad5c0e44d83e57b9d82b',
              hashlib.md5(d).hexdigest(),
              'Display Symbol Table (elf64)')
    d = e.getsectionbyname('.rela.dyn').readelf_display().encode('latin1')
    assertion('650cf3f99117d39d63fae73232e09acf',
              hashlib.md5(d).hexdigest(),
              'Display Reloc Table (elf64)')

def test_ELF_group(assertion):
    elf_group = open(__dir__+'/binary_input/elf_cpp.o', 'rb').read()
    assertion('57fed5de9474bc0600173a1db5ee6327',
              hashlib.md5(elf_group).hexdigest(),
              'Reading elf_cpp.o')
    e = ELF(elf_group)
    d = e.pack()
    assertion('57fed5de9474bc0600173a1db5ee6327',
              hashlib.md5(d).hexdigest(),
              'Packing after reading elf_cpp.o')
    # Packed file is identical :-)
    d = e.getsectionbyname('.group').readelf_display().encode('latin1')
    assertion('5c80b11a64a32e7aaee8ef378da4ccef',
              hashlib.md5(d).hexdigest(),
              'Display Group Section')

def test_ELF_TMP320C6x(assertion):
    elf_tmp320c6x = open(__dir__+'/binary_input/notle-tesla-dsp.xe64T', 'rb').read()
    assertion('fb83ed8d809f394e70f5d84d0c8e593f',
              hashlib.md5(elf_tmp320c6x).hexdigest(),
              'Reading notle-tesla-dsp.xe64T')
    e = ELF(elf_tmp320c6x)
    d = e.pack()
    assertion('fb83ed8d809f394e70f5d84d0c8e593f',
              hashlib.md5(d).hexdigest(),
              'Packing after reading notle-tesla-dsp.xe64T')
    # Packed file is identical :-)
    d = e.sh.readelf_display().encode('latin1')
    assertion('ecf169c765d29175177528e24601f1be',
              hashlib.md5(d).hexdigest(),
              'Display Section Headers (TMP320C6x)')

def test_ELF_invalid_entsize(assertion):
    global log_history
    # Some various ways for an ELF to be detected as invalid
    e = ELF()
    e.symbols.sh.entsize = 24
    e = ELF(e.pack())
    assertion([('error', ('SymTable has invalid entsize %d instead of %d', 24, 16), {})],
              log_history,
              'Invalid entsize for symbols (logs)')
    log_history = []

def test_ELF_invalid_shstrndx(assertion):
    global log_history
    e = ELF()
    e.Ehdr.shstrndx = 20
    e = ELF(e.pack())
    assertion([('error', ('No section of index shstrndx=20',), {})],
              log_history,
              'Invalid shstrndx (logs)')
    assertion(88,
              e.Ehdr.shoff,
              'Normal e.Ehdr.shoff')
    log_history = []

def test_ELF_offset_to_sections(assertion):
    global log_history
    data = StrPatchwork(ELF().pack())
    data[88+20] = struct.pack("<I", 0x1000)
    e = ELF(data)
    assertion([('error', ('Offset to end of section %d after end of file', 0), {})],
              log_history,
              'Section offset+size too far away (logs)')
    log_history = []
    data[88+16] = struct.pack("<I", 0x1000)
    e = ELF(data)
    assertion([('error', ('Offset to section %d after end of file', 0), {})],
              log_history,
              'Section offset very far away (logs)')
    log_history = []
    data[32] = struct.pack("<I", 100) # e.Ehdr.shoff
    e = ELF(data)
    assertion([('error', ('Offset to end of section headers after end of file',), {}),
               ('error', ('No section of index shstrndx=2',), {})],
              log_history,
              'SH offset too far away (logs)')
    log_history = []
    data[32] = struct.pack("<I", 0x2000) # e.Ehdr.shoff
    e = ELF(data)
    assertion([('error', ('Offset to section headers after end of file',), {}),
               ('error', ('No section of index shstrndx=2',), {})],
              log_history,
              'SH offset very far away (logs)')
    log_history = []

def test_ELF_wordsize_endianess(assertion):
    global log_history
    data = StrPatchwork(ELF().pack())
    data[4] = struct.pack("B", 4)
    e = ELF(data)
    assertion([('error', ('Invalid ELF, wordsize defined to %d', 128), {})],
              log_history,
              'Invalid ELF word size (logs)')
    log_history = []
    data = StrPatchwork(ELF().pack())
    data[5] = struct.pack("B", 0)
    e = ELF(data)
    assertion([('error', ('Invalid ELF, endianess defined to %d', 0), {})],
              log_history,
              'Invalid ELF endianess (logs)')
    log_history = []

def test_ELF_tiny84(assertion):
    global log_history
    elf_tiny = open(__dir__+'/binary_input/tiny84.bin', 'rb').read()
    assertion('90f9fa06566389883d82b9cda016b10d',
              hashlib.md5(elf_tiny).hexdigest(),
              'Reading tiny84')
    e = ELF(elf_tiny)
    assertion([('warn', ('No section (e.g. core file)',), {})],
              log_history,
              'tiny84 (logs)')
    log_history = []
    d = e.pack()
    assertion('90f9fa06566389883d82b9cda016b10d',
              hashlib.md5(d).hexdigest(),
              'Packing after reading tiny84')

def test_ELF_tiny76(assertion):
    global log_history
    elf_tiny = open(__dir__+'/binary_input/tiny76.bin', 'rb').read()
    assertion('3a5753c93c492d2d1d3fc6c227baec7a',
              hashlib.md5(elf_tiny).hexdigest(),
              'Reading tiny76')
    e = ELF(elf_tiny)
    d = e.pack()
    assertion('3a5753c93c492d2d1d3fc6c227baec7a',
              hashlib.md5(d).hexdigest(),
              'Packing after reading tiny76')
    assertion([('warn', ('No section (e.g. core file)',), {})],
              log_history,
              'tiny76 (logs)')
    log_history = []

def test_ELF_tiny64(assertion):
    global log_history
    elf_tiny = open(__dir__+'/binary_input/tiny64.bin', 'rb').read()
    assertion('0dd8a6325f7cf633ed8c527add5dc634',
              hashlib.md5(elf_tiny).hexdigest(),
              'Reading tiny64')
    e = ELF(elf_tiny)
    assertion([('warn', ('No section (e.g. core file)',), {})],
              log_history,
              'tiny64 (logs)')
    log_history = []
    d = e.pack()
    # Not identical, it is an invalid ELF, with invalid section headers
    assertion('05ab778ceccbbf67840d5d35bcd84ed9',
              hashlib.md5(d).hexdigest(),
              'Packing after reading tiny64')

def test_ELF_tiny52(assertion):
    global log_history
    elf_tiny = open(__dir__+'/binary_input/tiny52.bin', 'rb').read()
    assertion('18ddd4966cb003b80862735d19ddbeb7',
              hashlib.md5(elf_tiny).hexdigest(),
              'Reading tiny52')
    e = ELF(elf_tiny)
    assertion([('error', ('Invalid ELF, endianess defined to %d', 0), {}),
               ('error', ('Offset to section headers after end of file',), {}),
               ('error', ('Ehdr version is 65568 instead of 1',), {})],
              log_history,
              'tiny52 (logs)')
    log_history = []
    d = e.pack()
    assertion('18ddd4966cb003b80862735d19ddbeb7',
              hashlib.md5(d).hexdigest(),
              'Packing after reading tiny52')

def test_ELF_tiny45(assertion):
    global log_history
    elf_tiny = open(__dir__+'/binary_input/tiny45.bin', 'rb').read()
    assertion('44023f74799f2e009a1400c74de50cdd',
              hashlib.md5(elf_tiny).hexdigest(),
              'Reading tiny45')
    e = ELF(elf_tiny)
    assertion([('error', ('Invalid ELF, endianess defined to %d', 0), {}),
               ('error', ('Offset to section headers after end of file',), {}),
               ('error', ('Ehdr version is 65568 instead of 1',), {})],
              log_history,
              'tiny45 (logs)')
    log_history = []
    d = e.pack()
    # packing tiny45 generates tiny52 :-)
    assertion('18ddd4966cb003b80862735d19ddbeb7',
              hashlib.md5(d).hexdigest(),
              'Packing after reading tiny45')
    assertion([],
              log_history,
              'No non-regression test created unwanted log messages')

def run_test(assertion):
    for name, value in dict(globals()).items():
        if name.startswith('test_'):
            value(assertion)

if __name__ == "__main__":
    run_tests(run_test)
