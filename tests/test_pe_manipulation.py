#! /usr/bin/env python

import os
__dir__ = os.path.dirname(__file__)

from test_all import run_tests, hashlib
from elfesteem.pe_init import log, PE, COFF, Coff
from elfesteem.strpatchwork import StrPatchwork
from elfesteem import pe

def run_test():
    ko = []
    # We want to be able to verify warnings in non-regression test
    log_history = []
    log.warn = lambda *args, **kargs: log_history.append(('warn',args,kargs))
    log.warning = log.warn
    log.error = lambda *args, **kargs: log_history.append(('error',args,kargs))
    def assertion(target, value, message):
        if target != value: ko.append(message)
    import struct
    assertion('f71dbe52628a3f83a77ab494817525c6',
              hashlib.md5(struct.pack('BBBB',116,111,116,111)).hexdigest(),
              'MD5')
    e = PE()
    d = e.pack()
    assertion('901e6383ee161b569af1d35d3f77b038',
              hashlib.md5(d).hexdigest(),
              'Creation of a standard empty PE')
    e.SHList.add_section(name = 'new', rawsize = 0x1000)
    d = e.pack()
    assertion('15aefbcc8f4b39e9484df8b1ed277c75',
              hashlib.md5(d).hexdigest(),
              'Adding a section to an empty PE')
    e.SHList.add_section(name = 'nxt', rawsize = 0x1000)
    d = e.virt[0x401000:0x402000]
    assertion('620f0b67a91f7f74151bc5be745b7110',
              hashlib.md5(d).hexdigest(),
              'Extract chunk from mapped memory, across multiple sections')
    for _ in range(89):
        e.SHList.add_section(name = 'nxt', rawsize = 0x1000)
    assertion([('error', ('Cannot add section %s: not enough space for section list', 'nxt'), {})],
              log_history,
              'Add too many sections (logs)')
    log_history = []
    assertion(90, # Should be 91 if the last section could been added
              len(e.SHList),
              'Add too many sections')
    e = PE(wsize=64)
    d = e.pack()
    assertion('863bf62f521b0cad3209e42cff959eed',
              hashlib.md5(d).hexdigest(),
              'Creation of a standard empty PE+')
    pe_mingw = open(__dir__+'/binary_input/pe_mingw.exe', 'rb').read()
    e = PE(pe_mingw)
    # Packed file is not identical :-(
    # Are missing:
    # - the data between the end of DOS header and the start of PE header
    # - the padding after the list of sections, before the first section
    # - many parts of directories
    d = e.pack()
    assertion('2f08b8315c4e0a30d51a8decf104345c',
              hashlib.md5(d).hexdigest(),
              'Packing after reading pe_mingw.exe')
    d = PE(d).pack()
    assertion('2f08b8315c4e0a30d51a8decf104345c',
              hashlib.md5(d).hexdigest(),
              'Packing after reading pe_mingw.exe; fix point')
    d = e.SHList.display().encode('latin1')
    assertion('ba631f3f172712b6526e284269c1ecbb',
              hashlib.md5(d).hexdigest(),
              'Display Sections from PE')
    d = e.Symbols.display().encode('latin1')
    assertion('1ee89dc3dc2104190734747d148b7511',
              hashlib.md5(d).hexdigest(),
              'Display COFF Symbols')
    assertion('__gnu_exception_handler@4',
              e.Symbols.getbyindex(2).name,
              'Get symbol by index, found')
    assertion(None,
              e.Symbols.getbyindex(2000),
              'Get symbol by index, not existing')
    d = e.getsectionbyname('.text').pack()
    assertion('ad0d51a670cb6cd2015499840ffefb8f',
              hashlib.md5(d).hexdigest(),
              'Get existing section by name')
    d = e.getsectionbyoff(0x400+0x100).pack()
    assertion('ad0d51a670cb6cd2015499840ffefb8f',
              hashlib.md5(d).hexdigest(),
              'Get existing section by offset')
    d = e.getsectionbyvad(0x400000+0x1000+0x100).pack()
    assertion('ad0d51a670cb6cd2015499840ffefb8f',
              hashlib.md5(d).hexdigest(),
              'Get existing section by address')
    d = e.getsectionbyname('no_sect')
    assertion(None, d, 'Get non-existing section by name')
    d = e.getsectionbyoff(0x80000)
    assertion(None, d, 'Get non-existing section by offset')
    d = e.getsectionbyvad(0x1000)
    assertion(None, d, 'Get non-existing section by address')
    d = e[0x100:0x120]
    assertion('6b8897a89909959320f8adfc1d81c9ee',
              hashlib.md5(d).hexdigest(),
              'Extract chunk from raw data')
    assertion(True,
              e.virt.is_addr_in(0x401000),
              'Address in mapped virtual memory')
    assertion(False,
              e.virt.is_addr_in(0x201000),
              'Address not in mapped virtual memory')
    d = e.virt[0x401000]
    assertion('4c614360da93c0a041b22e537de151eb',
              hashlib.md5(d).hexdigest(),
              'Extract byte from mapped memory, in a section')
    d = e.virt[0x400100]
    assertion('93b885adfe0da089cdf634904fd59f71',
              hashlib.md5(d).hexdigest(),
              'Extract byte from mapped memory, in no section')
    d = e.virt[0x400100:0x400120]
    assertion('6b8897a89909959320f8adfc1d81c9ee',
              hashlib.md5(d).hexdigest(),
              'Extract chunk from mapped memory, in headers')
    d = e.virt[0x401000:0x401020]
    assertion('21ac18c2564a3b408b31aae0af19d502',
              hashlib.md5(d).hexdigest(),
              'Extract chunk from mapped memory, in a section')
    d = e.virt[0x100:0x200] # One null byte
    assertion([('warn', ('unknown rva address! -3fff00',), {})],
              log_history,
              'Extract chunk from non-mapped memory (logs)')
    log_history = []
    assertion('93b885adfe0da089cdf634904fd59f71',
              hashlib.md5(d).hexdigest(),
              'Extract chunk from non-mapped memory')
    assertion(e.virt[0x401000:0x401020],
              e.virt(0x401000,0x401020),
              'Extract chunk from mapped memory, old API')
    e[0x100:0x120] = e[0x100:0x120]
    d = e.pack()
    assertion('2f08b8315c4e0a30d51a8decf104345c',
              hashlib.md5(d).hexdigest(),
              'Writing in raw data')
    e.rva.set(0x1100, e.virt[0x401100:0x401120])
    d = e.pack()
    assertion('2f08b8315c4e0a30d51a8decf104345c',
              hashlib.md5(d).hexdigest(),
              'Writing at RVA')
    e.virt[0x401100:0x401120] = e.virt[0x401100:0x401120]
    d = e.pack()
    assertion('2f08b8315c4e0a30d51a8decf104345c',
              hashlib.md5(d).hexdigest(),
              'Writing in memory (interval)')
    e.virt[0x401100] = e.virt[0x401100:0x401120]
    d = e.pack()
    assertion('2f08b8315c4e0a30d51a8decf104345c',
              hashlib.md5(d).hexdigest(),
              'Writing in memory (address)')
    e.virt[0x400100:0x400120] = e.virt[0x400100:0x400120]
    assertion([('warn', ('Cannot write at RVA %s', slice(256, 288, None)), {})],
              log_history,
              'Writing at invalid RVA (logs)')
    log_history = []
    assertion(0x468e71, len(e.virt), 'Max virtual address')
    assertion([('warn', ('__len__ deprecated',), {})],
              log_history,
              '__len__ deprectated (logs)')
    log_history = []
    # Find leave; ret
    assertion(0x401294,
              e.virt.find(struct.pack('BB', 0xc9, 0xc3)),
              'Find pattern (from the start)')
    assertion(0x4014B4,
              e.virt.rfind(struct.pack('BB', 0xc9, 0xc3)),
              'Find pattern (from the end)')
    e.SHList.align_sections()
    d = e.pack()
    assertion('2f08b8315c4e0a30d51a8decf104345c',
              hashlib.md5(d).hexdigest(),
              'Align sections')
    # Remove Bound Import directory
    # Usually, its content is not stored in any section... that's
    # a future version of elfesteem will need to manage this
    # specific directory in a specific way.
    e.NThdr.optentries[pe.DIRECTORY_ENTRY_BOUND_IMPORT].rva = 0
    e.NThdr.optentries[pe.DIRECTORY_ENTRY_BOUND_IMPORT].size = 0
    # Create new sections with all zero content
    s_redir = e.SHList.add_section(name = "redir", size = 0x1000)
    s_test  = e.SHList.add_section(name = "test",  size = 0x1000)
    s_rel   = e.SHList.add_section(name = "rel",   size = 0x5000)
    d = e.pack()
    assertion('439f6c698d3d5238d88c5ccef99761e2',
              hashlib.md5(d).hexdigest(),
              'Adding sections')
    d = PE(d).pack()
    assertion('439f6c698d3d5238d88c5ccef99761e2',
              hashlib.md5(d).hexdigest(),
              'Adding sections; fix point')
    e = PE(pe_mingw)
    # Delete the last sections => OK
    for _ in range(2):
        del e.SHList._array[-1]
        e.SHList._size -= 40
        e.COFFhdr.numberofsections -= 1
    # Add two Descriptors in the Import Directory
    e.DirImport.add_dlldesc(
          [({"name":"kernel32.dll",
             "firstthunk":s_test.addr},
            ["CreateFileA",
             "SetFilePointer",
             "WriteFile",
             "CloseHandle",
             ]
            ),
           ({"name":"USER32.dll",
             "firstthunk":None},
            ["SetDlgItemInt",
             "GetMenu",
             "HideCaret",
             ]
            )
           ]
          )
    s_myimp = e.SHList.add_section(name="myimp", rawsize=len(e.DirImport))
    e.DirImport.set_rva(s_myimp.addr)
    assertion(0x4050a8,
              e.DirImport.get_funcvirt('KERNEL32.dll','ExitProcess'),
              'Import ExitProcess')
    assertion(None,
              e.DirImport.get_funcvirt(None,'LoadStringW'),
              'Import LoadStringW')
    assertion(None,
              e.DirExport.get_funcvirt('SetUserGeoID'),
              'Export SetUserGeoID')
    d = e.pack()
    assertion('8a3a1c8c9aa2db211e1d34c7efbb8473',
              hashlib.md5(d).hexdigest(),
              'Adding new imports')
    d = PE(d).pack()
    assertion([('warn', ('Section %d size %#x not aligned to %#x', 5, 294, 512), {})],
              log_history,
              'Adding new imports (logs)')
    log_history = []
    assertion('8a3a1c8c9aa2db211e1d34c7efbb8473',
              hashlib.md5(d).hexdigest(),
              'Adding new imports; fix point')
    # Add an export
    if e.DirExport.expdesc is None:
        e.DirExport.create(['coco'])
    assertion(0x40703e,
              e.DirExport.get_funcvirt('coco'),
              'Export: get_funcvirt')
    # 'eval' avoids warnings with python2.3
    assertion({1: eval("0xdeedc0fe"), 'coco': eval("0xdeedc0fe")},
              e.export_funcs(),
              'Export: export_funcs')
    d = e.pack()
    assertion('47a864481296d88f908126fb822ded59',
              hashlib.md5(d).hexdigest(),
              'Adding new exports')
    d = PE(d).pack()
    assertion([('warn', ('Section %d size %#x not aligned to %#x', 5, 294, 512), {})],
              log_history,
              'Adding new exports (logs)')
    log_history = []
    assertion('47a864481296d88f908126fb822ded59',
              hashlib.md5(d).hexdigest(),
              'Adding new exports; fix point')
    # Add a new Descriptor in the Import Directory
    e.DirImport.add_dlldesc([ ({"name":"MyDLL.dll"}, ["MyFunc"]) ])
    e.DirImport.set_rva(None)
    assertion('47a864481296d88f908126fb822ded59',
              hashlib.md5(d).hexdigest(),
              'Adding imports, no specified section')
    # Small DLL created with Visual Studio
    dll_vstudio = open(__dir__+'/binary_input/pe_vstudio.dll', 'rb').read()
    e = PE(dll_vstudio)
    d = e.pack()
    assertion('19028e1a1bde785fb4a58aeacf56007b',
              hashlib.md5(d).hexdigest(),
              'Packing after reading pe_vstudio.dll')
    # Test the display() functions
    d = e.DirImport.display().encode('latin1')
    assertion('e9f925c32ed91f889a2b57e73360d444',
              hashlib.md5(d).hexdigest(),
              'Display Directory IMPORT')
    d = e.DirExport.display().encode('latin1')
    assertion('2d262c4d834e58b17d4c7f2359d1f6f1',
              hashlib.md5(d).hexdigest(),
              'Display Directory EXPORT')
    d = e.DirRes.display().encode('latin1')
    assertion('a794e58acca2f6b2d9628e64008ad6d8',
              hashlib.md5(d).hexdigest(),
              'Display Directory RESOURCE')
    d = e.DirReloc.display().encode('latin1')
    assertion('33af05a3215689dec4cdae3656c63af0',
              hashlib.md5(d).hexdigest(),
              'Display Directory BASERELOC')
    d = '\n'.join([repr(_) for reldir in e.DirReloc for _ in reldir.rels])
    d = d.encode('latin1')
    assertion('87951bfbb3c09dec8c54d41f72cc4263',
              hashlib.md5(d).hexdigest(),
              'Display all relocations')
    # Parse some ill-formed PE made by Ange Albertini
    e = PE(open(__dir__+'/binary_input/Ange/resourceloop.exe', 'rb').read())
    assertion([('warn', ('Resource tree too deep',), {})]*212,
              log_history,
              'Ange/resourceloop.exe (logs)')
    log_history = []
    e = PE(open(__dir__+'/binary_input/Ange/namedresource.exe', 'rb').read())
    assertion([],
              log_history,
              'Ange/namedresource.exe (logs)')
    e = PE(open(__dir__+'/binary_input/Ange/weirdsord.exe', 'rb').read())
    assertion([('warn', ('Section %d offset %#x not aligned to %#x', 0, 513, 16384), {}), ('warn', ('Section %d size %#x not aligned to %#x', 0, 270, 16384), {})],
              log_history,
              'Ange/weirdsord.exe (logs)')
    log_history = []
    e = PE(open(__dir__+'/binary_input/Ange/nosectionW7.exe', 'rb').read())
    assertion([('warn', ('Number of rva %d does not match sizeofoptionalheader %d', 16, 0), {})],
              log_history,
              'Ange/nosectionW7.exe (logs)')
    log_history = []
    e = PE(open(__dir__+'/binary_input/Ange/imports_relocW7.exe', 'rb').read())
    assertion([],
              log_history,
              'Ange/imports_relocW7.exe (logs)')
    e = PE(open(__dir__+'/binary_input/Ange/imports_tinyXP.exe', 'rb').read())
    assertion([],
              log_history,
              'Ange/imports_tinyXP.exe (logs)')
    e = PE(open(__dir__+'/binary_input/Ange/bottomsecttbl.exe', 'rb').read())
    assertion([('warn', ('Number of rva %d does not match sizeofoptionalheader %d', 16, 696), {})],
              log_history,
              'Ange/bottomsecttbl.exe (logs)')
    log_history = []
    e = PE(open(__dir__+'/binary_input/Ange/delayfake.exe', 'rb').read())
    assertion([],
              log_history,
              'Ange/delayfake.exe (logs)')
    e = PE(open(__dir__+'/binary_input/Ange/exportobf.exe', 'rb').read())
    assertion([],
              log_history,
              'Ange/exportobf.exe (logs)')
    e = PE(open(__dir__+'/binary_input/Ange/dllbound-ld.exe', 'rb').read())
    assertion([],
              log_history,
              'Ange/dllbound-ld.exe (logs)')
    e = PE(open(__dir__+'/binary_input/Ange/d_tiny.dll', 'rb').read())
    assertion([('warn', ('Opthdr magic %#x', 31074), {}),
               ('warn', ('Number of rva %d does not match sizeofoptionalheader %d', 0, 13864), {}),
               ('warn', ('Windows 8 needs at least 13 directories, %d found', 0), {}),
               ('warn', ('Too many symbols: %d', 541413408), {}),
               ('warn', ('File too short for StrTable -0x61746127 != 0x0',), {})],
              log_history,
              'Ange/d_tiny.dll (logs)')
    log_history = []
    e = PE(open(__dir__+'/binary_input/Ange/dllfw.dll', 'rb').read())
    assertion([],
              log_history,
              'Ange/dllfw.dll (logs)')
    e = PE(open(__dir__+'/binary_input/Ange/tinydllXP.dll', 'rb').read())
    assertion([('warn', ('Number of rva %d does not match sizeofoptionalheader %d', 0, 0), {}),
               ('warn', ('Windows 8 needs at least 13 directories, %d found', 0), {}),
               ('warn', ('File too short for StrTable 0x55 != 0xc258016a',), {})],
              log_history,
              'Ange/tinydllXP.dll (logs)')
    log_history = []
    e = PE(open(__dir__+'/binary_input/Ange/resourceloop.exe', 'rb').read())
    log_history = []
    d = e.DirRes.display().encode('latin1')
    assertion('98701be30b09759a64340e5245e48195',
              hashlib.md5(d).hexdigest(),
              'Display Directory RESOURCE that is too deep')
    # Some various ways for a PE to be detected as invalid
    e = PE()
    data = StrPatchwork(e.pack())
    try:
        e.NTsig.signature = 0x2000
        e = PE(e.pack())
        ko.append('Not a PE, invalid NTsig')
    except ValueError:
        pass
    try:
        e.DOShdr.lfanew = 0x200000
        data[60] = struct.pack("<I", e.DOShdr.lfanew)
        e = PE(data)
        ko.append('Not a PE, NTsig offset after eof')
    except ValueError:
        pass
    # Now, we parse COFF files
    try:
        # Not COFF: OptHdr size too big
        e = Coff(open(__dir__+'/binary_input/README.txt', 'rb').read())
        ko.append('Not COFF')
    except ValueError:
        pass
    obj_mingw = open(__dir__+'/binary_input/coff_mingw.obj', 'rb').read()
    try:
        e = PE(obj_mingw)
        ko.append('Not PE')
    except ValueError:
        pass
    e = Coff(obj_mingw)
    d = e.rva2off(0x10, section='.text')
    assertion(0x8c+0x10, d, 'rva2off in a .obj')
    d = e.off2virt(0x10)
    assertion(None, d, 'Invalid RVA cannot be converted')
    d = e.virt2off(0x10)
    assertion(None, d, 'No virt for .obj')
    out_tms320 = open(__dir__+'/binary_input/C28346_Load_Program_to_Flash.out', 'rb').read()
    e = Coff(out_tms320)
    d = e.SHList.display().encode('latin1')
    assertion('a63cf686186105b83e49509f213b20ea',
              hashlib.md5(d).hexdigest(),
              'Display Sections from COFF')
    # C-Kermit binary for OSF1
    out_osf1 = open(__dir__+'/binary_input/cku200.dec-osf-1.3a', 'rb').read()
    e = Coff(out_osf1)
    d = repr(e.OSF1Symbols).encode('latin1')
    assertion('c7df867846612e6fc1c52a8042f706cc',
              hashlib.md5(d).hexdigest(),
              'Display OSF/1 Symbols')
    # C-Kermit binary for Clipper CLIX
    e = Coff(open(__dir__+'/binary_input/cku196.clix-3.1', 'rb').read())
    # C-Kermit binary for Apollo
    e = Coff(open(__dir__+'/binary_input/cku193a05.apollo-sr10-s5r3', 'rb').read())
    # C-Kermit XCOFF32 binary for AIX
    e = Coff(open(__dir__+'/binary_input/cku190.rs6aix32c-3.2.4', 'rb').read())
    # C-Kermit eCOFF32 binary for MIPS, big endian
    e = Coff(open(__dir__+'/binary_input/cku192.irix40', 'rb').read())
    # C-Kermit eCOFF32 binary for MIPS, little endian
    e = Coff(open(__dir__+'/binary_input/cku192.ultrix43c-mips3', 'rb').read())
    # Some various ways for a COFF to be detected as invalid
    obj_mingw = StrPatchwork(obj_mingw)
    e = COFF(obj_mingw)
    try:
        obj_mingw[2] = struct.pack("<H", 0)
        e = COFF(obj_mingw)
        ko.append('COFF cannot have no section')
    except ValueError:
        pass
    try:
        obj_mingw[2] = struct.pack("<H", 0x2000)
        e = COFF(obj_mingw)
        ko.append('Too many sections in COFF')
    except ValueError:
        pass
    try:
        obj_mingw[2] = struct.pack("<H", 0x100)
        e = COFF(obj_mingw)
        ko.append('Too many sections in COFF, past end of file')
    except ValueError:
        pass
    try:
        obj_mingw[2] = struct.pack("<H", 3)
        obj_mingw[8] = struct.pack("<I", 0x100000)
        e = COFF(obj_mingw)
        ko.append('COFF invalid ptr to symbol table')
    except ValueError:
        pass
    obj_mingw[8] = struct.pack("<I", 220)
    obj_mingw[436] = struct.pack("<I", 10000)
    e = COFF(obj_mingw)
    assertion([('warn', ('File too short for StrTable 0x4 != 0x2710',), {})],
              log_history,
              'File too short for StrTable (logs)')
    log_history = []
    assertion([],
              log_history,
              'No non-regression test created unwanted log messages')
    return ko
    # print('HASH', hashlib.md5(d).hexdigest())

if __name__ == "__main__":
    run_tests(run_test)
