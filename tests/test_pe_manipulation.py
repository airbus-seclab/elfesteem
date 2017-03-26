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

def run_test():
    ko = []
    def assertion(target, value, message):
        if target != value: ko.append(message)
    import struct
    assertion('f71dbe52628a3f83a77ab494817525c6',
              hashlib.md5(struct.pack('BBBB',116,111,116,111)).hexdigest(),
              'MD5')
    from elfesteem.pe_init import PE, Coff
    from elfesteem import pe
    # Remove warnings
    import logging
    pe.log.setLevel(logging.ERROR)
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
    pe.log.setLevel(logging.CRITICAL)
    for _ in range(89):
        e.SHList.add_section(name = 'nxt', rawsize = 0x1000)
    assertion(90, # Should be 91 if the last section could been added
              len(e.SHList),
              'Add too many sections')
    pe.log.setLevel(logging.ERROR)
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
    # Warning: Cannot write at RVA slice(256, 288, None)
    e.virt[0x400100:0x400120] = e.virt[0x400100:0x400120]
    # Warning: __len__ deprecated
    assertion(0x468e71, len(e.virt), 'Max virtual address')
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
    d = PE(d).pack() # Warning 'Section 5 size 0x126 not aligned to 0x200'
    assertion('8a3a1c8c9aa2db211e1d34c7efbb8473',
              hashlib.md5(d).hexdigest(),
              'Adding new imports; fix point')
    # Add an export
    if e.DirExport.expdesc is None:
        e.DirExport.create(['coco'])
    assertion(0x40703e,
              e.DirExport.get_funcvirt('coco'),
              'Export: get_funcvirt')
    assertion({1: 3740123390, 'coco': 3740123390},
              e.export_funcs(),
              'Export: export_funcs')
    d = e.pack()
    assertion('47a864481296d88f908126fb822ded59',
              hashlib.md5(d).hexdigest(),
              'Adding new exports')
    d = PE(d).pack()
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
    for f in (
        'resourceloop.exe',
        'namedresource.exe',
        'weirdsord.exe',
        'nosectionW7.exe',
        'imports_relocW7.exe',
        'imports_tinyXP.exe',
        'bottomsecttbl.exe',
        'delayfake.exe',
        'exportobf.exe',
        'dllbound-ld.exe',
        'd_tiny.dll',
        'dllfw.dll',
        'tinydllXP.dll',
        ):
        #e = PE(open('/Users/Shared/NoBackup/Temp/pocs/PE/bin/'+f, 'rb').read())
        e = PE(open(__dir__+'/binary_input/Ange/'+f, 'rb').read())
    e = PE(open(__dir__+'/binary_input/Ange/resourceloop.exe', 'rb').read())
    d = e.DirRes.display().encode('latin1')
    assertion('98701be30b09759a64340e5245e48195',
              hashlib.md5(d).hexdigest(),
              'Display Directory RESOURCE that is too deep')
    # Now, we parse COFF files
    try:
        # Not COFF: OptHdr size too big
        e = Coff(open(__dir__+'/binary_input/README.txt', 'rb').read())
        ko.append('Not COFF')
    except ValueError:
        pass
    obj_mingw = open(__dir__+'/binary_input/coff_mingw.obj', 'rb').read()
    e = PE(obj_mingw) # Warning 'ntsig after eof!'
    e = Coff(obj_mingw)
    d = e.rva2off(0x10, section='.text')
    assertion(0x8c+0x10, d, 'rva2off in a .obj')
    d = e.off2virt(0x10)
    assertion(None, d, 'Invalid RVA cannot be converted')
    d = e.virt2off(0x10)
    assertion(None, d, 'No virt for .obj')
    out_tms320 = open(__dir__+'/binary_input/C28346_Load_Program_to_Flash.out', 'rb').read()
    e = PE(out_tms320) # Warning 'not a valid pe!'
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
    return ko
    # print('HASH', hashlib.md5(d).hexdigest())

if __name__ == "__main__":
    ko = run_test()
    if ko:
        for k in ko:
            print('Non-regression failure for %r'%k)
    else:
        print('OK')

