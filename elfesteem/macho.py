#! /usr/bin/env python

from cstruct import CStruct
import macho_init, struct

MH_MAGIC    =    0xfeedface #     /* the mach magic number */
MH_CIGAM    =    0xcefaedfe #     /* NXSwapInt(MH_MAGIC) */
MH_MAGIC_64 =    0xfeedfacf #     /* the 64-bit mach magic number */
MH_CIGAM_64 =    0xcffaedfe #     /* NXSwapInt(MH_MAGIC_64) */
FAT_MAGIC   =    0xcafebabe
FAT_CIGAM   =    0xbebafeca #     /* NXSwapLong(FAT_MAGIC) */

CPU_TYPE_I386 = 0x00000007
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_POWERPC = 0x00000012
CPU_TYPE_POWERPC64 = 0x01000012
CPU_TYPE_ARM = 0x0000000C

CPU_SUBTYPE_MASK = 0x000000ff
CPU_CAPS_MASK = 0xffffff00

CPU_SUBTYPE_ARM_ALL = 0x00000000
CPU_SUBTYPE_POWERPC_ALL = 0x00000000
CPU_SUBTYPE_POWERPC_601 = 0x00000001
CPU_SUBTYPE_POWERPC_603 = 0x00000003
CPU_SUBTYPE_I386_ALL = 0x00000003
CPU_SUBTYPE_X86_64_ALL = 0x00000003
CPU_SUBTYPE_486 = 0x00000004
CPU_SUBTYPE_POWERPC_603e = 0x00000004
CPU_SUBTYPE_PENT = 0x00000005
CPU_SUBTYPE_586 = 0x00000005
CPU_SUBTYPE_POWERPC_603ev = 0x00000005
CPU_SUBTYPE_ARM_V4T = 0x00000005
CPU_SUBTYPE_ARM_V6 = 0x00000006
CPU_SUBTYPE_POWERPC_604 = 0x00000006
CPU_SUBTYPE_ARM_V5TEJ = 0x00000007
CPU_SUBTYPE_POWERPC_604e = 0x00000007
CPU_SUBTYPE_ARM_XSCALE = 0x00000008
CPU_SUBTYPE_ARM_V7 = 0x00000009
CPU_SUBTYPE_POWERPC_750 = 0x00000009
CPU_SUBTYPE_POWERPC_7400 = 0x0000000A
CPU_SUBTYPE_PENTIUM_4 = 0x0000000A
CPU_SUBTYPE_POWERPC_7450 = 0x0000000B
CPU_SUBTYPE_PENTPRO = 0x00000016
CPU_SUBTYPE_PENTII_M3 = 0x00000036
CPU_SUBTYPE_PENTII_M5 = 0x00000056
CPU_SUBTYPE_POWERPC_970 = 0x00000064
CPU_SUBTYPE_486SX = 0x00000084

SEGMENT_READ = 0x1
SEGMENT_WRITE = 0x2
SEGMENT_EXECUTE = 0x4

BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20

#cmd field of load commands
LC_SEGMENT	= 0x1
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xb
LC_LOAD_DYLIB = 0xc
LC_ID_DYLIB = 0xd
LC_LOAD_DYLINKER = 0xe
LC_UUID = 0x1b
LC_TWOLEVEL_HINTS =  0x16
LC_PREBIND_CKSUM = 0x17
LC_CODE_SIGNATURE = 0x1d #LoaderLinkEditDataCommand
LC_ENCRYPTION_INFO = 0x21
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_VERSION_MIN_MACOSX = 0x24
LC_FUNCTION_STARTS = 0x26 #LoaderLinkEditDataCommand
LC_MAIN = 0x80000028
LC_UNIXTHREAD = 0x5
LC_DATA_IN_CODE = 0x29 #LoaderLinkEditDataCommand
LC_SOURCE_VERSION = 0x2a
LC_DYLIB_CODE_SIGN_DRS = 0x2b #LoaderLinkEditDataCommand

#load commands flags
SG_PROTECTED_VERSION_1 = 0x8

# Section types: lsb of "flags"
S_REGULAR  = 0x00
S_ZEROFILL = 0x01
S_NON_LAZY_SYMBOL_POINTERS = 0x6
S_LAZY_SYMBOL_POINTERS = 0x7
S_SYMBOL_STUBS = 0x8
# Section flags
S_ATTR_SOME_INSTRUCTIONS = 0x00000400
S_ATTR_PURE_INSTRUCTIONS = 0x80000000


#32bits
class Mhdr(CStruct):
    _fields = [ ("magic","u32"),
                ("cputype","u32"),
                ("cpusubtype","u32"),
                ("filetype","u32"),
                ("ncmds","u32"),
                ("sizeofcmds","u32"),
                ("flags","u32") ]
    def __init__(self, *args, **kargs):
        CStruct.__init__(self, *args, **kargs)
        if self.magic not in [0xfeedface, 0xfeedfacf, 0xcafebabe]:
            raise ValueError('Not a little-endian Mach-O')
        if self._parent.interval is not None :
            self._parent.interval.delete(0,28)

class Mhdr_64(CStruct):
    _fields = [ ("magic","u32"),
                ("cputype","u32"),
                ("cpusubtype","u32"),
                ("filetype","u32"),
                ("ncmds","u32"),
                ("sizeofcmds","u32"),
                ("flags","u32"),
                ("reserved","u32") ]
    def __init__(self, *args, **kargs):
        CStruct.__init__(self, *args, **kargs)
        if self.magic not in [0xfeedface, 0xfeedfacf, 0xcafebabe]:
            raise ValueError('Not a little-endian Mach-O')
        if self._parent.interval is not None :
            self._parent.interval.delete(0,32)

class Fhdr(CStruct):
    _fields = [ ("magic","u32"),
                ("nfat_arch","u32") ]
    def __init__(self, *args, **kargs):
        CStruct.__init__(self, *args, **kargs)
        if self.magic not in [0xfeedface, 0xfeedfacf, 0xcafebabe]:
            raise ValueError('Not a little-endian Mach-O')
        if self._parent.interval is not None :
            self._parent.interval.delete(0,8)

class Farch(CStruct):
    _fields = [ ("cputype","u32"),
                ("cpusubtype","u32"),
                ("offset","u32"),
                ("size","u32"),
                ("align","u32") ]

class Lhdr(CStruct):
    _fields = [ ("cmd","u32"),
                ("cmdsize","u32") ]

class segment_command(CStruct):
    _fields = [ ("segname","16s"),
                ("vmaddr","u32"),
                ("vmsize","u32"),
                ("fileoff","u32"),
                ("filesize","u32"),
                ("maxprot","u32"),
                ("initprot","u32"),
                ("nsects","u32"),
                ("flags","u32")]

class segment_command_64(CStruct):
    _fields = [ ("segname","16s"),
                ("vmaddr","u64"),
                ("vmsize","u64"),
                ("fileoff","u64"),
                ("filesize","u64"),
                ("maxprot","u32"),
                ("initprot","u32"),
                ("nsects","u32"),
                ("flags","u32")]

class data_in_code_command(CStruct):
    _fields = [ ("data_incode_off","u32"),
                ("data_incode_size","u32")]


class dyld_info_command(CStruct):
    _fields = [ ("rebase_off","u32"),
                ("rebase_size","u32"),
                ("bind_off","u32"),
                ("bind_size","u32"),
                ("weak_bind_off","u32"),
                ("weak_bind_size","u32"),
                ("lazy_bind_off","u32"),
                ("lazy_bind_size","u32"),
                ("export_off","u32"),
                ("export_size","u32")]

class dysymtab_command(CStruct):
    _fields = [ ("ilocalsym","u32"),
                ("nlocalsym","u32"),
                ("iextdefsym","u32"),
                ("nextdefsym","u32"),
                ("iundefsym","u32"),
                ("nundefsym","u32"),
                ("toc_off","u32"),
                ("ntoc","u32"),
                ("modtab_off","u32"),
                ("nmodtab","u32"),
                ("extrefsym_off","u32"),
                ("nextrefsym","u32"),
                ("indirectsym_off","u32"),
                ("nindirectsym","u32"),
                ("extrel_off","u32"),
                ("nextrel","u32"),
                ("locrel_off","u32"),
                ("nlocrel","u32")]

class symtab_command(CStruct):
    _fields = [ ("sym_off","u32"),
                ("nsyms","u32"),
                ("str_off","u32"),
                ("str_size","u32")]

class dylinker_command(CStruct):
    _fields = [ ("stroffset","u32")]

class version_min_command(CStruct):
    _fields = [ ("version","u32"),
                ("sdk","u32")]

class unixthread_command(CStruct):
    _fields = [ ("flavor","u32"),
                ("count","u32")]

class twolevel_hints_command(CStruct):
    _fields = [ ("twolevelhints_off","u32"),
                ("nhints","u32")]

class prebind_cksum_command(CStruct):
    _fields = [ ("cksum","u32")]

class encryption_command(CStruct):
    _fields = [ ("crypt_off","u32"),
                ("crypt_size","u32"),
                ("crypt_id","u32")]

class source_version_command(CStruct):
    _fields = [ ("version","u64")]

class entry_point_command(CStruct):
    _fields = [ ("entryoff","u64"),
                ("stacksize","u64")]

class dylib_command(CStruct):
    _fields = [ ("stroffset","u32"),
                ("timestamp","u32"),
                ("current_version","u32"),
                ("compatibility_version","u32")]

class linkedit_data_command(CStruct):
    _fields = [ ("data_off","u32"),
                ("data_size","u32")]

class sectionHeader(CStruct):
    _namelen = 16
    _fields = [ ("pad_sectname","%ds"%_namelen),
                ("pad_segname","%ds"%_namelen),
                ("addr","u32"),
                ("size","u32"),
                ("offset","u32"),
                ("align","u32"),
                ("reloff","u32"),
                ("nreloc","u32"),
                ("all_flags","u32"),
                ("reserved1","u32"),
                ("reserved2","u32")]
    def get_type(self):
        return self.all_flags & 0xff
    def set_type(self, val):
        self.all_flags = (val & 0xff) | self.YY_flags
    type = property(get_type, set_type)
    def get_YY_flags(self):
        return self.all_flags & 0xffffff00
    def set_YY_flags(self, val):
        self.all_flags = (val & 0xffffff00) | self.type
    YY_flags = property(get_YY_flags, set_YY_flags)
    def changeOffsets(self, decalage, min_offset=None):
        if isOffsetChangeable(self.offset, min_offset):
            self.offset += decalage
        if isOffsetChangeable(self.reloff, min_offset):
            self.reloff += decalage
    def __init__(self, *args, **kargs):
        none_content = ('content' in kargs and kargs['content'] == None)
        if none_content:
            kargs['content'] = ""
        CStruct.__init__(self, *args, **kargs)
        if not none_content:
            return
        self.align = 1
        if not 'segment' in kargs:
            self.segname = "__LINKEDIT"
        if not 'sectname' in kargs:
            self.sectname = "__added_data"
        if self.sectname == "__text" :
            self.type = S_REGULAR
            self.flags = S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS
    def __call__(self, parent=None, addr=None, size=None, segment=None):
        self.addr = addr
        self.size = len(parent.content)
    def get_segname(self):
        return self.pad_segname.strip('\0')
    def set_segname(self, val):
        padding = self._namelen - len(val)
        if (padding < 0) : raise ValueError("segname is too long for the structure")
        self.pad_segname = val+'\0'*padding
    segname = property(get_segname, set_segname)
    def get_sectname(self):
        return self.pad_sectname.strip('\0')
    def set_sectname(self, val):
        padding = self._namelen - len(val)
        if (padding < 0) : raise ValueError("sectname is too long for the structure")
        self.pad_sectname = val+'\0'*padding
    sectname = property(get_sectname, set_sectname)

class sectionHeader_64(sectionHeader):
    _namelen = 16
    _fields = [ ("pad_sectname","%ds"%_namelen),
                ("pad_segname","%ds"%_namelen),
                ("addr","u64"),
                ("size","u64"),
                ("offset","u32"),
                ("align","u32"),
                ("reloff","u32"),
                ("nreloc","u32"),
                ("all_flags","u32"),
                ("reserved1","u32"),
                ("reserved2","u32"),
                ("reserved3","u32")]

class symbol(CStruct):
    _fields = [ ("strtabindex","u32"),
                ("type","u08"),
                ("sectionindex","u08"),
                ("description","u16"),
                ("value","u32")]
    def get_name(self):
        if self.strtabindex ==1 and self._parent.parent.parent._parent.parent.Mhdr.cputype == 0x0c:
            return
        else:
            return self._parent.parent.parent._parent.parent.get_stringtable().res[self.strtabindex]
    name = property(get_name)

class symbol_64(CStruct):
    _fields = [ ("strtabindex","u32"),
                ("type","u08"),
                ("sectionindex","u08"),
                ("description","u16"),
                ("value","u64")]
    def get_name(self):
        if self.strtabindex ==1 and self._parent.parent.parent._parent.parent.Mhdr.cputype == 0x0c:
            return
        else:
            return self._parent.parent.parent._parent.parent.get_stringtable().res[self.strtabindex]
    name = property(get_name)

class relocationSymbol(CStruct):
    _fields = [ ("relocaddr","u32"),
                ("relocsym","u32")]
    def __init__(self, *args, **kargs):
        CStruct.__init__(self, *args, **kargs)
        self.address = 0xffffff & self.relocaddr
        if 0x80000000 & self.relocaddr == 0:
            self.scattered = False
        else:
            self.scattered = True
        if self.scattered:
            self.pcrel = (0x40000000 & self.relocaddr)>>30
            self.length = (0x30000000 & self.relocaddr)>>28
            self.type = (0x0f000000 & self.relocaddr)>>24
            #self.address = 0xffffff & self.relocaddr
            self.symbolNumOrValue = self.relocsym
        else:
            self.type = (0xf0000000 & self.relocsym)>>28
            self.extern = (0x08000000 & self.relocsym)>>27
            self.length = (0x06000000 & self.relocsym)>>25
            self.pcrel = (0x01000000 & self.relocsym)>>24
            #self.address = self.relocaddr
            self.symbolNumOrValue = 0xffffff & self.relocsym

    def __repr__(self):
        fields = [ "pcrel", "length" ]
        if hasattr(self, 'extern'):
            fields.append("extern")
        fields.extend(["type", "scattered", "symbolNumOrValue"])
        return "<" + self.__class__.__name__ + " " + " -- ".join([x + " " + hex(getattr(self,x)) for x in fields]) + ">"
    def __str__(self):
        if self.scattered:
            return struct.pack("<I",(self.scattered<<31) + (self.pcrel<<30) + (self.length<<28) + (self.type<<24) + self.address) + struct.pack("<I",self.symbolNumOrValue)
        else:
            return struct.pack("<I", self.address) + struct.pack("<I", (self.type<<28) + (self.extern<<27) + (self.length<<25) +(self.pcrel<<24) + self.symbolNumOrValue)

if __name__ == "__main__":
    import sys
    MACHOFILE = sys.stdin
    if len(sys.argv) > 1:
        MACHOFILE = open(sys.argv[1])
    mhdr = Mhdr._from_file(MACHOFILE)

    MACHOFILE.seek(ehdr.phoff)
    phdr = Phdr._from_file(MACHOFILE)

    MACHOFILE.seek(ehdr.shoff)
    shdr = Shdr._from_file(MACHOFILE)

    for i in range(ehdr.shnum):
        ELFFILE.seek(ehdr.shoff+i*ehdr.shentsize)
        shdr = Shdr._from_file(ELFFILE)
        print "%(name)08x %(flags)x %(addr)08x %(offset)08x" % shdr
