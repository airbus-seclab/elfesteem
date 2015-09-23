#! /usr/bin/env python

from elfesteem.cstruct import CStruct
# To be compatible with python 2 and python 3
import struct, sys
from elfesteem.cstruct import data_empty, data_null
def data_bytes(s):
    if sys.version_info[0] < 3: return s
    else: return s.encode("latin1")

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

MH_OBJECT       = 0x1  # relocatable object file
MH_EXECUTE      = 0x2  # demand paged executable file
MH_FVMLIB       = 0x3  # fixed VM shared library file
MH_CORE         = 0x4  # core file
MH_PRELOAD      = 0x5  # preloaded executable file
MH_DYLIB        = 0x6  # dynamically bound shared library
MH_DYLINKER     = 0x7  # dynamic link editor
MH_BUNDLE       = 0x8  # dynamically bound bundle file
MH_DYLIB_STUB   = 0x9  # shared library stub for static linking only, no section contents
MH_DSYM         = 0xa  # companion file with only debug sections
MH_KEXT_BUNDLE  = 0xb  # x86_64 kexts

SEGMENT_READ = 0x1
SEGMENT_WRITE = 0x2
SEGMENT_EXECUTE = 0x4

BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20

#cmd field of load commands
# From /usr/include/mach-o/loader.h
LC_SEGMENT         = 0x1   # segment of this file to be mapped
LC_SYMTAB          = 0x2   # link-edit stab symbol table info
LC_SYMSEG          = 0x3   # link-edit gdb symbol table info (obsolete)
LC_THREAD          = 0x4   # thread
LC_UNIXTHREAD      = 0x5   # unix thread (includes a stack)
LC_LOADFVMLIB      = 0x6   # load a specified fixed VM shared library
LC_IDFVMLIB        = 0x7   # fixed VM shared library identification
LC_IDENT           = 0x8   # object identification info (obsolete)
LC_FVMFILE         = 0x9   # fixed VM file inclusion (internal use)
LC_PREPAGE         = 0xa   # prepage command (internal use)
LC_DYSYMTAB        = 0xb   # dynamic link-edit symbol table info
LC_LOAD_DYLIB      = 0xc   # load a dynamically linked shared library
LC_ID_DYLIB        = 0xd   # dynamically linked shared lib ident
LC_LOAD_DYLINKER   = 0xe   # load a dynamic linker
LC_ID_DYLINKER     = 0xf   # dynamic linker identification
LC_PREBOUND_DYLIB  = 0x10  # modules prebound for a dynamically linked shared library
LC_ROUTINES        = 0x11  # image routines
LC_SUB_FRAMEWORK   = 0x12  # sub framework
LC_SUB_UMBRELLA    = 0x13  # sub umbrella
LC_SUB_CLIENT      = 0x14  # sub client
LC_SUB_LIBRARY     = 0x15  # sub library
LC_TWOLEVEL_HINTS  = 0x16  # two-level namespace lookup hints
LC_PREBIND_CKSUM   = 0x17  # prebind checksum
LC_LOAD_WEAK_DYLIB = 0x18  # load a dynamically linked shared library that is allowed to be missing (all symbols are weak imported)
LC_SEGMENT_64      = 0x19  # 64-bit segment of this file to be mapped
LC_ROUTINES_64     = 0x1a  # 64-bit image routines
LC_UUID            = 0x1b  # the uuid
LC_RPATH           = 0x1c  # runpath additions
LC_CODE_SIGNATURE  = 0x1d  # local of code signature
LC_SEGMENT_SPLIT_INFO  = 0x1e # local of info to split segments
LC_REEXPORT_DYLIB  = 0x1f  # load and re-export dylib
LC_LAZY_LOAD_DYLIB = 0x20  # delay load of dylib until first use
LC_ENCRYPTION_INFO = 0x21  # encrypted segment information
LC_DYLD_INFO       = 0x22  # compressed dyld information
LC_DYLD_INFO_ONLY  = 0x22  # compressed dyld information only
LC_LOAD_UPWARD_DYLIB   = 0x23 # load upward dylib
LC_VERSION_MIN_MACOSX  = 0x24 # build for MacOSX min OS version
LC_VERSION_MIN_IPHONEOS= 0x25 # build for iPhoneOS min OS version
LC_FUNCTION_STARTS = 0x26  # compressed table of function start addresses
LC_DYLD_ENVIRONMENT= 0x27  # string for dyld to treat like environment variable
LC_MAIN            = 0x28  # replacement for LC_UNIXTHREAD
LC_DATA_IN_CODE    = 0x29  # table of non-instructions in __text
LC_SOURCE_VERSION  = 0x2A  # source version used to build binary
LC_DYLIB_CODE_SIGN_DRS = 0x2B # Code signing DRs copied from linked dylibs
LC_ENCRYPTION_INFO_64  = 0x2C # 64-bit encrypted segment information
LC_LINKER_OPTION       = 0x2D # linker options in MH_OBJECT files
LC_LINKER_OPTIMIZATION_HINT = 0x2E # optimization hints in MH_OBJECT files

# After MacOS X 10.1 when a new load command is added that is required to be
# understood by the dynamic linker for the image to execute properly the
# LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
# linker sees such a load command it it does not understand will issue a
# "unknown load command required for execution" error and refuse to use the
# image.  Other load commands without this bit that are not understood will
# simply be ignored.
LC_REQ_DYLD = 0x80000000
LC_LOAD_WEAK_DYLIB   |= LC_REQ_DYLD
LC_RPATH             |= LC_REQ_DYLD
LC_REEXPORT_DYLIB    |= LC_REQ_DYLD
LC_DYLD_INFO_ONLY    |= LC_REQ_DYLD
LC_LOAD_UPWARD_DYLIB |= LC_REQ_DYLD
LC_MAIN              |= LC_REQ_DYLD

#load commands flags
SG_PROTECTED_VERSION_1 = 0x8

# Section types: lsb of "flags"
S_REGULAR          = 0x0 # regular section
S_ZEROFILL         = 0x1 # zero fill on demand section
S_CSTRING_LITERALS = 0x2 # section with only literal C strings
S_4BYTE_LITERALS   = 0x3 # section with only 4 byte literals
S_8BYTE_LITERALS   = 0x4 # section with only 8 byte literals
S_LITERAL_POINTERS = 0x5 # section with only pointers to literals
S_NON_LAZY_SYMBOL_POINTERS   = 0x6  # section with only non-lazy symbol pointers
S_LAZY_SYMBOL_POINTERS       = 0x7  # section with only lazy symbol pointers
S_SYMBOL_STUBS               = 0x8  # section with only symbol stubs, byte size of stub in the reserved2 field
S_MOD_INIT_FUNC_POINTERS     = 0x9  # section with only function pointers for initialization
S_MOD_TERM_FUNC_POINTERS     = 0xa  # section with only function pointers for termination
S_COALESCED                  = 0xb  # section contains symbols that are to be coalesced
S_GB_ZEROFILL                = 0xc  # zero fill on demand section (that can be larger than 4 gigabytes)
S_INTERPOSING                = 0xd  # section with only pairs of function pointers for interposing
S_16BYTE_LITERALS            = 0xe  # section with only 16 byte literals
S_DTRACE_DOF                 = 0xf  # section contains DTrace Object Format
S_LAZY_DYLIB_SYMBOL_POINTERS = 0x10 # section with only lazy symbol pointers to lazy loaded dylibs
S_THREAD_LOCAL_REGULAR                = 0x11 # template of initial values for TLVs
S_THREAD_LOCAL_ZEROFILL               = 0x12 # template of initial values for TLVs
S_THREAD_LOCAL_VARIABLES              = 0x13 # TLV descriptors
S_THREAD_LOCAL_VARIABLE_POINTERS      = 0x14 # pointers to TLV descriptors
S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15 # functions to call to initialize TLV values

# Section flags
S_ATTR_PURE_INSTRUCTIONS   = 0x80000000 # section contains only true machine instructions
S_ATTR_NO_TOC              = 0x40000000 # section contains coalesced symbols that are not to be in a ranlib table of contents
S_ATTR_STRIP_STATIC_SYMS   = 0x20000000 # ok to strip static symbols in this section in files with the MH_DYLDLINK flag
S_ATTR_NO_DEAD_STRIP       = 0x10000000 # no dead stripping
S_ATTR_LIVE_SUPPORT        = 0x08000000 # blocks are live if they reference live blocks
S_ATTR_SELF_MODIFYING_CODE = 0x04000000 # Used with i386 code stubs written on by dyld

S_ATTR_SOME_INSTRUCTIONS = 0x00000400


def enumerate_constants(constants, globs):
    for type in constants:
        for val in filter(lambda x:x[:len(type)+1]==type+"_", globs.keys()):
            if not globs[val] in constants[type]:
                constants[type][globs[val]] = val[len(type)+1:]

constants = {
  'CPU_TYPE'  : {},
  'MH'  : {},
  'LC'  : {},
  'S'   : {},
  }
enumerate_constants(constants, globals())

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
                ("tocoff","u32"),
                ("ntoc","u32"),
                ("modtaboff","u32"),
                ("nmodtab","u32"),
                ("extrefsymoff","u32"),
                ("nextrefsyms","u32"),
                ("indirectsymoff","u32"),
                ("nindirectsyms","u32"),
                ("extreloff","u32"),
                ("nextrel","u32"),
                ("locreloff","u32"),
                ("nlocrel","u32")]

class symtab_command(CStruct):
    _fields = [ ("symoff","u32"),
                ("nsyms","u32"),
                ("stroff","u32"),
                ("strsize","u32")]

class dylinker_command(CStruct):
    _fields = [ ("stroffset","u32")]

class version_min_command(CStruct):
    _fields = [ ("version","u32"),
                ("sdk","u32")]

class unixthread_command(CStruct):
    _fields = [ ("flavor","u32"),
                ("count","u32")]

class twolevel_hints_command(CStruct):
    _fields = [ ("offset","u32"),
                ("nhints","u32")]

class prebind_cksum_command(CStruct):
    _fields = [ ("cksum","u32")]

class encryption_command(CStruct):
    _fields = [ ("cryptoff","u32"),
                ("cryptsize","u32"),
                ("cryptid","u32")]

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
    _fields = [ ("dataoff","u32"),
                ("datasize","u32")]

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
            kargs['content'] = data_empty
        CStruct.__init__(self, *args, **kargs)
        if not none_content:
            return
        self.align = 1
        if not 'segment' in kargs:
            self.segname = data_bytes("__LINKEDIT")
        if not 'sectname' in kargs:
            self.sectname = data_bytes("__added_data")
        if self.is_text_section():
            self.type = S_REGULAR
            self.flags = S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS
    def __call__(self, parent=None, addr=None, size=None, segment=None):
        self.addr = addr
        self.size = len(parent.content)
    def get_segname(self):
        return self.pad_segname.strip(data_null)
    def set_segname(self, val):
        padding = self._namelen - len(val)
        if (padding < 0) : raise ValueError("segname is too long for the structure")
        self.pad_segname = val+data_null*padding
    segname = property(get_segname, set_segname)
    def get_sectname(self):
        return self.pad_sectname.strip(data_null)
    def set_sectname(self, val):
        padding = self._namelen - len(val)
        if (padding < 0) : raise ValueError("sectname is too long for the structure")
        self.pad_sectname = val+data_null*padding
    sectname = property(get_sectname, set_sectname)
    def is_text_section(self):
        return self.sectname == data_bytes("__text")

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

# Cf. /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.9.sdk/usr/include/mach-o/nlist.h
# The 'n_type' aka. 'type' field
N_STAB  = 0xe0  # if any of these bits set, a symbolic debugging entry
N_PEXT  = 0x10  # private external symbol bit
N_TYPE  = 0x0e  # mask for the type bits
N_EXT   = 0x01  # external symbol bit, set for external symbols
# Values for N_TYPE bits of the n_type field.
N_UNDF  = 0x0   # undefined, n_sect == NO_SECT
N_ABS   = 0x2   # absolute, n_sect == NO_SECT
N_SECT  = 0xe   # defined in section number n_sect
N_PBUD  = 0xc   # prebound undefined (defined in a dylib)
N_INDR  = 0xa   # indirect


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
        print("%(name)08x %(flags)x %(addr)08x %(offset)08x" % shdr)
