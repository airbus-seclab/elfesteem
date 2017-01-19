#! /usr/bin/env python

from elfesteem.cstruct import CStruct
# To be compatible with python 2 and python 3
import struct, sys
from elfesteem.cstruct import data_empty, data_null
if sys.version_info[0] < 3:
    bytes_to_name = lambda s: s
    name_to_bytes = lambda s: s
else:
    bytes_to_name = lambda s: s.decode(encoding="latin1")
    name_to_bytes = lambda s: s.encode(encoding="latin1")

# Constants, cf. http://llvm.org/docs/doxygen/html/Support_2MachO_8h_source.html
MH_MAGIC    =    0xfeedface #     /* the mach magic number */
MH_CIGAM    =    0xcefaedfe #     /* NXSwapInt(MH_MAGIC) */
MH_MAGIC_64 =    0xfeedfacf #     /* the 64-bit mach magic number */
MH_CIGAM_64 =    0xcffaedfe #     /* NXSwapInt(MH_MAGIC_64) */
FAT_MAGIC   =    0xcafebabe
FAT_CIGAM   =    0xbebafeca #     /* NXSwapLong(FAT_MAGIC) */

# Constants for the "filetype" field
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

# Constant bits for the "flags" field
MH_NOUNDEFS                = 0x00000001
MH_INCRLINK                = 0x00000002
MH_DYLDLINK                = 0x00000004
MH_BINDATLOAD              = 0x00000008
MH_PREBOUND                = 0x00000010
MH_SPLIT_SEGS              = 0x00000020
MH_LAZY_INIT               = 0x00000040
MH_TWOLEVEL                = 0x00000080
MH_FORCE_FLAT              = 0x00000100
MH_NOMULTIDEFS             = 0x00000200
MH_NOFIXPREBINDING         = 0x00000400
MH_PREBINDABLE             = 0x00000800
MH_ALLMODSBOUND            = 0x00001000
MH_SUBSECTIONS_VIA_SYMBOLS = 0x00002000
MH_CANONICAL               = 0x00004000
MH_WEAK_DEFINES            = 0x00008000
MH_BINDS_TO_WEAK           = 0x00010000
MH_ALLOW_STACK_EXECUTION   = 0x00020000
MH_ROOT_SAFE               = 0x00040000
MH_SETUID_SAFE             = 0x00080000
MH_NO_REEXPORTED_DYLIBS    = 0x00100000
MH_PIE                     = 0x00200000
MH_DEAD_STRIPPABLE_DYLIB   = 0x00400000
MH_HAS_TLV_DESCRIPTORS     = 0x00800000
MH_NO_HEAP_EXECUTION       = 0x01000000
MH_APP_EXTENSION_SAFE      = 0x02000000

# Cf. /usr/include/mach/machine.h
# VEO is found on http://www.opensource.apple.com/source/cctools/cctools-809/include/mach/machine.h
CPU_ARCH_ABI64  = 0x01000000
CPU_TYPE_VAX         = 1
CPU_TYPE_ROMP        = 2 # Deprecated
CPU_TYPE_NS32032     = 4 # Deprecated
CPU_TYPE_NS32332     = 5 # Deprecated
CPU_TYPE_MC680x0     = 6
CPU_TYPE_X86         = 7
CPU_TYPE_I386        = CPU_TYPE_X86
CPU_TYPE_X86_64      = CPU_TYPE_X86 | CPU_ARCH_ABI64
CPU_TYPE_MIPS        = 8
CPU_TYPE_NS32532     = 9  # Deprecated
CPU_TYPE_MC98000     = 10
CPU_TYPE_HPPA        = 11
CPU_TYPE_ARM         = 12
CPU_TYPE_ARM64       = CPU_TYPE_ARM | CPU_ARCH_ABI64
CPU_TYPE_MC88000     = 13
CPU_TYPE_SPARC       = 14
CPU_TYPE_I860        = 15
CPU_TYPE_I860_LITTLE = 16 # Deprecated
CPU_TYPE_ALPHA       = 16
CPU_TYPE_RS6000      = 17 # Deprecated
CPU_TYPE_POWERPC     = 18
CPU_TYPE_POWERPC64   = CPU_TYPE_POWERPC | CPU_ARCH_ABI64
CPU_TYPE_VEO         = 255

CPU_SUBTYPE_MASK      = 0xff000000  # mask for feature flags
CPU_SUBTYPE_LIB64     = 0x80000000  # 64 bit libraries

# VAX subtypes.
CPU_SUBTYPE_VAX_ALL  = 0
CPU_SUBTYPE_VAX780   = 1
CPU_SUBTYPE_VAX785   = 2
CPU_SUBTYPE_VAX750   = 3
CPU_SUBTYPE_VAX730   = 4
CPU_SUBTYPE_UVAXI    = 5
CPU_SUBTYPE_UVAXII   = 6
CPU_SUBTYPE_VAX8200  = 7
CPU_SUBTYPE_VAX8500  = 8
CPU_SUBTYPE_VAX8600  = 9
CPU_SUBTYPE_VAX8650  = 10
CPU_SUBTYPE_VAX8800  = 11
CPU_SUBTYPE_UVAXIII  = 12

# ROMP subtypes.
CPU_SUBTYPE_RT_ALL = 0
CPU_SUBTYPE_RT_PC  = 1
CPU_SUBTYPE_RT_APC = 2
CPU_SUBTYPE_RT_135 = 3

# 2032/32332/32532 subtypes.
CPU_SUBTYPE_MMAX_ALL      = 0
CPU_SUBTYPE_MMAX_DPC      = 1 # 032 CPU
CPU_SUBTYPE_SQT           = 2
CPU_SUBTYPE_MMAX_APC_FPU  = 3 # 32081 FPU
CPU_SUBTYPE_MMAX_APC_FPA  = 4 # Weitek FPA
CPU_SUBTYPE_MMAX_XPC      = 5 # 532 CPU

# 680x0 subtypes
#   NeXT used to consider 68030 code as generic 68000 code.
#   For backwards compatability:
#   * CPU_SUBTYPE_MC68030 symbol has been preserved for source code
#     compatability.
#   * CPU_SUBTYPE_MC680x0_ALL has been defined to be the same
#     subtype as CPU_SUBTYPE_MC68030 for binary comatability.
#   * CPU_SUBTYPE_MC68030_ONLY has been added to allow new object
#     files to be tagged as containing 68030-specific instructions.
CPU_SUBTYPE_MC680x0_ALL  = 1
CPU_SUBTYPE_MC68030      = 1
CPU_SUBTYPE_MC68040      = 2
CPU_SUBTYPE_MC68030_ONLY = 3

# I386 subtypes.
def CPU_SUBTYPE_INTEL(f, m): return f + (m << 4)
CPU_SUBTYPE_I386_ALL       = CPU_SUBTYPE_INTEL(3, 0)
CPU_SUBTYPE_386            = CPU_SUBTYPE_INTEL(3, 0)
CPU_SUBTYPE_486            = CPU_SUBTYPE_INTEL(4, 0)
CPU_SUBTYPE_486SX          = CPU_SUBTYPE_INTEL(4, 8)
CPU_SUBTYPE_586            = CPU_SUBTYPE_INTEL(5, 0)
CPU_SUBTYPE_PENT           = CPU_SUBTYPE_INTEL(5, 0)
CPU_SUBTYPE_PENTPRO        = CPU_SUBTYPE_INTEL(6, 1)
CPU_SUBTYPE_PENTII_M3      = CPU_SUBTYPE_INTEL(6, 3)
CPU_SUBTYPE_PENTII_M5      = CPU_SUBTYPE_INTEL(6, 5)
CPU_SUBTYPE_CELERON        = CPU_SUBTYPE_INTEL(7, 6)
CPU_SUBTYPE_CELERON_MOBILE = CPU_SUBTYPE_INTEL(7, 7)
CPU_SUBTYPE_PENTIUM_3      = CPU_SUBTYPE_INTEL(8, 0)
CPU_SUBTYPE_PENTIUM_3_M    = CPU_SUBTYPE_INTEL(8, 1)
CPU_SUBTYPE_PENTIUM_3_XEON = CPU_SUBTYPE_INTEL(8, 2)
CPU_SUBTYPE_PENTIUM_M      = CPU_SUBTYPE_INTEL(9, 0)
CPU_SUBTYPE_PENTIUM_4      = CPU_SUBTYPE_INTEL(10, 0)
CPU_SUBTYPE_PENTIUM_4_M    = CPU_SUBTYPE_INTEL(10, 1)
CPU_SUBTYPE_ITANIUM        = CPU_SUBTYPE_INTEL(11, 0)
CPU_SUBTYPE_ITANIUM_2      = CPU_SUBTYPE_INTEL(11, 1)
CPU_SUBTYPE_XEON           = CPU_SUBTYPE_INTEL(12, 0)
CPU_SUBTYPE_XEON_MP        = CPU_SUBTYPE_INTEL(12, 1)

CPU_SUBTYPE_X86_ALL    = 3
CPU_SUBTYPE_X86_64_ALL = 3
CPU_SUBTYPE_X86_ARCH1  = 4
CPU_SUBTYPE_X86_64_H   = 8 # Haswell feature subset

# Mips subtypes.
CPU_SUBTYPE_MIPS_ALL     = 0
CPU_SUBTYPE_MIPS_R2300   = 1
CPU_SUBTYPE_MIPS_R2600   = 2
CPU_SUBTYPE_MIPS_R2800   = 3
CPU_SUBTYPE_MIPS_R2000a  = 4 # pmax
CPU_SUBTYPE_MIPS_R2000   = 5
CPU_SUBTYPE_MIPS_R3000a  = 6 # 3max
CPU_SUBTYPE_MIPS_R3000   = 7

# HPPA subtypes for Hewlett-Packard HP-PA family of risc processors.
# Port by NeXT to 700 series. 
CPU_SUBTYPE_HPPA_ALL     = 0
CPU_SUBTYPE_HPPA_7100    = 0
CPU_SUBTYPE_HPPA_7100LC  = 1

# MC88000 subtypes
CPU_SUBTYPE_MC88000_ALL  = 0
CPU_SUBTYPE_MMAX_JPC     = 1
CPU_SUBTYPE_MC88100      = 1
CPU_SUBTYPE_MC88110      = 2

# MC98000 (PowerPC) subtypes
CPU_SUBTYPE_MC98000_AL   = 0
CPU_SUBTYPE_MC98601      = 1


# I860 subtypes
CPU_SUBTYPE_I860_ALL     = 0
CPU_SUBTYPE_I860_860     = 1

CPU_SUBTYPE_I860_LITTLE_ALL = 0
CPU_SUBTYPE_I860_LITTLE     = 1

# RS6000 subtypes
CPU_SUBTYPE_RS6000_ALL = 0
CPU_SUBTYPE_RS6000     = 1

# Sun4 subtypes - port done at CMU
CPU_SUBTYPE_SUN4_ALL     = 0
CPU_SUBTYPE_SUN4_260     = 1
CPU_SUBTYPE_SUN4_110     = 2
CPU_SUBTYPE_SPARC_ALL    = 0

# PowerPC subtypes
CPU_SUBTYPE_POWERPC_ALL   = 0
CPU_SUBTYPE_POWERPC_601   = 1
CPU_SUBTYPE_POWERPC_602   = 2
CPU_SUBTYPE_POWERPC_603   = 3
CPU_SUBTYPE_POWERPC_603e  = 4
CPU_SUBTYPE_POWERPC_603ev = 5
CPU_SUBTYPE_POWERPC_604   = 6
CPU_SUBTYPE_POWERPC_604e  = 7
CPU_SUBTYPE_POWERPC_620   = 8
CPU_SUBTYPE_POWERPC_750   = 9
CPU_SUBTYPE_POWERPC_7400  = 10
CPU_SUBTYPE_POWERPC_7450  = 11
CPU_SUBTYPE_POWERPC_970   = 100

CPU_SUBTYPE_POWERPC64_ALL = 0

# VEO subtypes
#  Note: the CPU_SUBTYPE_VEO_ALL will likely change over time to be defined as
#  one of the specific subtypes.
CPU_SUBTYPE_VEO_1     = 1
CPU_SUBTYPE_VEO_2     = 2
CPU_SUBTYPE_VEO_3     = 3
CPU_SUBTYPE_VEO_4     = 4
CPU_SUBTYPE_VEO_ALL   = CPU_SUBTYPE_VEO_2

# Acorn subtypes
CPU_SUBTYPE_ARM_ALL    = 0
CPU_SUBTYPE_ARM_V4T    = 5
CPU_SUBTYPE_ARM_V6     = 6
CPU_SUBTYPE_ARM_V5TEJ  = 7
CPU_SUBTYPE_ARM_XSCALE = 8
CPU_SUBTYPE_ARM_V7     = 9
CPU_SUBTYPE_ARM_V7F    = 10 # Cortex A9
CPU_SUBTYPE_ARM_V7S    = 11 # Swift
CPU_SUBTYPE_ARM_V7K    = 12
CPU_SUBTYPE_ARM_V8     = 13
CPU_SUBTYPE_ARM_V6M    = 14 # Not meant to be run under xnu
CPU_SUBTYPE_ARM_V7M    = 15 # Not meant to be run under xnu
CPU_SUBTYPE_ARM_V7EM   = 16 # Not meant to be run under xnu

CPU_SUBTYPE_ARM64_ALL  = 0
CPU_SUBTYPE_ARM64_V8   = 1

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
LC_VERSION_MIN_TVOS    = 0x2F
LC_VERSION_MIN_WATCHOS = 0x30

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
S_ATTR_DEBUG               = 0x02000000 # A debug section

S_ATTR_SOME_INSTRUCTIONS = 0x00000400 # Section contains some machine instructions
S_ATTR_EXT_RELOC         = 0x00000200 # Section has external relocation entries
S_ATTR_LOC_RELOC         = 0x00000100 # Section has local relocation entries


# /usr/include/mach-o/reloc.h
# Relocation types used in a generic implementation.  Relocation entries for
# normal things use the generic relocation as discribed above and their r_type
# is GENERIC_RELOC_VANILLA (a value of zero).
# (...)
# The implemention is quite messy given the compatibility with the existing
# relocation entry format. (...)
GENERIC_RELOC_VANILLA        = 0 # generic relocation as described above
GENERIC_RELOC_PAIR           = 1 # Only follows a GENERIC_RELOC_SECTDIFF
GENERIC_RELOC_SECTDIFF       = 2
GENERIC_RELOC_PB_LA_PTR      = 3 # prebound lazy pointer */
GENERIC_RELOC_LOCAL_SECTDIFF = 4
GENERIC_RELOC_TLV            = 5 # thread local variables */

# /usr/include/mach-o/x86_64/reloc.h
# Relocations for x86_64 are a bit different than for other architectures in
# Mach-O: Scattered relocations are not used.  Almost all relocations produced
# by the compiler are external relocations.  An external relocation has the
# r_extern bit set to 1 and the r_symbolnum field contains the symbol table
# index of the target label.
# (...)
X86_64_RELOC_UNSIGNED    = 0 # for absolute addresses
X86_64_RELOC_SIGNED      = 1 # for signed 32-bit displacement
X86_64_RELOC_BRANCH      = 2 # a CALL/JMP instruction with 32-bit displacement
X86_64_RELOC_GOT_LOAD    = 3 # a MOVQ load of a GOT entry
X86_64_RELOC_GOT         = 4 # other GOT references
X86_64_RELOC_SUBTRACTOR  = 5 # must be followed by a X86_64_RELOC_UNSIGNED
X86_64_RELOC_SIGNED_1    = 6 # for signed 32-bit displacement with a -1 addend
X86_64_RELOC_SIGNED_2    = 7 # for signed 32-bit displacement with a -2 addend
X86_64_RELOC_SIGNED_4    = 8 # for signed 32-bit displacement with a -4 addend
X86_64_RELOC_TLV         = 9 # for thread local variables


def enumerate_constants(constants, globs):
    for type in constants:
        for val in filter(lambda x:x[:len(type)+1]==type+"_", globs.keys()):
            if not globs[val] in constants[type]:
                constants[type][globs[val]] = val[len(type)+1:]

constants = {
  'CPU_TYPE'  : {},
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
    _namelen = 16
    _fields = [ ("pad_segname","%ds"%_namelen),
                ("vmaddr","u32"),
                ("vmsize","u32"),
                ("fileoff","u32"),
                ("filesize","u32"),
                ("maxprot","u32"),
                ("initprot","u32"),
                ("nsects","u32"),
                ("flags","u32")]
    def get_segname(self):
        return bytes_to_name(self.pad_segname).strip('\0')
    def set_segname(self, val):
        padding = self._namelen - len(val)
        if (padding < 0) : raise ValueError("segname is too long for the structure")
        self.pad_segname = name_to_bytes(val)+data_null*padding
    segname = property(get_segname, set_segname)

class segment_command_64(segment_command):
    _namelen = 16
    _fields = [ ("pad_segname","%ds"%_namelen),
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

class fvmlib_command(CStruct):
    _fields = [ ("stroffset","u32"),
                ("minor version","u32"),
                ("header addr","u32")]

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

class linkeroption_command(CStruct):
    _fields = [ ("count","u32")]

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
            self.segname = "__LINKEDIT"
        if not 'sectname' in kargs:
            self.sectname = "__added_data"
        if self.is_text_section():
            self.type = S_REGULAR
            self.flags = S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS
    def __call__(self, parent=None, addr=None, size=None, segment=None):
        self.addr = addr
        self.size = len(parent.content)
    def get_segname(self):
        return bytes_to_name(self.pad_segname).strip('\0')
    def set_segname(self, val):
        padding = self._namelen - len(val)
        if (padding < 0) : raise ValueError("segname is too long for the structure")
        self.pad_segname = name_to_bytes(val)+data_null*padding
    segname = property(get_segname, set_segname)
    def get_sectname(self):
        return bytes_to_name(self.pad_sectname).strip('\0')
    def set_sectname(self, val):
        padding = self._namelen - len(val)
        if (padding < 0) : raise ValueError("sectname is too long for the structure")
        self.pad_sectname = name_to_bytes(val)+data_null*padding
    sectname = property(get_sectname, set_sectname)
    def is_text_section(self):
        return self.sectname == "__text"

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

class CStructWithStrTable(CStruct):
    def strtab(self):
        return self._parent.parent.parent._parent.parent.get_stringtable()
    strtab = property(strtab)
    def get_name(self):
        return self.strtab.get_name(self.strtabindex)
    def set_name(self, name):
        if self.strtabindex == 0:
            self.strtabindex = self.strtab.add_name(name)
        else:
            self.strtab.mod_name(self.strtabindex, name)
    name = property(get_name, set_name)

class symbol(CStructWithStrTable):
    _fields = [ ("strtabindex","u32"),
                ("type","u08"),
                ("sectionindex","u08"),
                ("description","u16"),
                ("value","u32")]

class symbol_64(CStructWithStrTable):
    _fields = [ ("strtabindex","u32"),
                ("type","u08"),
                ("sectionindex","u08"),
                ("description","u16"),
                ("value","u64")]

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


# Cf. /usr/include/mach-o/loader.h
INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS   = 0x40000000

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
