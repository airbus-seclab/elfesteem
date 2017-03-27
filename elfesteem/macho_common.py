#! /usr/bin/env python

from elfesteem.cstruct import CStruct
from elfesteem.cstruct import data_empty, data_null
from elfesteem.cstruct import bytes_to_name, name_to_bytes

import logging
log = logging.getLogger("mach-o")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)

#### Source: /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.9.sdk/usr/include/mach-o/nlist.h
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


#### Main source: /usr/include/mach/machine.h
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


#### Source: /usr/include/mach-o/loader.h

# The entries in the two-level namespace lookup hints table are twolevel_hint
# structs.  These provide hints to the dynamic link editor where to start
# looking for an undefined symbol in a two-level namespace image.  The
# isub_image field is an index into the sub-images (sub-frameworks and
# sub-umbrellas list) that made up the two-level image that the undefined
# symbol was found in when it was built by the static link editor.  If
# isub-image is 0 the the symbol is expected to be defined in library and not
# in the sub-images.  If isub-image is non-zero it is an index into the array
# of sub-images for the umbrella with the first index in the sub-images being
# 1. The array of sub-images is the ordered list of sub-images of the umbrella
# that would be searched for a symbol that has the umbrella recorded as its
# primary library.  The table of contents index is an index into the
# library's table of contents.  This is used as the starting point of the
# binary search or a directed linear search.
class twolevel_hint(CStruct):
    _fields = [ ("hint","u32") ]
    isub_image = property(lambda _:_.hint>>24)
    itoc       = property(lambda _:_.hint&0x00ffffff)

#### Source: /usr/include/mach-o/reloc.h

# * In reloc.h, there are two data structures: relocation_info and scattered_relocation_info, which are merged in one structure below.
R_SCATTERED = 0x80000000
class relocation_info(CStruct):
    _fields = [
        ("relocaddr","u32"),
        ("relocsym","u32"),
        ]
    scattered = property(lambda _:(_.relocaddr&0x80000000)>>31)
    address   = property(lambda _:(_.relocaddr&0x00ffffff))
    # Scattered
    pcrel_1  = property(lambda _:(_.relocaddr&0x40000000)>>30)
    length_1 = property(lambda _:(_.relocaddr&0x30000000)>>28)
    type_1   = property(lambda _:(_.relocaddr&0x0f000000)>>24)
    # Not scattered
    type_0   = property(lambda _:(_.relocsym&0xf0000000)>>28)
    extern_0 = property(lambda _:(_.relocsym&0x08000000)>>27)
    length_0 = property(lambda _:(_.relocsym&0x06000000)>>25)
    pcrel_0  = property(lambda _:(_.relocsym&0x01000000)>>24)
    value    = property(lambda _:(_.relocsym&0x00ffffff))
    # Generic
    type   = property(lambda _:getattr(_,"type_%s"%_.scattered))
    extern = property(lambda _:getattr(_,"extern_%s"%_.scattered))
    length = property(lambda _:getattr(_,"length_%s"%_.scattered))
    pcrel  = property(lambda _:getattr(_,"pcrel_%s"%_.scattered))
    def symbolNumOrValue(self):
        if self.scattered: return self.relocsym
        else:              return self.value
    symbolNumOrValue = property(symbolNumOrValue)
    def __repr__(self):
        fields = [ "pcrel", "length" ]
        if not self.scattered:
            fields.append("extern")
        fields.extend(["type", "scattered", "symbolNumOrValue"])
        return "<" + self.__class__.__name__ + " " + " -- ".join([x + " " + hex(getattr(self,x)) for x in fields]) + ">"

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

#### Source: /usr/include/mach-o/x86_64/reloc.h
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
