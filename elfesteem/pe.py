#! /usr/bin/env python

from elfesteem.cstruct import CBase, CString, CStruct, CArray
from elfesteem.cstruct import data_null, data_empty
from elfesteem.cstruct import bytes_to_name, name_to_bytes
from elfesteem.strpatchwork import StrPatchwork
import struct
import logging
log = logging.getLogger("pe")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)

import sys
if sys.version_info[0:2] == (2, 3):
    from elfesteem.compatibility_python23 import sorted

DIRECTORY_ENTRY_EXPORT           = 0
DIRECTORY_ENTRY_IMPORT           = 1
DIRECTORY_ENTRY_RESOURCE         = 2
DIRECTORY_ENTRY_EXCEPTION        = 3
DIRECTORY_ENTRY_SECURITY         = 4
DIRECTORY_ENTRY_BASERELOC        = 5
DIRECTORY_ENTRY_DEBUG            = 6
DIRECTORY_ENTRY_COPYRIGHT        = 7
DIRECTORY_ENTRY_GLOBALPTR        = 8
DIRECTORY_ENTRY_TLS              = 9
DIRECTORY_ENTRY_LOAD_CONFIG      = 10
DIRECTORY_ENTRY_BOUND_IMPORT     = 11
DIRECTORY_ENTRY_IAT              = 12
DIRECTORY_ENTRY_DELAY_IMPORT     = 13
DIRECTORY_ENTRY_COM_DESCRIPTOR   = 14
DIRECTORY_ENTRY_RESERVED         = 15


RT_CURSOR                        = 1
RT_BITMAP                        = 2
RT_ICON                          = 3
RT_MENU                          = 4
RT_DIALOG                        = 5
RT_STRING                        = 6
RT_FONTDIR                       = 7
RT_FONT                          = 8
RT_ACCELERATOR                   = 9
RT_RCDATA                        = 10
RT_MESSAGETABLE                  = 11
RT_GROUP_CURSOR                  = 12
RT_GROUP_ICON                    = 14
RT_VERSION                       = 16
RT_DLGINCLUDE                    = 17
RT_PLUGPLAY                      = 19
RT_VXD                           = 20
RT_ANICURSOR                     = 21
RT_ANIICON                       = 22
RT_HTML                          = 23
RT_MANIFEST                      = 24

# Constants, e.g. from http://llvm.org/docs/doxygen/html/namespacellvm_1_1COFF.html
# plus the ones known by pefile.py, and some other
IMAGE_FILE_MACHINE_UNKNOWN   = 0x0
IMAGE_FILE_MACHINE_AM33      = 0x13
IMAGE_FILE_MACHINE_TI        = 0xC2
IMAGE_FILE_MACHINE_MIPSIII   = 0x142
IMAGE_FILE_MACHINE_iAPX286SMALL   = 0x14A
IMAGE_FILE_MACHINE_I386      = 0x14C
IMAGE_FILE_MACHINE_I860      = 0x14D
IMAGE_FILE_MACHINE_mc68k     = 0x150
IMAGE_FILE_MACHINE_iAPX286LARGE   = 0x152
IMAGE_FILE_MACHINE_MIPSEB    = 0x160
IMAGE_FILE_MACHINE_R3000     = 0x162
IMAGE_FILE_MACHINE_R4000     = 0x166
IMAGE_FILE_MACHINE_R10000    = 0x168
IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169 
IMAGE_FILE_MACHINE_WE32000   = 0x170
IMAGE_FILE_MACHINE_I386_BIS  = 0x175
IMAGE_FILE_MACHINE_CLIPPER   = 0x17F
IMAGE_FILE_MACHINE_ALPHA_O   = 0x183 # OSF1/Tru64 Object file
IMAGE_FILE_MACHINE_ALPHA_PE  = 0x184 # Windows NT PE for Alpha
IMAGE_FILE_MACHINE_ALPHA_Z   = 0x188 # OSF1/Tru64 Compressed object file
IMAGE_FILE_MACHINE_ALPHA_U   = 0x18F # OSF1/Tru64 Ucode object file. Obsolete
IMAGE_FILE_MACHINE_APOLLOA88K= 0x194
IMAGE_FILE_MACHINE_APOLLOM68K= 0x197
IMAGE_FILE_MACHINE_SH3       = 0x1A2
IMAGE_FILE_MACHINE_SH3DSP    = 0x1A3
IMAGE_FILE_MACHINE_SH3E      = 0x1A4
IMAGE_FILE_MACHINE_SH4       = 0x1A6
IMAGE_FILE_MACHINE_SH5       = 0x1A8
IMAGE_FILE_MACHINE_ARM       = 0x1C0
IMAGE_FILE_MACHINE_THUMB     = 0x1C2
IMAGE_FILE_MACHINE_ARMV7     = 0x1C4
IMAGE_FILE_MACHINE_ARMNT     = 0x1C4 # same
IMAGE_FILE_MACHINE_AM33      = 0x1D3
IMAGE_FILE_MACHINE_XCOFF32   = 0x1DF
IMAGE_FILE_MACHINE_POWERPC   = 0x1F0
IMAGE_FILE_MACHINE_POWERPCFP = 0x1F1
IMAGE_FILE_MACHINE_XCOFF64   = 0x1F7
IMAGE_FILE_MACHINE_IA64      = 0x200
IMAGE_FILE_MACHINE_MIPS16    = 0x266
IMAGE_FILE_MACHINE_ALPHA64   = 0x284
IMAGE_FILE_MACHINE_AXP64     = 0x284 # same
IMAGE_FILE_MACHINE_MIPSFPU   = 0x366
IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466
IMAGE_FILE_MACHINE_TRICORE   = 0x520
IMAGE_FILE_MACHINE_CEF       = 0xCEF
IMAGE_FILE_MACHINE_EBC       = 0xEBC
IMAGE_FILE_MACHINE_AMD64     = 0x8664
IMAGE_FILE_MACHINE_M32R      = 0x9041
IMAGE_FILE_MACHINE_ARM64     = 0xAA64
IMAGE_FILE_MACHINE_CEE       = 0xC0EE

IMAGE_FILE_FLAG_RELOCS_STRIPPED         = 0x0001
IMAGE_FILE_FLAG_EXECUTABLE_IMAGE        = 0x0002
IMAGE_FILE_FLAG_LINE_NUMS_STRIPPED      = 0x0004
IMAGE_FILE_FLAG_LOCAL_SYMS_STRIPPED     = 0x0008
IMAGE_FILE_FLAG_AGGRESSIVE_WS_TRIM      = 0x0010
IMAGE_FILE_FLAG_LARGE_ADDRESS_AWARE     = 0x0020
IMAGE_FILE_FLAG_BYTES_REVERSED_LO       = 0x0080
IMAGE_FILE_FLAG_32BIT_MACHINE           = 0x0100
IMAGE_FILE_FLAG_DEBUG_STRIPPED          = 0x0200
IMAGE_FILE_FLAG_REMOVABLE_RUN_FROM_SWAP = 0x0400
IMAGE_FILE_FLAG_NET_RUN_FROM_SWAP       = 0x0800
IMAGE_FILE_FLAG_SYSTEM                  = 0x1000
IMAGE_FILE_FLAG_DLL                     = 0x2000
IMAGE_FILE_FLAG_UP_SYSTEM_ONLY          = 0x4000
IMAGE_FILE_FLAG_BYTES_REVERSED_HI       = 0x8000 

IMAGE_SYM_CLASS_END_OF_FUNCTION  = -1
IMAGE_SYM_CLASS_NULL             = 0
IMAGE_SYM_CLASS_AUTOMATIC        = 1
IMAGE_SYM_CLASS_EXTERNAL         = 2
IMAGE_SYM_CLASS_STATIC           = 3
IMAGE_SYM_CLASS_REGISTER         = 4
IMAGE_SYM_CLASS_EXTERNAL_DEF     = 5
IMAGE_SYM_CLASS_LABEL            = 6
IMAGE_SYM_CLASS_UNDEFINED_LABEL  = 7
IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = 8
IMAGE_SYM_CLASS_ARGUMENT         = 9
IMAGE_SYM_CLASS_STRUCT_TAG       = 10
IMAGE_SYM_CLASS_MEMBER_OF_UNION  = 11
IMAGE_SYM_CLASS_UNION_TAG        = 12
IMAGE_SYM_CLASS_TYPE_DEFINITION  = 13
IMAGE_SYM_CLASS_UNDEFINED_STATIC = 14
IMAGE_SYM_CLASS_ENUM_TAG         = 15
IMAGE_SYM_CLASS_MEMBER_OF_ENUM   = 16
IMAGE_SYM_CLASS_REGISTER_PARAM   = 17
IMAGE_SYM_CLASS_BIT_FIELD        = 18
IMAGE_SYM_CLASS_BLOCK            = 100
IMAGE_SYM_CLASS_FUNCTION         = 101
IMAGE_SYM_CLASS_END_OF_STRUCT    = 102
IMAGE_SYM_CLASS_FILE             = 103
IMAGE_SYM_CLASS_SECTION          = 104
IMAGE_SYM_CLASS_WEAK_EXTERNAL    = 105
IMAGE_SYM_CLASS_CLR_TOKEN        = 107 

IMAGE_SYM_TYPE_NULL   = 0
IMAGE_SYM_TYPE_VOID   = 1
IMAGE_SYM_TYPE_CHAR   = 2
IMAGE_SYM_TYPE_SHORT  = 3
IMAGE_SYM_TYPE_INT    = 4
IMAGE_SYM_TYPE_LONG   = 5
IMAGE_SYM_TYPE_FLOAT  = 6
IMAGE_SYM_TYPE_DOUBLE = 7
IMAGE_SYM_TYPE_STRUCT = 8
IMAGE_SYM_TYPE_UNION  = 9
IMAGE_SYM_TYPE_ENUM   = 10
IMAGE_SYM_TYPE_MOE    = 11
IMAGE_SYM_TYPE_BYTE   = 12
IMAGE_SYM_TYPE_WORD   = 13
IMAGE_SYM_TYPE_UINT   = 14
IMAGE_SYM_TYPE_DWORD  = 15 

IMAGE_SYM_DTYPE_NULL     = 0
IMAGE_SYM_DTYPE_POINTER  = 1
IMAGE_SYM_DTYPE_FUNCTION = 2
IMAGE_SYM_DTYPE_ARRAY    = 3
IMAGE_SYM_DTYPE_SCT_COMPLEX_TYPE_SHIFT = 4 

# Official names of these constants in Windows
IMAGE_NT_OPTIONAL_HDR32_MAGIC   = 0x10b
IMAGE_NT_OPTIONAL_HDR64_MAGIC   = 0x20b
IMAGE_NT_OPTIONAL_HDR_ROM_MAGIC = 0x107
# Better names, for consistency for COFF that are not in PE files
IMAGE_OPTIONAL_HDR_MAGIC_EXE32  = 0x10b
IMAGE_OPTIONAL_HDR_MAGIC_EXE64  = 0x20b
IMAGE_OPTIONAL_HDR_MAGIC_ROM    = 0x107
IMAGE_OPTIONAL_HDR_MAGIC_EXE_TI = 0x108 # TI COFF executables

# COFF section flags
STYP_DSECT     = 0x00000001 # Dummy section
STYP_TEXT      = 0x00000020 # Text only
STYP_DATA      = 0x00000040 # Data only
STYP_BSS       = 0x00000080 # Bss only
STYP_RDATA     = 0x00000100 # Read-only data only
STYP_SDATA     = 0x00000200 # Small data only
STYP_SBSS      = 0x00000400 # Small bss only
STYP_UCODE     = 0x00000800 # Obsolete
STYP_GOT       = 0x00001000 # Global offset table
STYP_DYNAMIC   = 0x00002000 # Dynamic linking information
STYP_DYNSYM    = 0x00004000 # Dynamic linking symbol table
STYP_REL_DYN   = 0x00008000 # Dynamic relocation information
STYP_DYNSTR    = 0x00010000 # Dynamic linking symbol table
STYP_HASH      = 0x00020000 # Dynamic symbol hash table
STYP_DSOLIST   = 0x00040000 # Shared library dependency list
STYP_MSYM      = 0x00080000 # Additional dynamic linking symbol table
STYP_CONFLICT  = 0x00100000 # Additional dynamic linking information
STYP_FINI      = 0x01000000 # Termination text only
STYP_COMMENT   = 0x02000000 # Comment section
STYP_RCONST    = 0x02200000 # Read-only constants
STYP_XDATA     = 0x02400000 # Exception scope table
STYP_TLSDATA   = 0x02500000 # Initialized TLS data
STYP_TLSBSS    = 0x02600000 # Uninitialized TLS data
STYP_TLSINIT   = 0x02700000 # Initialization for TLS data
STYP_PDATA     = 0x02800000 # Exception procedure table
STYP_LITA      = 0x04000000 # Address literals only
STYP_LIT8      = 0x08000000 # 8-byte literals only
STYP_EXTMASK   = 0x0ff00000 # Identifies bits used for multiple bit flag values
STYP_LIT4      = 0x10000000 # 4-byte literals only
S_NRELOC_OVFL2 = 0x20000000 # Section header field s_nreloc has overflowed
STYP_INIT      = 0x80000000 # Initialization text only

# PE section flags (somewhat compatible, with different names)
IMAGE_SCN_TYPE_NO_PAD              = 0x00000008
IMAGE_SCN_CNT_CODE                 = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA     = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA   = 0x00000080
IMAGE_SCN_LNK_INFO                 = 0x00000200
IMAGE_SCN_LNK_REMOVE               = 0x00000800
IMAGE_SCN_LNK_COMDAT               = 0x00001000
IMAGE_SCN_GPREL                    = 0x00008000
IMAGE_SCN_ALIGN_1BYTES             = 0x00010000
IMAGE_SCN_ALIGN_2BYTES             = 0x00020000
IMAGE_SCN_ALIGN_4BYTES             = 0x00030000
IMAGE_SCN_ALIGN_8BYTES             = 0x00040000
IMAGE_SCN_ALIGN_16BYTES            = 0x00050000
IMAGE_SCN_ALIGN_32BYTES            = 0x00060000
IMAGE_SCN_ALIGN_64BYTES            = 0x00070000
IMAGE_SCN_ALIGN_128BYTES           = 0x00080000
IMAGE_SCN_ALIGN_256BYTES           = 0x00090000
IMAGE_SCN_ALIGN_512BYTES           = 0x000A0000
IMAGE_SCN_ALIGN_1024BYTES          = 0x000B0000
IMAGE_SCN_ALIGN_2048BYTES          = 0x000C0000
IMAGE_SCN_ALIGN_4096BYTES          = 0x000D0000
IMAGE_SCN_ALIGN_8192BYTES          = 0x000E0000
IMAGE_SCN_LNK_NRELOC_OVFL          = 0x01000000
IMAGE_SCN_MEM_DISCARDABLE          = 0x02000000
IMAGE_SCN_MEM_NOT_CACHED           = 0x04000000
IMAGE_SCN_MEM_NOT_PAGED            = 0x08000000
IMAGE_SCN_MEM_SHARED               = 0x10000000
IMAGE_SCN_MEM_EXECUTE              = 0x20000000
IMAGE_SCN_MEM_READ                 = 0x40000000
IMAGE_SCN_MEM_WRITE                = 0x80000000

# subsytem, in NT headers
IMAGE_SUBSYSTEM_UNKNOWN     = 0
IMAGE_SUBSYSTEM_NATIVE      = 1 # Doesn't require a subsystem (such as a device driver)
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2 # Runs in the Windows GUI subsystem
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3 # Runs in the Windows character subsystem (a console app)
IMAGE_SUBSYSTEM_OS2_CUI     = 5 # Runs in the OS/2 character subsystem (OS/2 1.x apps only)
IMAGE_SUBSYSTEM_POSIX_CUI   = 7 # Runs in the Posix character subsystem
IMAGE_SUBSYSTEM_NATIVE_WINDOWS           = 8 # Native Win9x driver
IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           = 9 # Windows CE
IMAGE_SUBSYSTEM_EFI_APPLICATION          = 10
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = 11
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       = 12
IMAGE_SUBSYSTEM_EFI_ROM                  = 13
IMAGE_SUBSYSTEM_XBOX                     = 14
IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16

# Relocations
# The following relocation type indicators are defined for x64 and compatible processors
IMAGE_REL_AMD64_ABSOLUTE = 0x0000 # The relocation is ignored.
IMAGE_REL_AMD64_ADDR64   = 0x0001 # The 64-bit VA of the relocation target.
IMAGE_REL_AMD64_ADDR32   = 0x0002 # The 32-bit VA of the relocation target.
IMAGE_REL_AMD64_ADDR32NB = 0x0003 # The 32-bit address without an image base (RVA).
IMAGE_REL_AMD64_REL32    = 0x0004 # The 32-bit relative address from the byte following the relocation.
IMAGE_REL_AMD64_REL32_1  = 0x0005 # The 32-bit address relative to byte distance 1 from the relocation.
IMAGE_REL_AMD64_REL32_2  = 0x0006 # The 32-bit address relative to byte distance 2 from the relocation.
IMAGE_REL_AMD64_REL32_3  = 0x0007 # The 32-bit address relative to byte distance 3 from the relocation.
IMAGE_REL_AMD64_REL32_4  = 0x0008 # The 32-bit address relative to byte distance 4 from the relocation.
IMAGE_REL_AMD64_REL32_5  = 0x0009 # The 32-bit address relative to byte distance 5 from the relocation.
IMAGE_REL_AMD64_SECTION  = 0x000A # The 16-bit section index of the section that contains the target. This is used to support debugging information.
IMAGE_REL_AMD64_SECREL   = 0x000B # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
IMAGE_REL_AMD64_SECREL7  = 0x000C # A 7-bit unsigned offset from the base of the section that contains the target.
IMAGE_REL_AMD64_TOKEN    = 0x000D # CLR tokens.
IMAGE_REL_AMD64_SREL32   = 0x000E # A 32-bit signed span-dependent value emitted into the object.
IMAGE_REL_AMD64_PAIR     = 0x000F # A pair that must immediately follow every span-dependent value.
IMAGE_REL_AMD64_SSPAN32  = 0x0010 # A 32-bit signed span-dependent value that is applied at link time.
# The following relocation type indicators are defined for ARM processors.
IMAGE_REL_ARM_ABSOLUTE   = 0x0000 # The relocation is ignored.
IMAGE_REL_ARM_ADDR32     = 0x0001 # The 32-bit VA of the target.
IMAGE_REL_ARM_ADDR32NB   = 0x0002 # The 32-bit RVA of the target.
IMAGE_REL_ARM_BRANCH24   = 0x0003 # The 24-bit relative displacement to the target. 
IMAGE_REL_ARM_BRANCH11   = 0x0004 # The reference to a subroutine call. The reference consists of two 16-bit instructions with 11-bit offsets.
IMAGE_REL_ARM_SECTION    = 0x000E # The 16-bit section index of the section that contains the target. This is used to support debugging information.
IMAGE_REL_ARM_SECREL     = 0x000F # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
IMAGE_REL_ARM_MOV32      = 0x0010 # The 32-bit VA of the target. This relocation is applied using a MOVW instruction for the low 16 bits followed by a MOVT for the high 16 bits.
IMAGE_REL_THUMB_MOV32    = 0x0011 # The 32-bit VA of the target. This relocation is applied using a MOVW instruction for the low 16 bits followed by a MOVT for the high 16 bits.
IMAGE_REL_THUMB_BRANCH20 = 0x0012 # The instruction is fixed up with the 21-bit relative displacement to the 2-byte aligned target. The least significant bit of the displacement is always zero and is not stored. This relocation corresponds to a Thumb-2 32-bit conditional B instruction.
IMAGE_REL_THUMB_BRANCH24 = 0x0014 # The instruction is fixed up with the 25-bit relative displacement to the 2-byte aligned target. The least significant bit of the displacement is zero and is not stored. This relocation corresponds to a Thumb-2 B instruction.
IMAGE_REL_THUMB_BLX23    = 0x0015 # The instruction is fixed up with the 25-bit relative displacement to the 4-byte aligned target. The low 2 bits of the displacement are zero and are not stored. This relocation corresponds to a Thumb-2 BLX instruction.
IMAGE_REL_ARM_PAIR       = 0x0016 # The relocation is valid only when it immediately follows a ARM_REFHI or THUMB_REFHI. Its SymbolTableIndex contains a displacement and not an index into the symbol table.
# The following relocation type indicators are defined for ARM64 processors.
IMAGE_REL_ARM64_ABSOLUTE       = 0x0000 # The relocation is ignored.
IMAGE_REL_ARM64_ADDR32         = 0x0001 # The 32-bit VA of the target.
IMAGE_REL_ARM64_ADDR32NB       = 0x0002 # The 32-bit RVA of the target.
IMAGE_REL_ARM64_BRANCH26       = 0x0003 # The 26-bit relative displacement to the target, for B and BL instructions. 
IMAGE_REL_ARM64_PAGEBASE_REL21 = 0x0004 # The page base of the target, for ADRP instruction.
IMAGE_REL_ARM64_REL21          = 0x0005 # The 12-bit relative displacement to the target, for instruction ADR
IMAGE_REL_ARM64_PAGEOFFSET_12A = 0x0006 # The 12-bit page offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
IMAGE_REL_ARM64_PAGEOFFSET_12L = 0x0007 # The 12-bit page offset of the target, for instruction LDR (indexed, unsigned immediate).
IMAGE_REL_ARM64_SECREL         = 0x0008 # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
IMAGE_REL_ARM64_SECREL_LOW12A  = 0x0009 # Bit 0:11 of section offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
IMAGE_REL_ARM64_SECREL_HIGH12A = 0x000A # Bit 12:23 of section offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
IMAGE_REL_ARM64_SECREL_LOW12L  = 0x000B # Bit 0:11 of section offset of the target, for instruction LDR (indexed, unsigned immediate).
IMAGE_REL_ARM64_TOKEN          = 0x000C # CLR token.
IMAGE_REL_ARM64_SECTION        = 0x000D # The 16-bit section index of the section that contains the target. This is used to support debugging information.
IMAGE_REL_ARM64_ADDR64         = 0x000E # The 64-bit VA of the relocation target.
IMAGE_REL_ARM64_BRANCH19       = 0x000F # The 19-bit offset to the relocation target, for conditional B instruction.
IMAGE_REL_ARM64_BRANCH14       = 0x0010 # The 14-bit offset to the relocation target, for instructions TBZ and TBNZ.
# The following relocation type indicators are defined for Hitachi SH3 and SH4 processors. SH5-specific relocations are noted as SHM (SH Media).
IMAGE_REL_SH3_ABSOLUTE        = 0x0000 # The relocation is ignored.
IMAGE_REL_SH3_DIRECT16        = 0x0001 # A reference to the 16-bit location that contains the VA of the target symbol.
IMAGE_REL_SH3_DIRECT32        = 0x0002 # The 32-bit VA of the target symbol.
IMAGE_REL_SH3_DIRECT8         = 0x0003 # A reference to the 8-bit location that contains the VA of the target symbol.
IMAGE_REL_SH3_DIRECT8_WORD    = 0x0004 # A reference to the 8-bit instruction that contains the effective 16-bit VA of the target symbol.
IMAGE_REL_SH3_DIRECT8_LONG    = 0x0005 # A reference to the 8-bit instruction that contains the effective 32-bit VA of the target symbol.
IMAGE_REL_SH3_DIRECT4         = 0x0006 # A reference to the 8-bit location whose low 4 bits contain the VA of the target symbol.
IMAGE_REL_SH3_DIRECT4_WORD    = 0x0007 # A reference to the 8-bit instruction whose low 4 bits contain the effective 16-bit VA of the target symbol.
IMAGE_REL_SH3_DIRECT4_LONG    = 0x0008 # A reference to the 8-bit instruction whose low 4 bits contain the effective 32-bit VA of the target symbol.
IMAGE_REL_SH3_PCREL8_WORD     = 0x0009 # A reference to the 8-bit instruction that contains the effective 16-bit relative offset of the target symbol.
IMAGE_REL_SH3_PCREL8_LONG     = 0x000A # A reference to the 8-bit instruction that contains the effective 32-bit relative offset of the target symbol.
IMAGE_REL_SH3_PCREL12_WORD    = 0x000B # A reference to the 16-bit instruction whose low 12 bits contain the effective 16-bit relative offset of the target symbol.
IMAGE_REL_SH3_STARTOF_SECTION = 0x000C # A reference to a 32-bit location that is the VA of the section that contains the target symbol.
IMAGE_REL_SH3_SIZEOF_SECTION  = 0x000D # A reference to the 32-bit location that is the size of the section that contains the target symbol.
IMAGE_REL_SH3_SECTION         = 0x000E # The 16-bit section index of the section that contains the target. This is used to support debugging information.
IMAGE_REL_SH3_SECREL          = 0x000F # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
IMAGE_REL_SH3_DIRECT32_NB     = 0x0010 # The 32-bit RVA of the target symbol.
IMAGE_REL_SH3_GPREL4_LONG     = 0x0011 # GP relative.
IMAGE_REL_SH3_TOKEN           = 0x0012 # CLR token.
IMAGE_REL_SHM_PCRELPT         = 0x0013 # The offset from the current instruction in longwords. If the NOMODE bit is not set, insert the inverse of the low bit at bit 32 to select PTA or PTB.
IMAGE_REL_SHM_REFLO           = 0x0014 # The low 16 bits of the 32-bit address.
IMAGE_REL_SHM_REFHALF         = 0x0015 # The high 16 bits of the 32-bit address.
IMAGE_REL_SHM_RELLO           = 0x0016 # The low 16 bits of the relative address.
IMAGE_REL_SHM_RELHALF         = 0x0017 # The high 16 bits of the relative address.
IMAGE_REL_SHM_PAIR            = 0x0018 # The relocation is valid only when it immediately follows a REFHALF, RELHALF, or RELLO relocation. The SymbolTableIndex field of the relocation contains a displacement and not an index into the symbol table.
IMAGE_REL_SHM_NOMODE          = 0x8000 # The relocation ignores section mode.
# The following relocation type indicators are defined for PowerPC processors.
IMAGE_REL_PPC_ABSOLUTE   = 0x0000 # The relocation is ignored.
IMAGE_REL_PPC_ADDR64     = 0x0001 # The 64-bit VA of the target.
IMAGE_REL_PPC_ADDR32     = 0x0002 # The 32-bit VA of the target.
IMAGE_REL_PPC_ADDR24     = 0x0003 # The low 24 bits of the VA of the target. This is valid only when the target symbol is absolute and can be sign-extended to its original value.
IMAGE_REL_PPC_ADDR16     = 0x0004 # The low 16 bits of the target's VA.
IMAGE_REL_PPC_ADDR14     = 0x0005 # The low 14 bits of the target's VA. This is valid only when the target symbol is absolute and can be sign-extended to its original value.
IMAGE_REL_PPC_REL24      = 0x0006 # A 24-bit PC-relative offset to the symbol's location.
IMAGE_REL_PPC_REL14      = 0x0007 # A 14-bit PC-relative offset to the symbol's location.
IMAGE_REL_PPC_ADDR32NB   = 0x000A # The 32-bit RVA of the target.
IMAGE_REL_PPC_SECREL     = 0x000B # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
IMAGE_REL_PPC_SECTION    = 0x000C # The 16-bit section index of the section that contains the target. This is used to support debugging information.
IMAGE_REL_PPC_SECREL16   = 0x000F # The 16-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
IMAGE_REL_PPC_REFHI      = 0x0010 # The high 16 bits of the target's 32-bit VA. This is used for the first instruction in a two-instruction sequence that loads a full address. This relocation must be immediately followed by a PAIR relocation whose SymbolTableIndex contains a signed 16-bit displacement that is added to the upper 16 bits that was taken from the location that is being relocated.
IMAGE_REL_PPC_REFLO      = 0x0011 # The low 16 bits of the target's VA.
IMAGE_REL_PPC_PAIR       = 0x0012 # A relocation that is valid only when it immediately follows a REFHI or SECRELHI relocation. Its SymbolTableIndex contains a displacement and not an index into the symbol table.
IMAGE_REL_PPC_SECRELLO   = 0x0013 # The low 16 bits of the 32-bit offset of the target from the beginning of its section.
IMAGE_REL_PPC_GPREL      = 0x0015 # The 16-bit signed displacement of the target relative to the GP register.
IMAGE_REL_PPC_TOKEN      = 0x0016 # The CLR token.
# The following relocation type indicators are defined for Intel 386 and compatible processors.
IMAGE_REL_I386_ABSOLUTE  = 0x0000 # The relocation is ignored.
IMAGE_REL_I386_DIR16     = 0x0001 # Not supported.
IMAGE_REL_I386_REL16     = 0x0002 # Not supported.
IMAGE_REL_I386_DIR32     = 0x0006 # The target's 32-bit VA.
IMAGE_REL_I386_DIR32NB   = 0x0007 # The target's 32-bit RVA.
IMAGE_REL_I386_SEG12     = 0x0009 # Not supported.
IMAGE_REL_I386_SECTION   = 0x000A # The 16-bit section index of the section that contains the target. This is used to support debugging information.
IMAGE_REL_I386_SECREL    = 0x000B # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
IMAGE_REL_I386_TOKEN     = 0x000C # The CLR token.
IMAGE_REL_I386_SECREL7   = 0x000D # A 7-bit offset from the base of the section that contains the target.
IMAGE_REL_I386_REL32     = 0x0014 # The 32-bit relative displacement to the target. This supports the x86 relative branch and call instructions.
# The following relocation type indicators are defined for the Intel Itanium processor family and compatible processors. Note that relocations on instructions use the bundle's offset and slot number for the relocation offset.
IMAGE_REL_IA64_ABSOLUTE  = 0x0000 # The relocation is ignored.
IMAGE_REL_IA64_IMM14     = 0x0001 # The instruction relocation can be followed by an ADDEND relocation whose value is added to the target address before it is inserted into the specified slot in the IMM14 bundle. The relocation target must be absolute or the image must be fixed.
IMAGE_REL_IA64_IMM22     = 0x0002 # The instruction relocation can be followed by an ADDEND relocation whose value is added to the target address before it is inserted into the specified slot in the IMM22 bundle. The relocation target must be absolute or the image must be fixed.
IMAGE_REL_IA64_IMM64     = 0x0003 # The slot number of this relocation must be one (1). The relocation can be followed by an ADDEND relocation whose value is added to the target address before it is stored in all three slots of the IMM64 bundle.
IMAGE_REL_IA64_DIR32     = 0x0004 # The target's 32-bit VA. This is supported only for /LARGEADDRESSAWARE:NO images.
IMAGE_REL_IA64_DIR64     = 0x0005 # The target's 64-bit VA.
IMAGE_REL_IA64_PCREL21B  = 0x0006 # The instruction is fixed up with the 25-bit relative displacement to the 16-bit aligned target. The low 4 bits of the displacement are zero and are not stored.
IMAGE_REL_IA64_PCREL21M  = 0x0007 # The instruction is fixed up with the 25-bit relative displacement to the 16-bit aligned target. The low 4 bits of the displacement, which are zero, are not stored.
IMAGE_REL_IA64_PCREL21F  = 0x0008 # The LSBs of this relocation's offset must contain the slot number whereas the rest is the bundle address. The bundle is fixed up with the 25-bit relative displacement to the 16-bit aligned target. The low 4 bits of the displacement are zero and are not stored.
IMAGE_REL_IA64_GPREL22   = 0x0009 # The instruction relocation can be followed by an ADDEND relocation whose value is added to the target address and then a 22-bit GP-relative offset that is calculated and applied to the GPREL22 bundle.
IMAGE_REL_IA64_LTOFF22   = 0x000A # The instruction is fixed up with the 22-bit GP-relative offset to the target symbol's literal table entry. The linker creates this literal table entry based on this relocation and the ADDEND relocation that might follow.
IMAGE_REL_IA64_SECTION   = 0x000B # The 16-bit section index of the section contains the target. This is used to support debugging information.
IMAGE_REL_IA64_SECREL22  = 0x000C # The instruction is fixed up with the 22-bit offset of the target from the beginning of its section. This relocation can be followed immediately by an ADDEND relocation, whose Value field contains the 32-bit unsigned offset of the target from the beginning of the section.
IMAGE_REL_IA64_SECREL64I = 0x000D # The slot number for this relocation must be one (1). The instruction is fixed up with the 64-bit offset of the target from the beginning of its section. This relocation can be followed immediately by an ADDEND relocation whose Value field contains the 32-bit unsigned offset of the target from the beginning of the section.
IMAGE_REL_IA64_SECREL32  = 0x000E # The address of data to be fixed up with the 32-bit offset of the target from the beginning of its section.
IMAGE_REL_IA64_DIR32NB   = 0x0010 # The target's 32-bit RVA.
IMAGE_REL_IA64_SREL14    = 0x0011 # This is applied to a signed 14-bit immediate that contains the difference between two relocatable targets. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
IMAGE_REL_IA64_SREL22    = 0x0012 # This is applied to a signed 22-bit immediate that contains the difference between two relocatable targets. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
IMAGE_REL_IA64_SREL32    = 0x0013 # This is applied to a signed 32-bit immediate that contains the difference between two relocatable values. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
IMAGE_REL_IA64_UREL32    = 0x0014 # This is applied to an unsigned 32-bit immediate that contains the difference between two relocatable values. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
IMAGE_REL_IA64_PCREL60X  = 0x0015 # A 60-bit PC-relative fixup that always stays as a BRL instruction of an MLX bundle.
IMAGE_REL_IA64_PCREL60B  = 0x0016 # A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MBB bundle with NOP.B in slot 1 and a 25-bit BR instruction (with the 4 lowest bits all zero and dropped) in slot 2.
IMAGE_REL_IA64_PCREL60F  = 0x0017 # A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MFB bundle with NOP.F in slot 1 and a 25-bit (4 lowest bits all zero and dropped) BR instruction in slot 2.
IMAGE_REL_IA64_PCREL60I  = 0x0018 # A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MIB bundle with NOP.I in slot 1 and a 25-bit (4 lowest bits all zero and dropped) BR instruction in slot 2.
IMAGE_REL_IA64_PCREL60M  = 0x0019 # A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MMB bundle with NOP.M in slot 1 and a 25-bit (4 lowest bits all zero and dropped) BR instruction in slot 2.
IMAGE_REL_IA64_IMMGPREL64= 0x001a # A 64-bit GP-relative fixup.
IMAGE_REL_IA64_TOKEN     = 0x001b # A CLR token.
IMAGE_REL_IA64_GPREL32   = 0x001c # A 32-bit GP-relative fixup.
IMAGE_REL_IA64_ADDEND    = 0x001F # The relocation is valid only when it immediately follows one of the following relocations: IMM14, IMM22, IMM64, GPREL22, LTOFF22, LTOFF64, SECREL22, SECREL64I, or SECREL32. Its value contains the addend to apply to instructions within a bundle, not for data.
# The following relocation type indicators are defined for MIPS processors.
IMAGE_REL_MIPS_ABSOLUTE  = 0x0000 # The relocation is ignored.
IMAGE_REL_MIPS_REFHALF   = 0x0001 # The high 16 bits of the target's 32-bit VA.
IMAGE_REL_MIPS_REFWORD   = 0x0002 # The target's 32-bit VA.
IMAGE_REL_MIPS_JMPADDR   = 0x0003 # The low 26 bits of the target's VA. This supports the MIPS J and JAL instructions.
IMAGE_REL_MIPS_REFHI     = 0x0004 # The high 16 bits of the target's 32-bit VA. This is used for the first instruction in a two-instruction sequence that loads a full address. This relocation must be immediately followed by a PAIR relocation whose SymbolTableIndex contains a signed 16-bit displacement that is added to the upper 16 bits that are taken from the location that is being relocated.
IMAGE_REL_MIPS_REFLO     = 0x0005 # The low 16 bits of the target's VA.
IMAGE_REL_MIPS_GPREL     = 0x0006 # A 16-bit signed displacement of the target relative to the GP register.
IMAGE_REL_MIPS_LITERAL   = 0x0007 # The same as IMAGE_REL_MIPS_GPREL.
IMAGE_REL_MIPS_SECTION   = 0x000A # The 16-bit section index of the section contains the target. This is used to support debugging information.
IMAGE_REL_MIPS_SECREL    = 0x000B # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
IMAGE_REL_MIPS_SECRELLO  = 0x000C # The low 16 bits of the 32-bit offset of the target from the beginning of its section.
IMAGE_REL_MIPS_SECRELHI  = 0x000D # The high 16 bits of the 32-bit offset of the target from the beginning of its section. An IMAGE_REL_MIPS_PAIR relocation must immediately follow this one. The SymbolTableIndex of the PAIR relocation contains a signed 16-bit displacement that is added to the upper 16 bits that are taken from the location that is being relocated.
IMAGE_REL_MIPS_JMPADDR16 = 0x0010 # The low 26 bits of the target's VA. This supports the MIPS16 JAL instruction.
IMAGE_REL_MIPS_REFWORDNB = 0x0022 # The target's 32-bit RVA.
IMAGE_REL_MIPS_PAIR      = 0x0025 # The relocation is valid only when it immediately follows a REFHI or SECRELHI relocation. Its SymbolTableIndex contains a displacement and not an index into the symbol table.
# The following relocation type indicators are defined for the Mitsubishi M32R processors.
IMAGE_REL_M32R_ABSOLUTE  = 0x0000 # The relocation is ignored.
IMAGE_REL_M32R_ADDR32    = 0x0001 # The target's 32-bit VA.
IMAGE_REL_M32R_ADDR32NB  = 0x0002 # The target's 32-bit RVA.
IMAGE_REL_M32R_ADDR24    = 0x0003 # The target's 24-bit VA.
IMAGE_REL_M32R_GPREL16   = 0x0004 # The target's 16-bit offset from the GP register.
IMAGE_REL_M32R_PCREL24   = 0x0005 # The target's 24-bit offset from the program counter (PC), shifted left by 2 bits and sign-extended 
IMAGE_REL_M32R_PCREL16   = 0x0006 # The target's 16-bit offset from the PC, shifted left by 2 bits and sign-extended
IMAGE_REL_M32R_PCREL8    = 0x0007 # The target's 8-bit offset from the PC, shifted left by 2 bits and sign-extended
IMAGE_REL_M32R_REFHALF   = 0x0008 # The 16 MSBs of the target VA.
IMAGE_REL_M32R_REFHI     = 0x0009 # The 16 MSBs of the target VA, adjusted for LSB sign extension. This is used for the first instruction in a two-instruction sequence that loads a full 32-bit address. This relocation must be immediately followed by a PAIR relocation whose SymbolTableIndex contains a signed 16-bit displacement that is added to the upper 16 bits that are taken from the location that is being relocated.
IMAGE_REL_M32R_REFLO     = 0x000A # The 16 LSBs of the target VA.
IMAGE_REL_M32R_PAIR      = 0x000B # The relocation must follow the REFHI relocation. Its SymbolTableIndex contains a displacement and not an index into the symbol table.
IMAGE_REL_M32R_SECTION   = 0x000C # The 16-bit section index of the section that contains the target. This is used to support debugging information.
IMAGE_REL_M32R_SECREL    = 0x000D # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
IMAGE_REL_M32R_TOKEN     = 0x000E # The CLR token.


constants = {
  'RT' : {},
  'DIRECTORY_ENTRY' : {},
  'IMAGE_FILE_MACHINE' : {},
  'IMAGE_FILE_FLAG' : {},
  'IMAGE_SYM_CLASS' : {},
  'IMAGE_SYM_TYPE'  : {},
  'IMAGE_SYM_DTYPE' : {},
  'IMAGE_OPTIONAL_HDR_MAGIC' : {},
  'IMAGE_SUBSYSTEM' : {},
  'IMAGE_SCN' : {},
  'STYP' : {},
  }
def enumerate_constants(constants, globs):
    for type in constants:
        for val in filter(lambda x:x[:len(type)+1]==type+"_", globs.keys()):
            if not globs[val] in constants[type]:
                constants[type][globs[val]] = val[len(type)+1:]
enumerate_constants(constants, dict(globals()))

class InvalidOffset(Exception):
    pass

####################################################################
# Headers

class DOShdr(CStruct):
    _fields = [ ("magic", "u16"),
                ("cblp","u16"),
                ("cp","u16"),
                ("crlc","u16"),
                ("cparhdr","u16"),
                ("minalloc","u16"),
                ("maxalloc","u16"),
                ("ss","u16"),
                ("sp","u16"),
                ("csum","u16"),
                ("ip","u16"),
                ("cs","u16"),
                ("lfarlc","u16"),
                ("ovno","u16"),
                ("res","8s"),
                ("oemid","u16"),
                ("oeminfo","u16"),
                ("res2","20s"),
                ("lfanew","u32") ] # must be 4-bytes aligned

class NTsig(CStruct):
    _fields = [ ("signature","u32") ]
    # Needed for miasm2/analysis/binary.py
    signature_value = property(lambda _:_.signature)

class COFFhdr(CStruct):
    _fields = [ ("machine","u16"),
                ("numberofsections","u16"),
                ("timedatestamp","u32"),
                ("pointertosymboltable","ptr"),
                ("numberofsymbols","u32"),
                ("sizeofoptionalheader","u16"),
                ("characteristics","u16") ]

class XCOFFhdr64(CStruct):
    _fields = [ ("machine","u16"),
                ("numberofsections","u16"),
                ("timedatestamp","u32"),
                ("pointertosymboltable","ptr"),
                ("sizeofoptionalheader","u16"),
                ("characteristics","u16"),
                ("numberofsymbols","u32"),
                ]

# COFF Optional headers can have many variants
class Opthdr32(CStruct):
    _fields = [ ("magic","u16"),
                ("majorlinkerversion","u08"),
                ("minorlinkerversion","u08"),
                ("SizeOfCode","u32"),
                ("sizeofinitializeddata","u32"),
                ("sizeofuninitializeddata","u32"),
                ("AddressOfEntryPoint","u32"),
                ("BaseOfCode","u32"),
                ("BaseOfData","u32"),
                ]
    vstamp = property(lambda _:_.majorlinkerversion<<8+_.minorlinkerversion)
    tsize = property(lambda _:_.SizeOfCode)
    dsize = property(lambda _:_.sizeofinitializeddata)
    bsize = property(lambda _:_.sizeofuninitializeddata)
    entry = property(lambda _:_.AddressOfEntryPoint)
    text_start = property(lambda _:_.BaseOfCode)
    data_start = property(lambda _:_.BaseOfData)

class Opthdr64(Opthdr32):
    _fields = [ ("magic","u16"),
                ("majorlinkerversion","u08"),
                ("minorlinkerversion","u08"),
                ("SizeOfCode","u32"),
                ("sizeofinitializeddata","u32"),
                ("sizeofuninitializeddata","u32"),
                ("AddressOfEntryPoint","u32"),
                ("BaseOfCode","u32"),
                ]

# Specs of COFF for Apollo found at
# https://opensource.apple.com/source/gdb/gdb-908/src/include/coff/apollo.h
class OpthdrApollo(CStruct):
    _fields = [ ("magic","u16"),      # type of file
                ("vstamp","u16"),     # version stamp
                ("tsize","u32"),      # text size in bytes
                ("dsize","u32"),      # initialized data
                ("bsize","u32"),      # uninitialized data
                ("entry","u32"),      # entry point
                ("text_start","u32"), # base of text used for this file
                ("data_start","u32"), # base of data used for this file
                ("o_sri","u32"),      # Apollo specific - .sri data pointer
                ("o_inlib","u32"),    # Apollo specific - .inlib data pointer
                ("vid","u64"),        # Apollo specific - 64 bit version ID
                ]

# No spec for COFF for Intergraph Clipper of CLIX found
# We make the assumption that is is standard COFF plus additional field
class OpthdrClipper(CStruct):
    _fields = [ ("magic","u16"),
                ("vstamp","u16"),
                ("tsize","u32"),
                ("dsize","u32"),
                ("bsize","u32"),
                ("entry","u32"),
                ("text_start","u32"),
                ("data_start","u32"),
                ("c0","u32"),    # Clipper specific?
                ("c1","u32"),    # Clipper specific?
                ]

# 32-bit eCOFF (for MIPS)
# The only source of information found is binutils' include/coff/mips.h
class OpthdrECOFF32(CStruct):
    _fields = [ ("magic","u16"),
                ("vstamp","u16"),
                ("tsize","u32"),
                ("dsize","u32"),
                ("bsize","u32"),
                ("entry","u32"),
                ("text_start","u32"),
                ("data_start","u32"),
                ("bss_start","u32"),
                ("gprmask","u32"),
                ("cprmask0","u32"),
                ("cprmask1","u32"),
                ("cprmask2","u32"),
                ("cprmask3","u32"),
                ("gp_value","u32"),
                ]
    majorlinkerversion = property(lambda _:_.vstamp>>8)
    minorlinkerversion = property(lambda _:_.vstamp&0xff)

# Specs of eCOFF for Tru64 aka. OSF1 found at
# http://h41361.www4.hpe.com/docs/base_doc/DOCUMENTATION/V50A_ACRO_SUP/OBJSPEC.PDF
# Not fully consistent with binutils' include/coff/alpha.h
# Looking at sample files, it seems that binutils is right
class OpthdrECOFF64(CStruct):
    _fields = [ ("magic","u16"),
                ("vstamp","u16"),
                ("bldrev","u16"),
                ("padcell","u16"),
                ("tsize","u64"),
                ("dsize","u64"),
                ("bsize","u64"),
                ("entry","u64"),
                ("text_start","u64"),
                ("data_start","u64"),
                ("bss_start","u64"),
                ("gprmask","u32"),
                ("fprmask","u32"),  # As with binutils
                ("gp_value","u64"), # As with binutils
                #("fprmask","u64"),  # As with OBJSPEC.PDF
                #("gp_value","u32"), # As with OBJSPEC.PDF
                ]
    majorlinkerversion = property(lambda _:_.vstamp>>8)
    minorlinkerversion = property(lambda _:_.vstamp&0xff)

# Specs of XCOFF found at
# http://www.ibm.com/support/knowledgecenter/ssw_aix_72/com.ibm.aix.files/XCOFF.htm
class OpthdrXCOFF32(CStruct):
    _fields = [ ("magic","u16"),
                ("vstamp","u16"),
                ("tsize","u32"),
                ("dsize","u32"),
                ("size","u32"),
                ("entry","u32"),
                ("text_start","u32"),
                ("data_start","u32"),
                ("toc","u32"),
                ("snentry","u16"),
                ("sntext","u16"),
                ("sndata","u16"),
                ("sntoc","u16"),
                ("snloader","u16"),
                ("snbss","u16"),
                ("algntext","u16"),
                ("algndata","u16"),
                ("modtype","u16"),
                ("cpuflag","u08"),
                ("cputype","u08"),
                ("maxstack","u32"),
                ("maxdata","u32"),
                ("debugger","u32"),
                ("textpsize","u08"),
                ("datapsize","u08"),
                ("stackpsize","u08"),
                ("flags","u08"),
                ("sntdata","u16"),
                ("sntbss","u16"),
                ]

class OpthdrXCOFF64(CStruct):
    _fields = [ ("magic","u16"),
                ("vstamp","u16"),
                ("debugger","u32"),
                ("text_start","u64"),
                ("data_start","u64"),
                ("toc","u64"),
                ("snentry","u16"),
                ("sntext","u16"),
                ("sndata","u16"),
                ("sntoc","u16"),
                ("snloader","u16"),
                ("snbss","u16"),
                ("algntext","u16"),
                ("algndata","u16"),
                ("modtype","u16"),
                ("cpuflag","u08"),
                ("cputype","u08"),
                ("textpsize","u08"),
                ("datapsize","u08"),
                ("stackpsize","u08"),
                ("flags","u08"),
                ("tsize","u64"),
                ("dsize","u64"),
                ("size","u64"),
                ("entry","u64"),
                ("maxstack","u64"),
                ("maxdata","u64"),
                ("sntdata","u16"),
                ("sntbss","u16"),
                ("x64flags","u16"),
                ]

class OptNThdr(CStruct):
    _fields = [ ("rva","u32"),
                ("size","u32") ]

class OptNThdrs(CArray):
    _cls = OptNThdr
    count = lambda _: _.parent.numberofrvaandsizes

class NThdr(CStruct):
    _fields = [ ("ImageBase","ptr"),
                ("sectionalignment","u32"),
                ("filealignment","u32"),
                ("majoroperatingsystemversion","u16"),
                ("minoroperatingsystemversion","u16"),
                ("MajorImageVersion","u16"),
                ("MinorImageVersion","u16"),
                ("majorsubsystemversion","u16"),
                ("minorsubsystemversion","u16"),
                ("Reserved1","u32"),
                ("sizeofimage","u32"),
                ("sizeofheaders","u32"),
                ("CheckSum","u32"),
                ("subsystem","u16"),
                ("dllcharacteristics","u16"),
                ("sizeofstackreserve","ptr"),
                ("sizeofstackcommit","ptr"),
                ("sizeofheapreserve","ptr"),
                ("sizeofheapcommit","ptr"),
                ("loaderflags","u32"),
                ("numberofrvaandsizes","u32"),
                ("optentries",OptNThdrs) ]
    def get_optentries(self):
        return self.getf('optentries')._array
    def unpack(self, c, o):
        CStruct.unpack(self, c, o)
        sz_opt = self.parent.COFFhdr.sizeofoptionalheader
        if sz_opt != self.parent.Opthdr.bytelen + self.bytelen:
            log.warn('Number of rva %d does not match sizeofoptionalheader %d',
                self.numberofrvaandsizes, sz_opt)

####################################################################
# Sections

class SectionData(CBase):
    # This class include the section data (of size rsize) but also
    # the COFF relocations
    def pack(self):
        # section data is not in Shdr, therefore the answer is of size 0,
        # to avoid that Shdr packing includes the data.
        return data_empty
    def _initialize(self):
        # section data is not in Shdr, therefore it is made of size 0,
        # to avoid that Shdr packing includes the data
        self._size = 0
    def unpack(self, c, o):
        pefile = self.parent.parent.parent
        if hasattr(pefile, 'NThdr'):
            filealignment = pefile.NThdr.filealignment
        else:
            filealignment = 0
        self.data = StrPatchwork()
        if filealignment != 0:
            if self.parent.scnptr % filealignment:
                log.warn('Section %d offset %#x not aligned to %#x',
                    len(self.parent.parent), self.parent.scnptr, filealignment)
            if self.parent.rsize % filealignment:
                log.warn('Section %d size %#x not aligned to %#x',
                    len(self.parent.parent), self.parent.rsize, filealignment)
        raw_sz = self.parent.rsize
        raw_sz += self.parent.scnptr - self.parent.scn_baseoff
        if self.parent.scn_baseoff+raw_sz > len(c):
            raw_sz = len(c) - self.parent.scn_baseoff
        self.data[0] = c[self.parent.scn_baseoff:self.parent.scn_baseoff+raw_sz]
        if self.parent.relptr >= len(c):
            raise ValueError("COFF invalid relptr")
        self.relocs = COFFRelocations(parent=self.parent,
                                      content=c,
                                      start=self.parent.relptr)
    def update(self, **kargs):
        if 'data' in kargs:
            self.data = StrPatchwork()
            self.data[0] = kargs['data']
    def __getitem__(self, item):
        return self.data.__getitem__(item)
    def __setitem__(self, item, value):
        return self.data.__setitem__(item, value)
    def find(self, pattern, *args):
        return self.data.find(pattern, *args)
    def rfind(self, pattern, *args):
        return self.data.rfind(pattern, *args)

class COFFRelocation(CStruct):
    _fields = [ ("VirtualAddress","u32"),
                ("SymbolTableAddress","u32"),
                ("Type","u16") ]
    symbol = property(lambda _:
        _.parent.parent.parent.parent.Symbols.getbyindex(_.SymbolTableAddress))
    name = property(lambda _:_.symbol.name)
    def __repr__(self):
        return '<COFFRelocation Vaddr=%#010x Name=%r Type=%#x>' % (
            self.VirtualAddress, self.name, self.Type)

class COFFRelocations(CArray):
    _cls = COFFRelocation
    count = lambda _:_.parent.nreloc

class Shdr(CStruct):
    # 40-bytes long for 32-bit COFF ; 64-bytes long for 64-bit COFF
    # We use the field names mainly from http://wiki.osdev.org/COFF
    # They are not the same names as for PE files, but the usual names
    # for PE files don't always describe what is in the file!
    # The main problems are the fields that contain size information:
    # - The fourth field (rsize) always contains the size of the section
    #   in the PE/COFF file.
    # - The second field (paddr) usually contains the same value as
    #   vaddr in COFF files (e.g. this is always the case as per OSF1
    #   documentation, which also says that paddr is ignored) but some
    #   COFF files differ, e.g. Window .OBJ files where vaddr is always 0,
    #   but paddr not always, depending on the compiler.
    #   For PE files, the official documentation says that for executable
    #   images paddr is the virtual size, i.e. the size of the section in
    #   memory, and that if paddr is greater than rsize it is padded with
    #   zeroes, and that for object files paddr is zero
    #   ... but this is not true for all PE files.
    # Recent OS (e.g. Windows 7) checks that the virtual mapping of sections 
    # in memory is contiguous, by computing the section size using the
    # max of 'rsize' and 'paddr' rounded to the section alignment.
    _fields = [ ("name_data","8s"),
                ("paddr","ptr"),   # was named 'size'
                ("vaddr","ptr"),   # was named 'addr'
                ("rsize","ptr"),   # was named 'rawsize'
                ("scnptr","ptr"),  # was named 'offset'
                ("relptr","ptr"),  # was named 'pointertorelocations'
                ("lnnoptr","ptr"), # was named 'pointertolinenumbers'
                ("nreloc","u16"),  # was named 'numberofrelocations'
                ("nlnno","u16"),   # was named 'numberoflinenumbers'
                ("flags","u32"),
                ("section_data",SectionData) ]
    def name(self):
        # Offset in the string table, if more than 8 bytes long
        n = self.name_data
        if n[:4] == data_null*4 and n != data_null*8:
            n, = struct.unpack("I", n[4:])
            n = self.parent.parent.SymbolStrings.getby_offset(n)
        else:
            n = n.rstrip(data_null)
        return bytes_to_name(n)
    name = property(name)
    def scn_baseoff(self):
        if not self.parent.parent.isPE():
            return self.scnptr
        # The conversion from RVA to file offset is dependent on
        # the file alignment. Instead of 'scnptr', PE.rva2off
        # will use this 'scn_baseoff' value.
        filealignment = self.parent.parent.NThdr.filealignment
        if not filealignment:
            return self.scnptr
        # The following hack is what is needed to parse Ange
        # Albertini's weirdsord.exe, which defines FILEALIGN
        # to 0x4000 and then DELTA with an offset of 0x200, while
        # the section starts at 0x201. It suggests that Windows
        # always use an alignment of 0x200 independently of what
        # is in the NT header...
        filealignment = 0x200
        return (self.scnptr//filealignment)*filealignment
    scn_baseoff = property(scn_baseoff)
    def is_in_file(self):
        if self.rsize == 0:
            # Empty section, not in the file!
            return False
        if self.flags & (STYP_BSS|STYP_SBSS|STYP_DSECT):
            # bss/dummy section, not in the file!
            return False
        return True
    # For API compatibility with previous versions of elfesteem,
    # especially miasm2/jitter/loader/pe.py
    def set_rawsize(self, v):
        self.rsize = v
    rawsize = property(lambda _: _.rsize, set_rawsize)
    def set_offset(self, v):
        self.scnptr = v
    offset  = property(lambda _: _.scnptr, set_offset)
    addr    = property(lambda _: _.vaddr)
    def size(self):
        # Return the virtual size (for PE) or the RAW size (for COFF)
        if self.parent.parent.isPE(): return self.paddr
        else:                         return self.rawsize
    def set_size(self, value):
        if self.parent.parent.isPE(): self.paddr = value
        else:                         self.rawsize = value
    size    = property(size, set_size)
    def set_data(self, value):
        self.section_data.data = value
    data    = property(lambda _: _.section_data.data, set_data)
    def __str__(self):
        return "%18s %#10x %#10x %#10x %#10x %#10x" %(
               self.name.strip('\0'),
               self.scnptr, self.rsize,
               self.paddr, self.vaddr,
               self.flags)

class ShdrTI(Shdr):
    # 48 bytes long, when the standard COFF is 40 bytes long
    # Documented in http://www.ti.com/lit/an/spraao8/spraao8.pdf
    _fields = [ ("name_data","8s"),
                ("paddr","u32"),
                ("vaddr","u32"),
                ("rsize","u32"),
                ("scnptr","u32"),
                ("relptr","u32"),
                ("lnnoptr","u32"),
                ("nreloc","u32"),
                ("nlnno","u32"),
                ("flags","u32"),
                ("reserved","u16"),
                ("mem_page","u16"),
                ("data",SectionData) ]
    def rawsize(self):
        # NB: rawsize is the size in bytes
        # Based on the documentation by TI, for some CPU the "size" is
        # in word, therefore we need to multiply by 2
        # But in our sample file, this is not the case for .debug_* sections
        # (probably because of a compiler bug)
        # This sample file is https://github.com/slavaprokopiy/Mini-TMS320C28346/blob/master/For_user/C28346_Load_Program_to_Flash/Debug/C28346_Load_Program_to_Flash.out
        if self.parent.parent.CPU in ('TMS320C2800', 'TMS320C5400') \
                and not self.name.startswith('.debug_'):
            return self.rsize*2
        return self.rsize
    rawsize = property(rawsize)

class SHList(CArray):
    def _cls(self):
        if self.parent.COFFhdr.machine == IMAGE_FILE_MACHINE_TI:
            return ShdrTI
        return Shdr
    _cls = property(_cls)
    count = lambda self: self.parent.COFFhdr.numberofsections
    def shlist(self):
        return self._array
    shlist = property(shlist)
    def display(self):
        rep = ["#  section         offset   size   addr     flags   rawsize  "]
        for i, s in enumerate(self):
            l = "%-15s"%s.name.strip('\x00')
            l+="%(offset)08x %(size)06x %(vaddr)08x %(flags)08x %(rawsize)08x" % s
            l = ("%2i " % i)+ l
            rep.append(l)
        return "\n".join(rep)
    def __repr__(self):
        # Not respecting python's recommendation of what __repr__ should return
        return self.display()
    
    def add_section(self, name="default", data = data_empty, **args):
        if len(self):
            # Check that there is enough free space in the headers
            # to add a new section
            min_size = (self.parent.DOShdr.lfanew +
                        self.parent.NTsig.bytelen +
                        self.parent.COFFhdr.bytelen +
                        self.parent.COFFhdr.sizeofoptionalheader +
                        (1+len(self))*Shdr(parent=self).bytelen)
            first_section_offset = min_size
            for s in self.parent.SHList:
                if s.is_in_file() and first_section_offset > s.scnptr:
                    first_section_offset = s.scnptr
            # Should be equal to self.parent.NThdr.sizeofheaders
            if first_section_offset < min_size:
                log.error("Cannot add section %s: not enough space for section list", name)
                # Could be solved by changing the section offsets, but some
                # sections may contain data that depends on the offset.
                # Could be solved by changing lfanew, but it will be an unusual
                # PE file that may break some PE readers.
                return None
            # Cf. https://code.google.com/archive/p/corkami/wikis/PE.wiki
            # Section vaddr have to be in increasing order
            # This web page also says that "sections don't have to be
            # virtually contiguous", but it is not always true; for
            # example Windows 7 reject PE files with non-contiguous
            # sections, but Wine accepts them
            vaddr = self[-1].vaddr+self[-1].rawsize
            s_last = self[0]
            for s in self:
                if s_last.scnptr+s_last.rawsize<s.scnptr+s.rawsize:
                    s_last = s
            scnptr = s_last.scnptr+s_last.rawsize
        else:
            # First section
            vaddr = 0x1000
            scnptr = self.parent.DOShdr.lfanew
            scnptr += self.parent.NTsig.bytelen
            scnptr += self.parent.COFFhdr.bytelen
            scnptr += self.parent.COFFhdr.sizeofoptionalheader
            # space for 10 sections
            scnptr += Shdr(parent=self).bytelen * 10
            if scnptr > self.parent.NThdr.sizeofheaders:
               log.error('xxx')
            scnptr = max(scnptr, self.parent.NThdr.sizeofheaders)
        # alignment
        s_align = self.parent.NThdr.sectionalignment
        s_align = max(0x1000, s_align)
        f_align = self.parent.NThdr.filealignment
        vaddr = (vaddr+(s_align-1))&~(s_align-1)
        scnptr = (scnptr+(f_align-1))&~(f_align-1)
    
        # 'name' is a string, 'name_data' is a sequence of bytes
        name_data = name.encode('latin1') + (8-len(name))*data_null
        rsize = (len(data)+(f_align-1))&~(f_align-1)
        f = {"name_data":name_data,
             "paddr":len(data), # was named 'size'
             "vaddr":vaddr,     # was named 'addr'
             "rsize":rsize,     # was named 'rawsize'
             "scnptr":scnptr,   # was named 'offset'
             "relptr":0,  # was named 'pointertorelocations'
             "lnnoptr":0, # was named 'pointertolinenumbers'
             "nreloc":0,  # was named 'numberofrelocations'
             "nlnno":0,   # was named 'numberoflinenumbers'
             "flags":0xE0000020,
             "data":None
             }
        f.update(args)
        s = Shdr(parent=self, **f)
    
        if s.rawsize > len(data):
            # In PE file, paddr usually contains the size of the non-padded data
            s.paddr = len(data)
            data = data+data_null*(s.rawsize-len(data))
        if 'rawsize' in args:
            # When created with the old elfesteem API
            s.rsize = args['rawsize']
            s.paddr = args['rawsize']
            data = data+data_null*(s.rawsize-len(data))
        if 'size' in args:
            # When created with the old elfesteem API
            s.paddr = args['size']
        s.paddr = max(s.paddr, s_align)
        s.section_data = SectionData(parent=s, data=data)
    
        self.append(s)
        self.parent.COFFhdr.numberofsections = len(self)
    
        l = (s.vaddr+s.rawsize+(s_align-1))&~(s_align-1)
        self.parent.NThdr.sizeofimage = l
        return s
    
    def align_sections(self, f_align=None, s_align=None):
        if f_align == None:
            f_align = self.parent.NThdr.filealignment
            f_align = max(0x200, f_align)
        if s_align == None:
            s_align = self.parent.NThdr.sectionalignment
            s_align = max(0x1000, s_align)
        addr = self[0].offset
        for s in self:
            if not s.is_in_file():
                continue
            raw_off = f_align * ((addr + f_align - 1) // f_align)
            s.offset = raw_off
            s.rawsize = len(s.data)
            addr = raw_off + s.rawsize


####################################################################
# Directories

# Parsing a Directory is not complicated, it is a tree-like structure
# where RVA are pointers to be converted in offsets in the file.
# Modifying a Directory is more complicated.
# - It is not always entirely in one section; e.g. for some PE files
#   everything from the DelayImport directory is in .rdata, with the
#   exception of the current thunks, in .data
#   Therefore if we want to add an imported function, we may need to
#   modify two sections.
# - References withing a directory are RVA, which change when the
#   addresses and sizes of sections changes. Therefore if we change
#   something, we need to recompute all RVA, and therefore to know
#   where everything will be located.
# - References to directories from e.g. the executable section are
#   also RVA, they would need to be modified if the load address of
#   the directory changes.
# Therefore, if we change a Directory, we currently only allow to
# rebuild the file if a dedicated section is created to store the
# modifications.

# Depending on how the PE file has been generated, the place
# where the directories are found varies a lot. Option '-Sl'
# of readpe.py can show in whihc section are the directories and
# the layout of the file. Here are a few examples:
#
# MinGW
#   DirEnt IMPORT       in .idata (as recommended by the reference doc of PE)
#   DirEnt EXPORT       in .edata (as recommended by the reference doc of PE)
#
# Some old Microsoft files
#   DirEnt BOUND_IMPORT in headers (after PE header)
#   DirEnt IMPORT       in .text
#   DirEnt DELAY_IMPORT in .text
#   DirEnt EXPORT       in .text
#   DirEnt LOAD_CONFIG  in .text
#   DirEnt IAT          in .text (contains IMPORT current Thunks)
#   DirEnt DEBUG        in .text
#   DirEnt RESOURCE     in .rsrc
#   DirEnt BASERELOC    in .reloc
#   DirEnt SECURITY     in no section
#   Thunks DELAY_IMPORT original in .text, current in .data
#
# Some more recent Microsoft files
#   DirEnt BOUND_IMPORT in headers (after PE header)
#   DirEnt DEBUG        in .text
#   DirEnt IAT          in .rdata (contains IMPORT current Thunks)
#   DirEnt IMPORT       in .rdata
#   DirEnt DELAY_IMPORT in .rdata
#   DirEnt EXPORT       in .rdata
#   DirEnt LOAD_CONFIG  in .rdata
#   DirEnt EXCEPTION    in .pdata
#   DirEnt RESOURCE     in .rsrc
#   DirEnt BASERELOC    in .reloc
#   DirEnt SECURITY     in no section
#
# Some other executables
#   DirEnt DEBUG        in .text
#   DirEnt IAT          in .idata (contains IMPORT current Thunks)
#   DirEnt IMPORT       in .idata
#   DirEnt DELAY_IMPORT in .text
#   DirEnt EXPORT       in .text
#   DirEnt LOAD_CONFIG  in .text
#   DirEnt EXCEPTION    in .pdata
#   DirEnt RESOURCE     in .rsrc
#   DirEnt BASERELOC    in .reloc
#   DirEnt SECURITY     in no section
#   DirEnt TLS          in .rdata

from elfesteem.visual_studio_mangling import symbol_demangle

class CArrayDirectory(CArray):
    def unpack(self, c, o):
        if o is None:
            # Use the entry in the NT headers
            # .rva contains the RVA of the descriptor array
            # .size may contain the size of the descriptor array or of
            #   the whole directory entry, including thunks and names;
            #   it depends on the PE file.
            if self._idx >= len(self.parent.NThdr.optentries): return # No entry
            o = self.parent.NThdr.optentries[self._idx]
            if o.rva == 0: return # No directory
            o = self.parent.rva2off(o.rva)
            if o is None: return # Directory in no section
        CArray.unpack(self, c, o)

class ImportName(CStruct):
    _fields = [ ("hint", "u16"),
                ("name", CString) ]

class ImportNamePtr(CStruct):
    _fields = [ ("rva","ptr") ]
    def unpack(self, c, o):
        CStruct.unpack(self, c, o)
        # The function can be imported by name, or by ordinal
        mask = {32: 0x80000000, 64: 0x8000000000000000}[self.wsize]
        if self.rva is 0:
            self.name = None
        elif self.rva & mask:
            self.obj = self.rva & (mask-1)
            self.name = self.obj
        else:
            off = self.parent.parent.rva2off(self.rva)
            # When parsing 'firstthunk', either "off' is None
            # or it is identical to 'originalfirstthunk'.
            # But that's just what is usually the case, a valid PE
            # file may be different.
            if off is None:
                # Should never happen for originalfirstthunk
                self.obj = None
                self.name = None
            else:
                self.obj = ImportName(parent=self, content=c, start=off)
                self.name = str(self.obj.name)

class ImportThunks(CArray):
    _cls = ImportNamePtr

class ImportDescriptor(CStruct):
    _fields = [ ("originalfirstthunk","u32"), # Import Lookup Table
                ("timestamp","u32"),
                ("forwarderchain","u32"),
                ("name_rva","u32"),           # Imported DLL name
                ("firstthunk","u32"),         # Import Address Table
                                              # overwritten by the PE loader
              ]
    def rva2off(self, rva):
        return self.parent.parent.rva2off(rva)
    def unpack(self, c, o):
        CStruct.unpack(self, c, o)
        if self.parent.stop(self):
            # Don't continue to parse the terminator
            return
        # Follow the RVAs
        of = self.rva2off(self.name_rva)
        if of is None:
            name = '<invalid_dll_name>\0'.encode('latin1')
            self.name = CString(parent=self, content=name)
            # e.g. Ange Albertini's imports_relocW7.exe where relocation
            # is modifying the import table.
            # TODO: apply relocations before the decoding.
        else:
            self.name = CString(parent=self, content=c, start=of)
        # NB: it is possible for a PE to have many Import descriptors
        # pointing to the same IAT and ILT. elfesteem will take a
        # long time because the IAT and ILT will be parsed each time.
        # An example of such malformed file is
        # https://github.com/radare/radare2-regressions/blob/master/bins/fuzzed/file-rs-bf838568
        of = self.rva2off(self.firstthunk)
        if of is None:
            log.error('IAT')
        else:
            self.IAT = ImportThunks(parent=self, content=c, start=of)
        # NB: http://win32assembly.programminghorizon.com/pe-tut6.html
        # says "Some linkers generate PE files with 0 in
        # OriginalFirstThunk. This is considered a bug."
        # An example is the IDA installer!
        of = self.rva2off(self.originalfirstthunk)
        if not of in (0, None):
            self.ILT = ImportThunks(parent=self, content=c, start=of)

class DirImport(CArrayDirectory):
    _cls = ImportDescriptor
    _idx = DIRECTORY_ENTRY_IMPORT
    def display(self):
        res = '<%s>' % self.__class__.__name__
        def repr_obj(obj):
            if hasattr(obj, 'name'):
                name, _ = symbol_demangle(str(obj.name))
                return '%04X %r' % (obj.hint, name)
            else: return repr(obj)
        for idx, d in enumerate(self):
            res += '\n%2d %r' % (idx, str(d.name))
            for jdx, t in enumerate(d.IAT):
                t_virt = self.parent.rva2virt(d.firstthunk+jdx*t.bytelen)
                t_obj = repr_obj(t.obj)
                # Only display original thunks that are incoherent with current
                if hasattr(d, 'ILT') and jdx < len(d.ILT):
                    u = d.ILT[jdx]
                    if u.rva != t.rva:
                        t_obj += ' ' + repr_obj(u.obj)
                res += '\n        %2d %#10x %s' % (jdx, t_virt, t_obj)
        return res
    def pack(self):
        raise AttributeError("Cannot pack '%s': the Directory Entry data is not always contiguous"%self.__class__.__name__)
    def stop(self, elt):
        # Ange Albertini's imports_badterm.exe and imports_tinyXP.exe shows
        # that the ImportDescriptor does not need to be all zeroes to be a
        # terminator.
        return elt.name_rva == 0 or elt.firstthunk == 0
        # According to Ange Albertini's manyimportsW7.exe the AddressOfIndex
        # field of the TLS directory is a terminator too; but at this point
        # the TLS directory has not been parsed by elfesteem. This will be
        # handled if we handle relocations, and parse the file in multiple
        # passes.
    def _initialize(self):
        CArrayDirectory._initialize(self)
        # Imports are added in three steps: dll_to_add is computed, a
        # new section is created, this section is constructed.
        self.dll_to_add = []
    def add_dlldesc(self, new_dll):
        # Expand self.dll_to_add with new DLL and functions
        # new_dll is a list, where each member is a pair
        # - dll_name: dict with 'name' giving the DLL name
        #             The 'firstthunk' value is currently ignored:
        #             elfesteem used this value to indicate another
        #             section where the IAT would be located, and
        #             did not create an ILT.
        #             TODO: memorize this value to be used in
        #             'write_directory'
        # - dll_func: list of function names
        for dll_name, dll_func in new_dll:
            # First, an empty descriptor
            d = ImportDescriptor(parent=self)
            self.dll_to_add.append(d)
            # Add the DLL name
            d.name = CString(parent=d, s=dll_name['name'].encode('latin1'))
            # Add the Import names; they will be located after the two thunks
            thunk_len = (1+len(dll_func))*(self.wsize/8)
            thunk_len *= 2
            # Add the IAT & ILT
            d.ILT = ImportThunks(parent=d)
            for n in dll_func:
                t = ImportNamePtr(parent=d.ILT)
                t.obj = ImportName(parent=t, s=n.encode('latin1'))
                t.name = n
                thunk_len += t.obj.bytelen
                if thunk_len%2: thunk_len += 1
                d.ILT.append(t)
            d.IAT = ImportThunks(parent=d)
            for n in dll_func:
                t = ImportNamePtr(parent=d.ILT)
                t.name = n
                d.IAT.append(t)
    def write_directory(self, base_rva):
        # Creates in the section starting at 'base_rva' a new Import Directory
        # with the content of self.dll_to_add
        
        # Note that we need to avoid changing RVA of the current IAT, because
        # they can be used e.g. in the executable section .text
        # But there might not be enough space after the current list of
        # descriptors to add new descriptors...
        # The trick we use is to move the list of descriptors in a new
        # section (s_dir), where we will also store the new ILT, IAT and
        # names, leaving the original section unchanged.
        # 
        # TODO: The IAT can be stored in another section than the rest of
        # the directory (descriptors, names, ILT) ; provide this possibility.
        # TODO: The ILT is not necessary. Provide the possibility of not
        # creating it.
        # TODO: If base_rva is not the vaddr of an existing section, but
        # is inside na existing section, do we overwrite everything after
        # base_rva?

        e = self.parent
        for s_dir in e.SHList.shlist:
            # This section may have been created by
            #   e.SHList.add_section(name="myimp", rawsize=len(e.DirImport))
            # which is the original syntax with elfesteem but does not
            # use the appropriate value for rsize, because len(e.DirImport)
            # now is the number of DLLs and not the bytelen of the directory.
            # This does not matter, because we recompute s_dir.rsize at
            # the end of this function.
            if s_dir.vaddr == base_rva:
                break
        else:
            # Create the new section s_dir, with appropriate flags; write
            # is needed if we store the IAT.
            s_dir = e.SHList.add_section(
                name='.idata2',
                flags=IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_READ|IMAGE_SCN_CNT_INITIALIZED_DATA,
                rsize=0x1000,     # should be enough
                )
            base_rva = s_dir.vaddr
        s_dir.section_data.data = StrPatchwork()
        self._size += self._cls(parent=self).bytelen * len(self.dll_to_add)
        of = self.bytelen
        for d in self.dll_to_add:
            self._array.append(d)
            d.name_rva = base_rva+of
            s_dir.section_data.data[of] = d.name.pack()
            of += d.name.bytelen
            if of%2: of += 1
            thunk_len = (1+len(d.ILT))*(self.wsize//8)
            thunk_len *= 2
            for t in d.ILT:
                t.rva = base_rva+of+thunk_len
                s_dir.section_data.data[of+thunk_len] = t.obj.pack()
                thunk_len += t.obj.bytelen
                if thunk_len%2: thunk_len += 1
            d.originalfirstthunk = base_rva+of
            s_dir.section_data.data[of] = d.ILT.pack()
            of += d.ILT.bytelen
            d.firstthunk = base_rva+of
            for idx, t in enumerate(d.IAT):
                t.obj = d.ILT[idx].obj
                t.rva = d.ILT[idx].rva
            s_dir.section_data.data[of] = d.IAT.pack()
            of += thunk_len - d.ILT.bytelen
        self.dll_to_add = []
        # Write the descriptor list (now that all RVA have been computed)
        s_dir.section_data.data[0] = CArray.pack(self)
        # Update the section sizes
        s_dir.paddr = len(s_dir.section_data.data)
        if s_dir.rsize < s_dir.paddr:
            s_dir.rsize = s_dir.paddr
        s_dir.section_data.data[s_dir.paddr] = data_null*(s_dir.rsize-s_dir.paddr)
        e.NThdr.optentries[self._idx].rva = base_rva
        e.NThdr.optentries[self._idx].size = s_dir.paddr # Unused by PE loaders
    def get_funcrva(self, dllname, funcname):
        # Position of the function in the Import Address Table
        for d in self:
            if dllname is not None and str(d.name) != dllname:
                continue
            for idx, t in enumerate(d.IAT):
                if t.name == funcname:
                    return d.firstthunk+idx*t.bytelen
        return None
    def get_funcvirt(self, dllname, funcname):
        return self.parent.rva2virt(self.get_funcrva(dllname, funcname))
    # For API compatibility with previous versions of elfesteem
    def get_dlldesc(self):
        return [ ({'name': d.name}, [t.name for t in d.IAT]) for d in self ]
    def set_rva(self, addr):
        self.write_directory(addr)
    def impdesc(self):
        class ImpDesc_e(object):
            def __init__(self, d):
                self.firstthunk = d.firstthunk
                self.dlldescname = APICompatibilityName(str(d.name))
                self.impbynames = [APICompatibilityName(str(_.name)) for _ in d.IAT]
        return [ImpDesc_e(_) for _ in self]
    def set_impdesc(self, value):
        if value in (None, []):
            CArrayDirectory._initialize(self)
            return
        TODO
    impdesc = property(impdesc, set_impdesc)
class APICompatibilityName(object):
    def __init__(self, s):
        self.name = s
ImportByName = APICompatibilityName


# Delay Import Directory is similar to Import Directory
# The implementation below is incomplete, but useable because
# boundiat and unloadiat are optional and usually absent.
class DelayDescriptor(ImportDescriptor):
    _fields = [ ("attrs","u32"),
                ("name_rva","u32"),
                ("hmod","u32"),               # Module Handle
                ("firstthunk","u32"),         # Delay Import Address Table
                ("originalfirstthunk","u32"), # Delay Import Name Table
                ("boundiat","u32"),           # Bound Delay Import Table
                ("unloadiat","u32"),          # Unload Delay Import Table
                ("timestamp","u32"),
              ]
    def rva2off(self, rva):
        # Microsoft's pecoff.docx says that no attributes are defined
        # and that it is set to 0, but all our example files have 0x1.
        # Serpi implemented in elfesteem that if the 0x1 bit is not set
        # then the RVA has been incremented with ImageBase. We don't have
        # any supporting documentation.
        if not (self.attrs & 1):
            rva = self.parent.parent.virt2rva(rva)
        return self.parent.parent.rva2off(rva)

class DirDelay(DirImport):
    _cls = DelayDescriptor
    _idx = DIRECTORY_ENTRY_DELAY_IMPORT




class ExportAddressRVA(CStruct):
    _fields = [ ("rva","u32") ]
    def unpack(self, c, o):
        CStruct.unpack(self, c, o)
        # Follow the RVA if it is a "Forwarder RVA"
        # which is the case if the RVA points into the export section.
        # NB: IDA's export tab does not know about this, and just shows the RVA
        direxport = self.parent.parent.parent
        base = direxport.parent.NThdr.optentries[direxport._idx]
        if base.rva <= self.rva < base.rva+base.size:
            self.name = CString(parent=self, content=c,
                start=self.parent.parent.rva2off(self.rva))

class ExportAddressTable(CArray):
    _cls = ExportAddressRVA
    count = lambda _: _.parent.numberoffunctions

class ExportNamePointerRVA(CStruct):
    _fields = [ ("rva","u32") ]
    def unpack(self, c, o):
        CStruct.unpack(self, c, o)
        # Follow the RVA
        self.name = CString(parent=self, content=c,
            start=self.parent.parent.rva2off(self.rva))
        # For API compatibility with previous versions of elfesteem
        self.name.name = str(self.name)

class ExportNamePointersTable(CArray):
    _cls = ExportNamePointerRVA
    count = lambda _: _.parent.numberofnames

class ExportOrdinal(CStruct):
    _fields = [ ("ordinal","u16") ]

class ExportOrdinalTable(CArray):
    _cls = ExportOrdinal
    count = lambda _: _.parent.numberofnames

class ExportDescriptor(CStruct):
    _fields = [ ("characteristics","u32"), # Unused and always 0
                ("timestamp","u32"),
                ("majorv","u16"), # Unused and always 0
                ("minorv","u16"), # Unused and always 0
                ("name_rva","u32"),
                ("base","u32"),
                ("numberoffunctions","u32"),
                ("numberofnames","u32"),
                ("addressoffunctions","u32"),
                ("addressofnames","u32"),
                ("addressofordinals","u32"),
              ]
    def rva2off(self, rva):
        return self.parent.parent.rva2off(rva)
    def unpack(self, c, o):
        CStruct.unpack(self, c, o)
        # Follow the RVAs
        self.name = CString(parent=self, content=c,
            start=self.rva2off(self.name_rva))
        self.EAT = ExportAddressTable(parent=self, content=c,
            start=self.rva2off(self.addressoffunctions))
        self.ENPT = ExportNamePointersTable(parent=self, content=c,
            start=self.rva2off(self.addressofnames))
        self.EOT = ExportOrdinalTable(parent=self, content=c,
            start=self.rva2off(self.addressofordinals))
        self.compute_exports()
    def compute_exports(self):
        # 'exports' contains the same information as displayed by IDA's export
        # tab; it has issues, especially when the number of functions is not
        # the number of names
        self.exports = {}
        for i in range(len(self.ENPT)):
            # len(self.ENPT) is self.numberofnames, unless it is invalid.
            # If self.numberofnames is invalid we prefer the smaller value!
            j = self.EOT[i].ordinal
            if j >= self.numberoffunctions:
                print("Invalid ordinal[%d]: %d"%(i,j))
                continue
            if self.base+j in self.exports:
                print("Duplicate ordinal at %d"%(self.base+j))
                continue
            addr = self.EAT[j]
            name = self.ENPT[i].name
            self.exports[self.base+j] = (addr, name)
        # When ..numberoffunctions != ..numberofnames
        for i in range(len(self.EAT)):
            # len(self.EAT) is self.numberoffunctions, unless it is invalid.
            if not self.base+i in self.exports:
                addr = self.EAT[i]
                self.exports[self.base+i] = (addr, CString(parent=self))

class DirExport(CArrayDirectory):
    _cls = ExportDescriptor
    _idx = DIRECTORY_ENTRY_EXPORT
    count = lambda _: 1
    def display(self):
        res = '<%s>' % self.__class__.__name__
        if len(self) == 0: return
        d = self[0]
        res += '\n  %r' % str(d.name)
        for i in sorted(d.exports.keys()):
            addr, name = d.exports[i]
            if hasattr(addr, 'name'):
                addr = str(addr.name)
            else:
                addr = addr.rva
                if self.parent.COFFhdr.machine == IMAGE_FILE_MACHINE_ARMNT:
                    # To have the same display as IDA on PE for ARM
                    addr -= 1
                addr = '%08X' % self.parent.rva2virt(addr)
            name, _ = symbol_demangle(str(name))
            res += '\n    %2d %s %r' % (i, addr, name)
        return res
    def create(self, funcs, name = 'default.dll'):
        # Don't separate 'create()' and 'add_name()' because adding new
        # exports to an existing export table is very tricky: we need to
        # resize the EAT, ENPT and EOT.
        if len(self) != 0: return
        e = self.parent
        s = e.SHList.add_section(
            name='.edata2',
            flags=IMAGE_SCN_MEM_READ|IMAGE_SCN_CNT_INITIALIZED_DATA,
            rsize=0x1000,     # should be enough
            )
        base_rva = e.off2rva(s.scnptr)
        e.NThdr.optentries[self._idx].rva = base_rva
        s.section_data.data = StrPatchwork()
        # First, an empty descriptor
        d = ExportDescriptor(parent=self, base=1)
        self.append(d)
        of = self.bytelen
        # Add the DLL name
        d.name = CString(parent=d, s=name.encode('latin1'))
        d.name_rva = base_rva+of
        s.section_data.data[of] = d.name.pack()
        of += d.name.bytelen
        # Add the EAT, ENPT & EOT
        d.numberoffunctions += len(funcs)
        d.numberofnames     += len(funcs)
        d.EAT = ExportAddressTable(parent=d)
        for f in funcs:
            if isinstance(f, tuple):
                rva = f[1]
            else:
                # TODO: we should look for the RVA of a symbol of name 'f'
                rva = 0xdeadc0fe
            t = ExportAddressRVA(parent=d.EAT, rva=rva)
            d.EAT.append(t)
        d.addressoffunctions = base_rva+of
        s.section_data.data[of] = d.EAT.pack()
        of += d.EAT.bytelen
        d.EOT = ExportOrdinalTable(parent=d)
        for idx in range(len(funcs)):
            t = ExportOrdinal(parent=d.EOT, ordinal=idx)
            d.EOT.append(t)
        d.addressofordinals = base_rva+of
        s.section_data.data[of] = d.EOT.pack()
        of += d.EOT.bytelen
        pos = len(funcs)*4 # size of ENPT
        d.ENPT = ExportNamePointersTable(parent=d)
        for f in funcs:
            if isinstance(f, tuple): f = f[0] # The name of the function
            t = ExportNamePointerRVA(parent=d.ENPT)
            t.name = CString(parent=t, s=f.encode('latin1'))
            t.name.name = f # For API compatibility with previous versions
            t.rva = base_rva+of+pos
            s.section_data.data[of+pos] = t.name.pack()
            pos += t.name.bytelen
            d.ENPT.append(t)
        d.addressofnames = base_rva+of
        s.section_data.data[of] = d.ENPT.pack()
        # Write the descriptor list (now that everyting has been computed)
        s.section_data.data[0] = CArray.pack(self)
        # Update the section sizes
        s.paddr = len(s.section_data.data)
        e.NThdr.optentries[self._idx].size = s.paddr # Unused by PE loaders
        if s.rsize < s.paddr:
            s.rsize = s.paddr
        s.section_data.data[s.paddr] = data_null*(s.rsize-s.paddr)
        # Finalize
        d.compute_exports()
    def get_funcrva(self, name):
        for d in self:
            for t in d.ENPT:
                if str(t.name) == name: return t.rva
        return None
    def get_funcvirt(self, name):
        return self.parent.rva2virt(self.get_funcrva(name))
    # For API compatibility with previous versions of elfesteem
    def expdesc(self):
        if len(self): return self[0]
        else:         return None
    expdesc        = property(expdesc)
    f_address      = property(lambda _:getattr(_.expdesc,'EAT',[]))
    f_nameordinals = property(lambda _:getattr(_.expdesc,'EOT',[]))
    f_names        = property(lambda _:getattr(_.expdesc,'ENPT',[]))
    def add_name(self, name, rva = 0xdeadc0fe):
        DEPRECATED




class Relocation(CStruct):
    _fields = [ ("word","u16") ]
    type   = property(lambda _:_.word>>12)
    offset = property(lambda _:_.word&0xfff)
    rel    = property(lambda _:(_.type,_.offset))
    def __repr__(self):
        return "<%s=%s/%s>" % (self.__class__.__name__,
            self.type, self.offset)

class RelocationTable(CArray):
    _cls = Relocation
    count = lambda _: (_.parent.size-8)//2

class RelocationBlock(CStruct):
    _fields = [ ("rva","u32"),
                ("size","u32"), # Should be at least 8
                ("rels", RelocationTable) ]
    # TODO: don't parse 'rels' if it goes beyond the end of the directory
    def __repr__(self):
        return '<%s RVA=%#x size=%d [table of length %d]>' % (
            self.__class__.__name__,
            self.rva, self.size, len(self.rels))

class DirReloc(CArrayDirectory):
    _cls = RelocationBlock
    _idx = DIRECTORY_ENTRY_BASERELOC
    def count(self):
        if self._idx >= len(self.parent.NThdr.optentries):
            return -1
        # We don't know how many relocation block will be parsed, we stop
        # when reaching the end of the directory
        if self.bytelen < self.parent.NThdr.optentries[self._idx].size:
            return len(self)+1
        return -1
    def display(self):
        res = '<%s>' % self.__class__.__name__
        for b in self:
             res += '\n   %r' % b
             # Don't display the relocation table... too long
        return res
    def add_reloc(self, rels, rtype = 3, patchrel = True):
        TODO
    def del_reloc(self, taboffset):
        TODO
    # For API compatibility with previous versions of elfesteem
    reldesc        = property(lambda _:_)



class UStringData(CBase):
    def _initialize(self):
        self._size = 2*self.parent.length
    def unpack(self, c, o):
        self.value = c[o:o+self.bytelen]

class UString(CStruct):
    _fields = [ ("length", "u16"),
                ("value",UStringData) ]
    def __str__(self):
        return self.value.value.decode('utf16')

class ResourceDataDescription(CStruct):
    _fields = [ ("rva", "u32"),
                ("size","u32"),
                ("codepage","u32"),
                ("zero","u32") ]
    def unpack(self, c, o):
        CStruct.unpack(self, c, o)
        # Follow the RVA
        of=self.parent.rva2off(self.rva)
        if of is None:
            log.error("Invalid ResourceDataDescription with RVA %#x", self.rva)
            raise ValueError
        else:
            self.data = c[of:of+self.size]
    def __repr__(self):
        return '<%s RVA=%#x size=%d codepage=%d zero=%d>' % (
            self.__class__.__name__,
            self.rva, self.size, self.codepage, self.zero)

class ResourceDirectoryEntry(CStruct):
    _fields = [ ("id","u32"),
                ("offset","u32") ]
    base = property(lambda _:_.parent.base)
    def rva2off(self, rva):
        return self.parent.parent.parent.rva2off(rva)
    def unpack(self, c, o):
        CStruct.unpack(self, c, o)
        # Two types of entries: Named & Id
        # The self.parent.parent.numberofnamedentries first ones are Named
        # and the MSB of their name is 1
        pos = len(self.parent._array)
        if (pos < self.parent.parent.numberofnamedentries) \
            and (self.id & 0x80000000 == 0):
            log.error("Named resource entries should be the first ones")
        if (pos >= self.parent.parent.numberofnamedentries) \
            and (self.id & 0x80000000 != 0):
            log.error("Id resource entries should be the last ones")
        if self.id & 0x80000000:
            self.name = UString(parent=self, content=c,
                start=self.base + (self.id & 0x7FFFFFFF))
        if self.depth >= 10:
            # In Windows PE, should never be more than 2.
            # An example of file with an infinite depth is Ange Albertini's
            # resourceloop.exe
            log.warning('Resource tree too deep')
        elif self.offset & 0x80000000:
            self.dir = ResourceDescriptor(parent=self, content=c,
                start=self.base + (self.offset & 0x7FFFFFFF))
        else:
            self.data = ResourceDataDescription(parent=self, content=c,
                start=self.base + (self.offset & 0x7FFFFFFF))
    def depth(self):
        p = self.parent.parent.parent
        if isinstance(p, DirRes): return 0
        else:                     return p.depth+1
    depth = property(depth)
    def show_tree(self):
        if self.depth >= 10:
            return [ (0, None) ]
        def choose(val, true, false):
            if val & 0x80000000: return true
            else:                return false
        s = (
            self.parent._array.index(self),
            choose(self.id, getattr(self, 'name', None), self.id),
            choose(self.offset, None, getattr(self, 'data', None)),
            )
        tree = [ (0, s) ]
        if self.offset & 0x80000000:
            tree += [ (d+1,s) for d, s in self.dir.show_tree() ]
        return tree

class ResourceDirectoryEntries(CArray):
    _cls = ResourceDirectoryEntry
    def count(self):
        return self.parent.numberofnamedentries + self.parent.numberofidentries
    base = property(lambda _:_.parent.base)

class ResourceDescriptor(CStruct):
    _fields = [ ("characteristics","u32"), # Unused and always 0
                ("timestamp","u32"),
                ("majorv","u16"), # Unused and always 0
                ("minorv","u16"), # Unused and always 0
                ("numberofnamedentries","u16"),
                ("numberofidentries","u16"),
                ("entries",ResourceDirectoryEntries) ]
    base = property(lambda _:_.parent.base)
    def show_tree(self):
        tree = []
        for e in self.entries:
            tree.extend(e.show_tree())
        return tree

class DirRes(CArrayDirectory):
    _cls = ResourceDescriptor
    _idx = DIRECTORY_ENTRY_RESOURCE
    count = lambda _: 1
    base = property(lambda _:
        _.parent.rva2off(_.parent.NThdr.optentries[_._idx].rva))
    def rva2off(self, rva):
        return self.parent.rva2off(rva)
    def is_depth_3_tree(self):
        if len(self) == 0: return False
        for d, (x, y, z) in self[0].show_tree():
            if d < 2 and z is not None: return False
            if d == 2 and z is None: return False
            if d > 2: return False
        return True
    def display(self):
        res = '<%s>' % self.__class__.__name__
        if len(self) == 0:
            return res
        if self.is_depth_3_tree():
            # Windows-specific display, tree with all branches of depth 3
            assert self[0].characteristics == 0
            # MajorV is 0 for NTDLL-MIPS.DLL NTDLL-ALPHA.DLL notepad.exe
            #                 regedit-2.exe
            #           4 for A3DUtils.dll AdobeXMP.dll regedit-1.exe
            # https://msdn.microsoft.com/en-us/library/ms809762.aspx
            # says it is always 0
            assert self[0].majorv in (0, 4)
            assert self[0].minorv == 0
            res += '\n     Index     Type     Name Lang'
            pos = [None, None, None]
            val = [None, None, None]
            for d, (x, y, z) in self[0].show_tree():
                pos[d] = x
                val[d] = y
                if d < 2:
                    assert z is None
                    continue
                assert d == 2
                res += '\n  %2d %2d %2d %8s %8s %4s %r' % tuple(pos+val+[z])
        else:
            # Generic display
            for d, s in self[0].show_tree():
                if s is None:
                    res += '\n' + (1+d)*'  ' + str(s)
                else:
                    res += '\n' + (1+d)*'  ' + '%d %s %r' % s
        return res





class AuxSymbolFunc(CStruct):
    _fields = [ ("tagIndex","u32"),
                ("totalSize","u32"),
                ("pointerToLineNum","u32"),
                ("pointerToNextFunc","u32"),
                ("padding","u16")]

class AuxSymbolSect(CStruct):
    _fields = [ ("length","u32"),
                ("numberOfRelocations","u16"),
                ("numberOfLinenumbers","u16"),
                ("checksum","u32"),
                ("number","u16"),
                ("selection","u08"),
                ("padding1","u08"),
                ("padding2","u08"),
                ("padding3","u08")]

class AuxSymbolFile(CStruct):
    _fields = [ ("name_data","18s") ]
    def name(self):
        # Offset in the string table, if more than 18 bytes long
        n = self.name_data
        if n[:4] == data_null*4 and n != data_null*18:
            n, = struct.unpack("I", n[4:8])
            n = self.parent.parent.parent.parent.SymbolStrings.getby_offset(n)
        else:
            n = n.rstrip(data_null)
        return bytes_to_name(n)
    name = property(name)
    def __repr__(self):
        return "<%s=%r>" % (self.__class__.__name__, self.name)

class AuxSymbolDummy(CStruct):
    _fields = [ ("data","18s") ]

class AuxSymbols(CArray):
    def _cls(self):
        if   self.parent.storageclass == IMAGE_SYM_CLASS_EXTERNAL:
            return AuxSymbolFunc
        elif self.parent.storageclass == IMAGE_SYM_CLASS_STATIC:
            return AuxSymbolSect
        elif self.parent.storageclass == IMAGE_SYM_CLASS_FILE:
            return AuxSymbolFile
        else:
            return AuxSymbolDummy
    _cls = property(_cls)
    count = lambda _: _.parent.numberofauxsymbols
    def __repr__(self):
        return str([_ for _ in self])

class CoffSymbol(CStruct):
    _fields = [ ("name_data","8s"),
                ("value","u32"),
                ("sectionnumber","u16"),
                ("type","u16"),
                ("storageclass","u08"),
                ("numberofauxsymbols","u08"),
                ("aux",AuxSymbols) ]
    def name(self):
        # Offset in the string table, if more than 8 bytes long
        n = self.name_data
        if n[:4] == data_null*4 and n != data_null*8:
            n, = struct.unpack("I", n[4:])
            n = self.parent.parent.SymbolStrings.getby_offset(n)
        else:
            n = n.rstrip(data_null)
        n = bytes_to_name(n)
        n, _ = symbol_demangle(n)
        return n
    name = property(name)
    def section(self):
        SHList = self.parent.parent.SHList
        if 0 < self.sectionnumber < 1+len(SHList):
            return SHList[self.sectionnumber-1].name
        else:
            return '%#x' % self.sectionnumber
    section = property(section)
    def type_str(self):
        base_type = self.type & 0xf
        cplx_type = self.type >> 4
        if base_type != 0:
            return constants['IMAGE_SYM_TYPE'][base_type]
        elif cplx_type in constants['IMAGE_SYM_DTYPE']:
            return constants['IMAGE_SYM_DTYPE'][cplx_type]
        else:
            return '%#x' % cplx_type
    type_str = property(type_str)
    def storage(self):
        if self.storageclass in constants['IMAGE_SYM_CLASS']:
            return constants['IMAGE_SYM_CLASS'][self.storageclass]
        else:
            return '%#x' % self.storageclass
    storage = property(storage)
    def __repr__(self):
        return "<CoffSymbol %r value=%#x section=%s type=%s storage=%s aux=%r>" % (self.name, self.value, self.section, self.type_str, self.storage, self.aux)
    def __str__(self):
        return '%-36r %-8s %-9s %#010x %s' % (self.name, self.type_str, self.storage, self.value, self.section)

class CoffSymbols(CArray):
    _cls = CoffSymbol
    def count(self):
        # Note that numberofsymbols also count AuxSymbols, while the
        # length of this array does not. We need to keep track of the
        # number of AuxSymbols up to now
        if not hasattr(self, 'numberofaux'): self.numberofaux = 0
        if len(self._array): self.numberofaux += len(self[-1].aux)
        return self.parent.COFFhdr.numberofsymbols - self.numberofaux
    def unpack(self, c, o):
        if o is None:
            o = self.parent.COFFhdr.pointertosymboltable
        CArray.unpack(self, c, o)
    def getbyindex(self, n):
        # An aux symbol counts, too
        for s in self._array:
            if n == 0: return s
            n -= 1 + len(s.aux)
        else:
            return None
    def display(self):
        res = '<%s>' % self.__class__.__name__
        for s in self.symbols:
            res += '\n    name=%r' % s.name
            res += '\n        type=%-8s storage=%-9s value=%#010x section=%s' % (s.type_str, s.storage, s.value, s.section)
        return res

    # For API compatibility with previous versions of elfesteem
    symbols = property(lambda _: _._array)

class CoffOSF1Symbols(CStruct):
    _fields = [ ("magic", "u16"),  # 0x1992
                ("vstamp", "u16"), # 0x030b for version 3.13
                ("ilineMax", "u32"),
                ("idnMax", "u32"),
                ("ipdMax", "u32"),
                ("isymMax", "u32"),
                ("ioptMax", "u32"),
                ("iauxMax", "u32"),
                ("issMax", "u32"),
                ("issExtMax", "u32"),
                ("ifdMax", "u32"),
                ("crfd", "u32"),
                ("iextMax", "u32"),
                ("cbLine", "u64"),
                ("cbLineOffset", "u64"),
                ("cbDnOffset", "u64"),
                ("cbPdOffset", "u64"),
                ("cbSymOffset", "u64"),
                ("cbOptOffset", "u64"),
                ("cbAuxOffset", "u64"),
                ("cbSsOffset", "u64"),
                ("cbSsExtOffset", "u64"),
                ("cbFdOffset", "u64"),
                ("cbRfdOffset", "u64"),
                ("cbExtOffset", "u64"),
                ]
    # TODO: parse the various Symbol Tables
    def __repr__(self):
        s = '<%s\n' % self.__class__.__name__
        s += '  magic=%#x' % self.magic
        s += '  version %d.%d\n' % (self.vstamp>>8, self.vstamp&0xff)
        s += '  line  %#010x %d lines %d bytes\n'  % (self.cbLineOffset, self.ilineMax, self.cbLine)
        s += '  dn    %#010x %d (obsolete)\n'% (self.cbDnOffset, self.idnMax)
        s += '  pd    %#010x %d entries\n'   % (self.cbPdOffset, self.ipdMax)
        s += '  sym   %#010x %d entries\n'   % (self.cbSymOffset, self.isymMax)
        s += '  opt   %#010x %d bytes\n'     % (self.cbOptOffset, self.ioptMax)
        s += '  aux   %#010x %d entries\n'   % (self.cbAuxOffset, self.iauxMax)
        s += '  ss    %#010x %d bytes\n'     % (self.cbSsOffset, self.issMax)
        s += '  ssExt %#010x %d bytes\n'     % (self.cbSsExtOffset, self.issExtMax)
        s += '  fd    %#010x %d entries\n'   % (self.cbFdOffset, self.ifdMax)
        s += '  rfd   %#010x %d entries\n'   % (self.cbRfdOffset, self.crfd)
        s += '  ext   %#010x %d entries\n'   % (self.cbExtOffset, self.iextMax)
        s += '>'
        return s
