#! /usr/bin/env python

from elfesteem.cstruct import CBase, CString, CStruct, CArray
from elfesteem.cstruct import data_null, data_empty
from elfesteem.cstruct import bytes_to_name, name_to_bytes
from elfesteem.new_cstruct import CStruct as NEW_CStruct
from elfesteem.strpatchwork import StrPatchwork
import struct
import logging
log = logging.getLogger("pepy")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)

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


RT = {
    RT_CURSOR       :"RT_CURSOR",
    RT_BITMAP       :"RT_BITMAP",
    RT_ICON         :"RT_ICON",
    RT_MENU         :"RT_MENU",
    RT_DIALOG       :"RT_DIALOG",
    RT_STRING       :"RT_STRING",
    RT_FONTDIR      :"RT_FONTDIR",
    RT_FONT         :"RT_FONT",
    RT_ACCELERATOR  :"RT_ACCELERATOR",
    RT_RCDATA       :"RT_RCDATA",
    RT_MESSAGETABLE :"RT_MESSAGETABLE",
    RT_GROUP_CURSOR :"RT_GROUP_CURSOR",
    RT_GROUP_ICON   :"RT_GROUP_ICON",
    RT_VERSION      :"RT_VERSION",
    RT_DLGINCLUDE   :"RT_DLGINCLUDE",
    RT_PLUGPLAY     :"RT_PLUGPLAY",
    RT_VXD          :"RT_VXD",
    RT_ANICURSOR    :"RT_ANICURSOR",
    RT_ANIICON      :"RT_ANIICON",
    RT_HTML         :"RT_HTML",
    RT_MANIFEST     :"RT_MANIFEST",
    }


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
for t in constants.keys():
    for v in [v for v in globals().keys() if v[:len(t)+1]==t+"_"]:
        constants[t][globals()[v]] = v[len(t)+1:]

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

# Specs of COFF for Tru64 aka. OSF1 found at
# http://h41361.www4.hpe.com/docs/base_doc/DOCUMENTATION/V50A_ACRO_SUP/OBJSPEC.PDF
class OpthdrOSF1(CStruct):
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
                ("fprmask","u64"),
                ("gp_value","u32"),
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
    def count(self):
        numberofrva = self.parent.numberofrvaandsizes
        pefile = self.parent.parent
        sizeofrva = pefile.COFFhdr.sizeofoptionalheader - pefile.Opthdr.bytelen
        size_e = 8
        if sizeofrva < numberofrva * size_e:
            numberofrva = sizeofrva // size_e
            log.warn('Bad number of rva %#x: using default 0x10', numberofrva)
            numberofrva = 0x10
        return numberofrva

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

####################################################################
# Sections

class SectionData(CBase):
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
            if self.parent.pack()[1::2] == data_null*(self.parent._size//2):
                # May happen if a file is wrongly parsed as COFF
                raise ValueError("Not COFF section")
            filealignment = 0
        if pefile.loadfrommem:
            raw_off = self.parent.vaddr
        elif filealignment == 0:
            raw_off = self.parent.scnptr
        else:
            raw_off = filealignment*(self.parent.scnptr//filealignment)
        if raw_off != self.parent.scnptr:
            log.warn('unaligned raw section!')
        self.data = StrPatchwork()
        rs = self.parent.rsize
        if rs != 0 and filealignment != 0:
            if rs % filealignment:
                rs = (rs//filealignment+1)*filealignment
            rs = max(rs, 0x200)
        if raw_off+rs > len(c):
            rs = len(c) - raw_off
        self.data[0] = c[raw_off:raw_off+rs]
    def update(self, **kargs):
        if 'data' in kargs:
            self.data = StrPatchwork()
            self.data[0] = kargs['data']
    def __getitem__(self, item):
        return self.data.__getitem__(item)
    def __setitem__(self, item, value):
        return self.data.__setitem__(item, value)

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
                ("data",SectionData) ]
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
    # For API compatibility with previous versions of elfesteem
    rawsize = property(lambda self: self.rsize)
    offset  = property(lambda self: self.scnptr)
    addr    = property(lambda self: self.vaddr)
    def size(self):
        # Return the virtual size (for PE) or the RAW size (for COFF)
        if self.parent.parent.isPE(): return self.paddr
        else:                         return self.rawsize
    size    = property(size)

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
    def __repr__(self):
        rep = ["#  section         scnptr   size   vaddr     flags   paddr  "]
        for i, s in enumerate(self):
            l = "%-15s"%s.name.strip('\x00')
            l+="%(scnptr)08x %(size)06x %(vaddr)08x %(flags)08x %(paddr)08x" % s
            l = ("%2i " % i)+ l
            rep.append(l)
        return "\n".join(rep)
    
    def add_section(self, name="default", data = data_empty, **args):
        if len(self):
            # Check that there is enough free space in the headers
            # to add a new section
            first_section_offset = 0
            for s in self.parent.SHList:
                if first_section_offset < s.scnptr:
                    first_section_offset = s.scnptr
            # Should be equal to self.parent.NThdr.sizeofheaders
            if first_section_offset < (
                    self.parent.DOShdr.lfanew +
                    self.parent.NTsig._size +
                    self.parent.COFFhdr._size +
                    self.parent.COFFhdr.sizeofoptionalheader +
                    (1+len(self))*Shdr(parent=self)._size):
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
            scnptr += self.parent.NTsig._size
            scnptr += self.parent.COFFhdr._size
            scnptr += self.parent.COFFhdr.sizeofoptionalheader
            # space for 10 sections
            scnptr += Shdr(parent=self)._size * 10
        # alignment
        s_align = self.parent.NThdr.sectionalignment
        s_align = max(0x1000, s_align)
        f_align = self.parent.NThdr.filealignment
        vaddr = (vaddr+(s_align-1))&~(s_align-1)
        scnptr = (scnptr+(f_align-1))&~(f_align-1)
    
        name += (8-len(name))*data_null
        rsize = (len(data)+(f_align-1))&~(f_align-1)
        f = {"name_data":name,
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
        s.data = SectionData(parent=s, data=data)
    
        self.append(s)
        self.parent.COFFhdr.numberofsections = len(self)
    
        l = (s.vaddr+s.rawsize+(s_align-1))&~(s_align-1)
        self.parent.NThdr.sizeofimage = l
        return s


####################################################################
# Directories

# Parsing a Directory is not complicated, it is a tree-like structure
# where RVA are pointers to be converted in offsets in the file.
# Modifying a Directory makes is more complicated.
# - It is not always entirely in one section; e.g. for some PE files
#   everything from the DelayImport direction is in .rdata, with the
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
# where the directories are found varies a lot. Here are a
# few examples:
#
# MinGW
#   DirEnt IMPORT       in .idata (as recommended by the reference doc of PE)
#   DirEnt EXPORT       in .edata (as recommended by the reference doc of PE)
#
# Some old Microsoft files
#   DirEnt BOUND_IMPORT in headers (after PE header)
#   DirEnt IMPORT       in .text
#   DirEnt EXPORT       in .text
#   DirEnt DELAY_IMPORT in .text
#   DirEnt LOAD_CONFIG  in .text
#   DirEnt IAT          in .text (contains IMPORT current Thunks)
#   DirEnt DEBUG        in .text
#   DirEnt RESOURCE     in .rsrc
#   DirEnt BASERELOC    in .reloc
#   DirEnt SECURITY     in .reloc or in no section
#   Thunks DELAY_IMPORT original in .text, current in .data
#
# Some more recent Microsoft files
#   DirEnt BOUND_IMPORT in headers (after PE header)
#   DirEnt DEBUG        in .text
#   DirEnt IAT          in .rdata (contains IMPORT current Thunks)
#   DirEnt IMPORT       in .rdata
#   DirEnt EXPORT       in .rdata
#   DirEnt LOAD_CONFIG  in .rdata
#   DirEnt EXCEPTION    in .pdata
#   DirEnt RESOURCE     in .rsrc
#   DirEnt BASERELOC    in .reloc
#   DirEnt SECURITY     in .reloc

class ImportName(CStruct):
    _fields = [ ("hint", "u16"),
                ("name", CString) ]
    def update(self, **kargs):
        CStruct.update(self, **kargs)
        if 's' in kargs:
            # Update the string in the CString
            self.name.update(s=kargs['s'])
            self._size = 2+self.name._size

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
            if self.rva < self.parent.parent.parent.parent.NThdr.sizeofheaders:
                # Negate the hack in rva2off
                off = None
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
        if self.name_rva:
            # Follow the RVAs
            of = self.rva2off(self.name_rva)
            if of is None:
                log.error('NAME')
            else:
                self.name = CString(parent=self, content=c, start=of)
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

class DirImport(CArray):
    _cls = ImportDescriptor
    _idx = DIRECTORY_ENTRY_IMPORT
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
        CArray.unpack(self, c, o)
    def display(self):
        print("<%s>" % self.__class__.__name__)
        for idx, d in enumerate(self):
            print("%2d %r"%(idx,d.name))
            for jdx, t in enumerate(d.IAT):
                t_virt = self.parent.rva2virt(d.firstthunk+jdx*t._size)
                t_obj = repr(t.obj)
                # Only display original thunks that are incoherent with current
                if hasattr(d, 'ILT'):
                    u = d.ILT[jdx]
                    if u.rva != t.rva:
                        t_obj += ' %r' % u.obj
                print("        %2d %#10x %s"%(jdx,t_virt,t_obj))
    def pack(self):
        raise AttributeError("Cannot pack '%s': the Directory Entry data is not always contiguous"%self.__class__.__name__)
    def add_imports(self, *args):
        # We add a new ImportDescriptor for each new DLL
        # We need to avoid changing RVA of the current IAT, because they
        # can be used e.g. in the executable section .text
        # But there might not be enough space after the current list of
        # descriptors to add new descriptors...
        # The trick we use is to move the list of descriptors in a new
        # section, where we will also store the new ILT, IAT and names,
        # leaving the original section unchanged.
        e = self.parent
        s = e.SHList.add_section(
            name='.idata2',
            flags=IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_READ|IMAGE_SCN_CNT_INITIALIZED_DATA,
            rsize=0x1000,     # should be enough
            )
        base_rva = e.off2rva(s.scnptr)
        e.NThdr.optentries[self._idx].rva = base_rva
        self._size += self._last._size * len(args)
        of = self._size
        s.data.data = StrPatchwork()
        for dll_name, dll_func in args:
            # First, an empty descriptor
            d = ImportDescriptor(parent=self)
            self._array.append(d)
            # Add the DLL name
            d.name = CString(parent=d, s=dll_name)
            d.name_rva = base_rva+of
            s.data.data[of] = d.name.pack()
            of += d.name._size
            if of%2: of += 1
            # Add the Import names; they will be located after the two thunks
            thunk_len = (1+len(dll_func))*(self.wsize/8)
            thunk_len *= 2
            # Add the IAT & ILT
            d.ILT = ImportThunks(parent=d)
            for n in dll_func:
                t = ImportNamePtr(parent=d.ILT)
                t.obj = ImportName(parent=t, s=n)
                t.rva = base_rva+of+thunk_len
                t.name = n
                s.data.data[of+thunk_len] = t.obj.pack()
                thunk_len += t.obj._size
                if thunk_len%2: thunk_len += 1
                d.ILT.append(t)
            d.originalfirstthunk = base_rva+of
            s.data.data[of] = d.ILT.pack()
            of += d.ILT._size
            d.IAT = ImportThunks(parent=d)
            for n in dll_func:
                t = ImportNamePtr(parent=d.ILT)
                t.rva = d.ILT[len(d.IAT)].rva
                t.obj = d.ILT[len(d.IAT)].obj
                t.name = n
                d.IAT.append(t)
            d.firstthunk = base_rva+of
            s.data.data[of] = d.IAT.pack()
            of += thunk_len - d.ILT._size
        # Write the descriptor list (now that everyting has been computed)
        s.data.data[0] = CArray.pack(self)
        # Update the section sizes
        s.paddr = len(s.data.data)
        e.NThdr.optentries[self._idx].size = s.paddr # Unused by PE loaders
        if s.rsize < s.paddr:
            s.rsize = s.paddr
        s.data.data[s.paddr] = data_null*(s.rsize-s.paddr)
    # For API compatibility with previous versions of elfesteem
    def get_dlldesc(self):
        return [ ({'name': d.name}, [t.name for t in d.IAT]) for d in self ]
    def add_dlldesc(self, new_dll):
        args = []
        for dll_name, dll_func in new_dll:
            args.append((dll_name['name'],dll_func))
        self.add_imports(*args)
    def impdesc(self):
        class ImpDesc_e(object):
            def __init__(self, d):
                class Name(object):
                    def __init__(self, s):
                        self.name = s
                self.firstthunk = d.firstthunk
                self.dlldescname = Name(str(d.name))
                self.impbynames = [Name(str(_.obj.name)) for _ in d.ILT]
        return [ImpDesc_e(_) for _ in self]
    impdesc = property(impdesc)
    def get_funcrva(self, name):
        # Position of the function in the Import Address Table
        for d in self:
            for idx, t in enumerate(d.IAT):
                if t.name == name:
                    return d.firstthunk+idx*t._size
        return None
    def get_funcvirt(self, name):
        return self.parent.rva2virt(self.get_funcrva(name))




class Rva(NEW_CStruct):
    _fields = [ ("rva","ptr"),
                ]

class Rva32(NEW_CStruct):
    _fields = [ ("rva","u32"),
                ]

class DescName(NEW_CStruct):
    _fields = [ ("name", (lambda c, s, of:c.gets(s, of),
                          lambda c, value:c.sets(value)))
                ]
    def gets(self, s, of):
        if of < 0x1000:
            log.warn("descname in pe hdr, used as offset")
            ofname = of
        else:
            ofname = self.parent_head.rva2off(of)
        name = self.parent_head[ofname:self.parent_head._content.find(data_null, ofname)]
        return name, of+len(name)+1
    def sets(self, value):
        return value+data_null



class struct_array(object):
    def __init__(self, c, s, of, cstr, num = None):
        self.l = []
        self.cls = c
        self.end = None
        i = 0
        if not s:
            return

        while (num == None) or (num and i <num):
            e, l = cstr.unpack_l(s, of,
                                 c.parent_head,
                                 c.parent_head._sex,
                                 c.parent_head._wsize)
            # Special case: off between header and first section
            if c.parent_head.NThdr.sizeofheaders <= of < c.parent_head.SHList[0].scnptr:
                self.end = data_null*l
                break
            if num == None:
                if s[of:of+l] == data_null*l:
                    self.end = data_null*l
                    break
            self.l.append(e)
            of += l
            i += 1

    def __str__(self): 
        raise AttributeError("Use pack() instead of str()")

    def pack(self): 
        out = data_empty.join([x.pack() for x in self.l])
        if self.end != None:
            out += self.end
        return out

    def __getitem__(self, item):
        return self.l.__getitem__(item)

    def __len__(self):
        return len(self.l)

    def append(self, a):
        self.l.append(a)
    def insert(self, index, i):
        self.l.insert(index, i)


class ExpDesc_e(NEW_CStruct):
    _fields = [ ("characteristics","u32"),
                ("timestamp","u32"),
                ("majorv","u16"),
                ("minorv","u16"),
                ("name","u32"),
                ("base","u32"),
                ("numberoffunctions","u32"),
                ("numberofnames","u32"),
                ("addressoffunctions","u32"),
                ("addressofnames","u32"),
                ("addressofordinals","u32"),
              ]

class DirExport(NEW_CStruct):
    _fields = [ ("expdesc", (lambda c, s, of:c.gete(s, of),
                             lambda c, value:c.sete(value)))]
    def gete(self, s, of):
        of_o = of
        if not of:
            return None, of
        of = self.parent_head.rva2off(of)
        of_sav = of
        expdesc = ExpDesc_e.unpack(s,
                                   of,
                                   self.parent_head)
        if self.parent_head.rva2off(expdesc.addressoffunctions) == None or \
                self.parent_head.rva2off(expdesc.addressofnames) == None or \
                self.parent_head.rva2off(expdesc.addressofordinals) == None:
            log.warn("export dir malformed!")
            return None, of_o
        self.dlldescname = DescName.unpack(s, expdesc.name, self.parent_head)
        self.f_address = struct_array(self, s,
                                      self.parent_head.rva2off(expdesc.addressoffunctions), 
                                      Rva32, expdesc.numberoffunctions)
        self.f_names = struct_array(self, s,
                                    self.parent_head.rva2off(expdesc.addressofnames), 
                                    Rva32, expdesc.numberofnames)
        self.f_nameordinals = struct_array(self, s,
                                           self.parent_head.rva2off(expdesc.addressofordinals), 
                                           Ordinal, expdesc.numberofnames)
        for n in self.f_names:
            n.name = DescName.unpack(s, n.rva, self.parent_head)
        return expdesc, of_sav

    def sete(self, v):
        return self.expdesc.pack()

    def build_content(self, c):
        direxp = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_EXPORT]
        of1 = direxp.rva
        if self.expdesc is None: # No Export
            return
        c[self.parent_head.rva2off(of1)] = self.expdesc.pack()
        c[self.parent_head.rva2off(self.expdesc.name)] = self.dlldescname.pack()
        c[self.parent_head.rva2off(self.expdesc.addressoffunctions)] = self.f_address.pack()
        if self.expdesc.addressofnames!=0:
            c[self.parent_head.rva2off(self.expdesc.addressofnames)] = self.f_names.pack()
        if self.expdesc.addressofordinals!=0:
            c[self.parent_head.rva2off(self.expdesc.addressofordinals)] = self.f_nameordinals.pack()
        for n in self.f_names:
            c[self.parent_head.rva2off(n.rva)] = n.name.pack()

        # XXX BUG names must be alphanumeric ordered
        names = [n.name for n in self.f_names]
        names_ = names[:]
        if names != names_:
            log.warn("unsorted export names, may bug")

    def set_rva(self, rva, size = None):
        if self.expdesc is None:
            return
        self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_EXPORT].rva = rva
        if not size:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_EXPORT].size= len(self)
        else:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_EXPORT].size= size
        rva+=len(self.expdesc)
        self.expdesc.name = rva
        rva+=len(self.dlldescname)
        self.expdesc.addressoffunctions = rva
        rva+=len(self.f_address)*self.parent_head._wsize/8# Rva size
        self.expdesc.addressofnames = rva
        rva+=len(self.f_names)*self.parent_head._wsize/8# Rva size
        self.expdesc.addressofordinals = rva
        rva+=len(self.f_nameordinals)*2# Ordinal size
        for n in self.f_names:
            n.rva = rva
            rva+=len(n.name)

    def __len__(self):
        l = 0
        if self.expdesc is None:
            return l
        l+=len(self.expdesc)
        l+=len(self.dlldescname)
        l+=len(self.f_address)*self.parent_head._wsize/8# Rva size
        l+=len(self.f_names)*self.parent_head._wsize/8# Rva size
        l+=len(self.f_nameordinals)*2# Ordinal size
        for n in self.f_names:
            l+=len(n.name)
        return l

    def __repr__(self):
        rep = "<%s>\n" % self.__class__.__name__
        if self.expdesc is None:
            return rep
        rep = "<%s %d (%r) %r>\n" % (self.__class__.__name__,
                                     self.expdesc.numberoffunctions,
                                     self.dlldescname,
                                     self.expdesc)
        tmp_names = [[] for x in range(self.expdesc.numberoffunctions)]
        for i, n in enumerate(self.f_names):
            tmp_names[self.f_nameordinals[i].ordinal].append(n.name)
        for i,s in enumerate(self.f_address):
            if not s.rva:
                continue
            rep += "%2d %.8X %r\n" % (i+self.expdesc.base, s.rva, tmp_names[i])
        return rep

    def create(self, name = 'default.dll'):
        self.expdesc = ExpDesc_e(self.parent_head)
        for x in [ "characteristics",
                   "timestamp",
                   "majorv",
                   "minorv",
                   "name",
                   "base",
                   "numberoffunctions",
                   "numberofnames",
                   "addressoffunctions",
                   "addressofnames",
                   "addressofordinals",
                   ]:
            setattr(self.expdesc, x, 0)

        self.dlldescname = DescName(self.parent_head)
        self.dlldescname.name = name
        self.f_address = struct_array(self, None,
                                      None,
                                      Rva)
        self.f_names = struct_array(self, None,
                                    None,
                                    Rva)
        self.f_nameordinals = struct_array(self, None,
                                           None,
                                           Ordinal)
        self.expdesc.base = 1


    def add_name(self, name, rva = 0xdeadc0fe):
        if self.expdesc is None:
            return
        l = len(self.f_names)
        names = [n.name.name for n in self.f_names]
        names_s = names[:]
        names_s.sort()
        if names_s != names:
            log.warn('tab names was not sorted may bug')
        names.append(name)
        names.sort()
        index = names.index(name)
        descname = DescName(self.parent_head)

        descname.name = name
        wname = Rva(self.parent_head)

        wname.name = descname
        woffset = Rva(self.parent_head)
        woffset.rva = rva
        wordinal = Ordinal(self.parent_head)
        #func is append to list
        wordinal.ordinal = len(self.f_address)
        self.f_address.append(woffset)
        #self.f_names.insert(index, wname)
        #self.f_nameordinals.insert(index, wordinal)
        self.f_names.insert(index, wname)
        self.f_nameordinals.insert(index, wordinal)
        self.expdesc.numberofnames+=1
        self.expdesc.numberoffunctions+=1

    def get_funcrva(self, f_str):
        if self.expdesc is None:
            return None
        for i, f in enumerate(self.f_names):
            if f_str != f.name.name:
                continue
            o = self.f_nameordinals[i].ordinal
            rva = self.f_address[o].rva
            return rva
        return None

    def get_funcvirt(self, f):
        rva = self.get_funcrva(f)
        if rva==None:
            return
        return self.parent_head.rva2virt(rva)


class ImportByName(NEW_CStruct):
    _fields = [ ("hint", "u16"),
                ("name", "sz")
                ]

class Delaydesc_e(NEW_CStruct):
    _fields = [ ("attrs","u32"),
                ("name","u32"),
                ("hmod","u32"),
                ("firstthunk","u32"),
                ("originalfirstthunk","u32"),
                ("boundiat","u32"),
                ("unloadiat","u32"),
                ("timestamp","u32"),
              ]

class DirDelay(NEW_CStruct):
    _fields = [ ("delaydesc", (lambda c, s, of:c.gete(s, of),
                               lambda c, value:c.sete(value)))]

    def gete(self, s, of):
        if not of:
            return None, of
        of = self.parent_head.rva2off(of)
        out = struct_array(self, s, of, Delaydesc_e)
        if self.parent_head._wsize == 32:
            mask_ptr = 0x80000000
        elif self.parent_head._wsize == 64:
            mask_ptr = 0x8000000000000000

        parent = self.parent_head
        for i, d in enumerate(out):
            isfromva = (d.attrs & 1) == 0
            if isfromva:
                isfromva = lambda x:parent.virt2rva(x)
            else:
                isfromva = lambda x:x
            d.dlldescname = DescName.unpack(s, isfromva(d.name),
                                            self.parent_head)
            if d.originalfirstthunk:
                d.originalfirstthunks = struct_array(self, s,
                                                     self.parent_head.rva2off(isfromva(d.originalfirstthunk)),
                                                     Rva)
            else:
                d.originalfirstthunks

            if d.firstthunk:
                d.firstthunks = struct_array(self, s,
                                             self.parent_head.rva2off(isfromva(d.firstthunk)),
                                             Rva)
            else:
                d.firstthunk = None

            d.impbynames = []
            if d.originalfirstthunk and self.parent_head.rva2off(isfromva(d.originalfirstthunk)):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise ValueError("no thunk in delay dir!! ")
            for i in range(len(tmp_thunk)):
                if tmp_thunk[i].rva&mask_ptr == 0:
                    n = ImportByName.unpack(s,
                                            self.parent_head.rva2off(isfromva(tmp_thunk[i].rva)),
                                            self.parent_head)
                    d.impbynames.append(n)
                else:
                    d.impbynames.append(isfromva(tmp_thunk[i].rva&(mask_ptr-1)))
                    #print(repr(d[-1]))
                    #raise ValueError('XXX to check')
        return out, of

    def sete(self, v):
        c = data_empty.join([x.pack() for x in v])+data_null*(4*8) #DelayDesc_e
        return c


    def __len__(self):
        l = (len(self.delaydesc)+1)*(4*8) #DelayDesc_e
        for i, d in enumerate(self.delaydesc):
            l+=len(d.dlldescname)
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                l+=(len(d.originalfirstthunks)+1)*self.parent_head._wsize/8 #Rva size
            if d.firstthunk:
                l+=(len(d.firstthunks)+1)*self.parent_head._wsize/8 #Rva size
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            """
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            """
            for i, imp in enumerate(d.impbynames):
                if isinstance(imp, ImportByName):
                    l+=len(imp)
        return l

    def set_rva(self, rva, size = None):
        self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_DELAY_IMPORT].rva = rva
        if not size:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_DELAY_IMPORT].size= len(self)
        else:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_DELAY_IMPORT].size= size
        rva+=(len(self.delaydesc)+1)*(4*8) #DelayDesc_e
        parent = self.parent_head
        for i, d in enumerate(self.delaydesc):
            isfromva = (d.attrs & 1) == 0
            if isfromva:
                isfromva = lambda x:self.parent_head.rva2virt(x)
            else:
                isfromva = lambda x:x

            d.name = isfromva(rva)
            rva+=len(d.dlldescname)
            if d.originalfirstthunk:# and self.parent_head.rva2off(d.originalfirstthunk):
                d.originalfirstthunk = isfromva(rva)
                rva+=(len(d.originalfirstthunks)+1)*self.parent_head._wsize/8 # rva size
            #XXX rva fthunk not patched => fun addr
            #if d.firstthunk:
            #    d.firstthunk = rva
            #    rva+=(len(d.firstthunks)+1)*pe.Rva._size
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            for i, imp in enumerate(d.impbynames):
                if isinstance(imp, ImportByName):
                    tmp_thunk[i].rva = isfromva(rva)
                    rva+=len(imp)

    def build_content(self, c):
        if len(self.parent_head.NThdr.optentries) < DIRECTORY_ENTRY_DELAY_IMPORT:
            return
        dirdelay = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_DELAY_IMPORT]
        of1 = dirdelay.rva
        if not of1: # No Delay Import
            return
        c[self.parent_head.rva2off(of1)] = self.pack()
        for i, d in enumerate(self.delaydesc):
            c[self.parent_head.rva2off(d.name)] = d.dlldescname.pack()
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                c[self.parent_head.rva2off(d.originalfirstthunk)] = d.originalfirstthunks.pack()
            if d.firstthunk:
                c[self.parent_head.rva2off(d.firstthunk)] = d.firstthunks.pack()
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            for j, imp in enumerate(d.impbynames):
                if isinstance(imp, ImportByName):
                    c[self.parent_head.rva2off(tmp_thunk[j].rva)] = imp.pack()

    def __repr__(self):
        rep = "<%s>\n" % self.__class__.__name__
        if self.delaydesc is None:
            return rep
        for i,s in enumerate(self.delaydesc):
            rep += "%2d %-25r %r\n" % (i, s.dlldescname, s)
            for ii, f in enumerate(s.impbynames):
                rep += "    %2d %-16r\n" % (ii, f)
        return rep

    def add_dlldesc(self, new_dll):
        if self.parent_head._wsize == 32:
            mask_ptr = 0x80000000
        elif self.parent_head._wsize == 64:
            mask_ptr = 0x8000000000000000
        new_impdesc = []
        of1 = None
        for nd, fcts in new_dll:
            for x in ["attrs","name","hmod","firstthunk","originalfirstthunk","boundiat","unloadiat","timestamp"]:
                if not x in nd:
                    nd[x] = 0
            d = DelayDesc_e(self.parent_head,**nd)
            #d.cstr.__dict__.update(nd)
            if d.firstthunk!=None:
                of1 = d.firstthunk
            elif of1 == None:
                raise "set fthunk"
            else:
                d.firstthunk = of1
            d.dlldescname = DescName(self.parent_head, name = d.name)
            d.originalfirstthunk = 0
            d.originalfirstthunks = struct_array(self, None,
                                                 None,
                                                 Rva)
            d.firstthunks = struct_array(self, None,
                                         None,
                                         Rva)

            impbynames = []
            for nf in fcts:
                f = Rva(self.parent_head)
                if type(nf) in [int, long]:
                    f.rva = mask_ptr+nf
                    ibn = None
                elif type(nf) in [str]:
                    f.rva = True
                    ibn = ImportByName(self.parent_head)
                    ibn.name = nf
                    ibn.hint = 0
                else:
                    raise ValueError('unknown func type %s'%nf)
                impbynames.append(ibn)
                d.originalfirstthunks.append(f)

                ff = Rva(self.parent_head)
                if ibn != None:
                    ff.rva = 0xDEADBEEF #default func addr
                else:
                    #ord ?XXX?
                    ff.rva = f.rva
                d.firstthunks.append(ff)
                of1+=4
            #for null thunk
            of1+=4
            d.impbynames = impbynames
            new_delaydesc.append(d)
        if self.delaydesc is None:
            self.delaydesc = struct_array(self, None,
                                          None,
                                          Delaydesc)
            self.delaydesc.l = new_delaydesc
        else:
            for d in new_delaydesc:
                self.delaydesc.append(d)

    def get_funcrva(self, f):
        for i, d in enumerate(self.delaydesc):
            isfromva = (d.attrs & 1) == 0
            if isfromva:
                isfromva = lambda x:self.parent_head.virt2rva(x)
            else:
                isfromva = lambda x:x
            if d.originalfirstthunk and self.parent_head.rva2off(isfromva(d.originalfirstthunk)):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            if type(f) is str:
                for j, imp in enumerate(d.impbynames):
                    if isinstance(imp, ImportByName):
                        if f == imp.name:
                            return isfromva(d.firstthunk)+j*4
            elif type(f) in (int, long):
                for j, imp in enumerate(d.impbynames):
                    if not isinstance(imp, ImportByName):
                        if isfromva(tmp_thunk[j].rva&0x7FFFFFFF) == f:
                            return isfromva(d.firstthunk)+j*4
            else:
                raise ValueError('unknown func type %s'%f)
    def get_funcvirt(self, f):
        rva = self.get_funcrva(f)
        if rva==None:
            return
        return self.parent_head.rva2virt(rva)


class Rel(NEW_CStruct):
    _fields = [ ("rva","u32"),
                ("size","u32")
                ]

class Reloc(NEW_CStruct):
    _fields = [ ("rel",(lambda c, s, of:c.gete(s, of),
                        lambda c, value:c.sete(value))) ]
    def gete(self, s, of):
        rel = struct.unpack('H', s[of:of+2])[0]
        return (rel>>12, rel&0xfff), of+2
    def sete(self, value):
        return struct.pack('H', (value[0]<<12) | value[1])
    def __repr__(self):
        return '<%d %d>'%(self.rel[0], self.rel[1])

class DirReloc(NEW_CStruct):
    _fields = [ ("reldesc", (lambda c, s, of:c.gete(s, of),
                             lambda c, value:c.sete(value)))]

    def gete(self, s, of):
        if not of:
            return None, of

        of1 = self.parent_head.rva2off(of)
        ofend = of1+self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_BASERELOC].size
        out = []
        while of1 < ofend:
            reldesc, l = Rel.unpack_l(s,
                                      of1,
                                      self.parent_head)
            if reldesc.size == 0:
                log.warn('warning null reldesc')
                reldesc.size = l
                break
            of2 = of1 + l
            reldesc.rels = struct_array(self, s,
                                        of2,
                                        Reloc,
                                        (reldesc.size-l)/2) # / Reloc size
            reldesc.patchrel = False
            out.append(reldesc)
            of1+=reldesc.size
        return out, of

    def sete(self, v):
        rep = []
        for n in v:
            rep.append(n.pack())
            rep.append(n.rels.pack())
        return data_empty.join(rep)

    def set_rva(self, rva, size = None):
        if self.reldesc is None:
            return
        self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_BASERELOC].rva = rva
        if not size:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_BASERELOC].size= len(self)
        else:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_BASERELOC].size= size

    def build_content(self, c):
        dirrel = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_BASERELOC]
        dirrel.size  = len(self)
        of1 = dirrel.rva
        if self.reldesc is None: # No Reloc
            return
        c[self.parent_head.rva2off(of1)] = self.pack()

    def __len__(self):
        if self.reldesc is None:
            return 0
        l = 0
        for n in self.reldesc:
            l+=n.size
        return l

    def __str__(self):
        raise AttributeError("Use pack() instead of str()")

    def pack(self):
        rep = []
        for n in self.reldesc:
            rep.append(n.pack())
            rep.append(n.rels.pack())
        return data_empty.join(rep)


    def __repr__(self):
        rep = "<%s>\n" % self.__class__.__name__
        if self.reldesc is None:
            return rep
        for i, n in enumerate(self.reldesc):
            rep += "%2d %r\n" % (i, n)
            """
            #displays too many lines...
            for ii, m in enumerate(n.rels):
                rep += "\t%2d %r\n" % (ii, m)
            """
            rep += "\t%2d rels...\n" % (len(n.rels))
        return rep

    def add_reloc(self, rels, rtype = 3, patchrel = True):
        dirrel = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_BASERELOC]
        if not rels:
            return
        rels.sort()
        all_base_ad = set([x & 0xFFFFF000 for x in rels])
        all_base_ad = list(all_base_ad)
        all_base_ad.sort()
        rels_by_base = {}
        while rels:
            r = rels.pop()
            base = all_base_ad[-1]
            if not base in rels_by_base: rels_by_base[base] = []
            if r >= base:
                rels_by_base[base].append(r)
            else:
                all_base_ad.pop()
                rels_by_base[base].append(r)
        rels_by_base = [x for x in rels_by_base.items()]
        rels_by_base.sort()
        for o_init, rels in rels_by_base:
            #o_init = rels[0]&0xFFFFF000
            offsets = struct_array(self, None, None, Reloc, 0)
            for o in rels:
                if (o&0xFFFFF000) !=o_init:
                    raise "relocs must be in same range"
                r = Reloc(self.parent_head)
                r.rel = (rtype, o-o_init)
                offsets.append(r)
            while len(offsets) &3:
                r = Reloc(self.parent_head)
                r.rel = (0, 0)
                offsets.append(r)
            reldesc = Rel(self.parent_head)#Reloc(self.parent_head)
            reldesc.rva = o_init
            reldesc.size = (len(offsets)*2+8)
            reldesc.rels = offsets
            reldesc.patchrel = patchrel
            self.reldesc.append(reldesc)
            dirrel.size+=reldesc.size

    def del_reloc(self, taboffset):
        if self.reldesc is None:
            return
        for rel in self.reldesc:
            of1 = rel.rva
            i = 0
            while i < len(rel.rels):
                r = rel.rels[i]
                if r.rel[0] != 0 and r.rel[1]+of1 in taboffset:
                    print('del reloc %x' % r.rel[1]+of1)
                    del rel.rels[i]
                    rel.size-=Reloc._size
                else:
                    i+=1


class DirRes(NEW_CStruct):
    _fields = [ ("resdesc", (lambda c, s, of:c.gete(s, of),
                             lambda c, value:c.sete(value)))]

    def gete(self, s, of):
        if not of:
            return None, of
        of1 = self.parent_head.rva2off(of)
        if of1 == None:
            log.warning('cannot parse resources, %X'%of)
            return None, of

        resdesc, l = ResDesc_e.unpack_l(s,
                                        of1,
                                        self.parent_head)

        nbr = resdesc.numberofnamedentries + resdesc.numberofidentries
        if 1:#try:
            resdesc.resentries = struct_array(self, s,
                                              of1 + l,
                                              ResEntry,
                                              nbr)
        if 0:#except:
            log.warning('cannot parse resources')
            resdesc.resentries = struct_array(self, s,
                                              of1 + l,
                                              ResEntry,
                                              0)
        dir_todo = {of1:resdesc}
        dir_done = {}
        xx = 0
        cpt = 0
        while dir_todo:
            of1, my_dir = dir_todo.popitem()
            dir_done[of1] = my_dir
            for e in my_dir.resentries:
                of1 = e.offsettosubdir
                if not of1:
                    #data dir
                    of1 = e.offsettodata
                    data = ResDataEntry.unpack(s,
                                               self.parent_head.rva2off(of1),
                                               self.parent_head)
                    of1 = data.offsettodata
                    offile = self.parent_head.rva2off(of1)
                    data.s = StrPatchwork(s[offile:offile + data.size])
                    e.data = data
                    continue
                #subdir
                if of1 in dir_done:
                    log.warn('warning recusif subdir')
                    fdds
                    continue
                subdir, l = ResDesc_e.unpack_l(s,
                                               self.parent_head.rva2off(of1),
                                               self.parent_head)
                nbr = subdir.numberofnamedentries + subdir.numberofidentries
                subdir.resentries = struct_array(self, s,
                                                 self.parent_head.rva2off(of1 + l),
                                                 ResEntry,
                                                 nbr)

                e.subdir = subdir
                dir_todo[of1] = e.subdir
        return resdesc, of

    def build_content(self, c):
        if self.resdesc is None:
            return
        of1 = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva
        c[self.parent_head.rva2off(of1)] = self.resdesc.pack()
        dir_todo = {self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva:self.resdesc}
        dir_done = {}
        while dir_todo:
            of1, my_dir = dir_todo.popitem()
            dir_done[of1] = my_dir
            c[self.parent_head.rva2off(of1)] = my_dir.pack()
            c[self.parent_head.rva2off(of1+len(my_dir))] = my_dir.resentries.pack()
            for e in my_dir.resentries:
                if e.name_s:
                    c[self.parent_head.rva2off(e.name)] = e.name_s.pack()
                of1 = e.offsettosubdir
                if not of1:
                    c[self.parent_head.rva2off(e.offsettodata)] = e.data.pack()
                    c[self.parent_head.rva2off(e.data.offsettodata)] = e.data.s.pack()
                    continue
                dir_todo[of1] = e.subdir


    def __len__(self):
        l = 0
        if self.resdesc is None:
            return l
        dir_todo = [self.resdesc]
        dir_done = []
        while dir_todo:
            my_dir = dir_todo.pop()
            if not my_dir in dir_done:
                dir_done.append(my_dir)
            else:
                raise 'recursif dir'
            l+=len(my_dir)
            l+=len(my_dir.resentries)*8 # ResEntry size
            for e in my_dir.resentries:
                if not e.offsettosubdir:
                    continue
                if not e.subdir in dir_todo:
                    dir_todo.append(e.subdir)
                else:
                    raise "recursive dir"
                    fds
                    continue

        dir_todo = dir_done
        while dir_todo:
            my_dir = dir_todo.pop()
            for e in my_dir.resentries:
                if e.name_s:
                    l+=len(e.name_s)
                of1 = e.offsettosubdir
                if not of1:
                    l+=4*4 # WResDataEntry size
                    #XXX because rva may be even rounded
                    l+=1
                    l+=e.data.size
                    continue
        return l

    def set_rva(self, rva, size = None):
        if self.resdesc is None:
            return
        self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva = rva
        if not size:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].size = len(self)
        else:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].size = size
        dir_todo = [self.resdesc]
        dir_done = {}
        while dir_todo:
            my_dir = dir_todo.pop()
            dir_done[rva] = my_dir
            rva+=len(my_dir)
            rva+=len(my_dir.resentries)*8 # ResEntry size
            for e in my_dir.resentries:
                if not e.offsettosubdir:
                    continue
                if not e.subdir in dir_todo:
                    dir_todo.append(e.subdir)
                else:
                    raise "recursive dir"
                    fds
                    continue
        dir_todo = dir_done
        dir_inv = dict(map(lambda x:(x[1], x[0]), dir_todo.items()))
        while dir_todo:
            rva_tmp, my_dir = dir_todo.popitem()
            for e in my_dir.resentries:
                if e.name_s:
                    e.name = rva
                    rva+=len(e.name_s)
                of1 = e.offsettosubdir
                if not of1:
                    e.offsettodata = rva
                    rva+=4*4 # ResDataEntry size
                    #XXX menu rsrc must be even aligned?
                    if rva%2:rva+=1
                    e.data.offsettodata = rva
                    rva+=e.data.size
                    continue
                e.offsettosubdir = dir_inv[e.subdir]

    def __repr__(self):
        rep = "<%s>\n" % self.__class__.__name__
        if self.resdesc is None:
            return rep
        dir_todo = [self.resdesc]
        out = []
        index = -1
        while dir_todo:
            a = dir_todo.pop(0)
            if isinstance(a, int):
                index+=a
            elif isinstance(a, ResDesc_e):
                #out.append((index, repr(a)))
                dir_todo=[1]+a.resentries.l+[-1]+dir_todo
            elif isinstance(a, ResEntry):
                if a.offsettosubdir:
                    out.append((index, repr(a)))
                    dir_todo = [a.subdir]+dir_todo
                else:
                    out.append((index, repr(a)))
            else:
                raise "zarb"
        for i, c in out:
            rep += ' '*4*i + c + '\n'
        return rep

class Ordinal(NEW_CStruct):
    _fields = [ ("ordinal","u16"),
                ]



class ResDesc_e(NEW_CStruct):
    _fields = [ ("characteristics","u32"),
                ("timestamp","u32"),
                ("majorv","u16"),
                ("minorv","u16"),
                ("numberofnamedentries","u16"),
                ("numberofidentries","u16")
              ]

class SUnicode(NEW_CStruct):
    _fields = [ ("length", "u16"),
                ("value", (lambda c, s, of:c.gets(s, of),
                           lambda c, value:c.sets(value)))
                ]
    def gets(self, s, of):
        v = s[of:of+self.length*2]
        return v, of+self.length
    def sets(self, value):
        return self.value

class ResEntry(NEW_CStruct):
    _fields = [ ("name",(lambda c, s, of:c.getn(s, of),
                         lambda c, value:c.setn(value))),
                ("offsettodata",(lambda c, s, of:c.geto(s, of),
                                 lambda c, value:c.seto(value)))
                ]

    def getn(self, s, of):
        self.data = None
        #of = self.parent_head.rva2off(of)
        name = struct.unpack('I', s[of:of+4])[0]
        self.name_s = None
        if name & 0x80000000:
            name = (name & 0x7FFFFFFF) + self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva # XXX res rva??
            name &= 0x7FFFFFFF
            self.name_s = SUnicode.unpack(s,
                                          self.parent_head.rva2off(name),
                                          self.parent_head)
        return name, of+4

    def setn(self, v):
        name = v
        if self.name_s:
            name=(self.name-self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva)+0x80000000
        return struct.pack('I', name)

    def geto(self, s, of):
        self.offsettosubdir = None
        offsettodata_o = struct.unpack('I', s[of:of+4])[0]
        offsettodata = (offsettodata_o & 0x7FFFFFFF) + self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva #XXX res rva??
        if offsettodata_o & 0x80000000:
            self.offsettosubdir = offsettodata
        return offsettodata, of+4
    def seto(self, v):
        offsettodata = v - self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva
        if self.offsettosubdir:
            offsettodata=(self.offsettosubdir-self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva)+0x80000000
        return struct.pack('I', offsettodata)

    def __repr__(self):
        if self.name_s:
            nameid = "%s"%repr(self.name_s)
        else:
            if self.name in RT:# and not self.offsettosubdir:
                nameid = "ID %s"%RT[self.name]
            else:
                nameid = "ID %d"%self.name
        if self.offsettosubdir:
            offsettodata = "subdir: %x"%self.offsettosubdir
        else:
            offsettodata = "data: %x"%self.offsettodata
        return "<%s %s>"%(nameid, offsettodata)



class ResDataEntry(NEW_CStruct):
    _fields = [ ("offsettodata","u32"),
                ("size","u32"),
                ("codepage","u32"),
                ("reserved","u32"),
                ]


class Symb(NEW_CStruct):
    _fields = [ ("name","8s"),
                ("res1","u32"),
                ("res2","u32"),
                ("res3","u16")]

class CoffSymbol(NEW_CStruct):
    _fields = [ ("name", (lambda c, s, of:c.getname(s, of),
                          lambda c, value:c.setname(value))),
                ("value","u32"),
                ("sectionnumber","u16"),
                ("type","u16"),
                ("storageclass","u08"),
                ("numberofauxsymbols","u08"),
                ("aux", (lambda c, s, of:c.getaux(s, of),
                         lambda c, value:c.setaux(value))) ]
    def getname(self, s, of):
        name = s[of:of+8]
        if name[0:4] == data_null*4:
            name = self.parent_head.parent_head.SymbolStrings.getby_offset(struct.unpack('<I', name[4:8])[0])
        else:
            name = name.strip(data_null)
        if type(name) != str: name = str(name, encoding='latin1')
        return name, of+8
    def setname(self, value):
        if len(value) > 8:
            of = self.parent_head.parent_head.SymbolStrings.add(value)
            return struct.pack("<II", 0, of)
        else:
            value += data_null*8
            return value[0:8]
    def getaux(self, s, of):
        aux = []
        for i in range(self.numberofauxsymbols):
            if   self.storageclass == IMAGE_SYM_CLASS_EXTERNAL:
                aux.append(SymbolAuxFunc.unpack(s, of, self.parent_head))
            elif self.storageclass == IMAGE_SYM_CLASS_STATIC:
                aux.append(SymbolAuxSect.unpack(s, of, self.parent_head))
            elif self.storageclass == IMAGE_SYM_CLASS_FILE:
                aux.append(SymbolAuxFile.unpack(s, of, self.parent_head))
            else:
                aux.append(struct.unpack('<18s', s[of:of+18])[0])
            of += 18
        return aux, of
    def setaux(self, value):
        res = data_empty
        for aux in value:
            res += aux.pack()
        return res
    def __repr__(self):
        s  = repr(self.name)
        s += " value=0x%x" % self.value
        if 0 < self.sectionnumber < 1+len(self.parent_head.parent_head.SHList):
            s += " section=%s" % self.parent_head.parent_head.SHList[self.sectionnumber-1].name
        else:
            s += " section=0x%x" % self.sectionnumber
        base_type = self.type & 0xf
        cplx_type = self.type >> 4
        if base_type != 0:
            s += " type=%s" % constants['IMAGE_SYM_TYPE'][base_type]
        elif cplx_type in constants['IMAGE_SYM_DTYPE']:
            s += " type=%s" % constants['IMAGE_SYM_DTYPE'][cplx_type]
        else:
            s += " type=0x%x" % cplx_type
        if self.storageclass in constants['IMAGE_SYM_CLASS']:
            s += " storage=%s" % constants['IMAGE_SYM_CLASS'][self.storageclass]
        else:
            s += " storage=0x%x" % self.storageclass
        s += " aux=%r" % self.aux
        return "<CoffSymbol " + s + ">"

class SymbolAuxFile(NEW_CStruct):
    _fields = [ ("name", (lambda c, s, of:c.getname(s, of),
                          lambda c, value:c.setname(value)))]
    def getname(self, s, of):
        name = s[of:of+18]
        if name[0:4] == data_null*4:
            name = self.parent_head.parent_head.SymbolStrings.getby_offset(struct.unpack('<I', name[4:8])[0])
        else:
            name = name.strip(data_null)
        if type(name) != str: name = str(name, encoding='latin1')
        return name, of+18
    def setname(self, value):
        if len(value) > 18:
            of = self.parent_head.parent_head.SymbolStrings.add(value)
            return struct.pack("<IIIIH", 0, of, 0, 0, 0)
        else:
            value += data_null*18
            return value[0:18]

class SymbolAuxFunc(NEW_CStruct):
    _fields = [ ("tagIndex","u32"),
                ("totalSize","u32"),
                ("pointerToLineNum","u32"),
                ("pointerToNextFunc","u32"),
                ("padding","u16")]

class SymbolAuxSect(NEW_CStruct):
    _fields = [ ("length","u32"),
                ("numberOfRelocations","u16"),
                ("numberOfLinenumbers","u16"),
                ("checksum","u32"),
                ("number","u16"),
                ("selection","u08"),
                ("padding1","u08"),
                ("padding2","u08"),
                ("padding3","u08")]
