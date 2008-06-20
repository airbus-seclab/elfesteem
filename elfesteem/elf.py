#! /usr/bin/env python

from cstruct import CStruct

class Ehdr(CStruct):
    _fields = [ ("ident","16s"),
                ("type","H"),
                ("machine","H"),
                ("version","I"),
                ("entry","I"),
                ("phoff","I"),
                ("shoff","I"),
                ("flags","I"),
                ("ehsize","H"),
                ("phentsize","H"),
                ("phnum","H"),
                ("shentsize","H"),
                ("shnum","H"),
                ("shstrndx","H") ]


class Shdr(CStruct):
    _fields = [ ("name","I"),
                ("type","I"),
                ("flags","I"),
                ("addr","I"),
                ("offset","I"),
                ("size","I"),
                ("link","I"),
                ("info","I"),
                ("addralign","I"),
                ("entsize","I") ]

class Phdr(CStruct):
    _fields = [ ("type","I"),
                ("offset","I"),
                ("vaddr","I"),
                ("paddr","I"),
                ("filesz","I"),
                ("memsz","I"),
                ("flags","I"),
                ("align","I") ]

class Sym(CStruct):
    _fields = [ ("name","I"),
                ("value","I"),
                ("size","I"),
                ("info","B"),
                ("other","B"),
                ("shndx","H") ]

class Dym(CStruct):
    _fields = [ ("tag","I"),
                ("val","I") ]

class Rel(CStruct):
    _packformat = "="
    _fields = [ ("offset","I"),
                ("type","B"),
                ("sym","H"),
                ("zero","B") ]

class Rela(CStruct):
    _fields = [ ("offset","I"),
                ("type","B"),
                ("sym","B"),
                ("zero","H"),
                ("addend","i") ]

class Dynamic(CStruct):
    _fields = [ ("type","I"),
                ("name","I") ]


# Legal values for e_type (object file type). 

ET_NONE =         0               # No file type
ET_REL =          1               # Relocatable file
ET_EXEC =         2               # Executable file
ET_DYN =          3               # Shared object file
ET_CORE =         4               # Core file
ET_NUM =          5               # Number of defined types
ET_LOOS =         0xfe00L         # OS-specific range start
ET_HIOS =         0xfeffL         # OS-specific range end
ET_LOPROC =       0xff00L         # Processor-specific range start
ET_HIPROC =       0xffffL         # Processor-specific range end

# Legal values for sh_type (section type). 

SHT_NULL =          0             # Section header table entry unused
SHT_PROGBITS =      1             # Program data
SHT_SYMTAB =        2             # Symbol table
SHT_STRTAB =        3             # String table
SHT_RELA =          4             # Relocation entries with addends
SHT_HASH =          5             # Symbol hash table
SHT_DYNAMIC =       6             # Dynamic linking information
SHT_NOTE =          7             # Notes
SHT_NOBITS =        8             # Program space with no data (bss)
SHT_REL =           9             # Relocation entries, no addends
SHT_SHLIB =         10            # Reserved
SHT_DYNSYM =        11            # Dynamic linker symbol table
SHT_INIT_ARRAY =    14            # Array of constructors
SHT_FINI_ARRAY =    15            # Array of destructors
SHT_PREINIT_ARRAY = 16            # Array of pre-constructors
SHT_GROUP =         17            # Section group
SHT_SYMTAB_SHNDX =  18            # Extended section indeces
SHT_NUM =           19            # Number of defined types. 
SHT_LOOS =          0x60000000L   # Start OS-specific
SHT_GNU_LIBLIST =   0x6ffffff7L   # Prelink library list
SHT_CHECKSUM =      0x6ffffff8L   # Checksum for DSO content. 
SHT_LOSUNW =        0x6ffffffaL   # Sun-specific low bound. 
SHT_SUNW_move =     0x6ffffffaL
SHT_SUNW_COMDAT =   0x6ffffffbL
SHT_SUNW_syminfo =  0x6ffffffcL
SHT_GNU_verdef =    0x6ffffffdL   # Version definition section. 
SHT_GNU_verneed =   0x6ffffffeL   # Version needs section. 
SHT_GNU_versym =    0x6fffffffL   # Version symbol table. 
SHT_HISUNW =        0x6fffffffL   # Sun-specific high bound. 
SHT_HIOS =          0x6fffffffL   # End OS-specific type
SHT_LOPROC =        0x70000000L   # Start of processor-specific
SHT_HIPROC =        0x7fffffffL   # End of processor-specific
SHT_LOUSER =        0x80000000L   # Start of application-specific
SHT_HIUSER =        0x8fffffffL   # End of application-specific

# Legal values for sh_flags (section flags). 
  
SHF_WRITE =            (1 << 0)   # Writable
SHF_ALLOC =            (1 << 1)   # Occupies memory during execution
SHF_EXECINSTR =        (1 << 2)   # Executable
SHF_MERGE =            (1 << 4)   # Might be merged
SHF_STRINGS =          (1 << 5)   # Contains nul-terminated strings
SHF_INFO_LINK =        (1 << 6)   # `sh_info' contains SHT index
SHF_LINK_ORDER =       (1 << 7)   # Preserve order after combining
SHF_OS_NONCONFORMING = (1 << 8)   # Non-standard OS specific handling required
SHF_GROUP =           (1 << 9)    # Section is member of a group. 
SHF_TLS =             (1 << 10)   # Section hold thread-local data. 
SHF_MASKOS =          0x0ff00000L # OS-specific. 
SHF_MASKPROC =        0xf0000000L # Processor-specific

# Section group handling.

GRP_COMDAT =      0x1             # Mark group as COMDAT. 

# Legal values for p_type (segment type). 

PT_NULL =         0               # Program header table entry unused
PT_LOAD =         1               # Loadable program segment
PT_DYNAMIC =      2               # Dynamic linking information
PT_INTERP =       3               # Program interpreter
PT_NOTE =         4               # Auxiliary information
PT_SHLIB =        5               # Reserved
PT_PHDR =         6               # Entry for header table itself
PT_TLS =          7               # Thread-local storage segment
PT_NUM =          8               # Number of defined types
PT_LOOS =         0x60000000L     # Start of OS-specific
PT_GNU_EH_FRAME = 0x6474e550L     # GCC .eh_frame_hdr segment
PT_GNU_STACK =    0x6474e551L     # Indicates stack executability
PT_LOSUNW =       0x6ffffffaL
PT_SUNWBSS =      0x6ffffffaL     # Sun Specific segment
PT_SUNWSTACK =    0x6ffffffbL     # Stack segment
PT_HISUNW =       0x6fffffffL
PT_HIOS =         0x6fffffffL     # End of OS-specific
PT_LOPROC =       0x70000000L     # Start of processor-specific
PT_HIPROC =       0x7fffffffL     # End of processor-specific

# Legal values for p_flags (segment flags). 

PF_X =            (1 << 0)        # Segment is executable
PF_W =            (1 << 1)        # Segment is writable
PF_R =            (1 << 2)        # Segment is readable
PF_MASKOS =       0x0ff00000L     # OS-specific
PF_MASKPROC =     0xf0000000L     # Processor-specific

# Legal values for note segment descriptor types for core files.

NT_PRSTATUS =     1               # Contains copy of prstatus struct
NT_FPREGSET =     2               # Contains copy of fpregset struct
NT_PRPSINFO =     3               # Contains copy of prpsinfo struct
NT_PRXREG =       4               # Contains copy of prxregset struct
NT_TASKSTRUCT =   4               # Contains copy of task structure
NT_PLATFORM =     5               # String from sysinfo(SI_PLATFORM)
NT_AUXV =         6               # Contains copy of auxv array
NT_GWINDOWS =     7               # Contains copy of gwindows struct
NT_ASRS =         8               # Contains copy of asrset struct
NT_PSTATUS =      10              # Contains copy of pstatus struct
NT_PSINFO =       13              # Contains copy of psinfo struct
NT_PRCRED =       14              # Contains copy of prcred struct
NT_UTSNAME =      15              # Contains copy of utsname struct
NT_LWPSTATUS =    16              # Contains copy of lwpstatus struct
NT_LWPSINFO =     17              # Contains copy of lwpinfo struct
NT_PRFPXREG =     20              # Contains copy of fprxregset struct

# Legal values for the note segment descriptor types for object files. 

NT_VERSION =      1               # Contains a version string. 

# Legal values for ST_BIND subfield of st_info (symbol binding).
# bind = Sym.info >> 4
# val = Sym.info 0xf

STB_LOCAL       = 0               # Local symbol
STB_GLOBAL      = 1               # Global symbol
STB_WEAK        = 2               # Weak symbol
STB_NUM         = 3               # Number of defined types. 
STB_LOOS        = 10              # Start of OS-specific
STB_HIOS        = 12              # End of OS-specific
STB_LOPROC      = 13              # Start of processor-specific
STB_HIPROC      = 15              # End of processor-specific

#Legal values for ST_TYPE subfield of st_info (symbol type).

STT_NOTYPE      = 0               # Symbol type is unspecified
STT_OBJECT      = 1               # Symbol is a data object
STT_FUNC        = 2               # Symbol is a code object
STT_SECTION     = 3               # Symbol associated with a section
STT_FILE        = 4               # Symbol's name is file name
STT_COMMON      = 5               # Symbol is a common data object
STT_TLS         = 6               # Symbol is thread-local data object*/
STT_NUM         = 7               # Number of defined types. 
STT_LOOS        = 10              # Start of OS-specific
STT_HIOS        = 12              # End of OS-specific
STT_LOPROC      = 13              # Start of processor-specific
STT_HIPROC      = 15              # End of processor-specific

# Legal values for d_tag (dynamic entry type). 

DT_NULL         = 0               # Marks end of dynamic section
DT_NEEDED       = 1               # Name of needed library
DT_PLTRELSZ     = 2               # Size in bytes of PLT relocs
DT_PLTGOT       = 3               # Processor defined value
DT_HASH         = 4               # Address of symbol hash table
DT_STRTAB       = 5               # Address of string table
DT_SYMTAB       = 6               # Address of symbol table
DT_RELA         = 7               # Address of Rela relocs
DT_RELASZ       = 8               # Total size of Rela relocs
DT_RELAENT      = 9               # Size of one Rela reloc
DT_STRSZ        = 10              # Size of string table
DT_SYMENT       = 11              # Size of one symbol table entry
DT_INIT         = 12              # Address of init function
DT_FINI         = 13              # Address of termination function
DT_SONAME       = 14              # Name of shared object
DT_RPATH        = 15              # Library search path (deprecated)
DT_SYMBOLIC     = 16              # Start symbol search here
DT_REL          = 17              # Address of Rel relocs
DT_RELSZ        = 18              # Total size of Rel relocs
DT_RELENT       = 19              # Size of one Rel reloc
DT_PLTREL       = 20              # Type of reloc in PLT
DT_DEBUG        = 21              # For debugging; unspecified
DT_TEXTREL      = 22              # Reloc might modify .text
DT_JMPREL       = 23              # Address of PLT relocs
DT_BIND_NOW     = 24              # Process relocations of object
DT_INIT_ARRAY   = 25              # Array with addresses of init fct
DT_FINI_ARRAY   = 26              # Array with addresses of fini fct
DT_INIT_ARRAYSZ = 27              # Size in bytes of DT_INIT_ARRAY
DT_FINI_ARRAYSZ = 28              # Size in bytes of DT_FINI_ARRAY
DT_RUNPATH      = 29              # Library search path
DT_FLAGS        = 30              # Flags for the object being loaded
DT_ENCODING     = 32              # Start of encoded range
DT_PREINIT_ARRAY = 32             # Array with addresses of preinit fct
DT_PREINIT_ARRAYSZ = 33           # size in bytes of DT_PREINIT_ARRAY
DT_NUM          = 34              # Number used
DT_LOOS         = 0x6000000d      # Start of OS-specific
DT_HIOS         = 0x6ffff000      # End of OS-specific
DT_LOPROC       = 0x70000000      # Start of processor-specific
DT_HIPROC       = 0x7fffffff      # End of processor-specific
#DT_PROCNUM      = DT_MIPS_NUM     # Most used by any processor

# DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
# Dyn.d_un.d_val field of the Elf*_Dyn structure.  This follows Sun's
# approach.
DT_VALRNGLO     = 0x6ffffd00
DT_GNU_PRELINKED = 0x6ffffdf5     # Prelinking timestamp
DT_GNU_CONFLICTSZ = 0x6ffffdf6    # Size of conflict section
DT_GNU_LIBLISTSZ = 0x6ffffdf7     # Size of library list
DT_CHECKSUM     = 0x6ffffdf8
DT_PLTPADSZ     = 0x6ffffdf9
DT_MOVEENT      = 0x6ffffdfa
DT_MOVESZ       = 0x6ffffdfb
DT_FEATURE_1    = 0x6ffffdfc      # Feature selection (DTF_*). 
DT_POSFLAG_1    = 0x6ffffdfd      # Flags for DT_* entries, effecting the following DT_* entry.
DT_SYMINSZ      = 0x6ffffdfe      # Size of syminfo table (in bytes)
DT_SYMINENT     = 0x6ffffdff      # Entry size of syminfo
DT_VALRNGHI     = 0x6ffffdff
DT_VALNUM = 12

# DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
# Dyn.d_un.d_ptr field of the Elf*_Dyn structure.
#
# If any adjustment is made to the ELF object after it has been
# built these entries will need to be adjusted.
DT_ADDRRNGLO    = 0x6ffffe00
DT_GNU_CONFLICT = 0x6ffffef8      # Start of conflict section
DT_GNU_LIBLIST  = 0x6ffffef9      # Library list
DT_CONFIG       = 0x6ffffefa      # Configuration information. 
DT_DEPAUDIT     = 0x6ffffefb      # Dependency auditing. 
DT_AUDIT        = 0x6ffffefc      # Object auditing. 
DT_PLTPAD       = 0x6ffffefd      # PLT padding. 
DT_MOVETAB      = 0x6ffffefe      # Move table. 
DT_SYMINFO      = 0x6ffffeff      # Syminfo table. 
DT_ADDRRNGHI    = 0x6ffffeff
DT_ADDRNUM = 10

# The versioning entry types.  The next are defined as part of the
# GNU extension.
DT_VERSYM       = 0x6ffffff0

DT_RELACOUNT    = 0x6ffffff9
DT_RELCOUNT     = 0x6ffffffa

# These were chosen by Sun. 
DT_FLAGS_1      = 0x6ffffffb      # State flags, see DF_1_* below. 
DT_VERDEF       = 0x6ffffffc      # Address of version definition table
DT_VERDEFNUM    = 0x6ffffffd      # Number of version definitions
DT_VERNEED      = 0x6ffffffe      # Address of table with needed versions
DT_VERNEEDNUM   = 0x6fffffff      # Number of needed versions
DT_VERSIONTAGNUM = 16

# Sun added these machine-independent extensions in the "processor-specific"
# range.  Be compatible.
DT_AUXILIARY    = 0x7ffffffd      # Shared object to load before self
DT_FILTER       = 0x7fffffff      # Shared object to get values from
DT_EXTRANUM     = 3

# Values of `d_un.d_val' in the DT_FLAGS entry. 
DF_ORIGIN       = 0x00000001      # Object may use DF_ORIGIN
DF_SYMBOLIC     = 0x00000002      # Symbol resolutions starts here
DF_TEXTREL      = 0x00000004      # Object contains text relocations
DF_BIND_NOW     = 0x00000008      # No lazy binding for this object
DF_STATIC_TLS   = 0x00000010      # Module uses the static TLS model

# State flags selectable in the `d_un.d_val' element of the DT_FLAGS_1
# entry in the dynamic section.  
DF_1_NOW        = 0x00000001      # Set RTLD_NOW for this object. 
DF_1_GLOBAL     = 0x00000002      # Set RTLD_GLOBAL for this object. 
DF_1_GROUP      = 0x00000004      # Set RTLD_GROUP for this object. 
DF_1_NODELETE   = 0x00000008      # Set RTLD_NODELETE for this object.
DF_1_LOADFLTR   = 0x00000010      # Trigger filtee loading at runtime.
DF_1_INITFIRST  = 0x00000020      # Set RTLD_INITFIRST for this object
DF_1_NOOPEN     = 0x00000040      # Set RTLD_NOOPEN for this object. 
DF_1_ORIGIN     = 0x00000080      # $ORIGIN must be handled. 
DF_1_DIRECT     = 0x00000100      # Direct binding enabled. 
DF_1_TRANS      = 0x00000200
DF_1_INTERPOSE  = 0x00000400      # Object is used to interpose. 
DF_1_NODEFLIB   = 0x00000800      # Ignore default lib search path. 
DF_1_NODUMP     = 0x00001000      # Object can't be dldump'ed. 
DF_1_CONFALT    = 0x00002000      # Configuration alternative created.
DF_1_ENDFILTEE  = 0x00004000      # Filtee terminates filters search.
DF_1_DISPRELDNE = 0x00008000      # Disp reloc applied at build time.
DF_1_DISPRELPND = 0x00010000      # Disp reloc applied at run-time. 

# Flags for the feature selection in DT_FEATURE_1. 
DTF_1_PARINIT   = 0x00000001
DTF_1_CONFEXP   = 0x00000002

# Flags in the DT_POSFLAG_1 entry effecting only the next DT_* entry. 
DF_P1_LAZYLOAD  = 0x00000001      # Lazyload following object. 
DF_P1_GROUPPERM = 0x00000002      # Symbols from next object are not generally available.


# Intel 80386 specific definitions. 

# i386 relocs. 

R_386_NONE         = 0            # No reloc
R_386_32           = 1            # Direct 32 bit 
R_386_PC32         = 2            # PC relative 32 bit
R_386_GOT32        = 3            # 32 bit GOT entry
R_386_PLT32        = 4            # 32 bit PLT address
R_386_COPY         = 5            # Copy symbol at runtime
R_386_GLOB_DAT     = 6            # Create GOT entry
R_386_JMP_SLOT     = 7            # Create PLT entry
R_386_RELATIVE     = 8            # Adjust by program base
R_386_GOTOFF       = 9            # 32 bit offset to GOT
R_386_GOTPC        = 10           # 32 bit PC relative offset to GOT
R_386_32PLT        = 11
R_386_TLS_TPOFF    = 14           # Offset in static TLS block
R_386_TLS_IE       = 15           # Address of GOT entry for static TLS block offset
R_386_TLS_GOTIE    = 16           # GOT entry for static TLS block offset
R_386_TLS_LE       = 17           # Offset relative to static TLS block
R_386_TLS_GD       = 18           # Direct 32 bit for GNU version of general dynamic thread local data
R_386_TLS_LDM      = 19           # Direct 32 bit for GNU version of local dynamic thread local data in LE code
R_386_16           = 20
R_386_PC16         = 21
R_386_8            = 22
R_386_PC8          = 23
R_386_TLS_GD_32    = 24           # Direct 32 bit for general dynamic thread local data
R_386_TLS_GD_PUSH  = 25           # Tag for pushl in GD TLS code
R_386_TLS_GD_CALL  = 26           # Relocation for call to __tls_get_addr()
R_386_TLS_GD_POP   = 27           # Tag for popl in GD TLS code
R_386_TLS_LDM_32   = 28           # Direct 32 bit for local dynamic thread local data in LE code
R_386_TLS_LDM_PUSH = 29           # Tag for pushl in LDM TLS code
R_386_TLS_LDM_CALL = 30           # Relocation for call to __tls_get_addr() in LDM code
R_386_TLS_LDM_POP  = 31           # Tag for popl in LDM TLS code
R_386_TLS_LDO_32   = 32           # Offset relative to TLS block
R_386_TLS_IE_32    = 33           # GOT entry for negated static TLS block offset
R_386_TLS_LE_32    = 34           # Negated offset relative to static TLS block
R_386_TLS_DTPMOD32 = 35           # ID of module containing symbol
R_386_TLS_DTPOFF32 = 36           # Offset in TLS block
R_386_TLS_TPOFF32  = 37           # Negated offset in static TLS block
# Keep this the last entry. 
R_386_NUM          = 38

if __name__ == "__main__":
    import sys
    ELFFILE = sys.stdin
    if len(sys.argv) > 1:
        ELFFILE = open(sys.argv[1])
    ehdr = Ehdr._from_file(ELFFILE)

    ELFFILE.seek(ehdr.phoff)
    phdr = Phdr._from_file(ELFFILE)
    
    ELFFILE.seek(ehdr.shoff)
    shdr = Shdr._from_file(ELFFILE)
    
    for i in range(ehdr.shnum):
        ELFFILE.seek(ehdr.shoff+i*ehdr.shentsize)
        shdr = Shdr._from_file(ELFFILE)
        print "%(name)08x %(flags)x %(addr)08x %(offset)08x" % shdr
    
        
    


    
    
