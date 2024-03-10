from elfesteem.macho.common import *
from elfesteem.cstruct import convert_size2type, Constants, CBase, CArray
import struct

constants = {}
def SetConstants(**kargs):
    Constants(globs = globals(), table = constants, **kargs)

#### Source: /usr/include/mach-o/loader.h

# * In loader.h, there are two data structures: mach_header and mach_header_64, which are merged in one structure below.
class mach_header(CStruct):
    _fields = [
        ("magic","u32"),      # mach magic number identifier
        ("cputype","u32"),    # cpu specifier
        ("cpusubtype","u32"), # machine specifier
        ("filetype","u32"),   # type of file
        ("ncmds","u32"),      # number of load commands
        ("sizeofcmds","u32"), # the size of all the load commands
        ("flags","ptr"),      # flags
        ]
    def __init__(self, *args, **kargs):
        CStruct.__init__(self, *args, **kargs)
        if self.magic not in (MH_MAGIC, MH_MAGIC_64):
            raise ValueError('Not a little-endian Mach-O')
        if self.parent.interval is not None :
            self.parent.interval.delete(0,24+self.wsize//8)

import sys
if sys.version_info[0:2] == (2, 3):
    SetConstants(
    name = 'MH_MAGIC',
    MH_MAGIC    =    eval("0xfeedfaceL"),
    MH_CIGAM    =    eval("0xcefaedfeL"),
    MH_MAGIC_64 =    eval("0xfeedfacfL"),
    MH_CIGAM_64 =    eval("0xcffaedfeL"),
    )
else:
    SetConstants(
    name = 'MH_MAGIC',
    MH_MAGIC    =    0xfeedface, #     /* the mach magic number */
    MH_CIGAM    =    0xcefaedfe, #     /* NXSwapInt(MH_MAGIC) */
    MH_MAGIC_64 =    0xfeedfacf, #     /* the 64-bit mach magic number */
    MH_CIGAM_64 =    0xcffaedfe, #     /* NXSwapInt(MH_MAGIC_64) */
    )

SetConstants(
# Constants for the "filetype" field
name = 'MH_FILETYPE',
MH_OBJECT       = 0x1,  # relocatable object file
MH_EXECUTE      = 0x2,  # demand paged executable file
MH_FVMLIB       = 0x3,  # fixed VM shared library file
MH_CORE         = 0x4,  # core file
MH_PRELOAD      = 0x5,  # preloaded executable file
MH_DYLIB        = 0x6,  # dynamically bound shared library
MH_DYLINKER     = 0x7,  # dynamic link editor
MH_BUNDLE       = 0x8,  # dynamically bound bundle file
MH_DYLIB_STUB   = 0x9,  # shared library stub for static linking only, no section contents
MH_DSYM         = 0xa,  # companion file with only debug sections
MH_KEXT_BUNDLE  = 0xb,  # x86_64 kexts
)

SetConstants(
# Constant bits for the "flags" field
name = 'MH_FLAGS',
MH_NOUNDEFS                = 0x00000001,
MH_INCRLINK                = 0x00000002,
MH_DYLDLINK                = 0x00000004,
MH_BINDATLOAD              = 0x00000008,
MH_PREBOUND                = 0x00000010,
MH_SPLIT_SEGS              = 0x00000020,
MH_LAZY_INIT               = 0x00000040,
MH_TWOLEVEL                = 0x00000080,
MH_FORCE_FLAT              = 0x00000100,
MH_NOMULTIDEFS             = 0x00000200,
MH_NOFIXPREBINDING         = 0x00000400,
MH_PREBINDABLE             = 0x00000800,
MH_ALLMODSBOUND            = 0x00001000,
MH_SUBSECTIONS_VIA_SYMBOLS = 0x00002000,
MH_CANONICAL               = 0x00004000,
MH_WEAK_DEFINES            = 0x00008000,
MH_BINDS_TO_WEAK           = 0x00010000,
MH_ALLOW_STACK_EXECUTION   = 0x00020000,
MH_ROOT_SAFE               = 0x00040000,
MH_SETUID_SAFE             = 0x00080000,
MH_NO_REEXPORTED_DYLIBS    = 0x00100000,
MH_PIE                     = 0x00200000,
MH_DEAD_STRIPPABLE_DYLIB   = 0x00400000,
MH_HAS_TLV_DESCRIPTORS     = 0x00800000,
MH_NO_HEAP_EXECUTION       = 0x01000000,
MH_APP_EXTENSION_SAFE      = 0x02000000,
)

# The load commands directly follow the mach_header.  The total size of all
# of the commands is given by the sizeofcmds field in the mach_header.  All
# load commands must have as their first two fields cmd and cmdsize.  The cmd
# field is filled in with a constant for that command type.  Each command type
# has a structure specifically for it.  The cmdsize field is the size in bytes
# of the particular load command structure plus anything that follows it that
# is a part of the load command (i.e. section structures, strings, etc.).  To
# advance to the next load command the cmdsize can be added to the offset or
# pointer of the current load command.  The cmdsize for 32-bit architectures
# MUST be a multiple of 4 bytes and for 64-bit architectures MUST be a multiple
# of 8 bytes (these are forever the maximum alignment of any load commands).
# The padded bytes must be zero.  All tables in the object file must also
# follow these rules so the file can be memory mapped.  Otherwise the pointers
# to these tables will not work well or at all on some machines.  With all
# padding zeroed like objects will compare byte for byte.
class load_command(CStruct):
    _fields = [
        ("cmd","u32"),     # type of load command
        ("cmdsize","u32"), # total size of command in bytes
        ]

# Hereafter, elfesteem creates 'LoadCommand' which registers all known
# load commands.
from elfesteem.cstruct import CStruct_metaclass
class LoadMetaclass(CStruct_metaclass):
    registered = {}
    def __new__(cls, name, bases, dct):
        if '_fields' in dct:
            # Those fields are common to all commands, we insert them here.
            dct['_fields'][:0] = load_command._fields
        if '_offsets_in_data' in dct:
            # There is some additional data in a variable-length load command
            fmt = ''.join([convert_size2type(t,None) for _, t in dct['_fields']])
            s = struct.calcsize(fmt)
            dct['_fields'].append( ("data",CData(lambda _,s=s:_.cmdsize-s)) )
            def get_in_data(self, f=None, s=0):
                value = getattr(self, f)
                if value < s:
                    return None
                data = self.data.pack()
                if f == "linked_modules":
                    data, = struct.unpack("B", data[value-s:value-s+1])
                    data = [str((data&(1<<i))>>i) for i in range(min(8,self.nmodules))]
                    return ''.join(data) + '...'
                else:
                    data = data[(value-s):data.index(data_null,value-s)]
                    return str(data.decode('latin1'))
            for f in dct['_offsets_in_data']:
                dct['str_'+f] = property(lambda _,f=f,s=s:
                                    get_in_data(_,f=f,s=s))
        o = CStruct_metaclass.__new__(cls, name, bases, dct)
        # Parse the list of load commands for this data structure.
        for cmd in dct.get('lc_types',()):
            assert not cmd in LoadCommand.registered
            LoadCommand.registered[cmd] = o
        return o
    # These two lines give the same result.
    #   LoadCommand(parent=p, content=c, start=o)
    #   LoadCommand.registered[cmd](parent=p, content=c, start=o)
    # We can also create a load command with default content
    #   LoadCommand(sex='<', wsize=32, cmd=LC_SEGMENT)
    def __call__(cls, *args, **kargs):
        if 'cmd' in kargs:
            if not 'parent' in kargs: kargs['parent'] = None
            cmd = struct.pack("I",kargs['cmd'])
        else:
            c = kargs['content']
            o = kargs.get('start',0)
            cmd = c[o:o+4]
        p = kargs['parent']
        sex = kargs.get('sex',getattr(p,'sex',''))
        if len(cmd) >= 4: cmd, = struct.unpack(sex+"I",cmd)
        else:             cmd = 0
        if not 'cmd' in kargs:
            # Early test that 'cmdsize' has a valid value
            cmdsize = c[o+4:o+8]
            if len(cmdsize) < 4:
                raise ValueError("cmdsize after end of file")
            cmdsize, = struct.unpack(sex+"I",cmdsize)
            if cmdsize < 8:
                log.error("load command %d with size less than 8 bytes", len(p))
            if hasattr(p, 'parent'):
                if o+cmdsize > p.offset+p.parent.Mhdr.sizeofcmds:
                    log.error("load command %d bigger than sizeofcmds", len(p))
                if p.parent.interval is not None and not p.parent.interval.contains(o,o+cmdsize):
                    raise ValueError("Parsing cmd %d of size %d reads a part of the file that has already been parsed" % (cmd, cmdsize))
        if cmd in cls.lc_types:
            # A subclass of LoadCommand has been used
            lh = super(LoadMetaclass,cls).__call__(*args, **kargs)
        elif len(cls.lc_types):
            # A subclass of LoadCommand has been used, with an incoherent cmd
            # We don't use the class name, because one class may correspond
            # to many values for cmd.
            log.warning("Incoherent input cmd=%#x for %s", cmd, cls.__name__)
            lh = super(LoadMetaclass,cls).__call__(*args, **kargs)
        elif cmd in LoadCommand.registered:
            # LoadCommand has been used with a known cmd
            lh = LoadCommand.registered[cmd](*args, **kargs)
        else:
            # LoadCommand has been used with an unknown cmd
            lh = super(LoadMetaclass,cls).__call__(*args, **kargs)
        if not 'content' in kargs:
            lh.cmdsize = lh.bytelen
        else:
            assert c[o:o+lh.bytelen] == lh.pack()
        return lh
LoadBase = LoadMetaclass('LoadBase', (CStruct,), {})

from elfesteem.cstruct import CData
class LoadCommand(LoadBase):
    # A generic load command may have arbitrary data following
    # the first two values 'cmd' and 'cmdsize'.
    # Note that this is not sufficient when the load command
    # should trigger the analysis of sections, referred by their
    # offset in the file.
    lc_types = ()
    _fields = [ ("data",CData(lambda _:max(0,_.cmdsize-8))) ]
    def changeOffsets(self, decalage, min_offset=None):
        pass
    def otool(self, llvm=False):
        # Output similar to llvm-otool (depending on llvm version)
        # Cf. https://opensource.apple.com/source/cctools/cctools-895/otool/ofile_print.c
        # and others
        import time
        lc_value = []
        shift = 1
        for name, f_type in self._fields:
            value = getattr(self, name)
            if   name == "cmd":
                value = "LC_"+constants['LC'].get(self.cmd, hex(self.cmd))
            elif name == "cmdsize":
                pass
            elif name in getattr(self, '_offsets_in_data', []):
                data = getattr(self, 'str_'+name)
                if data is None: value = "?(bad offset %u)" % value
                else:            value = "%s (offset %u)" % (data, value)
                name = "%12s" % name
            elif name in ["vmaddr", "vmsize"]:
                if self.cmd == LC_SEGMENT_64: value = "%#018x" % value
                else:                         value = "%#010x" % value
            elif name in ["maxprot", "initprot", "cksum", "header addr"]:
                value = "%#010x" % value
            elif name == "flags":
                value = "%#x" % value
            elif name in ("sdk", "minos"):
                if value == 0:
                    value = "n/a"
                else:
                    value = split_integer(value, 8, 3, truncate=1)
            elif name == "tools":
                for tool in value:
                    value = tool.tool
                    lc_value.append(('tool', value))
                    value = split_integer(tool.version, 8, 3, truncate=2)
                    lc_value.append(('version', value))
            elif name == "timestamp":
                name = "time stamp"
                value = "%u %s" %(value, time.ctime(value))
            elif name in ["current_version", "compatibility_version"]:
                shift = 0
                name = name[:-8]
                value = "version " + split_integer(value, 8, 3)
            elif name == "pad_segname":
                name = "segname"
                value = str(value.rstrip(data_null).decode('latin1'))
            elif name == "raw_uuid":
                name = "uuid"
                value = "%.8X-%.4X-%.4X-%.4X-%.4X%.8X" % self.uuid
            elif self.cmd in version_min_command.lc_types:
                shift = 2
                value = split_integer(value, 8, 3, truncate=2)
            elif self.cmd == LC_SOURCE_VERSION:
                shift = 2
                value = split_integer(value, 10, 5, truncate=2)
            elif self.cmd == LC_ENCRYPTION_INFO:
                shift = 4
            elif self.cmd in (LC_THREAD, LC_UNIXTHREAD):
                shift = 4
                # Display text values if they are the expected ones.
                if name == "flavor" and not 'unknown' in self.flavorname:
                    value = self.flavorname
                if name == "count"  and not 'unknown' in self.flavorname:
                    value = self.flavorcount
            if isinstance(f_type, str):
                lc_value.append((name, value))
        # otool displays lc_value with a nice alignment
        name_max_len = 0
        for name, _ in lc_value:
            if name_max_len < len(name):
                name_max_len = len(name)
        format = "%%%ds %%s" % (name_max_len+shift)
        return [format % _ for _ in lc_value]
        # NB: for some load commands, additional information will be displayed

def split_integer(v, nbits, ndigits, truncate=None):
    mask = (1<<nbits)-1
    res = []
    while ndigits > 0:
        res.insert(0, v & mask)
        v = v >> nbits
        ndigits -= 1
    res[0] += v << nbits
    if truncate is not None:
        while len(res) > truncate and res[-1] == 0:
            res = res[:-1]
    return ".".join(["%u"%_ for _ in res])

# After MacOS X 10.1 when a new load command is added that is required to be
# understood by the dynamic linker for the image to execute properly the
# LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
# linker sees such a load command it it does not understand will issue a
# "unknown load command required for execution" error and refuse to use the
# image.  Other load commands without this bit that are not understood will
# simply be ignored.
if sys.version_info[0:2] == (2, 3):
    LC_REQ_DYLD = eval("0x80000000L")
else:
    LC_REQ_DYLD = 0x80000000

SetConstants(
LC_SEGMENT         = 0x1,   # segment of this file to be mapped
LC_SYMTAB          = 0x2,   # link-edit stab symbol table info
LC_SYMSEG          = 0x3,   # link-edit gdb symbol table info (obsolete)
LC_THREAD          = 0x4,   # thread
LC_UNIXTHREAD      = 0x5,   # unix thread (includes a stack)
LC_LOADFVMLIB      = 0x6,   # load a specified fixed VM shared library
LC_IDFVMLIB        = 0x7,   # fixed VM shared library identification
LC_IDENT           = 0x8,   # object identification info (obsolete)
LC_FVMFILE         = 0x9,   # fixed VM file inclusion (internal use)
LC_PREPAGE         = 0xa,   # prepage command (internal use)
LC_DYSYMTAB        = 0xb,   # dynamic link-edit symbol table info
LC_LOAD_DYLIB      = 0xc,   # load a dynamically linked shared library
LC_ID_DYLIB        = 0xd,   # dynamically linked shared lib ident
LC_LOAD_DYLINKER   = 0xe,   # load a dynamic linker
LC_ID_DYLINKER     = 0xf,   # dynamic linker identification
LC_PREBOUND_DYLIB  = 0x10,  # modules prebound for a dynamically linked shared library
LC_ROUTINES        = 0x11,  # image routines
LC_SUB_FRAMEWORK   = 0x12,  # sub framework
LC_SUB_UMBRELLA    = 0x13,  # sub umbrella
LC_SUB_CLIENT      = 0x14,  # sub client
LC_SUB_LIBRARY     = 0x15,  # sub library
LC_TWOLEVEL_HINTS  = 0x16,  # two-level namespace lookup hints
LC_PREBIND_CKSUM   = 0x17,  # prebind checksum
LC_LOAD_WEAK_DYLIB = 0x18|LC_REQ_DYLD,  # load a dynamically linked shared library that is allowed to be missing (all symbols are weak imported)
LC_SEGMENT_64      = 0x19,  # 64-bit segment of this file to be mapped
LC_ROUTINES_64     = 0x1a,  # 64-bit image routines
LC_UUID            = 0x1b,  # the uuid
LC_RPATH           = 0x1c|LC_REQ_DYLD,  # runpath additions
LC_CODE_SIGNATURE  = 0x1d,  # local of code signature
LC_SEGMENT_SPLIT_INFO  = 0x1e, # local of info to split segments
LC_REEXPORT_DYLIB  = 0x1f|LC_REQ_DYLD,  # load and re-export dylib
LC_LAZY_LOAD_DYLIB = 0x20,  # delay load of dylib until first use
LC_ENCRYPTION_INFO = 0x21,  # encrypted segment information
LC_DYLD_INFO       = 0x22,  # compressed dyld information
LC_DYLD_INFO_ONLY  = 0x22|LC_REQ_DYLD,  # compressed dyld information only
LC_LOAD_UPWARD_DYLIB   = 0x23|LC_REQ_DYLD, # load upward dylib
LC_VERSION_MIN_MACOSX  = 0x24, # build for MacOSX min OS version
LC_VERSION_MIN_IPHONEOS= 0x25, # build for iPhoneOS min OS version
LC_FUNCTION_STARTS = 0x26,  # compressed table of function start addresses
LC_DYLD_ENVIRONMENT= 0x27,  # string for dyld to treat like environment variable
LC_MAIN            = 0x28|LC_REQ_DYLD,  # replacement for LC_UNIXTHREAD
LC_DATA_IN_CODE    = 0x29,  # table of non-instructions in __text
LC_SOURCE_VERSION  = 0x2A,  # source version used to build binary
LC_DYLIB_CODE_SIGN_DRS = 0x2B, # Code signing DRs copied from linked dylibs
LC_ENCRYPTION_INFO_64  = 0x2C, # 64-bit encrypted segment information
LC_LINKER_OPTION       = 0x2D, # linker options in MH_OBJECT files
LC_LINKER_OPTIMIZATION_HINT = 0x2E, # optimization hints in MH_OBJECT files
LC_VERSION_MIN_TVOS    = 0x2F,
LC_VERSION_MIN_WATCHOS = 0x30,
LC_NOTE            = 0x31, # arbitrary data included within a Mach-O file
LC_BUILD_VERSION   = 0x32, # build for platform min OS version
LC_DYLD_EXPORTS_TRIE  = 0x33|LC_REQ_DYLD, # used with linkedit_data_command, payload is trie
LC_DYLD_CHAINED_FIXUPS= 0x34|LC_REQ_DYLD, # used with linkedit_data_command
)

# * In loader.h, there are two data structures: section and section_64, which are merged in one structure below.
class sectionHeader(CStruct):
    _namelen = 16
    _fields = [
        ("pad_sectname","%ds"%_namelen), # name of this section
        ("pad_segname","%ds"%_namelen),  # segment this section goes in
        ("addr","ptr"),      # memory address of this section
        ("size","ptr"),      # size in bytes of this section
        ("offset","u32"),    # file offset of this section
        ("align","u32"),     # section alignment (power of 2)
        ("reloff","u32"),    # file offset of relocation entries
        ("nreloc","u32"),    # number of relocation entries
        ("flags","u32"),     # flags (section type and attributes)
        ("reserved1","u32"), # reserved (for offset or index)
        ("reserved2","ptr"), # reserved (for count or sizeof)
        ]
    def __str__(self):
        return "%-30s %#010x %#010x %#010x" % (self.name, self.addr, self.offset, self.size)
    def get_type(self):
        return self.flags & SECTION_TYPE
    def set_type(self, val):
        self.flags = (val & SECTION_TYPE) | self.flags
    type = property(get_type, set_type)
    def get_attributes(self):
        return self.flags & SECTION_ATTRIBUTES
    def set_attributes(self, val):
        self.flags = (val & SECTION_ATTRIBUTES) | self.type
    attributes = property(get_attributes, set_attributes)
    def changeOffsets(self, decalage, min_offset=None):
        if isOffsetChangeable(self.offset, min_offset):
            self.offset += decalage
        if isOffsetChangeable(self.reloff, min_offset):
            self.reloff += decalage
    def __init__(self, *args, **kargs):
        if kargs.get('content', None) is None:
            kargs['content'] = data_empty
        CStruct.__init__(self, *args, **kargs)
        if kargs['content'] != data_empty:
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
    name = property(lambda _:"%s,%s"%(_.segname,_.sectname))
    def is_text_section(self):
        return self.sectname == "__text"
    all_flags = property(lambda _:_.flags) # Backwards compatibility

SetConstants(
prefix = 'S_',
# Constants for the type of a section
SECTION_TYPE                    = 0x000000ff, # Up to 256 section types
S_REGULAR                             = 0x00, # regular section
S_ZEROFILL                            = 0x01, # zero fill on demand section
S_CSTRING_LITERALS                    = 0x02, # section with only literal C strings
S_4BYTE_LITERALS                      = 0x03, # section with only 4 byte literals
S_8BYTE_LITERALS                      = 0x04, # section with only 8 byte literals
S_LITERAL_POINTERS                    = 0x05, # section with only pointers to literals
S_NON_LAZY_SYMBOL_POINTERS            = 0x06, # section with only non-lazy symbol pointers
S_LAZY_SYMBOL_POINTERS                = 0x07, # section with only lazy symbol pointers
S_SYMBOL_STUBS                        = 0x08, # section with only symbol stubs, byte size of stub in the reserved2 field
S_MOD_INIT_FUNC_POINTERS              = 0x09, # section with only function pointers for initialization
S_MOD_TERM_FUNC_POINTERS              = 0x0a, # section with only function pointers for termination
S_COALESCED                           = 0x0b, # section contains symbols that are to be coalesced
S_GB_ZEROFILL                         = 0x0c, # zero fill on demand section (that can be larger than 4 gigabytes)
S_INTERPOSING                         = 0x0d, # section with only pairs of function pointers for interposing
S_16BYTE_LITERALS                     = 0x0e, # section with only 16 byte literals
S_DTRACE_DOF                          = 0x0f, # section contains DTrace Object Format
S_LAZY_DYLIB_SYMBOL_POINTERS          = 0x10, # section with only lazy symbol pointers to lazy loaded dylibs
S_THREAD_LOCAL_REGULAR                = 0x11, # template of initial values for TLVs
S_THREAD_LOCAL_ZEROFILL               = 0x12, # template of initial values for TLVs
S_THREAD_LOCAL_VARIABLES              = 0x13, # TLV descriptors
S_THREAD_LOCAL_VARIABLE_POINTERS      = 0x14, # pointers to TLV descriptors
S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15, # functions to call to initialize TLV values
)

SetConstants(
prefix = 'S_ATTR',
# Constants for the section attributes part of the flags field of a section structure.
SECTION_ATTRIBUTES         = 0xffffff00, # Up to 24 section attributes
SECTION_ATTRIBUTES_USR     = 0xff000000, # User setable attributes
S_ATTR_PURE_INSTRUCTIONS   = 0x80000000, #  section contains only true machine instructions
S_ATTR_NO_TOC              = 0x40000000, #  section contains coalesced symbols that are not to be in a ranlib table of contents
S_ATTR_STRIP_STATIC_SYMS   = 0x20000000, #  ok to strip static symbols in this section in files with the MH_DYLDLINK flag
S_ATTR_NO_DEAD_STRIP       = 0x10000000, #  no dead stripping
S_ATTR_LIVE_SUPPORT        = 0x08000000, #  blocks are live if they reference live blocks
S_ATTR_SELF_MODIFYING_CODE = 0x04000000, #  Used with i386 code stubs written on by dyld
S_ATTR_DEBUG               = 0x02000000, #  A debug section
SECTION_ATTRIBUTES_SYS     = 0x00ffff00, # system setable attributes
S_ATTR_SOME_INSTRUCTIONS   = 0x00000400, #  Section contains some machine instructions
S_ATTR_EXT_RELOC           = 0x00000200, #  Section has external relocation entries
S_ATTR_LOC_RELOC           = 0x00000100, #  Section has local relocation entries
)

# The currently known segment names and the section names in those segments
SEG_PAGEZERO      = "__PAGEZERO"      # the pagezero segment which has no protections and catches NULL references for MH_EXECUTE files
SEG_TEXT          = "__TEXT"          # the tradition UNIX text segment
SECT_TEXT         = "__text"          # - the real text part of the text section no headers, and no padding
SECT_FVMLIB_INIT0 = "__fvmlib_init0"  # - the fvmlib initialization section
SECT_FVMLIB_INIT1 = "__fvmlib_init1"  # - the section following the fvmlib initialization section
SEG_DATA          = "__DATA"          # the tradition UNIX data segment
SECT_DATA         = "__data"          # - the real initialized data section no padding, no bss overlap
SECT_BSS          = "__bss"           # - the real uninitialized data section no padding
SECT_COMMON       = "__common"        # - the section common symbols are allocated in by the link editor
SEG_OBJC          = "__OBJC"          # objective-C runtime segment
SECT_OBJC_SYMBOLS = "__symbol_table"  # - symbol table
SECT_OBJC_MODULES = "__module_info"   # - module information
SECT_OBJC_STRINGS = "__selector_strs" # - string table
SECT_OBJC_REFS    = "__selector_refs" # - string table
SEG_ICON          = "__ICON"          # the icon segment
SECT_ICON_HEADER  = "__header"        # - the icon headers
SECT_ICON_TIFF    = "__tiff"          # - the icons in tiff format
SEG_LINKEDIT      = "__LINKEDIT"      # the segment containing all structs created and maintained by the link editor.
                                      #  Created with -seglinkedit option to ld(1) for MH_EXECUTE and FVMLIB file types only
SEG_UNIXSTACK     = "__UNIXSTACK"     # the unix stack segment
SEG_IMPORT        = "__IMPORT"        # the segment for the self (dyld) modifing code stubs that has read, write and execute permissions

# The segment load command indicates that a part of this file is to be
# mapped into the task's address space.  The size of this segment in memory,
# vmsize, maybe equal to or larger than the amount to map from this file,
# filesize.  The file is mapped starting at fileoff to the beginning of
# the segment in memory, vmaddr.  The rest of the memory of the segment,
# if any, is allocated zero fill on demand.  The segment's maximum virtual
# memory protection and initial virtual memory protection are specified
# by the maxprot and initprot fields.  If the segment has sections then the
# section structures directly follow the segment command and their size is
# reflected in cmdsize.
# * In loader.h, there are two data structures: segment_command and segment_command_64, which are merged in one structure below.
class sectionHeaderArray(CArray):
    _cls = sectionHeader
    count = lambda _:_.parent.nsects
class segment_command(LoadCommand):
    lc_types = (LC_SEGMENT, LC_SEGMENT_64)
    _namelen = 16
    _fields = [
        ("pad_segname","%ds"%_namelen), # segment name
        ("vmaddr","ptr"),   # memory address of this segment
        ("vmsize","ptr"),   # memory size of this segment
        ("fileoff","ptr"),  # file offset of this segment
        ("filesize","ptr"), # amount to map from the file
        ("maxprot","u32"),  # maximum VM protection
        ("initprot","u32"), # initial VM protection
        ("nsects","u32"),   # number of sections in segment
        ("flags","u32"),    # flags
        ("sh",sectionHeaderArray),
        ]
    def get_segname(self):
        return bytes_to_name(self.pad_segname).strip('\0')
    def set_segname(self, val):
        padding = self._namelen - len(val)
        if (padding < 0) : raise ValueError("segname is too long for the structure")
        self.pad_segname = name_to_bytes(val)+data_null*padding
    segname = property(get_segname, set_segname)
    def otool(self, llvm=False):
        res = LoadCommand.otool(self, llvm=llvm)
        e = self.parent.parent
        self.sectionsToAdd(e.content)
        for s in self.sect:
            if hasattr(s, 'reloclist') :
                continue
            res.append("Section")
            res.append("  sectname %.16s" %s.parent.sectname)
            res.append("   segname %.16s" %s.parent.segname)
            if self.cmd == LC_SEGMENT_64: fmt = "%#018x"
            else:                         fmt = "%#010x"
            res.append(("      addr "+fmt) %s.parent.addr)
            if (not llvm or llvm in (8, 9, 10, 11)) and s.parent.offset + s.parent.size > len(e.content):
                fmt += " (past end of file)"
            res.append(("      size "+fmt) %s.parent.size)
            res.append("    offset %u" %s.parent.offset)
            res.append("     align 2^%u (%d)" %(s.parent.align, 1 << s.parent.align))
            res.append("    reloff %u" %s.parent.reloff)
            res.append("    nreloc %u" %s.parent.nreloc)
            res.append("     flags %#010x" %s.parent.flags)
            comment1 = ""
            if s.parent.type in (
                    S_SYMBOL_STUBS,
                    S_LAZY_SYMBOL_POINTERS,
                    S_NON_LAZY_SYMBOL_POINTERS,
                    S_LAZY_DYLIB_SYMBOL_POINTERS):
                comment1 = " (index into indirect symbol table)"
            res.append(" reserved1 %u%s" %(s.parent.reserved1,comment1))
            comment2 = ""
            if s.parent.type == S_SYMBOL_STUBS:
                comment2 = " (size of stubs)"
            res.append(" reserved2 %u%s" %(s.parent.reserved2,comment2))
        return res
    def sectionsToAdd(self, raw):
        from elfesteem.macho.sections import Section, Reloc, SymbolStubList, SymbolPtrList
        self.sect = []
        for sh in self.sh:
            if sh.type == S_ZEROFILL or sh.type == S_THREAD_LOCAL_ZEROFILL or sh.type == S_GB_ZEROFILL:
                sh.sect = Section(parent=sh, content=data_empty)
            elif sh.type == S_SYMBOL_STUBS:
                sh.sect = SymbolStubList(parent=sh, content=raw, start=sh.offset)
            elif sh.type in (S_NON_LAZY_SYMBOL_POINTERS,
                             S_LAZY_SYMBOL_POINTERS):
                sh.sect = SymbolPtrList(parent=sh, content=raw, start=sh.offset)
            else:
                # One byte of padding may be present. For data sections,
                # it is usually \x00, and can be ignored, but for text
                # sections it is ususally a nop (e.g. \x90 for x86) and
                # keeping it is is necessary if we want pack() to reconstruct
                # the file as it has been input.
                size = sh.size
                if (sh.offset+sh.size) % 2 == 1: size += 1
                sh.sect = Section(parent=sh, content=raw, start=sh.offset, size=size)
            self.sect.append(sh.sect)
        for sh in self.sh:
            if sh.reloff != 0:
                sh.reloc = Reloc(parent=sh, content=raw, start=sh.reloff)
                self.sect.append(sh.reloc)
        return self.sect
    def changeOffsets(self, decalage, min_offset=None):
        for sh in self.sh:
            sh.changeOffsets(decalage, min_offset)
        if isOffsetChangeable(self.fileoff, min_offset):
            self.fileoff += decalage
    def is_text_segment(self):
        return self.segname == "__TEXT"
    def addSH(self, s):
        maxoff = self.fileoff
        if not hasattr(self, 'sect'):
            self.sect = []
            offset = 0
            size = 0 
        if len(self.sect)>0:
            offset = 0
            size = 0
            for se in self.sect:
                if offset < se.offset :
                    offset = se.offset
                    size = se.size
            maxoff = offset + size
        self.nsects += 1
        self.cmdsize += len(s.parent.pack())
        self._size = self.cmdsize
        s.parent.parent = self
        s.parent.offset = maxoff 
        s.parent.addr = self.vmaddr - self.fileoff + s.parent.offset
        s.parent.align = 4
        # Values and positions by default
        self.sh.append(s.parent)
        self.sect.append(s)
        s.parent.size = len(s.pack())
        s.parent.offset = maxoff
        if offset + size > self.fileoff + self.filesize:
            raise ValueError("not enough space in segment")
            #self.parent.extendSegment(self, 0x1000*(s.parent.size/0x1000 +1))
        else:
            self.filesize += len(s.pack())
            self.vmsize += len(s.pack())   

SetConstants(
# Constants for the flags field of the segment_command
SG_HIGHVM              = 0x1, # the file contents for this segment is for the high part of the VM space, the low part is zero filled (for stacks in core files)
SG_FVMLIB              = 0x2, # this segment is the VM that is allocated by a fixed VM library, for overlap checking in the link editor
SG_NORELOC             = 0x4, # this segment has nothing that was relocated in it and nothing relocated to it, that is it maybe safely replaced without relocation
SG_PROTECTED_VERSION_1 = 0x8, # This segment is protected.  If the segment starts at file offset 0, the first page of the segment is not protected.  All other pages of the segment are protected.
)


# Fixed virtual memory shared libraries are identified by two things.  The
# target pathname (the name of the library as found for execution), and the
# minor version number.  The address of where the headers are loaded is in
# header_addr. (THIS IS OBSOLETE and no longer supported).
class fvmlib_command(LoadCommand):
    lc_types = (LC_IDFVMLIB, LC_LOADFVMLIB, LC_FVMFILE)
    _offsets_in_data = ("name",)
    _fields = [
        ("name","u32"),          # library's target pathname
        ("minor_version","u32"), # library's minor version number
        ("header_addr","u32"),   # library's header address
        ]

# A dynamically linked shared library (filetype == MH_DYLIB in the mach header)
# contains a dylib_command (cmd == LC_ID_DYLIB) to identify the library.
# An object that uses a dynamically linked shared library also contains a
# dylib_command (cmd == LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, or
# LC_REEXPORT_DYLIB) for each library it uses.
class dylib_command(LoadCommand):
    lc_types = (LC_LOAD_DYLIB, LC_LAZY_LOAD_DYLIB, LC_ID_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_WEAK_DYLIB, LC_LOAD_UPWARD_DYLIB)
    _offsets_in_data = ("name",)
    _fields = [
        ("name","u32"),                  # library's path name
        ("timestamp","u32"),             # library's build time stamp
        ("current_version","u32"),       # library's current version
        ("compatibility_version","u32"), # library's compatibility vers number
        ]

# A dynamically linked shared library may be a subframework of an umbrella
# framework.  If so it will be linked with "-umbrella umbrella_name" where
# Where "umbrella_name" is the name of the umbrella framework. A subframework
# can only be linked against by its umbrella framework or other subframeworks
# that are part of the same umbrella framework.  Otherwise the static link
# editor produces an error and states to link against the umbrella framework.
# The name of the umbrella framework for subframeworks is recorded in the
# following structure.
class sub_framework_command(LoadCommand):
    lc_types = (LC_SUB_FRAMEWORK,)
    _offsets_in_data = ("umbrella",)
    _fields = [ ("umbrella","u32") ] # the umbrella framework name

# For dynamically linked shared libraries that are subframework of an umbrella
# framework they can allow clients other than the umbrella framework or other
# subframeworks in the same umbrella framework.  To do this the subframework
# is built with "-allowable_client client_name" and an LC_SUB_CLIENT load
# command is created for each -allowable_client flag.  The client_name is
# usually a framework name.  It can also be a name used for bundles clients
# where the bundle is built with "-client_name client_name".
class sub_client_command(LoadCommand):
    lc_types = (LC_SUB_CLIENT,)
    _offsets_in_data = ("client",)
    _fields = [ ("client","u32") ] # the client name

# A dynamically linked shared library may be a sub_umbrella of an umbrella
# framework.  If so it will be linked with "-sub_umbrella umbrella_name" where
# Where "umbrella_name" is the name of the sub_umbrella framework.  When
# staticly linking when -twolevel_namespace is in effect a twolevel namespace 
# umbrella framework will only cause its subframeworks and those frameworks
# listed as sub_umbrella frameworks to be implicited linked in.  Any other
# dependent dynamic libraries will not be linked it when -twolevel_namespace
# is in effect.  The primary library recorded by the static linker when
# resolving a symbol in these libraries will be the umbrella framework.
# Zero or more sub_umbrella frameworks may be use by an umbrella framework.
# The name of a sub_umbrella framework is recorded in the following structure.
class sub_umbrella_command(LoadCommand):
    lc_types = (LC_SUB_UMBRELLA,)
    _offsets_in_data = ("sub_umbrella",)
    _fields = [ ("sub_umbrella","u32") ] # the sub_umbrella framework name

# A dynamically linked shared library may be a sub_library of another shared
# library.  If so it will be linked with "-sub_library library_name" where
# Where "library_name" is the name of the sub_library shared library.  When
# staticly linking when -twolevel_namespace is in effect a twolevel namespace 
# shared library will only cause its subframeworks and those frameworks
# listed as sub_umbrella frameworks and libraries listed as sub_libraries to
# be implicited linked in.  Any other dependent dynamic libraries will not be
# linked it when -twolevel_namespace is in effect.  The primary library
# recorded by the static linker when resolving a symbol in these libraries
# will be the umbrella framework (or dynamic library). Zero or more sub_library
# shared libraries may be use by an umbrella framework or (or dynamic library).
# The name of a sub_library framework is recorded in the following structure.
# For example /usr/lib/libobjc_profile.A.dylib would be recorded as "libobjc".
class sub_library_command(LoadCommand):
    lc_types = (LC_SUB_LIBRARY,)
    _offsets_in_data = ("sub_library",)
    _fields = [ ("sub_library","u32") ] # the sub_library name

# A program (filetype == MH_EXECUTE) that is
# prebound to its dynamic libraries has one of these for each library that
# the static linker used in prebinding.  It contains a bit vector for the
# modules in the library.  The bits indicate which modules are bound (1) and
# which are not (0) from the library.  The bit for module 0 is the low bit
# of the first byte.  So the bit for the Nth module is:
# (linked_modules[N/8] >> N%8) & 1
class prebound_dylib_command(LoadCommand):
    lc_types = (LC_PREBOUND_DYLIB,)
    _offsets_in_data = ("name","linked_modules")
    _fields = [
        ("name","u32"),           # library's path name
        ("nmodules","u32"),       # number of modules in library
        ("linked_modules","u32"), # bit vector of linked modules
        ]

# A program that uses a dynamic linker contains a dylinker_command to identify
# the name of the dynamic linker (LC_LOAD_DYLINKER).  And a dynamic linker
# contains a dylinker_command to identify the dynamic linker (LC_ID_DYLINKER).
# A file can have at most one of these.
# This struct is also used for the LC_DYLD_ENVIRONMENT load command and
# contains string for dyld to treat like environment variable.
class dylinker_command(LoadCommand):
    lc_types = (LC_DYLD_ENVIRONMENT, LC_LOAD_DYLINKER, LC_ID_DYLINKER)
    _offsets_in_data = ("name",)
    _fields = [ ("name","u32") ] # dynamic linker's path name

#### Source: /usr/include/mach-o/loader.h

# Thread commands contain machine-specific data structures suitable for
# use in the thread state primitives.  The machine specific data structures
# follow the struct thread_command as follows.
# Each flavor of machine specific data structure is preceded by an unsigned
# long constant for the flavor of that data structure, an uint32_t
# that is the count of longs of the size of the state data structure and then
# the state data structure follows.  This triple may be repeated for many
# flavors.  The constants for the flavors, counts and state data structure
# definitions are expected to be in the header file <machine/thread_status.h>.

class ThreadStateMetaclass(type):
    registered = {}
    def __new__(cls, name, bases, dct):
        o = type.__new__(cls, name, bases, dct)
        if 'cputype' in dct and 'flavor' in dct:
            ThreadStateBase.registered[(dct['cputype'],dct['flavor'])] = o
        return o
    def __call__(cls, lc):
        key = (lc.cputype, lc.flavor)
        if not hasattr(cls, 'cputype') and key in ThreadStateBase.registered:
            return ThreadStateBase.registered[key](lc)
        else:
            return super(ThreadStateMetaclass,cls).__call__(lc)

class ThreadStateBase(ThreadStateMetaclass('ThreadStateBase', (object,), {})):
    registers = []
    def __init__(self, lc):
        self.c = lc
        # When all registers have the same size, we can precompute the
        # values used in reg_slice.
        # If they don't all have the same size, we need to redefine
        # flavorcount and reg_slice.
        self.t = convert_size2type("ptr",self.c.wsize)
        self.s = self.c.wsize//8
    flavorcount = property(lambda _:_.s//4*len(_.registers))
    def reg_slice(self, pos):
        if pos in self.registers:
            pos = self.registers.index(pos)
        return self.t, slice(self.s*pos, self.s*(pos+1))
    def __getitem__(self, pos):
        if isinstance(pos, slice):
            assert pos.step is None
            return tuple([self[_] for _ in range(pos.start, pos.stop)])
        else:
            fmt, pos = self.reg_slice(pos)
            return struct.unpack(self.c.sex + fmt, self.c.state[pos])[0]
    def __setitem__(self, pos, val):
        fmt, pos = self.reg_slice(pos)
        self.c.state[pos] = struct.pack(self.c.sex + fmt, val)
    def otool(self):
        return []

#### Source: /usr/include/mach/*/{_structs.h,thread_status.h}
# The data for all known architectures can be found at
# https://github.com/opensource-apple/cctools/blob/master/include/...

class ThreadStatePPC(ThreadStateBase):
    cputype    = CPU_TYPE_POWERPC
    flavor     = 1
    flavorname = 'PPC_THREAD_STATE'
    entrypoint = 'srr0'
    registers  = ['srr0', 'srr1'] + ['r%d'%_ for _ in range(32)] + \
                 ['cr', 'xer', 'lr', 'ctr', 'mq', 'vrsave']
    def otool(self):
        return [
    "    r0  %#010x r1  %#010x r2  %#010x r3   %#010x r4   %#010x"%self[2:7],
    "    r5  %#010x r6  %#010x r7  %#010x r8   %#010x r9   %#010x"%self[7:12],
    "    r10 %#010x r11 %#010x r12 %#010x r13  %#010x r14  %#010x"%self[12:17],
    "    r15 %#010x r16 %#010x r17 %#010x r18  %#010x r19  %#010x"%self[17:22],
    "    r20 %#010x r21 %#010x r22 %#010x r23  %#010x r24  %#010x"%self[22:27],
    "    r25 %#010x r26 %#010x r27 %#010x r28  %#010x r29  %#010x"%self[27:32],
    "    r30 %#010x r31 %#010x cr  %#010x xer  %#010x lr   %#010x"%self[32:37],
    "    ctr %#010x mq  %#010x vrsave %#010x srr0 %#010x srr1 %#010x"
    % (self[37], self[38], self[39], self[0], self[1]),
            ]

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_POWERPC
    flavor     = 2
    flavorname = 'PPC_FLOAT_STATE'
    registers  = ['f%d'%_ for _ in range(32)] + [ 'fpscr' ]
    flavorcount = 66
    def reg_slice(self, pos):
        if pos in self.registers:
            pos = self.registers.index(pos)
        if pos == 32: # fpscr is 64 bits, 32 bits of rubbish
            return 'Q', slice(8*pos, 8*pos+8)
        return 'd', slice(8*pos, 8*pos+8)
    def otool(self):
        return [
    "       f0  %f    f1  %f\n       f2  %f    f3  %f"%self[0:4],
    "       f4  %f    f5  %f\n       f6  %f    f7  %f"%self[4:8],
    "       f8  %f    f9  %f\n       f10 %f    f11 %f"%self[8:12],
    "       f12 %f    f13 %f\n       f14 %f    f15 %f"%self[12:16],
    "       f16 %f    f17 %f\n       f18 %f    f19 %f"%self[16:20],
    "       f20 %f    f21 %f\n       f22 %f    f23 %f"%self[20:24],
    "       f24 %f    f25 %f\n       f26 %f    f27 %f"%self[24:28],
    "       f28 %f    f29 %f\n       f30 %f    f31 %f"%self[28:32],
    "       fpscr_pad %#x fpscr %#x"%(self[32]>>32,self[32]&0xffffffff),
            ]

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_POWERPC
    flavor     = 3
    flavorname = 'PPC_EXCEPTION_STATE'
    registers  = ['dar', 'dsisr', 'exception', 'pad0'] + ['pad1[%d]'%_ for _ in range(4)]
    def otool(self):
        return [
    "      dar 0x%x dsisr 0x%x exception 0x%x pad0 0x%x"%self[0:4],
    "      pad1[0] 0x%x pad1[1] 0x%x pad1[2] 0x%x pad1[3] 0x%x"%self[4:8],
            ]

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_POWERPC
    flavor     = 4
    flavorname = 'PPC_VECTOR_STATE'

class ThreadStatePPC64(ThreadStateBase):
    cputype    = CPU_TYPE_POWERPC64
    flavor     = 5
    flavorname = 'PPC_THREAD_STATE64'
    entrypoint = 'srr0'
    registers  = ['srr0', 'srr1'] + ['r%d'%_ for _ in range(32)] + \
                 ['cr', 'xer', 'lr', 'ctr', 'vrsave']
    # NB: cr and vrsave are 32-bit, while all other registers are 64-bit.
    flavorcount = 76
    def reg_slice(self, pos):
        if pos in self.registers:
            pos = self.registers.index(pos)
        if pos == 34: return 'I', slice(8*pos, 8*pos+4)   # 'cr' is 32-bit
        if pos == 38: return 'I', slice(8*pos-8, 8*pos-4) # 'vrsave' is 32-bit
        if 34 < pos < 38: return 'Q', slice(8*pos-4, 8*pos+4) # Shifted by 32 bits
        return 'Q', slice(8*pos, 8*(pos+1))
    def otool(self):
        return [
    "    r0  %#018x r1  %#018x r2   %#018x"%self[2:5],
    "    r3  %#018x r4  %#018x r5   %#018x"%self[5:8],
    "    r6  %#018x r7  %#018x r8   %#018x"%self[8:11],
    "    r9  %#018x r10 %#018x r11  %#018x"%self[11:14],
    "   r12  %#018x r13 %#018x r14  %#018x"%self[14:17],
    "   r15  %#018x r16 %#018x r17  %#018x"%self[17:20],
    "   r18  %#018x r19 %#018x r20  %#018x"%self[20:23],
    "   r21  %#018x r22 %#018x r23  %#018x"%self[23:26],
    "   r24  %#018x r25 %#018x r26  %#018x"%self[26:29],
    "   r27  %#018x r28 %#018x r29  %#018x"%self[29:32],
    "   r30  %#018x r31 %#018x cr   %#010x"%self[32:35],
    "   xer  %#018x lr  %#018x ctr  %#018x"%self[35:38],
    "vrsave  %#010x        srr0 %#018x srr1 %#018x"%(self[38], self[0], self[1]),
            ]

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_POWERPC64
    flavor     = 6
    flavorname = 'PPC_EXCEPTION_STATE64'

class ThreadStateX86(ThreadStateBase):
    cputype    = CPU_TYPE_I386
    flavor     = 1
    flavorname = 'x86_THREAD_STATE32' # New name
    flavorname = 'i386_THREAD_STATE'  # Legacy name
    entrypoint = 'eip'
    registers  = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp', 'esp',
                  'ss', 'eflags', 'eip', 'cs', 'ds', 'es', 'fs', 'gs']
    def otool(self):
        return [
    "\t    eax %#010x ebx    %#010x ecx %#010x edx %#010x"%self[0:4],
    "\t    edi %#010x esi    %#010x ebp %#010x esp %#010x"%self[4:8],
    "\t    ss  %#010x eflags %#010x eip %#010x cs  %#010x"%self[8:12],
    "\t    ds  %#010x es     %#010x fs  %#010x gs  %#010x"%self[12:16],
            ]

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_I386
    flavor     = 2
    flavorname = 'x86_FLOAT_STATE32' # New name
    flavorname = 'i386_FLOAT_STATE'  # Legacy name

class ThreadStateX86(ThreadStateBase):
    cputype    = CPU_TYPE_I386
    flavor     = 3
    flavorname = 'x86_EXCEPTION_STATE32' # New name
    flavorname = 'i386_EXCEPTION_STATE'  # Legacy name

class ThreadStateX64(ThreadStateBase):
    cputype    = CPU_TYPE_X86_64
    flavor     = 4
    flavorname = 'x86_THREAD_STATE64'
    entrypoint = 'rip'
    registers  = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp', 'rsp',
                  'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip',
                  'rflags', 'cs', 'fs', 'gs']
    def otool(self):
        return [
    "   rax  %#018x rbx %#018x rcx  %#018x"%self[0:3],
    "   rdx  %#018x rdi %#018x rsi  %#018x"%self[3:6],
    "   rbp  %#018x rsp %#018x r8   %#018x"%self[6:9],
    "    r9  %#018x r10 %#018x r11  %#018x"%self[9:12],
    "   r12  %#018x r13 %#018x r14  %#018x"%self[12:15],
    "   r15  %#018x rip %#018x"            %self[15:17],
    "rflags  %#018x cs  %#018x fs   %#018x"%self[17:20],
    "    gs  %#018x"                       %self[20],
            ]

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_X86_64
    flavor     = 5
    flavorname = 'x86_FLOAT_STATE64'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_X86_64
    flavor     = 6
    flavorname = 'x86_EXCEPTION_STATE64'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_I386
    flavor     = 7
    flavorname = 'x86_THREAD_STATE'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_X86_64
    flavor     = 7
    flavorname = 'x86_THREAD_STATE'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_I386
    flavor     = 8
    flavorname = 'x86_FLOAT_STATE'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_X86_64
    flavor     = 8
    flavorname = 'x86_FLOAT_STATE'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_I386
    flavor     = 9
    flavorname = 'x86_EXCEPTION_STATE'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_X86_64
    flavor     = 9
    flavorname = 'x86_EXCEPTION_STATE'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_I386
    flavor     = 10
    flavorname = 'x86_DEBUG_STATE32'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_X86_64
    flavor     = 11
    flavorname = 'x86_DEBUG_STATE64'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_I386
    flavor     = 12
    flavorname = 'x86_DEBUG_STATE'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_X86_64
    flavor     = 12
    flavorname = 'x86_DEBUG_STATE'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_I386
    flavor     = 16
    flavorname = 'x86_AVX_STATE32'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_X86_64
    flavor     = 17
    flavorname = 'x86_AVX_STATE64'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_I386
    flavor     = 18
    flavorname = 'x86_AVX_STATE'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_X86_64
    flavor     = 18
    flavorname = 'x86_AVX_STATE'

class ThreadStateARM(ThreadStateBase):
    cputype    = CPU_TYPE_ARM
    flavor     = 1
    flavorname = 'ARM_THREAD_STATE'
    entrypoint = 'pc'
    registers  = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
                  'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc', 'cpsr']
    def otool(self):
        return [
    "\t    r0  %#010x r1     %#010x r2  %#010x r3  %#010x"%self[0:4],
    "\t    r4  %#010x r5     %#010x r6  %#010x r7  %#010x"%self[4:8],
    "\t    r8  %#010x r9     %#010x r10 %#010x r11 %#010x"%self[8:12],
    "\t    r12 %#010x sp     %#010x lr  %#010x pc  %#010x"%self[12:16],
    "\t   cpsr %#010x"%self[16],
            ]

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_ARM
    flavor     = 2
    flavorname = 'ARM_VFP_STATE'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_ARM
    flavor     = 3
    flavorname = 'ARM_EXCEPTION_STATE'
    def otool(self):
        return [ "\t    exception %#010x fsr %#010x far %#010x"%self[0:3] ]

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_ARM
    # pre-armv8
    flavor     = 4
    flavorname = 'ARM_DEBUG_STATE'

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_ARM64
    flavor     = 6
    flavorname = 'ARM_THREAD_STATE64'
    entrypoint = 'pc'
    registers  = ['x%d'%_ for _ in range(29)] + ['fp', 'sp', 'lr', 'pc', 'cpsr']
    flavorcount = 68
    # NB: cpsr is 32-bit, while all other registers are 64-bit.
    # Therefore flavorcount should be 67, but the C compiler adds 32-bits
    # of padding at the end of the __darwin_arm_thread_state64 structure.
    def reg_slice(self, pos):
        if pos in self.registers:
            pos = self.registers.index(pos)
        if pos == 33: return 'I', slice(8*pos, 8*pos+4)   # 'cpsr' is 32-bit
        return 'Q', slice(8*pos, 8*(pos+1))
    def otool(self):
        return [
    "\t    x0  %#018x x1  %#018x x2  %#018x"%self[0:3],
    "\t    x3  %#018x x4  %#018x x5  %#018x"%self[3:6],
    "\t    x6  %#018x x7  %#018x x8  %#018x"%self[6:9],
    "\t    x9  %#018x x10 %#018x x11 %#018x"%self[9:12],
    "\t    x12 %#018x x13 %#018x x14 %#018x"%self[12:15],
    "\t    x15 %#018x x16 %#018x x17 %#018x"%self[15:18],
    "\t    x18 %#018x x19 %#018x x20 %#018x"%self[18:21],
    "\t    x21 %#018x x22 %#018x x23 %#018x"%self[21:24],
    "\t    x24 %#018x x25 %#018x x26 %#018x"%self[24:27],
    "\t    x27 %#018x x28 %#018x  fp %#018x"%self[27:30],
    "\t     lr %#018x sp  %#018x  pc %#018x"%self[30:33],
    "\t   cpsr %#010x"%self[33],
            ]

class ThreadState(ThreadStateBase):
    cputype    = CPU_TYPE_ARM64
    flavor     = 7
    flavorname = 'ARM_EXCEPTION_STATE64'
    def otool(self):
        return [ "\t    far %#018x esr %#010x exception %#010x"
                 % (self[0], self[1]>>32, self[1]&0xFFFFFFFF) ]

class ThreadState(ThreadStateBase):
    # Default output
    flavorname = property(lambda _:'%d (unknown)'%_.c.flavor)
    def otool(self):
        return [ "      state (Unknown cputype/cpusubtype)" ]

#### Source: /usr/include/mach-o/loader.h

class thread_command(LoadCommand):
    lc_types = (LC_THREAD, LC_UNIXTHREAD)
    _fields = [
        ("flavor","u32"),     # flavor of thread state
        ("count","u32"),      # count of longs in thread state
        ("state",CData(lambda _:_.cmdsize-16)), # thread state for this flavor
        ]
    def __init__(self, *args, **kargs):
        LoadCommand.__init__(self, *args, **kargs)
        self.reg = ThreadState(self)
    def get_entrypoint(self):
        return self.reg[self.reg.entrypoint]
    def set_entrypoint(self, val):
        self.reg[self.reg.entrypoint] = val
    entrypoint = property(get_entrypoint, set_entrypoint)
    def cputype(self):
        if type(self.parent) == dict: return self.parent['cputype']
        else:                         return self.parent.parent.Mhdr.cputype
    cputype = property(cputype)
    flavorname = property(lambda _:_.reg.flavorname)
    def flavorcount(self):
        flavorcount = self.reg.flavorname+'_COUNT'
        if self.count != self.reg.flavorcount:
            flavorcount = '%d (not %s)' % (self.count, flavorcount)
        return flavorcount
    flavorcount = property(flavorcount)
    def otool(self, llvm=False):
        return LoadCommand.otool(self, llvm=llvm) + self.reg.otool()



# The routines command contains the address of the dynamic shared library
# initialization routine and an index into the module table for the module
# that defines the routine.  Before any modules are used from the library the
# dynamic linker fully binds the module that defines the initialization routine
# and then calls it.  This gets called before any module initialization
# routines (used for C++ static constructors) in the library.
# * In loader.h, there are two data structures: routines_command and routines_command_64, which are merged in one structure below.
class routines_command(LoadCommand):
    lc_types = (LC_ROUTINES, LC_ROUTINES_64)
    _fields = [
        ("init_address","ptr"),  # address of initialization routine
        ("init_module","ptr"),   # index into the module table that the init routine is defined in
        ("reserved1","ptr"),
        ("reserved2","ptr"),
        ("reserved3","ptr"),
        ("reserved4","ptr"),
        ("reserved5","ptr"),
        ("reserved6","ptr"),
        ]

# The symtab_command contains the offsets and sizes of the link-edit 4.3BSD
# "stab" style symbol table information as described in the header files
# <nlist.h> and <stab.h>.
class symtab_command(LoadCommand):
    lc_types = (LC_SYMTAB,)
    _fields = [
        ("symoff","u32"),  # symbol table offset
        ("nsyms","u32"),   # number of symbol table entries
        ("stroff","u32"),  # string table offset
        ("strsize","u32"), # string table size in bytes
        ]
    def sectionsToAdd(self, raw):
        from elfesteem.macho.sections import StringTable, SymbolTable
        self.sect = []
        # We parse the String Table first, to be able to know the names
        # of symbols.
        assert self.stroff != 0
        self.sect.append(StringTable(parent=self, content=raw, start=self.stroff))
        assert self.symoff != 0
        self.sect.append(SymbolTable(parent=self, content=raw, start=self.symoff))
        return self.sect
    strtab = property(lambda _:_.sect[0])
    def sectionsMappedInMemory(self):
        return [self]
    def changeOffsets(self, decalage, min_offset=None):
        if isOffsetChangeable(self.stroff, min_offset):
            self.stroff += decalage
        if isOffsetChangeable(self.symoff, min_offset):
            self.symoff += decalage

# This is the second set of the symbolic information which is used to support
# the data structures for the dynamically link editor.
# (...)
# The symbols indicated by symoff and nsyms of the LC_SYMTAB load command
# are grouped into the following three groups:
#    local symbols (further grouped by the module they are from)
#    defined external symbols (further grouped by the module they are from)
#    undefined symbols
# The local symbols are used only for debugging.  The dynamic binding
# process may have to use them to indicate to the debugger the local
# symbols for a module that is being bound.
# The last two groups are used by the dynamic binding process to do the
# binding (indirectly through the module table and the reference symbol
# table when this is a dynamically linked shared library file).
from elfesteem.macho.sections import DySymArray
class dysymtab_command(LoadCommand):
    lc_types = (LC_DYSYMTAB,)
    _sym = DySymArray
    _fields = [
        ("ilocalsym","u32"), # index to local symbols
        ("nlocalsym","u32"), # number of local symbols
        ("iextdefsym","u32"), # index to externally defined symbols
        ("nextdefsym","u32"), # number of externally defined symbols
        ("iundefsym","u32"), # index to undefined symbols
        ("nundefsym","u32"), # number of undefined symbols
        ("tocoff","u32"), # file offset to table of contents
        ("ntoc","u32"),   # number of entries in table of contents
        ("modtaboff","u32"), # file offset to module table
        ("nmodtab","u32"),   # number of module table entries
        ("extrefsymoff","u32"), # offset to referenced symbol table
        ("nextrefsyms","u32"),  # number of referenced symbol table entries
        ("indirectsymoff","u32"), # file offset to the indirect symbol table
        ("nindirectsyms","u32"),  # number of indirect symbol table entries
        ("extreloff","u32"), # offset to external relocation entries
        ("nextrel","u32"),   # number of external relocation entries
        ("locreloff","u32"), # offset to local relocation entries
        ("nlocrel","u32"),   # number of local relocation entries
        ]
    def sectionsToAdd(self, raw):
        self.sect = []
        for object_offset, _ in self._fields:
            if not object_offset.endswith('off'): continue
            of = getattr(self, object_offset)
            if of != 0:
                t = object_offset[:-3]
                if not t in self._sym: raise NotImplementedError
                self.sect.append(self._sym[t](parent=self, content=raw, start=of))
        return self.sect
    def changeOffsets(self, decalage, min_offset=None):
        for object_offset, _ in self._fields:
            if not object_offset.endswith('off'): continue
            of = getattr(self, object_offset)
            if isOffsetChangeable(of, min_offset):
                setattr(self, object_offset, of + decalage)

# The twolevel_hints_command contains the offset and number of hints in the
# two-level namespace lookup hints table.
class twolevel_hints_command(LoadCommand):
    lc_types = (LC_TWOLEVEL_HINTS,)
    _fields = [
        ("offset","u32"), # offset to the hint table
        ("nhints","u32"), # number of hints in the hint table
        ]
    def sectionsToAdd(self, raw):
        from elfesteem.macho.sections import Hint
        self.sect = []
        if self.offset != 0:
            self.sect.append(Hint(parent=self, content=raw, start=self.offset))
        return self.sect
    def changeOffsets(self, decalage, min_offset=None):
        if isOffsetChangeable(self.offset, min_offset):
            self.offset += decalage

# The prebind_cksum_command contains the value of the original check sum for
# prebound files or zero.  When a prebound file is first created or modified
# for other than updating its prebinding information the value of the check sum
# is set to zero.  When the file has it prebinding re-done and if the value of
# the check sum is zero the original check sum is calculated and stored in
# cksum field of this load command in the output file.  If when the prebinding
# is re-done and the cksum field is non-zero it is left unchanged from the
# input file.
class prebind_cksum_command(LoadCommand):
    lc_types = (LC_PREBIND_CKSUM,)
    _fields = [ ("cksum","u32") ] # the check sum or zero

# The uuid load command contains a single 128-bit unique random number that
# identifies an object produced by the static link editor.
class uuid_command(LoadCommand):
    lc_types = (LC_UUID,)
    _fields = [ ("raw_uuid","16s") ] # the 128-bit uuid
    def get_uuid_tuple(self):
        return struct.unpack(">IHHHHI", self.raw_uuid)
    def set_uuid_tuple(self, value):
        self.raw_uuid = struct.pack(">IHHHHI", *value)
    uuid = property(get_uuid_tuple, set_uuid_tuple)
    def __repr__(self):
        return '<LC_UUID %.8X-%.4X-%.4X-%.4X-%.4X%.8X>' % self.uuid
    def changeUUID(self, uuid):
        self.raw_uuid = struct.pack("B"*16, *[int(uuid[2*i:2*i+2],16) for i in range(len(uuid)//2)])

# The rpath_command contains a path which at runtime should be added to
# the current run path used to find @rpath prefixed dylibs.
class rpath_command(LoadCommand):
    lc_types = (LC_RPATH,)
    _offsets_in_data = ("path",)
    _fields = [ ("path","u32") ] # path to add to run path

# The linkedit_data_command contains the offsets and sizes of a blob
# of data in the __LINKEDIT segment.
class linkedit_data_command(LoadCommand):
    lc_types = (LC_FUNCTION_STARTS,LC_DATA_IN_CODE,LC_DYLIB_CODE_SIGN_DRS,LC_CODE_SIGNATURE,LC_LINKER_OPTIMIZATION_HINT,LC_SEGMENT_SPLIT_INFO)
    _fields = [
        ("dataoff","u32"),  # file offset of data in __LINKEDIT segment
        ("datasize","u32"), # file size of data in __LINKEDIT segment
        ]
    def sectionsToAdd(self, raw):
        from elfesteem.macho.sections import FunctionStarts, DataInCode, DylibCodeSign, CodeSignature, OptimizationHint, SegmentSplitInfo
        # The Load Commands below have some additional data in the LINKEDIT segment,
        # this data is considered as being a section inside this segment.
        self.sect = []
        if self.datasize != 0:
            c = {
                LC_FUNCTION_STARTS: FunctionStarts,
                LC_DATA_IN_CODE: DataInCode,
                LC_DYLIB_CODE_SIGN_DRS: DylibCodeSign,
                LC_CODE_SIGNATURE: CodeSignature,
                LC_LINKER_OPTIMIZATION_HINT: OptimizationHint,
                LC_SEGMENT_SPLIT_INFO: SegmentSplitInfo,
                }[self.cmd]
            self.sect.append(c(parent=self, content=raw, start=self.dataoff))
        return self.sect
    def changeOffsets(self, decalage, min_offset=None):
        if isOffsetChangeable(self.dataoff, min_offset):
            self.dataoff += decalage

# The encryption_info_command contains the file offset and size of an
# of an encrypted segment.
class encryption_info_command(LoadCommand):
    lc_types = (LC_ENCRYPTION_INFO,)
    _fields = [
        ("cryptoff","u32"), # file offset of encrypted range
        ("cryptsize","u32"),# file size of encrypted range
        ("cryptid","u32"),  # which enryption system, 0 means not-encrypted yet
        ]
    def sectionsToAdd(self, raw):
        from elfesteem.macho.sections import Encryption
        self.sect = []
        if self.cryptoff != 0:
            self.sect.append(Encryption(self,content=raw, start=self.cryptoff, type='crypt'))
        return self.sect
    def changeOffsets(self, decalage, min_offset=None):
        if isOffsetChangeable(self.cryptoff, min_offset):
            self.cryptoff += decalage
        if isOffsetChangeable(self.cryptsize, min_offset):
            self.cryptsize += decalage
        if isOffsetChangeable(self.cryptid, min_offset):
            self.cryptid += decalage

class encryption_info_command_64(encryption_info_command):
    lc_types = (LC_ENCRYPTION_INFO_64,)
    _fields = [
        ("cryptoff","u32"), # file offset of encrypted range
        ("cryptsize","u32"),# file size of encrypted range
        ("cryptid","u32"),  # which enryption system, 0 means not-encrypted yet
        ("pad","u32"),      # padding to make this struct's size a multiple of 8 bytes
        ]

# The version_min_command contains the min OS version on which this
# binary was built to run.
class version_min_command(LoadCommand):
    lc_types = (LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS,
                LC_VERSION_MIN_WATCHOS, LC_VERSION_MIN_TVOS)
    _fields = [
        ("version","u32"), # X.Y.Z is encoded in nibbles xxxx.yy.zz
        ("sdk","u32"),     # X.Y.Z is encoded in nibbles xxxx.yy.zz
        ]

# The build_version_command contains the min OS version on which this 
# binary was built to run for its platform.  The list of known platforms and
# tool values following it.
class build_tool_version(CStruct):
    _fields = [
        ("tool","u32"),    # enum for the tool
        ("version","u32"), # version number of the tool
        ]

class toolsArray(CArray):
    _cls = build_tool_version
    count = lambda _:_.parent.ntools

class build_version_command(LoadCommand):
    lc_types = (LC_BUILD_VERSION, )
    _fields = [
        ("platform","u32"),# platform
        ("minos","u32"),   # X.Y.Z is encoded in nibbles xxxx.yy.zz
        ("sdk","u32"),     # X.Y.Z is encoded in nibbles xxxx.yy.zz
        ("ntools","u32"),  # number of tool entries following this
        ("tools",toolsArray),
        ]
    def otool(self, llvm=False):
        if llvm == 9:
            res = [
                    "       cmd %s" % "LC_"+constants['LC'].get(self.cmd, hex(self.cmd)),
                    "   cmdsize %s" % self.cmdsize,
                    "  platform %s" % {1: "macos"}.get(self.platform, self.platform),
                    "       sdk %s" % split_integer(self.sdk, 8, 3, truncate=1),
                    "     minos %s" % split_integer(self.minos, 8, 3, truncate=1),
                    "    ntools %s" % self.ntools,
                ]
            for tool in self.tools:
                res.extend([
                    "      tool %s" % {3: "ld"}.get(tool.tool, tool.tool),
                    "   version %s" % split_integer(tool.version, 8, 3, truncate=2),
                    ])
            return res
        if llvm == 11:
            res = [
                    "       cmd %s" % "LC_"+constants['LC'].get(self.cmd, hex(self.cmd)),
                    "   cmdsize %s" % self.cmdsize,
                    "  platform %s" % self.platform,
                    "       sdk %s" % split_integer(self.sdk, 8, 3, truncate=1),
                    "     minos %s" % split_integer(self.minos, 8, 3, truncate=1),
                    "    ntools %s" % self.ntools,
                ]
            for tool in self.tools:
                res.extend([
                    "      tool %s" % tool.tool,
                    "   version %s" % split_integer(tool.version, 8, 3, truncate=2),
                    ])
            return res
        return LoadCommand.otool(self, llvm=llvm)

# The dyld_info_command contains the file offsets and sizes of
# the new compressed form of the information dyld needs to
# load the image.  This information is used by dyld on Mac OS X
# 10.6 and later.  All information pointed to by this command
# is encoded using byte streams, so no endian swapping is needed
# to interpret it.
from elfesteem.macho.sections import DyldArray
class dyld_info_command(dysymtab_command):
    lc_types = (LC_DYLD_INFO, LC_DYLD_INFO_ONLY)
    _sym = DyldArray
    _fields = [
        ("rebase_off","u32"),     # file offset to rebase info
        ("rebase_size","u32"),    # size of rebase info
        ("bind_off","u32"),       # file offset to binding info
        ("bind_size","u32"),      # size of binding info
        ("weak_bind_off","u32"),  # file offset to weak binding info
        ("weak_bind_size","u32"), # size of weak binding info
        ("lazy_bind_off","u32"),  # file offset to lazy binding info
        ("lazy_bind_size","u32"), # size of lazy binding info
        ("export_off","u32"),     # file offset to lazy binding info
        ("export_size","u32"),    # size of lazy binding info
        ]

# The linker_option_command contains linker options embedded in object files.
class linkeroption_command(LoadCommand):
    lc_types = (LC_LINKER_OPTION,)
    _fields = [
        ("count","u32"), # number of strings
        ("linker_options",CData(lambda _:_.cmdsize-12)),
        ]
    def otool(self, llvm=False):
        res = LoadCommand.otool(self, llvm=llvm)
        # linker_options is a concatenation of zero terminated UTF8 strings,
        # zero filled at end to align.
        data = self.linker_options.pack()
        strings = []
        idx = 0
        while (len(strings) < self.count):
            s = data[idx:data.index(data_null,idx)]
            strings.append(s.decode('utf-8'))
            idx += len(s)+1
        for i, s in enumerate(strings):
            res.append("  string #%d %s" % (i+1, s))
        return res


# The symseg_command contains the offset and size of the GNU style
# symbol table information as described in the header file <symseg.h>.
# The symbol roots of the symbol segments must also be aligned properly
# in the file.  So the requirement of keeping the offsets aligned to a
# multiple of a 4 bytes translates to the length field of the symbol
# roots also being a multiple of a long.  Also the padding must again be
# zeroed. (THIS IS OBSOLETE and no longer supported).
class symseg_command(LoadCommand):
    lc_types = (LC_SYMSEG,)
    _fields = [
        ("offset","u32"), # symbol segment offset
        ("size","u32"),   # symbol segment size in bytes
        ]

# The ident_command contains a free format string table following the
# ident_command structure.  The strings are null terminated and the size of
# the command is padded out with zero bytes to a multiple of 4 bytes/
# (THIS IS OBSOLETE and no longer supported).
class ident_command(LoadCommand):
    lh_types = (LC_IDENT,)
    _fields = [ ]

# The fvmfile_command contains a reference to a file to be loaded at the
# specified virtual address.  (Presently, this command is reserved for
# internal use.  The kernel ignores this command when loading a program into
# memory).
class fvmfile_command(CStruct):
    _fields = [
        ("stroffset","u32"),     # files pathname
        ("header_addr","u32"),   # files virtual address
        ]

# The entry_point_command is a replacement for thread_command.
# It is used for main executables to specify the location (file offset)
# of main().  If -stack_size was used at link time, the stacksize
# field will contain the stack size need for the main thread.
class entry_point_command(LoadCommand):
    lc_types = (LC_MAIN,)
    _fields = [
        ("entryoff","u64"),  # file (__TEXT) offset of main()
        ("stacksize","u64"), # if not zero, initial stack size
        ]
    def changeOffsets(self, decalage, min_offset=None):
        if isOffsetChangeable(self.entryoff, min_offset):
            self.entryoff += decalage

# The source_version_command is an optional load command containing
# the version of the sources used to build the binary.
class source_version_command(LoadCommand):
    lc_types = (LC_SOURCE_VERSION,)
    _fields = [ ("version","u64") ] # A.B.C.D.E packed as a24.b10.c10.d10.e10

# The LC_DATA_IN_CODE load commands uses a linkedit_data_command
# to point to an array of data_in_code_entry entries. Each entry
# describes a range of data in a code section.
class data_in_code_command(CStruct):
    _fields = [
        ("offset","u32"), # from mach_header to start of data range
        ("length","u16"), # number of bytes in data range
        ("kind","u16"),   # a DICE_KIND_* value
        ]
    data_incode_off = property(lambda _:_.offset)
    data_incode_size = property(lambda _:_.length)

SetConstants(
DICE_KIND_DATA              = 0x0001,
DICE_KIND_JUMP_TABLE8       = 0x0002,
DICE_KIND_JUMP_TABLE16      = 0x0003,
DICE_KIND_JUMP_TABLE32      = 0x0004,
DICE_KIND_ABS_JUMP_TABLE32  = 0x0005,
)


######################################################################

def isOffsetChangeable(offset, min_offset):
    return (min_offset is None or offset >= min_offset) and offset != 0

class LoadCommands(CBase):
    def unpack(self, c, o):
        self.offset = o
        self.lhlist = []
        if self.parent.Mhdr.sizeofcmds > self.parent.datasize:
            log.error("LoadCommands longer than file length")
            return
        if self.parent.Mhdr.ncmds*8 > self.parent.Mhdr.sizeofcmds:
            log.error("Too many load command: %d commands cannot fit in %d bytes", self.parent.Mhdr.ncmds, self.parent.Mhdr.sizeofcmds)
            return
        for i in range(self.parent.Mhdr.ncmds):
            lh = LoadCommand(parent=self, content=self.parent.content, start=o)
            if lh.cmdsize > lh.bytelen:
                log.warning("%s has %d bytes of additional padding", lh.__class__.__name__, lh.cmdsize-lh.bytelen)
            elif 8 <= lh.cmdsize < lh.bytelen:
                log.warning("%s is %d bytes too short", lh.__class__.__name__, lh.bytelen-lh.cmdsize)
            self.lhlist.append(lh)
            if self.parent.interval is not None :
                self.parent.interval.delete(o,o+lh.bytelen)
            o += lh.cmdsize
        if self.parent.Mhdr.sizeofcmds > o-self.offset:
            log.warning("LoadCommands have %d bytes of additional padding", self.parent.Mhdr.sizeofcmds-o+self.offset)
    def pack(self):
        data = data_empty
        for lc in self.lhlist:
            data += lc.pack()
        return data
    def append(self, lh):
        self.lhlist.append(lh)
        self.parent.Mhdr.ncmds += 1
        self.parent.Mhdr.sizeofcmds += lh.bytelen
    def getpos(self, lht):
        poslist = []
        for lc in self.lhlist:
            if lht == lc.cmd:
                poslist.append(self.lhlist.index(lc))
        return poslist
    def removepos(self, pos):
        self.parent.Mhdr.sizeofcmds -= len(self.lhlist[pos].pack())
        self.parent.Mhdr.ncmds-=1
        self.lhlist.remove(self.lhlist[pos])
    def changeOffsets(self, decalage, min_offset=None):
        for lc in self.lhlist:
            lc.changeOffsets(decalage, min_offset)
    
    def addSH(self, s):
        for lc in self.lhlist:
            if hasattr(lc, 'addSH') and lc.segname == s.parent.segname:
                lc.addSH(s)
                return True
        return False
    
    def __iter__(self):
        return self.lhlist.__iter__()
    def __len__(self):
        return self.lhlist.__len__()
    def __getitem__(self, item):
        return self.lhlist[item]
    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    def extendSegment(self,lc,size):
        if lc.maxprot == 0:
            raise ValueError('Maximum Protection is 0')
        lc.filesize += size 
        lc.vmsize += size
        for lco in self.lhlist:
             if hasattr(lco,'segname'):
                if lco.fileoff > lc.fileoff:
                    lco.fileoff += size
                    lco.vmaddr += size
                    if hasattr(lco,'sect'):
                        for s in lco.sect:
                            if not s.offset == 0 :
                                s.offset += size
                            if not s.addr == 0 :
                                s.addr += size
             else :
                if not lco.cmd == LC_MAIN:
                    lco.changeOffsets(size)

    def findlctext(self):
        for lc in self.lhlist:
            if lc.cmd == LC_SEGMENT or lc.cmd == LC_SEGMENT_64:
                if lc.is_text_segment():
                    return lc
