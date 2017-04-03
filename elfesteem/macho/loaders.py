from elfesteem.macho.common import *
from elfesteem.cstruct import convert_size2type, CBase, CArray
import struct

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
        if self.magic not in [0xfeedface, 0xfeedfacf, 0xcafebabe]:
            raise ValueError('Not a little-endian Mach-O')
        if self.parent.interval is not None :
            self.parent.interval.delete(0,24+self.wsize//8)

MH_MAGIC    =    0xfeedface #     /* the mach magic number */
MH_CIGAM    =    0xcefaedfe #     /* NXSwapInt(MH_MAGIC) */
MH_MAGIC_64 =    0xfeedfacf #     /* the 64-bit mach magic number */
MH_CIGAM_64 =    0xcffaedfe #     /* NXSwapInt(MH_MAGIC_64) */

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
        o = CStruct_metaclass.__new__(cls, name, bases, dct)
        if '_offsets_in_data' in dct:
            # There is some additional data in a variable-length load command
            fmt = ''.join([convert_size2type(t,None) for _, t in o._fields])
            s = struct.calcsize(fmt)
            dct['_fields'].append( ("data",CData(lambda _,s=s:_.cmdsize-s)) )
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
        if cmd in cls.lc_types:
            # A subclass of LoadCommand has been used
            lh = super(LoadMetaclass,cls).__call__(*args, **kargs)
        elif len(cls.lc_types):
            # A subclass of LoadCommand has been used, with an incoherent cmd
            # We don't use the class name, because one class may correspond
            # to many values for cmd.
            log.warn("Incoherent input cmd=%#x for %s", cmd, cls.__name__)
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

from elfesteem.rprc import CData
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
        res = []
        import time
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
        lc_value = []
        shift = 1
        for name, f_type in self._fields:
            value = getattr(self, name)
            if   name == "cmd":
                value = "LC_"+constants['LC'][self.cmd]
            elif name == "cmdsize":
                pass
            elif name in getattr(self, '_offsets_in_data', []):
                base = struct.calcsize(''.join([convert_size2type(t,None) for _, t in self._fields[:-1]]))
                if value >= base:
                    data = self.data.pack()
                    if name == "linked_modules":
                        data, = struct.unpack("B", data[value-base:value-base+1])
                        data = [str((data&(1<<i))>>i) for i in range(min(8,self.nmodules))]
                        data = ''.join(data) + '...'
                    else:
                        data = data[(value-base):data.index(data_null,value-base)]
                        data = data.decode('latin1')
                    value = "%s (offset %u)" %(data, value)
                else:
                    value = "?(bad offset %u)" % value
                name = "%12s" % name
            elif name in ["vmaddr", "vmsize"]:
                if self.cmd == LC_SEGMENT_64: value = "%#018x" % value
                else:                         value = "%#010x" % value
            elif name in ["maxprot", "initprot", "cksum", "header addr"]:
                value = "%#010x" % value
            elif name == "flags":
                value = "%#x" % value
            elif name == "sdk" and value == 0:
                value = "n/a"
            elif name == "timestamp":
                name = "time stamp"
                value = "%u %s" %(value, time.ctime(value))
            elif name in ["current_version", "compatibility_version"]:
                shift = 0
                name = name[:-8]
                value = "version " + split_integer(value, 8, 3)
            elif name == "pad_segname":
                name = "segname"
                value = value.rstrip(data_null).decode('latin1')
            elif name == "raw_uuid":
                name = "uuid"
                value = "%.8X-%.4X-%.4X-%.4X-%.4X%.8X" % self.uuid
            elif self.cmd == LC_VERSION_MIN_MACOSX:
                shift = 2
                value = split_integer(value, 8, 3, truncate=1)
            elif self.cmd == LC_VERSION_MIN_IPHONEOS:
                shift = 2
                value = split_integer(value, 8, 3, truncate=2)
            elif self.cmd == LC_SOURCE_VERSION:
                shift = 2
                value = split_integer(value, 10, 5, truncate=2)
            elif self.cmd == LC_ENCRYPTION_INFO:
                shift = 4
            elif self.cmd == LC_UNIXTHREAD:
                shift = 4
                # Display text values if they are the expected ones.
                if name == "flavor" and self.flavorname != "":
                    value = self.flavorname
                if name == "count":
                    flavorcount = self.flavorname+'_COUNT'
                    if value == globals()[flavorcount]:
                        value = flavorcount
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


# Constants for the cmd field of all load commands, the type
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
    def get_type(self):
        return self.flags & SECTION_TYPE
    def set_type(self, val):
        self.flags = (val & SECTION_TYPE) | self.YY_flags
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

# Constants for the type of a section
SECTION_TYPE                    = 0x000000ff # Up to 256 section types
S_REGULAR                             = 0x00 # regular section
S_ZEROFILL                            = 0x01 # zero fill on demand section
S_CSTRING_LITERALS                    = 0x02 # section with only literal C strings
S_4BYTE_LITERALS                      = 0x03 # section with only 4 byte literals
S_8BYTE_LITERALS                      = 0x04 # section with only 8 byte literals
S_LITERAL_POINTERS                    = 0x05 # section with only pointers to literals
S_NON_LAZY_SYMBOL_POINTERS            = 0x06 # section with only non-lazy symbol pointers
S_LAZY_SYMBOL_POINTERS                = 0x07 # section with only lazy symbol pointers
S_SYMBOL_STUBS                        = 0x08 # section with only symbol stubs, byte size of stub in the reserved2 field
S_MOD_INIT_FUNC_POINTERS              = 0x09 # section with only function pointers for initialization
S_MOD_TERM_FUNC_POINTERS              = 0x0a # section with only function pointers for termination
S_COALESCED                           = 0x0b # section contains symbols that are to be coalesced
S_GB_ZEROFILL                         = 0x0c # zero fill on demand section (that can be larger than 4 gigabytes)
S_INTERPOSING                         = 0x0d # section with only pairs of function pointers for interposing
S_16BYTE_LITERALS                     = 0x0e # section with only 16 byte literals
S_DTRACE_DOF                          = 0x0f # section contains DTrace Object Format
S_LAZY_DYLIB_SYMBOL_POINTERS          = 0x10 # section with only lazy symbol pointers to lazy loaded dylibs
S_THREAD_LOCAL_REGULAR                = 0x11 # template of initial values for TLVs
S_THREAD_LOCAL_ZEROFILL               = 0x12 # template of initial values for TLVs
S_THREAD_LOCAL_VARIABLES              = 0x13 # TLV descriptors
S_THREAD_LOCAL_VARIABLE_POINTERS      = 0x14 # pointers to TLV descriptors
S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15 # functions to call to initialize TLV values

# Constants for the section attributes part of the flags field of a section structure.
SECTION_ATTRIBUTES         = 0xffffff00 # Up to 24 section attributes
SECTION_ATTRIBUTES_USR     = 0xff000000 # User setable attributes
S_ATTR_PURE_INSTRUCTIONS   = 0x80000000 #  section contains only true machine instructions
S_ATTR_NO_TOC              = 0x40000000 #  section contains coalesced symbols that are not to be in a ranlib table of contents
S_ATTR_STRIP_STATIC_SYMS   = 0x20000000 #  ok to strip static symbols in this section in files with the MH_DYLDLINK flag
S_ATTR_NO_DEAD_STRIP       = 0x10000000 #  no dead stripping
S_ATTR_LIVE_SUPPORT        = 0x08000000 #  blocks are live if they reference live blocks
S_ATTR_SELF_MODIFYING_CODE = 0x04000000 #  Used with i386 code stubs written on by dyld
S_ATTR_DEBUG               = 0x02000000 #  A debug section
SECTION_ATTRIBUTES_SYS     = 0x00ffff00 # system setable attributes
S_ATTR_SOME_INSTRUCTIONS   = 0x00000400 #  Section contains some machine instructions
S_ATTR_EXT_RELOC           = 0x00000200 #  Section has external relocation entries
S_ATTR_LOC_RELOC           = 0x00000100 #  Section has local relocation entries

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
            if (not llvm or llvm >= 8) and s.parent.offset + s.parent.size > len(e.content):
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
            if sh.type == S_ZEROFILL:
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

# Constants for the flags field of the segment_command
SG_HIGHVM              = 0x1 # the file contents for this segment is for the high part of the VM space, the low part is zero filled (for stacks in core files)
SG_FVMLIB              = 0x2 # this segment is the VM that is allocated by a fixed VM library, for overlap checking in the link editor
SG_NORELOC             = 0x4 # this segment has nothing that was relocated in it and nothing relocated to it, that is it maybe safely replaced without relocation
SG_PROTECTED_VERSION_1 = 0x8 # This segment is protected.  If the segment starts at file offset 0, the first page of the segment is not protected.  All other pages of the segment are protected.


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

#### Source: /usr/include/mach/*/thread_status.h

# these are the legacy names which should be deprecated in the future
# they are externally known which is the only reason we don't just get
# rid of them
i386_THREAD_STATE             = 1
i386_FLOAT_STATE              = 2
i386_EXCEPTION_STATE          = 3
# these are the supported flavors
x86_THREAD_STATE32            = 1
x86_FLOAT_STATE32             = 2
x86_EXCEPTION_STATE32         = 3
x86_THREAD_STATE64            = 4
x86_FLOAT_STATE64             = 5
x86_EXCEPTION_STATE64         = 6
x86_THREAD_STATE              = 7
x86_FLOAT_STATE               = 8
x86_EXCEPTION_STATE           = 9
x86_DEBUG_STATE32             = 10
x86_DEBUG_STATE64             = 11
x86_DEBUG_STATE               = 12
THREAD_STATE_NONE             = 13
# 14 and 15 are used for the internal x86_SAVED_STATE flavours
x86_AVX_STATE32               = 16
x86_AVX_STATE64               = 17
x86_AVX_STATE                 = 18

# manually computed for elfesteem
i386_THREAD_STATE_COUNT  = 16
x86_THREAD_STATE64_COUNT = 42

PPC_THREAD_STATE = 1
PPC_THREAD_STATE_COUNT = 40
ARM_THREAD_STATE = 1
ARM_THREAD_STATE_REGISTERS = ('r0', 'r1', 'r2', 'r3',
                'r4', 'r5', 'r6', 'r7',
                'r8', 'r9', 'r10', 'r11',
                'r12', 'sp', 'lr', 'pc',
                'cpsr')
ARM_THREAD_STATE_COUNT = len(ARM_THREAD_STATE_REGISTERS)

globs = globals()
threadStatus = {}
def add_to_threadStatus(cpu, prefix, suffix):
    data = {}
    for val in filter(lambda _:_.startswith(prefix) and _.endswith(suffix), globs.keys()):
        if val.endswith('_COUNT'): continue
        if val.endswith('_REGISTERS'): continue
        data[globs[val]] = val
    threadStatus[cpu] = data
add_to_threadStatus(CPU_TYPE_ARM,     'ARM', '')
add_to_threadStatus(CPU_TYPE_POWERPC, 'PPC', '')
add_to_threadStatus(CPU_TYPE_I386,    'i386', '')
add_to_threadStatus(CPU_TYPE_X86_64,  'x86', '64')

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
class ThreadState(object):
    def __init__(self, command):
        self.c = command
    def __getitem__(self, pos):
        s_type = convert_size2type("ptr",self.c.wsize)
        w_byte = self.c.wsize//8
        if isinstance(pos, slice):
            assert pos.step is None
            ep = struct.unpack(self.c.sex + s_type*(pos.stop-pos.start),
                               self.c.state[w_byte*pos.start:w_byte*pos.stop])
            return ep
        else:
            ep, = struct.unpack(self.c.sex + s_type,
                               self.c.state[w_byte*pos:w_byte*(pos+1)])
            return ep
    def __setitem__(self, pos, val):
        assert False is isinstance(pos, slice)
        s_type = convert_size2type("ptr",self.c.wsize)
        w_byte = self.c.wsize//8
        self.c.state[w_byte*pos:w_byte*(pos+1)] = struct.pack(self.c.sex + s_type, val)
class thread_command(LoadCommand):
    # TODO: how is LC_THREAD different from LC_UNIXTHREAD?
    lc_types = (LC_THREAD, LC_UNIXTHREAD)
    _fields = [
        ("flavor","u32"),     # flavor of thread state
        ("count","u32"),      # count of longs in thread state
        ("state",CData(lambda _:_.cmdsize-16)), # thread state for this flavor
        ]
    def __init__(self, *args, **kargs):
        LoadCommand.__init__(self, *args, **kargs)
        self.reg = ThreadState(self)
    registerInstructionPointer = {
        CPU_TYPE_I386: 10,
        CPU_TYPE_X86_64: 16,
        }
    def get_entrypoint(self):
        return self.reg[self.registerInstructionPointer[self.cputype]]
    def set_entrypoint(self, val):
        self.reg[self.registerInstructionPointer[self.cputype]] = val
    entrypoint = property(get_entrypoint, set_entrypoint)
    def cputype(self):
        if type(self.parent) == dict: return self.parent['cputype']
        else:                         return self.parent.parent.Mhdr.cputype
    cputype = property(cputype)
    flavorname = property(lambda _:threadStatus.get(_.cputype,{}).get(_.flavor,''))
    def otool(self, llvm=False):
        res = LoadCommand.otool(self, llvm=llvm)
        if False:
            # We may want to build the output automatically
            """
            registers = getattr(macho, lc.flavorname+'_REGISTERS')
            state = zip(registers, self.reg)
            res.append(state)
            """
        elif self.cputype == CPU_TYPE_POWERPC:
            res.append("    r0  %#010x r1  %#010x r2  %#010x r3   %#010x r4   %#010x"%self.reg[2:7])
            res.append("    r5  %#010x r6  %#010x r7  %#010x r8   %#010x r9   %#010x"%self.reg[7:12])
            res.append("    r10 %#010x r11 %#010x r12 %#010x r13  %#010x r14  %#010x"%self.reg[12:17])
            res.append("    r15 %#010x r16 %#010x r17 %#010x r18  %#010x r19  %#010x"%self.reg[17:22])
            res.append("    r20 %#010x r21 %#010x r22 %#010x r23  %#010x r24  %#010x"%self.reg[22:27])
            res.append("    r25 %#010x r26 %#010x r27 %#010x r28  %#010x r29  %#010x"%self.reg[27:32])
            res.append("    r30 %#010x r31 %#010x cr  %#010x xer  %#010x lr   %#010x"%self.reg[32:37])
            res.append("    ctr %#010x mq  %#010x vrsave %#010x srr0 %#010x srr1 %#010x"%(self.reg[37], self.reg[38], self.reg[39], self.reg[0], self.reg[1]))
        elif self.cputype == CPU_TYPE_POWERPC64:
            res.append("    r0  %#018x r1  %#018x r2   %#018x"%self.reg[2:4])
            res.append("    r3  %#018x r4  %#018x r5   %#018x"%self.reg[4:8])
            res.append("    r6  %#018x r7  %#018x r8   %#018x"%self.reg[8:11])
            res.append("    r9  %#018x r10 %#018x r11  %#018x"%self.reg[11:14])
            res.append("   r12  %#018x r13 %#018x r14  %#018x"%self.reg[14:17])
            res.append("   r15  %#018x r16 %#018x r17  %#018x"%self.reg[17:20])
            res.append("   r18  %#018x r19 %#018x r20  %#018x"%self.reg[20:23])
            res.append("   r21  %#018x r22 %#018x r23  %#018x"%self.reg[23:26])
            res.append("   r24  %#018x r25 %#018x r26  %#018x"%self.reg[26:29])
            res.append("   r27  %#018x r28 %#018x r29  %#018x"%self.reg[29:32])
            res.append("   r30  %#018x r31 %#018x cr   %#010x"%self.reg[32:35])
            res.append("   xer  %#018x lr  %#018x ctr  %#018x"%self.reg[35:38])
            res.append("vrsave  %#010x        srr0 %#018x srr1 %#018x"%(self.reg[38], self.reg[0], self.reg[1]))
        elif self.cputype == CPU_TYPE_ARM:
            res.append("\t    r0  %#010x r1     %#010x r2  %#010x r3  %#010x"%self.reg[0:4])
            res.append("\t    r4  %#010x r5     %#010x r6  %#010x r7  %#010x"%self.reg[4:8])
            res.append("\t    r8  %#010x r9     %#010x r10 %#010x r11 %#010x"%self.reg[8:12])
            res.append("\t    r12 %#010x sp     %#010x lr  %#010x pc  %#010x"%self.reg[12:16])
            res.append("\t   cpsr %#010x"%self.reg[16])
        elif self.cputype == CPU_TYPE_I386 and self.flavor == 1:
            res.append("\t    eax %#010x ebx    %#010x ecx %#010x edx %#010x"%self.reg[0:4])
            res.append("\t    edi %#010x esi    %#010x ebp %#010x esp %#010x"%self.reg[4:8])
            res.append("\t    ss  %#010x eflags %#010x eip %#010x cs  %#010x"%self.reg[8:12])
            res.append("\t    ds  %#010x es     %#010x fs  %#010x gs  %#010x"%self.reg[12:16])
        elif self.cputype == CPU_TYPE_X86_64:
            res.append("   rax  %#018x rbx %#018x rcx  %#018x"%self.reg[0:3])
            res.append("   rdx  %#018x rdi %#018x rsi  %#018x"%self.reg[3:6])
            res.append("   rbp  %#018x rsp %#018x r8   %#018x"%self.reg[6:9])
            res.append("    r9  %#018x r10 %#018x r11  %#018x"%self.reg[9:12])
            res.append("   r12  %#018x r13 %#018x r14  %#018x"%self.reg[12:15])
            res.append("   r15  %#018x rip %#018x"            %self.reg[15:17])
            res.append("rflags  %#018x cs  %#018x fs   %#018x"%self.reg[17:20])
            res.append("    gs  %#018x"                       %self.reg[20])
        else:
            res.append("      state (Unknown cputype/cpusubtype)")
        return res



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
class dysymtab_command(LoadCommand):
    lc_types = (LC_DYSYMTAB,)
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
    symbolsize = (
        ('toc',         2*4),
        ('modtab',      {32: 13*4, 64: 12*4+8}),
        ('extrefsym',   4),
        ('indirectsym', 4),
        ('extrel',      2*4),
        ('locrel',      2*4),
        )
    def sectionsToAdd(self, raw):
        from elfesteem.macho.sections import DySymbolTable
        self.sect = []
        for t, object_size in self.symbolsize:
            if type(object_size) == dict: object_size = object_size[self.wsize]
            object_count = 'n'+t
            if t.endswith('sym'): object_count += 's'
            size = getattr(self, object_count)*object_size
            setattr(self, t+'size', size)
            of = getattr(self, t+'off')
            if of != 0:
                self.sect.append(DySymbolTable(parent=self, content=raw, start=of, type=t))
        return self.sect
    def changeOffsets(self, decalage, min_offset=None):
        for t, _ in self.symbolsize:
            object_offset = t+'off'
            of = getattr(self,object_offset)
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
            self.sect.append(Hint(self,content=raw, start=self.offset))
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
class Xlinkedit_data_command(CStruct):
    _fields = [
        ("dataoff","u32"),  # file offset of data in __LINKEDIT segment
        ("datasize","u32"), # file size of data in __LINKEDIT segment
        ]
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
    lc_types = (LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS)
    _fields = [
        ("version","u32"), # X.Y.Z is encoded in nibbles xxxx.yy.zz
        ("sdk","u32"),     # X.Y.Z is encoded in nibbles xxxx.yy.zz
        ]

# The dyld_info_command contains the file offsets and sizes of
# the new compressed form of the information dyld needs to
# load the image.  This information is used by dyld on Mac OS X
# 10.6 and later.  All information pointed to by this command
# is encoded using byte streams, so no endian swapping is needed
# to interpret it.
class dyld_info_command(LoadCommand):
    lc_types = (LC_DYLD_INFO, LC_DYLD_INFO_ONLY)
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
    def sectionsToAdd(self, raw):
        from elfesteem.macho.sections import DynamicLoaderInfo
        self.sect = []
        for t, _ in self._fields:
            if not t.endswith('_off'): continue
            if getattr(self, t):
                self.sect.append(DynamicLoaderInfo(parent=self, content=raw,
                                 start=getattr(self, t), type=t[:-3]))
        return self.sect
    def changeOffsets(self, decalage, min_offset=None):
        for t, _ in self._fields:
            if not t.endswith('_off'): continue
            off = getattr(self, t)
            if isOffsetChangeable(off, min_offset):
                setattr(self, t, off + decalage)

# The following are used to encode rebasing information
REBASE_IMMEDIATE_MASK                                   = 0x0F
REBASE_TYPE_POINTER                                     = 1
REBASE_TYPE_TEXT_ABSOLUTE32                             = 2
REBASE_TYPE_TEXT_PCREL32                                = 3
REBASE_OPCODE_MASK                                      = 0xF0
REBASE_OPCODE_DONE                                      = 0x00
REBASE_OPCODE_SET_TYPE_IMM                              = 0x10
REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB               = 0x20
REBASE_OPCODE_ADD_ADDR_ULEB                             = 0x30
REBASE_OPCODE_ADD_ADDR_IMM_SCALED                       = 0x40
REBASE_OPCODE_DO_REBASE_IMM_TIMES                       = 0x50
REBASE_OPCODE_DO_REBASE_ULEB_TIMES                      = 0x60
REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB                   = 0x70
REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB        = 0x80

# The following are used to encode binding information
BIND_TYPE_POINTER                            =  1
BIND_TYPE_TEXT_ABSOLUTE32                    =  2
BIND_TYPE_TEXT_PCREL32                       =  3
BIND_SPECIAL_DYLIB_SELF                      =  0
BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE           = -1
BIND_SPECIAL_DYLIB_FLAT_LOOKUP               = -2
BIND_IMMEDIATE_MASK                          = 0x0F
BIND_SYMBOL_FLAGS_WEAK_IMPORT                = 0x01
BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION        = 0x08
BIND_OPCODE_MASK                             = 0xF0
BIND_OPCODE_DONE                             = 0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM            = 0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB           = 0x20
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM            = 0x30
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM    = 0x40
BIND_OPCODE_SET_TYPE_IMM                     = 0x50
BIND_OPCODE_SET_ADDEND_SLEB                  = 0x60
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB      = 0x70
BIND_OPCODE_ADD_ADDR_ULEB                    = 0x80
BIND_OPCODE_DO_BIND                          = 0x90
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB            = 0xA0
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED      = 0xB0
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0

# The following are used on the flags byte of a terminal node
# in the export information.
EXPORT_SYMBOL_FLAGS_KIND_MASK                = 0x03
EXPORT_SYMBOL_FLAGS_KIND_REGULAR             = 0x00
EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL        = 0x01
EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION          = 0x04
EXPORT_SYMBOL_FLAGS_REEXPORT                 = 0x08
EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER        = 0x10

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
DICE_KIND_DATA              = 0x0001
DICE_KIND_JUMP_TABLE8       = 0x0002
DICE_KIND_JUMP_TABLE16      = 0x0003
DICE_KIND_JUMP_TABLE32      = 0x0004
DICE_KIND_ABS_JUMP_TABLE32  = 0x0005



#### Finalize
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


######################################################################

def isOffsetChangeable(offset, min_offset):
    return (min_offset == None or offset >= min_offset) and offset != 0

class LoadCommands(CBase):
    def unpack(self, c, o):
        self.lhlist = []
        for i in range(self.parent.Mhdr.ncmds):
            lh = LoadCommand(parent=self, content=self.parent.content, start=o)
            assert lh.cmdsize == lh.bytelen
            self.lhlist.append(lh)
            assert lh.cmdsize == len(lh.pack())
            if self.parent.interval is not None :
                if not self.parent.interval.contains(o,o+lh.bytelen):
                    log.error("Parsing %r (%d,%d)" % (lh,o,lh.bytelen))
                    raise ValueError("This part of file has already been parsed")
                self.parent.interval.delete(o,o+lh.bytelen)
            o += lh.cmdsize
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
                if not lco.cmd == 0x80000028:
                    lco.changeOffsets(size)

    def findlctext(self):
        for lc in self.lhlist:
            if lc.cmd == LC_SEGMENT or lc.cmd == LC_SEGMENT_64:
                if lc.is_text_segment():
                    return lc
