import struct
from elfesteem.macho.common import *
from elfesteem.cstruct import Constants, CBase, CData, CString, CArray, CStructWithStrTable
from elfesteem.strpatchwork import StrPatchwork

import sys
if sys.version_info[0:2] == (2, 3):
    mask32 = (eval("1L")<<32)-1 # 'eval' avoids SyntaxError with python3.x
    mask64 = (eval("1L")<<64)-1
else:
    mask32 = eval("0xffffffff") # 'eval' avoids warnings with python2.3
    mask64 = eval("0xffffffffffffffff")

dyld_constants = {}
def SetConstants(**kargs):
    Constants(globs = globals(), table = dyld_constants, **kargs)

############################################################
# Sections, containing data, at a given offset in the file
# 
# NB: the LINKEDIT segment contains data from numerous Load Commands,
# which are not identified as true sections (nsects == 0 for this
# segment).
# We manage them almost as if they were true sections.

class BaseSection(CBase):
    # Give direct access to the offset in the file, which is mentioned
    # in the parent structure. The name of the field depend on the type
    # of section.
    def get_offset(self):
        if self.type is None: return self.parent.offset
        else:                 return getattr(self.parent, self.type + 'off')
    def set_offset(self, val):
        if self.type is None: self.parent.offset = val
        else:                 setattr(self.parent, self.type + 'off', val)
    offset = property(get_offset, set_offset)
    def __str__(self):
        return "%-30s %-10s %#010x %#010x" % (self.__class__.__name__, '', self.offset, len(self))

class TrueSection(BaseSection):
    name = property(lambda _:_.parent.name)
    def set_size(self, val):
        self.parent.size = val
    size = property(lambda _:_.parent.size, set_size)
    addr = property(lambda _:_.parent.addr)
    # 'sh' member should be obsolete, but is used to detect a true section.
    sh = property(lambda _:_.parent)
    def __str__(self):
        return str(self.parent)

class Section(TrueSection):
    type = None
    def unpack(self, c, o):
        self.content = c
        if self.parent is not None: assert o == self.offset
        self._off = o
    def pack(self):
        return self.content.pack()
    def get_content(self):
        return self.__content
    def set_content(self,val):
        self.__content = StrPatchwork(val)
    content = property(get_content, set_content)
    def update(self, **kargs):
        if 'size' in kargs:              self._size = kargs['size']
        elif hasattr(self, '__content'): self._size = len(self.content)
        else:                            return
        self.content = self.content[self._off:self._off+self._size]

class symbolPointer(CStruct):
    _fields = [ ("address","ptr") ]

class SymbolPtrList(TrueSection,CArray):
    type = None
    _cls = symbolPointer
    count = lambda _:_.parent.size//(_.wsize//8)
    # TODO: update self.parent.size when the array size changes

class symbolStub(CBase):
    def unpack(self, c, o):
        self._size = self.parent.parent.reserved2
        self.content = c[o:o+self._size]
    def pack(self):
        return self.content

class SymbolStubList(TrueSection,CArray):
    type = None
    _cls = symbolStub
    count = lambda _:_.parent.size//_.parent.reserved2
    # TODO: update self.parent.size when the array size changes

class Reloc(TrueSection,CArray):
    type = 'rel' # Offset is parent.reloff
    _cls = relocation_info
    count = lambda _:_.parent.nreloc
    size = property(lambda _:_.parent.nreloc//8)
    addr = property(lambda _:_.parent.reloff)
    reloclist = property(lambda _:_._array)
    def __str__(self):
        p = self.parent
        return "%-30s %-10s %#010x %#010x" % (p.name, 'relocs', p.reloff, p.nreloc)
    # TODO: update self.parent.nreloc when the array size changes

#### Source: /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.9.sdk/usr/include/mach-o/nlist.h
# The 'n_type' aka. 'type' field
N_STAB  = 0xe0  # if any of these bits set, a symbolic debugging entry
N_PEXT  = 0x10  # private external symbol bit
N_TYPE  = 0x0e  # mask for the type bits
N_EXT   = 0x01  # external symbol bit, set for external symbols
# Values for N_TYPE bits of the n_type field.
N_UNDF  = 0x0   # undefined, n_sect == NO_SECT
N_ABS   = 0x2   # absolute, n_sect == NO_SECT
#         0x4   # (found in 'Decibels' for iOS, meaning unknown)
N_SECT  = 0xe   # defined in section number n_sect
N_PBUD  = 0xc   # prebound undefined (defined in a dylib)
N_INDR  = 0xa   # indirect

class symbol(CStructWithStrTable):
    _fields = [ ("name_idx","u32"),
                ("type","u08"),
                ("sectionindex","u08"),
                ("description","u16"),
                ("value","ptr")]
    def strtab(self):
        return self.parent.parent.strtab
    strtab = property(strtab)
    def __str__(self):
        return self.otool()
    def otool(self):
        n_type = {
            N_UNDF: 'U',
            N_ABS : 'A',
            N_SECT: 'S',
            N_PBUD: 'P',
            N_INDR: 'I',
            }.get(self.type & N_TYPE, hex(self.type & N_TYPE))
        n_type += [ ' ', 'X' ] [self.type & N_EXT]
        n_type += [ ' ', 'X' ] [(self.type & N_PEXT)>>4]
        if self.type & N_STAB:
            n_type += 'D'
        desc = self.description
        e = self.parent.parent.parent.parent
        if self.sectionindex == 0:
            section = "NO_SECT"
        elif 0 <= self.sectionindex-1 < len(e.sect):
            section = e.sect[self.sectionindex-1].parent
            if hasattr(section, 'name'):
                section = section.name
            else:
                section = "INVALID(%d)" % self.sectionindex
        else:
            section = "INVALID(%d)" % self.sectionindex
        return "%-35s %-15s %-4s 0x%08x %04x"%(self.name,section,n_type,self.value,desc)

class SymbolNotFound(object):
    pass
SymbolNotFound = SymbolNotFound()
class SymbolTable(BaseSection,CArray):
    type = 'sym'
    _cls = symbol
    count = lambda _:_.parent.nsyms
    def update(self, **kargs):
        self.symbols_from_name = {}
        # This cannot be done if the string table was not parsed
        for symbol in self.symbols:
            self.symbols_from_name[symbol.name] = symbol
    symbols = property(lambda _:_._array)
    def __iter__(self):
        return self.symbols.__iter__()
    def __getitem__(self, idx):
        try:
            if type(idx) == int:
                return self.symbols[idx]
            else:
                return self.symbols_from_name[idx.strip('\0')]
        except IndexError:
            log.error("Cannot find symbol with index %r", idx)
            return SymbolNotFound

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

class Hint(BaseSection,CArray):
    type = None
    _cls = twolevel_hint
    count = lambda _:_.parent.nhints

# NB: the following sections are used by LC_DYSYMTAB; dysymarray_register
# registers these sections.
DySymArray = {}
def dysymarray_register(cls):
    DySymArray[cls.type] = cls

# An indirect symbol table entry is simply a 32bit index into the symbol table
# to the symbol that the pointer or stub is refering to.  Unless it is for a
# non-lazy symbol pointer section for a defined symbol which strip(1) as
# removed.  In which case it has the value INDIRECT_SYMBOL_LOCAL.  If the
# symbol was also absolute INDIRECT_SYMBOL_ABS is or'ed with that.
INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS   = 0x40000000
class dylib_indirect_entry(CStruct):
    _fields = [ ("index","u32") ]

class DySymIndirect(BaseSection,CArray):
    type = 'indirectsym'
    _cls = dylib_indirect_entry
    count = lambda _:_.parent.nindirectsyms
    entries = property(lambda _:_)
dysymarray_register(DySymIndirect)

# A table of contents entry
class dylib_table_of_contents(CStruct):
    _fields = [
        ("symbol_index","u32"), # the defined external symbol (index into the symbol table)
        ("module_index","u32"), # index into the module table this symbol is defined in
        ]

class DySymToc(BaseSection,CArray):
    type = 'toc'
    _cls = dylib_table_of_contents
    count = lambda _:_.parent.ntoc
dysymarray_register(DySymToc)

# A module table entry
# * In loader.h, there are two data structures: dylib_module and dylib_module_64, which are merged in one structure below.
class dylib_module(CStruct):
    _fields = [
        ("module_name","u32"), # the module name (index into string table)
        ("iextdefsym","u32"),  # index into externally defined symbols
        ("nextdefsym","u32"),  # number of externally defined symbols
        ("irefsym","u32"),     # index into reference symbol table
        ("nrefsym","u32"),     # number of reference symbol table entries
        ("ilocalsym","u32"),   # index into symbols for local symbols
        ("nlocalsym","u32"),   # number of local symbols
        ("iextrel","u32"),     # index into external relocation entries
        ("nextrel","u32"),     # number of external relocation entries
        ("iinit_iterm","u32"), # low 16 bits are the index into the init section, high 16 bits are the index into the term section 
        ("ninit_nterm","u32"), # low 16 bits are the number of init section entries, high 16 bits are the number of term section entries
        # for this module, address & size of the start of the (__OBJC,__module_info) section
        ("objc_module_info_1","u32"),
        ("objc_module_info_2","ptr"),
        ]
    def get_addr(self):
        if self.wsize == 32: return self.objc_module_info_1
        if self.wsize == 64: return self.objc_module_info_2
    def set_addr(self, value):
        if self.wsize == 32: self.objc_module_info_1 = value
        if self.wsize == 64: self.objc_module_info_2 = value
    def get_size(self):
        if self.wsize == 32: return self.objc_module_info_2
        if self.wsize == 64: return self.objc_module_info_1
    def set_size(self, value):
        if self.wsize == 32: self.objc_module_info_2 = value
        if self.wsize == 64: self.objc_module_info_1 = value
    objc_module_info_addr = property(get_addr, set_addr)
    objc_module_info_size = property(get_size, set_size)

class DySymModTab(BaseSection,CArray):
    type = 'modtab'
    _cls = dylib_module
    count = lambda _:_.parent.nmodtab
dysymarray_register(DySymModTab)

# The entries in the reference symbol table are used when loading the module
# (both by the static and dynamic link editors) and if the module is unloaded
# or replaced.  Therefore all external symbols (defined and undefined) are
# listed in the module's reference table.  The flags describe the type of
# reference that is being made.  The constants for the flags are defined in
# <mach-o/nlist.h> as they are also used for symbol table entries.
class dylib_reference(CStruct):
    _fields = [ ("index","u32") ]
    isym  = property(lambda _:_.index>>8)
    flags = property(lambda _:_.index&0x000000ff)

class DySymExtref(BaseSection,CArray):
    type = 'extrefsym'
    _cls = dylib_reference
    count = lambda _:_.parent.nextrefsyms
dysymarray_register(DySymExtref)

class DySymLocRel(BaseSection,CArray):
    type = 'locrel'
    _cls = relocation_info
    count = lambda _:_.parent.nlocrel
dysymarray_register(DySymLocRel)

class DySymExtRel(BaseSection,CArray):
    type = 'extrel'
    _cls = relocation_info
    count = lambda _:_.parent.nextrel
dysymarray_register(DySymExtRel)

# NB: the following sections are used by LC_DYLD_INFO, LC_DYLD_INFO_ONLY;
# dyldarray_register registers these sections.
# NB: some example code decoding these load commands is at:
# https://github.com/espes/Slave-in-the-Magic-Mirror/blob/master/dyld_info.py
# https://opensource.apple.com/source/ld64/ld64-264.3.102/src/other/dyldinfo.cpp.auto.html
DyldArray = {}
def dyldarray_register(cls):
    DyldArray[cls.type] = cls

class Uleb128(CBase):
    def _parent_parse(self, kargs):
        pass # Independent of endianess and wordsize
    def _initialize(self):
        self.value = 0
        self._size = 0
    def unpack(self, c, o):
        pos = 0
        while True:
            val, = struct.unpack("B",c[o:o+1])
            if sys.version_info[0:2] == (2, 3):
                val += eval("0L")
            self.value += (val&0x7f) << pos
            self._size += 1; o += 1; pos += 7
            if not val & 0x80: break
        return val, pos
    def pack(self):
        if self.value == 0:
            return struct.pack("B", 0)
        v = self.value
        c = struct.pack("")
        while v:
            if v > 0x7f: c += struct.pack("B", (v&0x7f)|0x80)
            else:        c += struct.pack("B", v)
            v >>= 7
        return c
    def __int__(self):
        return self.value

class Sleb128(Uleb128):
    def unpack(self, c, o):
        val, pos = Uleb128.unpack(self, c, o)
        if val & 0x40:
            self.value |= (-1) << pos
    def pack(self):
        if self.value == 0:
            return struct.pack("B", 0)
        v = self.value
        c = struct.pack("")
        while v:
            w = v & 0x7f
            if   v >  0x7f: c += struct.pack("B", w|0x80)
            elif v < -0x7f: c += struct.pack("B", w|0x80)
            else:           c += struct.pack("B", w)
            v >>= 7
            if v == -1: break
        return c

class DyldArrayGeneric(BaseSection,CArray):
    _cls = None
    def count(self):
        if self.bytelen < self.size: return len(self)+1
        else:                        return -1
    def get_size(self):
        return getattr(self.parent, self.type + 'size')
    def set_size(self, val):
        setattr(self.parent, self.type + 'size', val)
    size = property(get_size, set_size)
    def _initialize(self):
        CArray._initialize(self)
        # "uncompressed" data is stored in self._info, while the "compressed"
        # data is in self._array; modifying this information is tricky, and
        # the API for doing this in a safe way will be implemented later...
        self._info = []
        self.addend = 0   # default value for bind
        self.index = 0    # default value for lazy_bind
        if   self.type == 'bind_':      self.cls = Bind
        elif self.type == 'weak_bind_': self.cls = WeakBind
        elif self.type == 'lazy_bind_': self.cls = LazyBind
        elif self.type == 'rebase_':    self.cls = Rebase
    def update(self, **kargs):
        try:
            for op in self:
                op.apply()
        except ValueError:
            log.error("Invalid opcode %s", op)
    info = property(lambda _:_._info)

#### Source: /usr/include/mach-o/loader.h

# The bind information is a stream of byte sized 
# opcodes whose symbolic names start with BIND_OPCODE_.
# Conceptually the bind information is a table of tuples:
#    <seg-index, seg-offset, type, symbol-library-ordinal, symbol-name, addend>
# The opcodes are a compressed way to encode the table by only
# encoding when a column changes.  In addition simple patterns
# like for runs of pointers initialized to the same value can be 
# encoded in a few bytes.

# The following are used to encode binding information
SetConstants(
BIND_TYPE_POINTER                            =  1,
BIND_TYPE_TEXT_ABSOLUTE32                    =  2,
BIND_TYPE_TEXT_PCREL32                       =  3,
)
SetConstants(
BIND_SPECIAL_DYLIB_SELF                      =  0,
BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE           = -1,
BIND_SPECIAL_DYLIB_FLAT_LOOKUP               = -2,
)

BIND_IMMEDIATE_MASK                          = 0x0F
SetConstants(
BIND_SYMBOL_FLAGS_WEAK_IMPORT                = 0x01,
BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION        = 0x08,
)
BIND_OPCODE_MASK                             = 0xF0
SetConstants(
BIND_OPCODE_DONE                             = 0x00,
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM            = 0x10,
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB           = 0x20,
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM            = 0x30,
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM    = 0x40,
BIND_OPCODE_SET_TYPE_IMM                     = 0x50,
BIND_OPCODE_SET_ADDEND_SLEB                  = 0x60,
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB      = 0x70,
BIND_OPCODE_ADD_ADDR_ULEB                    = 0x80,
BIND_OPCODE_DO_BIND                          = 0x90,
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB            = 0xA0,
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED      = 0xB0,
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0,
)

def get_lib_name(e, idx):
    from elfesteem.macho.loaders import LC_LOAD_DYLIB
    lc = [ _ for _ in e.load if _.cmd == LC_LOAD_DYLIB ]
    if idx == 0:
        return 'this-image'
    elif idx > 0 and len(lc) > idx-1:
        lib = lc[idx-1].str_name
        if '/' in lib: lib = lib[lib.rindex('/')+1:]
        if '.' in lib: lib = lib[:lib.index('.')]
        return lib
    else:
        return None

class Bind(object):
    _to_copy = ('sym', 'weak_import', 'seg', 'addr', 'libord', 'info_type', 'addend')
    def __init__(self, entry):
        for f in self._to_copy:
            if not hasattr(entry.parent, f): raise ValueError
            setattr(self, f, getattr(entry.parent, f))
        e = entry.parent.parent.parent.parent
        self.sec = e.getsectionbyvad(self.addr)
        if self.sec is None: raise ValueError
        self.sec = self.sec.parent.sectname
        if 'libord' in self._to_copy:
            self.libord = get_lib_name(e, self.libord)
    def __str__(self):
        return "%-7s %-16s 0x%08X    %-7s %6d %-16s %s%s" % (
            self.seg, self.sec, self.addr,
            self.info_type, self.addend, self.libord,
            self.sym, self.weak_import)

class WeakBind(Bind):
    _to_copy = ('sym', 'weak_import', 'seg', 'addr', 'info_type', 'addend')
    def __str__(self):
        return "%-7s %-16s 0x%08X    %-7s  %6d %s%s" % (
            self.seg, self.sec, self.addr,
            self.info_type, self.addend,
            self.sym, self.weak_import)

class LazyBind(Bind):
    _to_copy = ('sym', 'weak_import', 'seg', 'addr', 'libord', 'index')
    def __str__(self):
        return "%-7s %-16s 0x%08X 0x%04X %-16s %s%s" % (
            self.seg, self.sec, self.addr,
            self.index, self.libord,
            self.sym, self.weak_import)

from elfesteem.cstruct import CStruct_metaclass
class bind_metaclass(CStruct_metaclass):
    registered = {}
    def __new__(cls, name, bases, dct):
        o = CStruct_metaclass.__new__(cls, name, bases, dct)
        if 'opcode' in dct:
            cls.registered[dct['opcode']] = o
        return o
    def __call__(cls, *args, **kargs):
        c = kargs['content']
        o = kargs.get('start',0)
        val, = struct.unpack("B",c[o:o+1])
        opcode = val & BIND_OPCODE_MASK
        if hasattr(cls, 'opcode'):
            op = super(bind_metaclass,cls).__call__(*args, **kargs)
        elif opcode in bind_metaclass.registered:
            op = bind_metaclass.registered[opcode](*args, **kargs)
        else:
            op = super(bind_metaclass,cls).__call__(*args, **kargs)
        op.opcode = opcode
        return op
bind_base = bind_metaclass('bind_base', (CStruct,), {})

class bind_entry(bind_base):
    _fields = [ ("val", "u08") ]
    imm = property(lambda _: _.val & BIND_IMMEDIATE_MASK)
    def unpack(self, c, o):
        CStruct.unpack(self, c, o)
        self.index  = o - self.parent.offset
    def __str__(self):
        return "0x%04X BIND_OPCODE_%s" % (self.index,
            dyld_constants['BIND_OPCODE'].get(self.opcode, hex(self.opcode)))
    def apply(self):
        pass

class bind_opcode(bind_entry):
    opcode = BIND_OPCODE_DONE
    _fields = [ ("val", "u08") ]
    def apply(self):
        self.parent.index = self.index + self.bytelen

class bind_opcode(bind_entry):
    opcode = BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
    _fields = [ ("val", "u08") ]
    libord = property(lambda _: _.imm)
    def __str__(self):
        return bind_entry.__str__(self) + '(%d)' % self.libord
    def apply(self):
        self.parent.libord = int(self.libord)

class bind_opcode(bind_opcode):
    opcode = BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB
    _fields = [ ("val", "u08"), ("libord", Uleb128) ]

class bind_opcode(bind_opcode):
    opcode = BIND_OPCODE_SET_DYLIB_SPECIAL_IMM
    _fields = [ ("val", "u08") ]
    def libord(self):
        if self.imm: return self.imm | BIND_OPCODE_MASK
        else:        return 0
    libord = property(libord)

class bind_opcode(bind_entry):
    opcode = BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
    _fields = [ ("val", "u08"), ("sym", CString) ]
    def __str__(self):
        return bind_entry.__str__(self) + '(0x%02X, %s)' % (self.imm, self.sym)
    def apply(self):
        self.parent.sym = self.sym
        if self.imm & BIND_SYMBOL_FLAGS_WEAK_IMPORT:
            self.parent.weak_import = " (weak import)"
        else:
            self.parent.weak_import = ""

class bind_opcode(bind_entry):
    opcode = BIND_OPCODE_SET_TYPE_IMM
    _fields = [ ("val", "u08") ]
    info_type = property(lambda _: _.imm)
    def __str__(self):
        return bind_entry.__str__(self) + '(%d)' % self.imm
    def apply(self):
        self.parent.info_type = {
            BIND_TYPE_POINTER: "pointer",
            BIND_TYPE_TEXT_ABSOLUTE32: "text abs32",
            BIND_TYPE_TEXT_PCREL32: "text rel32",
            }.get(self.imm,"!!unknown!!")

class bind_opcode(bind_entry):
    opcode = BIND_OPCODE_SET_ADDEND_SLEB
    _fields = [ ("val", "u08"), ("addend", Sleb128) ]
    def __str__(self):
        return bind_entry.__str__(self) + '(%d)' % int(self.addend)
    def apply(self):
        self.parent.addend = self.addend

class bind_opcode(bind_entry):
    opcode = BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
    _fields = [ ("val", "u08"), ("addr", Uleb128) ]
    def __str__(self):
        return bind_entry.__str__(self) + '(0x%02X, 0x%08X)' % (self.imm, int(self.addr))
    def apply(self):
        from elfesteem.macho.loaders import LC_SEGMENT, LC_SEGMENT_64
        e = self.parent.parent.parent.parent
        lc = [ _ for _ in e.load if _.cmd in (LC_SEGMENT, LC_SEGMENT_64) ]
        if len(lc) > self.imm:
            self.parent.seg = lc[self.imm].segname
            self.parent.addr = lc[self.imm].vmaddr + int(self.addr)
        else:
            self.parent.seg = None
            self.parent.addr = None

class bind_opcode(bind_entry):
    opcode = BIND_OPCODE_ADD_ADDR_ULEB
    _fields = [ ("val", "u08"), ("addr", Uleb128) ]
    def __str__(self):
        return bind_entry.__str__(self) + '(0x%08X)' % (int(self.addr) & mask32)
    def apply(self):
        if not hasattr(self.parent, 'addr'): raise ValueError
        self.parent.addr += int(self.addr)
        self.parent.addr &= mask64

class bind_opcode(bind_entry):
    opcode = BIND_OPCODE_DO_BIND
    _fields = [ ("val", "u08") ]
    def __str__(self):
        return bind_entry.__str__(self) + '()'
    def apply(self):
        if not hasattr(self.parent, 'addr'): raise ValueError
        self.parent._info.append(self.parent.cls(self))
        self.parent.addr += self.wsize//8

class bind_opcode(bind_entry):
    opcode = BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB
    _fields = [ ("val", "u08"), ("addr", Uleb128) ]
    def __str__(self):
        return bind_entry.__str__(self) + '(0x%08X)' % (int(self.addr) & mask32)
    def apply(self):
        if not hasattr(self.parent, 'addr'): raise ValueError
        self.parent._info.append(self.parent.cls(self))
        self.parent.addr += self.wsize//8 + int(self.addr)
        self.parent.addr &= mask64

class bind_opcode(bind_entry):
    opcode = BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED
    _fields = [ ("val", "u08") ]
    add_addr = property(lambda _: (_.imm+1)*(_.wsize//8))
    def __str__(self):
        return bind_entry.__str__(self) + '(0x%08X)' % self.add_addr
    def apply(self):
        self.parent._info.append(self.parent.cls(self))
        self.parent.addr += self.add_addr

class bind_opcode(bind_entry):
    opcode = BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
    _fields = [ ("val", "u08"), ("count", Uleb128), ("skip", Uleb128) ]
    def __str__(self):
        return bind_entry.__str__(self) + '(%d, 0x%08X)' % (int(self.count), int(self.skip))
    def apply(self):
        if not hasattr(self.parent, 'addr'): raise ValueError
        if int(self.count) > mask64: raise ValueError
        for i in range(int(self.count)):
            self.parent._info.append(self.parent.cls(self))
            self.parent.addr += int(self.skip) + self.wsize//8

del bind_opcode

class DyldArrayBind(DyldArrayGeneric):
    type = 'bind_'
    _cls = bind_entry
dyldarray_register(DyldArrayBind)

class DyldArrayWeakBind(DyldArrayGeneric):
    type = 'weak_bind_'
    _cls = bind_entry
dyldarray_register(DyldArrayWeakBind)

class DyldArrayLazyBind(DyldArrayGeneric):
    type = 'lazy_bind_'
    _cls = bind_entry
dyldarray_register(DyldArrayLazyBind)

#### Source: /usr/include/mach-o/loader.h

# Dyld rebases an image whenever dyld loads it at an address different
# from its preferred address.  The rebase information is a stream
# of byte sized opcodes whose symbolic names start with REBASE_OPCODE_.
# Conceptually the rebase information is a table of tuples:
#    <seg-index, seg-offset, type>
# The opcodes are a compressed way to encode the table by only
# encoding when a column changes.  In addition simple patterns
# like "every n'th offset for m times" can be encoded in a few
# bytes.

# The following are used to encode rebasing information
REBASE_IMMEDIATE_MASK                                   = 0x0F
SetConstants(
REBASE_TYPE_POINTER                                     = 1,
REBASE_TYPE_TEXT_ABSOLUTE32                             = 2,
REBASE_TYPE_TEXT_PCREL32                                = 3,
)
REBASE_OPCODE_MASK                                      = 0xF0
SetConstants(
REBASE_OPCODE_DONE                                      = 0x00,
REBASE_OPCODE_SET_TYPE_IMM                              = 0x10,
REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB               = 0x20,
REBASE_OPCODE_ADD_ADDR_ULEB                             = 0x30,
REBASE_OPCODE_ADD_ADDR_IMM_SCALED                       = 0x40,
REBASE_OPCODE_DO_REBASE_IMM_TIMES                       = 0x50,
REBASE_OPCODE_DO_REBASE_ULEB_TIMES                      = 0x60,
REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB                   = 0x70,
REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB        = 0x80,
)

class Rebase(Bind):
    _to_copy = ('seg', 'addr', 'info_type')
    def __str__(self):
        return "%-7s %-16s 0x%08X  %s" % (
            self.seg, self.sec, self.addr,
            self.info_type)

from elfesteem.cstruct import CStruct_metaclass
class rebase_metaclass(CStruct_metaclass):
    registered = {}
    def __new__(cls, name, bases, dct):
        o = CStruct_metaclass.__new__(cls, name, bases, dct)
        if 'opcode' in dct:
            cls.registered[dct['opcode']] = o
        return o
    def __call__(cls, *args, **kargs):
        c = kargs['content']
        o = kargs.get('start',0)
        val, = struct.unpack("B",c[o:o+1])
        opcode = val & REBASE_OPCODE_MASK
        if hasattr(cls, 'opcode'):
            op = super(rebase_metaclass,cls).__call__(*args, **kargs)
        elif opcode in rebase_metaclass.registered:
            op = rebase_metaclass.registered[opcode](*args, **kargs)
        else:
            op = super(rebase_metaclass,cls).__call__(*args, **kargs)
        op.opcode = opcode
        return op
rebase_base = rebase_metaclass('rebase_base', (CStruct,), {})

class rebase_entry(rebase_base):
    _fields = [ ("val", "u08") ]
    imm = property(lambda _: _.val & REBASE_IMMEDIATE_MASK)
    def unpack(self, c, o):
        CStruct.unpack(self, c, o)
        self.index  = o - self.parent.offset
    def __str__(self):
        return "0x%04X REBASE_OPCODE_%s" % (self.index,
            dyld_constants['REBASE_OPCODE'].get(self.opcode, hex(self.opcode)))
    def apply(self):
        pass

class rebase_opcode(rebase_entry):
    opcode = REBASE_OPCODE_DONE
    _fields = [ ("val", "u08") ]
    def __str__(self):
        return rebase_entry.__str__(self) + '()'

class rebase_opcode(rebase_entry):
    opcode = REBASE_OPCODE_SET_TYPE_IMM
    _fields = [ ("val", "u08") ]
    info_type = property(lambda _: _.imm)
    def __str__(self):
        return rebase_entry.__str__(self) + '(%d)' % self.imm
    def apply(self):
        self.parent.info_type = {
            REBASE_TYPE_POINTER: "pointer",
            REBASE_TYPE_TEXT_ABSOLUTE32: "text abs32",
            REBASE_TYPE_TEXT_PCREL32: "text rel32",
            }.get(self.imm,"!!unknown!!")

class rebase_opcode(rebase_entry):
    opcode = REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
    _fields = [ ("val", "u08"), ("addr", Uleb128) ]
    def __str__(self):
        return rebase_entry.__str__(self) + '(%d, 0x%08X)' % (self.imm, int(self.addr))
    def apply(self):
        from elfesteem.macho.loaders import LC_SEGMENT, LC_SEGMENT_64
        e = self.parent.parent.parent.parent
        lc = [ _ for _ in e.load if _.cmd in (LC_SEGMENT, LC_SEGMENT_64) ]
        if len(lc) > self.imm:
            self.parent.seg = lc[self.imm].segname
            self.parent.addr = lc[self.imm].vmaddr + int(self.addr)
        else:
            self.parent.seg = None
            self.parent.addr = None

class rebase_opcode(rebase_entry):
    opcode = REBASE_OPCODE_ADD_ADDR_ULEB
    _fields = [ ("val", "u08"), ("addr", Uleb128) ]
    def __str__(self):
        return rebase_entry.__str__(self) + '(0x%X)' % (int(self.addr) & mask32)
    def apply(self):
        if not hasattr(self.parent, 'addr'): raise ValueError
        self.parent.addr += int(self.addr)

class rebase_opcode(rebase_entry):
    opcode = REBASE_OPCODE_ADD_ADDR_IMM_SCALED
    _fields = [ ("val", "u08") ]
    add_addr = property(lambda _: _.imm*(_.wsize//8))
    def __str__(self):
        return rebase_entry.__str__(self) + '(0x%X)' % self.add_addr
    def apply(self):
        if not hasattr(self.parent, 'addr'): raise ValueError
        self.parent.addr += self.add_addr

class rebase_opcode(rebase_entry):
    opcode = REBASE_OPCODE_DO_REBASE_IMM_TIMES
    _fields = [ ("val", "u08") ]
    def __str__(self):
        return rebase_entry.__str__(self) + '(%d)' % self.imm
    def apply(self):
        if not hasattr(self.parent, 'addr'): raise ValueError
        for i in range(self.imm):
            self.parent._info.append(self.parent.cls(self))
            self.parent.addr += self.wsize//8

class rebase_opcode(rebase_entry):
    opcode = REBASE_OPCODE_DO_REBASE_ULEB_TIMES
    _fields = [ ("val", "u08"), ("count", Uleb128) ]
    def __str__(self):
        return rebase_entry.__str__(self) + '(%d)' % int(self.count)
    def apply(self):
        if not hasattr(self.parent, 'addr'): raise ValueError
        for i in range(int(self.count)):
            self.parent._info.append(self.parent.cls(self))
            self.parent.addr += self.wsize//8

class rebase_opcode(rebase_entry):
    opcode = REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB
    _fields = [ ("val", "u08"), ("value", Uleb128) ]
    add_addr = property(lambda _: _.wsize//8 + int(_.value))
    def __str__(self):
        return rebase_entry.__str__(self) + '(%d)' % (self.add_addr & mask32)
    def apply(self):
        if not hasattr(self.parent, 'addr'): raise ValueError
        self.parent._info.append(self.parent.cls(self))
        self.parent.addr += self.add_addr

class rebase_opcode(rebase_entry):
    opcode = REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
    _fields = [ ("val", "u08"), ("count", Uleb128), ("skip", Uleb128) ]
    def __str__(self):
        return rebase_entry.__str__(self) + '(%d, %d)' % (int(self.count), int(self.skip))
    def apply(self):
        if not hasattr(self.parent, 'addr'): raise ValueError
        for i in range(int(self.count)):
            self.parent._info.append(self.parent.cls(self))
            self.parent.addr += int(self.skip) + self.wsize//8

del rebase_opcode

class DyldArrayRebase(DyldArrayGeneric):
    _cls = rebase_entry
    type = 'rebase_'
dyldarray_register(DyldArrayRebase)

#### Source: /usr/include/mach-o/loader.h

# The symbols exported by a dylib are encoded in a trie.  This
# is a compact representation that factors out common prefixes.
# It also reduces LINKEDIT pages in RAM because it encodes all  
# information (name, address, flags) in one small, contiguous range.
# The export area is a stream of nodes.  The first node sequentially
# is the start node for the trie.  
#
# Nodes for a symbol start with a uleb128 that is the length of
# the exported symbol information for the string so far.
# If there is no exported symbol, the node starts with a zero byte. 
# If there is exported info, it follows the length.  
#
# First is a uleb128 containing flags. Normally, it is followed by
# a uleb128 encoded offset which is location of the content named
# by the symbol from the mach_header for the image.  If the flags
# is EXPORT_SYMBOL_FLAGS_REEXPORT, then following the flags is
# a uleb128 encoded library ordinal, then a zero terminated
# UTF8 string.  If the string is zero length, then the symbol
# is re-export from the specified dylib with the same name.
#
# If the flags is EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER, then following
# the flags is two uleb128s: the stub offset and the resolver offset.
# The stub is used by non-lazy pointers.  The resolver is used
# by lazy pointers and must be called to get the actual address to use.
#
# After the optional exported symbol information is a byte of
# how many edges (0-255) that this node has leaving it, 
# followed by each edge.
# Each edge is a zero terminated UTF8 of the addition chars
# in the symbol, followed by a uleb128 offset for the node that
# edge points to.

# The following are used on the flags byte of a terminal node
# in the export information.
EXPORT_SYMBOL_FLAGS_KIND_MASK                = 0x03
EXPORT_SYMBOL_FLAGS_KIND_REGULAR             = 0x00
EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL        = 0x01
EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE            = 0x02
EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION          = 0x04
EXPORT_SYMBOL_FLAGS_REEXPORT                 = 0x08
EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER        = 0x10

class export_entry(object):
    def __init__(self, entry, sym, flags, addr, other, name):
        self.sym = sym
        self.flags = int(flags)
        self.addr = int(addr)
        self.other = int(other)
        self.name = name
        self.macho = entry.parent.parent.parent
    def __str__(self):
        if self.flags & EXPORT_SYMBOL_FLAGS_REEXPORT: addr = '[re-export]'
        else: addr = '0x%08X ' % self.addr
        flags = []
        if self.flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION:
            flags.append('weak_def')
        if (self.flags & EXPORT_SYMBOL_FLAGS_KIND_MASK) == EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL:
            flags.append('per-thread')
        if (self.flags & EXPORT_SYMBOL_FLAGS_KIND_MASK) == EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE:
            flags.append('absolute')
        if self.flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER:
            flags.append('resolver=0x%08X'%self.other)
        flags = ','.join(flags)
        if flags: flags = '[flags]'
        if self.flags & EXPORT_SYMBOL_FLAGS_REEXPORT:
            lib = get_lib_name(self.macho, self.addr)
            name = str(self.name)
            if len(name): name += ' '
            lib = ' (%sfrom %s)' % (name, lib)
        else:
            lib = ''
        return "%s %s%s%s" % (addr, flags, self.sym, lib)

class dyld_trie(CBase):
    def unpack(self, c, o):
        # 'p' will always be the DyldTrieExport object, independently of
        # the trie depth.
        p = self.parent
        while not hasattr(p, 'info'):
            p = p.parent
        if o >= p.offset + p.size:
            raise ValueError
        self.prefix = self.parent.prefix
        if hasattr(self.parent, 'suffix'):
            self.prefix += str(self.parent.suffix)
        self._size = 0
        termSize, = struct.unpack("B",c[o:o+1])
        p.interval_add(o, o+1)
        self._size += 1
        if termSize:
            flags = Uleb128(parent=self, content=c, start=o+self._size)
            p.interval_add(o+self._size, o+self._size+flags.bytelen)
            self._size += flags.bytelen
            addr = Uleb128(parent=self, content=c, start=o+self._size)
            p.interval_add(o+self._size, o+self._size+addr.bytelen)
            self._size += addr.bytelen
            if   int(flags) & EXPORT_SYMBOL_FLAGS_REEXPORT:
                name = CString(parent=self, content=c, start=o+self._size)
                p.interval_add(o+self._size, o+self._size+name.bytelen)
                other = 0
            elif int(flags) & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER:
                name = None
                other = Uleb128(parent=self, content=c, start=o+self._size)
                p.interval_add(o+self._size, o+self._size+other.bytelen)
            else:
                name = None
                other = 0
            p.info.append(export_entry(p, self.prefix, flags, addr, other, name))
        childCount, = struct.unpack("B",c[o+termSize+1:o+termSize+2])
        p.interval_add(o+termSize+1, o+termSize+2)
        self._size = termSize+2
        for i in range(childCount):
            self.suffix = CString(parent=self, content=c, start=o+self._size)
            p.interval_add(o+self._size, o+self._size+self.suffix.bytelen)
            self._size += self.suffix.bytelen
            offset = Uleb128(parent=self, content=c, start=o+self._size)
            p.interval_add(o+self._size, o+self._size+offset.bytelen)
            self._size += offset.bytelen
            dyld_trie(parent=self, content=c, start=p.offset+int(offset))

class DyldTrieExport(BaseSection):
    type = 'export_'
    def get_size(self):
        return getattr(self.parent, self.type + 'size')
    def set_size(self, val):
        setattr(self.parent, self.type + 'size', val)
    size = property(get_size, set_size)
    def unpack(self, c, o):
        # The trie is a recursive structure with information stored at
        # explicit offsets: malformed files can cause infinite loops.
        # We use 'intervals' to detect such loops.
        from elfesteem.intervals import Intervals
        self.interval = Intervals()
        self.info = []
        self.prefix = ''
        try:
            self.trie = dyld_trie(parent=self, content=c, start=o)
        except ValueError:
            pass
        self.c = c[self.offset:self.offset+self.size]
        # NB: even in well-formed files, not everything is parsed
        #print("TARGET   [%d:%d]"%(self.offset,self.offset+self.size))
        #print("INTERVAL %s"%self.interval)
    def pack(self):
        return self.c
    def interval_add(self, start, stop):
        if self.interval.contains(start, stop):
            log.error('The export trie is malformed, there is a risk of infinite loop')
            raise ValueError
        self.interval.add(start, stop)
    def __str__(self):
        return "%-30s %-10s %#010x %#010x" % (self.__class__.__name__, '', self.offset, len(self.info))
dyldarray_register(DyldTrieExport)

#### Many other sections inside the __LINKEDIT segment

class LinkEditSection(BaseSection):
    type = 'data'
    def unpack(self, c, o):
        if self.parent is not None: assert o == self.offset
        self.content = StrPatchwork(c[o:o+self.size])
    def get_size(self):
        return getattr(self.parent, self.type + 'size')
    def set_size(self, val):
        setattr(self.parent, self.type + 'size', val)
    size = property(get_size, set_size)
    addr = property(lambda _:0)
    def pack(self):
        return self.content.pack()
    def __str__(self):
        return "%-30s %-10s %#010x %#010x" % (self.__class__.__name__, '', self.offset, self.size)

class FunctionStarts(LinkEditSection):
    pass

class DataInCode(LinkEditSection):
    pass

class CodeSignature(LinkEditSection):
    pass

class OptimizationHint(LinkEditSection):
    pass

class Encryption(LinkEditSection):
    type = 'crypt'

class SegmentSplitInfo(LinkEditSection):
    pass

class DylibCodeSign(LinkEditSection):
    pass
    """
    def unpack(self, c, o):
        self.content = StrPatchwork(c)
        self.blobs = []
        of = 0
        while self.content[of:of+2] == '\xfa\xde':
            self.blobs.append(self.content[of:of+20])
            of += 20
        self.string = self.content[of:of+16]
        self.int = self.content[of+16:of+20]
        self.end = self.content[of+20:] # need to be improved
    """

class StringTable(LinkEditSection):
    type = 'str'
    def get_name(self, idx):
        return bytes_to_name(self.content[idx:self.content.find(data_null,idx)])
    def add_name(self, name):
        name = name_to_bytes(name)
        if data_null+name+data_null in self.content:
            return self.content.find(name)
        data = self.content
        if type(data) != str: data = data.pack()
        idx = len(data)
        self.content = data+name+data_null
        for sh in self.parent.shlist:
            if sh.sh.offset > self.sh.offset:
                sh.sh.offset += len(name)+1
        return idx
    def mod_name(self, idx, name):
        name = name_to_bytes(name)
        n = self.content[idx:self.content.find(data_null,idx)]
        data = self.content
        if type(data) != str: data = data.pack()
        data = data[:idx]+name+data[idx+len(n):]
        dif = len(name) - len(n)
        if dif != 0:
            for sh in self.parent.shlist:
                if sh.sh.name_idx > idx:
                    sh.sh.name_idx += dif
                if sh.sh.offset > self.sh.offset:
                    sh.sh.offset += dif
        return idx
    def __str__(self):
        return "%-30s %-10s %#010x %#010x" % ('StringTable', '', self.offset, self.size)

class Sections(object):
    def __init__(self, parent):
        self.parent = parent
        self.sect = []
        lc_list = [ _ for _ in parent.load if hasattr(_, 'sectionsToAdd') ]
        # First, create all sections depending on each load command
        for lc in lc_list:
            lc.sectionsToAdd(self.parent.content)
            self.sect.extend(lc.sect)
            if parent.interval is not None :
                for s in lc.sect:
                    if s.__class__.__name__== 'Encryption':
                        log.warn("Some encrypted text is not parsed with the section headers of LC_SEGMENT(__TEXT)")
                        continue
                    if not parent.interval.contains(s.offset,s.offset+len(s.pack())):
                        #log.warn("This part of file has already been parsed")
                        pass
                    parent.interval.delete(s.offset,s.offset+len(s.pack()))
        # Then if the load command is not a segment, add the section to the
        # list of sections in the relevant segment.
        for lc in lc_list:
            if not hasattr(lc,'segname'):
                for s in lc.sect:
                    segm = parent.getsegment_byoffset(s.offset)
                    if segm is not None: segm.sect.append(s)
    def add(self, s):
        # looking in s.lc to know where to insert
        pos = 0
        for lc in self.parent.load:
            if not hasattr(lc, 'sect'):
                pass
            elif s in lc.sect:
                pos += lc.sect.index(s)
                self.sect[pos:pos] = [s]
                break
            else:
                pos += len(lc.sect)

    def getpos(self, section):
        poslist = []
        for i, s in enumerate(self.sect):
            if s == section :
                poslist.append(i)
        return poslist
    def removepos(self, pos):
        self.sect.remove(self.sect[pos])
    def __getitem__(self, pos):
        return self.sect.__getitem__(pos)
    def __iter__(self):
        return self.sect.__iter__()
    def __len__(self):
        return self.sect.__len__()
    def __repr__(self):
        return "".join(str(self.sect))
    def __str__(self):
        raise ValueError('class Section cannot be output as a bytestream')
