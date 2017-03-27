from elfesteem.macho_common import *
from elfesteem.cstruct import CBase, CData, CArray, CStructWithStrTable
from elfesteem.strpatchwork import StrPatchwork

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
        raise AttributeError("Use pack() instead of str()")

class TrueSection(BaseSection):
    name = property(lambda _:_.parent.name)
    def set_size(self, val):
        self.parent.size = val
    size = property(lambda _:_.parent.size, set_size)
    addr = property(lambda _:_.parent.addr)
    # 'sh' member should be obsolete, but is used to detect a true section.
    sh = property(lambda _:_.parent)

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
    # TODO: update self.parent.nreloc when the array size changes

class symbol(CStructWithStrTable):
    _fields = [ ("name_idx","u32"),
                ("type","u08"),
                ("sectionindex","u08"),
                ("description","u16"),
                ("value","ptr")]
    def strtab(self):
        return self.parent.parent.strtab
    strtab = property(strtab)

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
    def __getitem__(self, idx):
        if type(idx) == int:
            return self.symbols[idx]
        else:
            return self.symbols_from_name[idx.strip(data_null)]
        raise ValueError("Cannot find symbol with index %r"%idx)

class Hint(BaseSection,CArray):
    type = None
    _cls = twolevel_hint
    count = lambda _:_.parent.nhints

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

class LinkEditSectionWithType(LinkEditSection):
    def unpack(self, c, o):
        self._off = o
        self.content = StrPatchwork(c)
    def update(self, **kargs):
        self.type = kargs['type']
        if self.parent is not None: assert self._off == self.offset
        self._parsecontent()
    def _parsecontent(self):
        pass

class DynamicLoaderInfo(LinkEditSectionWithType):
    def _parsecontent(self):
        """
        if self.type == 'bind':
            of = getattr(self.parent,self.type+'_off')
            if of != 0:
                self.BindSymbolOpcodeList = []
                offset = 0
                size = len(str(self.content))
                bindSymbolOpcode = BindSymbolOpcode(self.content)
                while bindSymbolOpcode:
                    self.BindSymbolOpcodeList.append(bindSymbolOpcode)
                    offset += len(bindSymbolOpcode)
                    bindSymbolOpcode = BindSymbolOpcode(self.content[offset:])
        """
        if self.type == 'lazy_bind':
            of = getattr(self.parent,self.type+'_off')
            if of != 0:
                self.SymbolOpcodeList = []
                offset = 0
                size = len(self.content.pack())
                symbolOpcode = SymbolOpcode(self.content, self)
                while symbolOpcode:
                    self.SymbolOpcodeList.append(symbolOpcode)
                    offset += len(symbolOpcode)
                    symbolOpcode = SymbolOpcode(self.content[offset:], self)
        else:
            self.c = self.content[self.offset:self.offset+self.size]
    def pack(self):
        if self.type == 'lazy_bind':
            data = data_empty
            for x in self.SymbolOpcodeList:
                data += x.pack()
            return data
        else:
            return self.c

#### Source: /usr/include/mach-o/loader.h

# An indirect symbol table entry is simply a 32bit index into the symbol table
# to the symbol that the pointer or stub is refering to.  Unless it is for a
# non-lazy symbol pointer section for a defined symbol which strip(1) as
# removed.  In which case it has the value INDIRECT_SYMBOL_LOCAL.  If the
# symbol was also absolute INDIRECT_SYMBOL_ABS is or'ed with that.
INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS   = 0x40000000
class dylib_indirect_entry(CStruct):
    _fields = [ ("index","u32") ]

# A table of contents entry
class dylib_table_of_contents(CStruct):
    _fields = [
        ("symbol_index","u32"), # the defined external symbol (index into the symbol table)
        ("module_index","u32"), # index into the module table this symbol is defined in
        ]

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

#### Source: unknown

class DySymbolTable(LinkEditSectionWithType):
    def _parsecontent(self):
        self.entries = []
        of = self._off
        object_count = 'n'+self.type
        if self.type.endswith('sym'): object_count += 's'
        count = getattr(self.parent, object_count)
        one_sym_size = self.size//count
        sym_type = {
            'indirectsym': dylib_indirect_entry,
            'extrefsym':   dylib_reference,
            'locrel':      relocation_info,
            'extrel':      relocation_info,
            'toc':         dylib_table_of_contents,
            'modtab':      dylib_module,
            }[self.type]
        for i in range(count):
            symbol = sym_type(parent=self, content=self.content, start=of)
            self.entries.append(symbol)
            of += symbol.bytelen
    def pack(self):
        data = data_empty
        for x in self.entries:
            data += x.pack()
        return data

"""
class BindSymbolOpcode(object):
    def __init__(self, content):
        pass
"""

class SymbolOpcode(object):
    def __init__(self, content, parent):
        self.offset = 0
        self.opsize = 0
        content = StrPatchwork(content)
        self.segment, = struct.unpack("B",content[self.opsize:self.opsize+1])
        self.opsize += 1
        """
        self.startuleb = self.opsize
        """
        uleb128termination = False
        while not uleb128termination:
            ulebbyte, = struct.unpack("B",content[self.opsize:self.opsize+1])
            uleb128termination = (ulebbyte < 128)
            self.offset += (ulebbyte % 128) * 128**(self.opsize-1)
            self.opsize += 1
        """
        self.enduleb = self.opsize
        self.uleb = content[self.startuleb:self.enduleb]
        """
        self.dylib, = struct.unpack("B",content[self.opsize:self.opsize+1])
        self.opsize += 1
        if self.dylib == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            self.libraryOrdinal, = struct.unpack("B",content[self.opsize:self.opsize+1])
            self.opsize += 1
        self.flags,  = struct.unpack("B",content[self.opsize:self.opsize+1])
        self.opsize += 1
        self.name = content[self.opsize:content.find(data_null,self.opsize)]
        self.opsize += len(self.name)+1
        self.doBind,self.done, = struct.unpack("BB",content[self.opsize:self.opsize+2])
        self.opsize += 2
        self.addr = self.offset + parent.parent.parent.parent.parent.load[self.segment & 0x0f].vmaddr
        self.realoffset = self.offset + parent.parent.parent.parent.parent.load[self.segment & 0x0f].fileoff
        if (self.doBind, self.done) != (0x90, 0):
            self.opsize = 0
            return

    def __repr__(self):
        fields = [ "segment", "offset", "dylib" ]
        if hasattr(self, 'libraryOrdinal'):
            fields.append("libraryOrdinal")
        fields.extend(["flags", "doBind", "done"])
        return "<" + self.__class__.__name__ + " " + " -- ".join([x + " " + hex(getattr(self,x)) for x in fields]) + " -- " + "name" + " " + self.name + ">"

    def __str__(self):
        NEVER

    def pack(self):
        val = self.offset
        uleb = data_empty
        uleb128termination = False
        while not uleb128termination:
            byte = val%128
            val = int(val/128)
            uleb128termination = (val == 0)
            if not uleb128termination:
                byte += 128
            uleb += struct.pack("B", byte)
        if hasattr(self, 'libraryOrdinal'):
            return struct.pack("B",self.segment) + uleb + struct.pack("B",self.dylib) + struct.pack("B",self.libraryOrdinal) + struct.pack("B",self.flags) + self.name+data_null + struct.pack("B",self.doBind) + struct.pack("B",self.done)
        else:
            return struct.pack("B",self.segment) + uleb + struct.pack("B",self.dylib) + struct.pack("B",self.flags) + self.name+data_null + struct.pack("B",self.doBind) + struct.pack("B",self.done)
    def __len__(self):
        return self.opsize

class Sections(object):
    def __init__(self, parent):
        self.parent = parent
        self.sect = []
        for lc in parent.load:
            if hasattr(lc, 'sectionsToAdd'):
                lc.sectionsToAdd(self.parent.content)
                self.sect.extend(lc.sect)
                if not hasattr(lc,'segname'):
                    for s in lc.sect:
                        for loco in parent.load:
                            if hasattr(loco,'segname'):# searching in parent.lh of LC_segment
                                if loco.fileoff < s.offset and s.offset < loco.fileoff + loco.filesize :
                                    loco.sect.append(s)# ajout a sect
                if parent.interval is not None :
                    for s in lc.sect:
                        if s.__class__.__name__== 'Encryption':
                            log.warn("Some encrypted text is not parsed with the section headers of LC_SEGMENT(__TEXT)")
                            continue
                        if not parent.interval.contains(s.offset,s.offset+len(s.pack())):
                            #log.warn("This part of file has already been parsed")
                            pass
                        parent.interval.delete(s.offset,s.offset+len(s.pack()))
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
    def __iter__(self):
        return self.sect.__iter__()
    def __len__(self):
        return self.sect.__len__()
    def __repr__(self):
        return "".join(str(self.sect))
    def __str__(self):
        raise ValueError('class Section cannot be output as a bytestream')
