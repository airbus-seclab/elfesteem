#! /usr/bin/env python

import struct
import elf
from strpatchwork import StrPatchwork

class StructWrapper(object):
    class __metaclass__(type):
        def __new__(cls, name, bases, dct):
            wrapped = dct["wrapped"]
            if wrapped is not None: # XXX: make dct lookup look into base classes
                for fname,v in wrapped._fields:
                    dct[fname] = property(dct.pop("get_"+fname,
                                                  lambda self,fname=fname: getattr(self.cstr,fname)),
                                          dct.pop("set_"+fname,
                                                  lambda self,v,fname=fname: setattr(self.cstr,fname,v)),
                                          dct.pop("del_"+fname, None))
            
            return type.__new__(cls, name, bases, dct)
    wrapped = None
    
    def __init__(self, parent, *args, **kargs):
        self.cstr = self.wrapped(*args, **kargs)
        self.parent = parent
    def __getitem__(self, item):
        return getattr(self,item)
    def __repr__(self):
        return "<W-"+repr(self.cstr)[1:]
    def __str__(self):
        return str(self.cstr)
            


class WEhdr(StructWrapper):
    wrapped = elf.Ehdr
    def set_shstrndx(self, val):
        self.cstr.shstrndx = val

class WSym(StructWrapper):
    wrapped = elf.Sym
    def get_name(self):
        return self.parent.linksection.get_name(self.cstr.name)

class WRel(StructWrapper):
    wrapped = elf.Rel
    def get_sym(self):
        return self.parent.linksection.symtab[self.cstr.sym].name

class WRela(WRel):
    wrapped = elf.Rela

class WShdr(StructWrapper):
    wrapped = elf.Shdr
    def get_name(self):
        return self.parent.parent._shstr.get_name(self.cstr.name)

class WDynamic(StructWrapper):
    wrapped = elf.Dynamic
    def get_name(self):
        if self.type == elf.DT_NEEDED:
            return self.parent.linksection.get_name(self.cstr.name)
        return self.cstr.name

class WPhdr(StructWrapper):
    wrapped = elf.Phdr


class ContentManager(object):
    def __get__(self, owner, x):
        if hasattr(owner, '_content'):
            return owner._content
    def __set__(self, owner, val):
        owner._content=val
        owner.parse_content()
    def __delete__(self, owner):
        self.__set__(owner, None)
        


### Sections


class Section(object):
    sectypes = {}
    class __metaclass__(type):
        def __new__(cls, name, bases, dct):
            o = type.__new__(cls, name, bases, dct)
            if name != "Section":
                Section.register(o)
            return o
        def register(cls, o):
            if o.sht is not None:
                cls.sectypes[o.sht] = o
        def __call__(cls, parent, shstr=None):
            sh = None
            if shstr is not None:
                sh = WShdr(None, shstr)
                if sh.type in Section.sectypes:
                    cls = Section.sectypes[sh.type]
            i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
            if sh is not None:
                sh.parent=i
            i.__init__(parent,sh)
            return i

    content = ContentManager()
    def parse_content(self):
        pass
    def get_linksection(self):
        return self.parent[self.sh.link]
    def set_linksection(self, val):
        if isinstance(val, Section):
            val = self.parent.shlist.find(val)
        if type(val) is int:
            self.sh.link = val
    linksection = property(get_linksection, set_linksection)
    def get_infosection(self):
        return self.parent[self.sh.info]
    def set_infosection(self, val):
        if isinstance(val, Section):
            val = self.parent.shlist.find(val)
        if type(val) is int:
            self.sh.info = val
    infosection = property(get_infosection, set_infosection)
    
    def __init__(self, parent, sh=None):
        self.parent=parent
        self.sh=sh
        self._content=""

    
class NullSection(Section):
    sht = elf.SHT_NULL

class ProgBits(Section):
    sht = elf.SHT_PROGBITS

class HashSection(Section):
    sht = elf.SHT_HASH

class NoBitsSection(Section):
    sht = elf.SHT_NOBITS

class ShLibSection(Section):
    sht = elf.SHT_SHLIB

class InitArray(Section):
    sht = elf.SHT_INIT_ARRAY

class FiniArray(Section):
    sht = elf.SHT_FINI_ARRAY
    
class GroupSection(Section):
    sht = elf.SHT_GROUP
    
class SymTabSHIndeces(Section):
    sht = elf.SHT_SYMTAB_SHNDX
    
class GNUVerSym(Section):
    sht = elf.SHT_GNU_versym
    
class GNUVerNeed(Section):
    sht = elf.SHT_GNU_verneed
    
class GNUVerDef(Section):
    sht = elf.SHT_GNU_verdef
    
class GNULibLIst(Section):
    sht = elf.SHT_GNU_LIBLIST
    
class CheckSumSection(Section):
    sht = elf.SHT_CHECKSUM
    

class NoteSection(Section):
    sht = elf.SHT_NOTE
    def parse_content(self):
        c = self.content
        self.notes = []
        while c:
            namesz,descsz,typ = struct.unpack("III",c[:12])
            name = c[12:12+namesz]
            desc = c[12+namesz:12+namesz+descsz]
            c = c[12+namesz+descsz:]
            self.notes.append((typ,name,desc))



class Dynamic(Section):
    sht = elf.SHT_DYNAMIC
    def parse_content(self):
        c = self.content
        self.dyntab = []
        self.dynamic = {}
        sz = self.sh.entsize
        while c:
            s,c = c[:sz],c[sz:]
            dyn = WDynamic(self,s)
            self.dyntab.append(dyn)
            if type(dyn.name) is str:
                self.dynamic[dyn.name] = dyn
    def __getitem__(self,item):
        if type(item) is str:
            return self.dynamic[item]
        return self.dyntab[item]
            
            
        
    

class StrTable(Section):
    sht = elf.SHT_STRTAB

    def parse_content(self):
        self.res = {}
        c = self.content
        q = 0
        while c:
            p = c.find("\0")
            if p < 0:
                glog.warning("Missing trailing 0 for string [%s]" % c) # XXX
                p = len(c)
            self.res[q] = c[:p]
            q += p+1
            c = c[p+1:]
        
    def get_name(self, ofs):
        n = self.content[ofs:]
        n = n[:n.find("\0")]
        return n

    def add_name(self, name):
        if name in self.content:
            return self.content.index(name)
        n = len(self.content)
        self.content += name+"\0"
        return n

    
class SymTable(Section):
    sht = elf.SHT_SYMTAB
    def parse_content(self):
        c = self.content
        self.symtab=[]
        self.symbols={}
        sz = self.sh.entsize
        while c:
            s,c = c[:sz],c[sz:]
            sym = WSym(self,s)
            self.symtab.append(sym)
            self.symbols[sym.name] = sym
    def __getitem__(self,item):
        if type(item) is str:
            return self.symbols[item]
        return self.symtab[item]

class DynSymTable(SymTable):
    sht = elf.SHT_DYNSYM


class RelTable(Section):
    sht = elf.SHT_REL
    def parse_content(self):
        c = self.content
        self.reltab=[]
        self.rel = {}
        sz = self.sh.entsize
        while c:
            s,c = c[:sz],c[sz:]
            rel = WRel(self,s)
            self.reltab.append(rel)
            self.rel[rel.sym] = rel
    

### Section List

class SHList:
    def __init__(self, parent):
        self.parent = parent
        self.shlist = []
        ehdr = self.parent.Ehdr
        of1 = ehdr.shoff
        if not of1: # No SH table
            return
        for i in range(ehdr.shnum):
            of2 = of1+ehdr.shentsize
            shstr = parent[of1:of2]
            self.shlist.append( Section(self, shstr=shstr) )
            of1=of2
        self._shstr = self.shlist[ehdr.shstrndx]

        for s in self.shlist:
            if not isinstance(s, NoBitsSection):
                s._content = parent[s.sh.offset: s.sh.offset+s.sh.size]
            
            
        # Follow dependencies when initializing sections
        zero = self.shlist[0]
        todo = self.shlist[1:]
        done = []
        while todo:
            s = todo.pop(0)
            if ( (s.linksection == zero or s.linksection in done)
                 and  (s.infosection == zero or s.infosection in done)):
                done.append(s)
                s.parse_content()
            else:
                todo.append(s)
            
        for s in self.shlist:
            self.do_add_section(s)
        
    def do_add_section(self, section):
        n = section.sh.name
        if n.startswith("."):
            n = n[1:]
        n = n.replace(".","_").replace("-","_")
        setattr(self, n, section) #xxx
        
    def append(self, item):
        self.do_add_section(item)
        self.shlist.append(item)
    def __getitem__(self, item):
        return self.shlist[item]
    def __repr__(self):
        rep = ["#  section         offset   size   addr     flags"]
        for i,s in enumerate(self.shlist):
            l = "%(name)-15s %(offset)08x %(size)06x %(addr)08x %(flags)x " % s.sh
            l = ("%2i " % i)+ l + s.__class__.__name__
            rep.append(l)
        return "\n".join(rep)
    def __str__(self):
        c = []
        for s in self.shlist:
            c.append(str(s.sh))
        return "".join(c)
        

### Program Header List


class ProgramHeader:
    def __init__(self, parent, phstr):
        self.parent = parent
        self.ph = WPhdr(self,phstr)
        self.shlist = []
        for s in self.parent.parent.sh:
            if isinstance(s, NullSection):
                continue
            if ( (isinstance(s,NoBitsSection) and s.sh.offset == self.ph.offset+self.ph.filesz)
                 or  self.ph.offset <= s.sh.offset < self.ph.offset+self.ph.filesz ):
                s.phparent = self
                self.shlist.append(s)
        
                
    

class PHList:
    def __init__(self, parent):
        self.parent = parent
        self.phlist = []
        ehdr = self.parent.Ehdr
        of1 = ehdr.phoff
        for i in range(ehdr.phnum):
            of2 = of1+ehdr.phentsize
            phstr = parent[of1:of2]
            self.phlist.append(ProgramHeader(self, phstr))
            of1 = of2
        
    def __getitem__(self, item):
        return self.phlist[item]

    def __repr__(self):
        r = ["   offset filesz vaddr    memsz"]
        for i,p in enumerate(self.phlist):
            l = "%(offset)06x %(filesz)06x %(vaddr)08x %(memsz)06x "%p.ph
            l = ("%2i " % i)+l
            r.append(l)
            r.append("   "+" ".join([s.sh.name for s in p.shlist]))
        return "\n".join(r)
    def __str__(self):
        c = []
        for p in self.phlist:
            c.append(str(p.ph))
        return "".join(c)
                


# ELF object

class ELF(object):
    def __init__(self, elfstr):
        self.content = elfstr
    
    content = ContentManager()
    def parse_content(self):
        self.Ehdr = WEhdr(self, self.content)
        self.sh = SHList(self)
        self.ph = PHList(self)
    def __getitem__(self, item):
        return self.content[item]

    def build_content(self):
        c = StrPatchwork()
        c[0] = str(self.Ehdr)
        c[self.Ehdr.phoff] = str(self.ph)
        for s in self.sh:
            c[s.sh.offset] = s.content
        c[self.Ehdr.shoff] = str(self.sh)
        return str(c)

    def __str__(self):
        return self.content
        


if __name__ == "__main__":
    import rlcompleter,readline,pdb
    from pprint import pprint as pp
    readline.parse_and_bind("tab: complete")

    e = ELF(open("/bin/ls").read())
    o = ELF(open("/tmp/svg-main.o").read())
