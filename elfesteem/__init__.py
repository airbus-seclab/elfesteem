#! /usr/bin/env python

import elf

class StructWrapper(object):
    class __metaclass__(type):
        def __new__(cls, name, bases, dct):
            wrapped = dct["wrapped"]
            if wrapped is not None:
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
            


class WEhdr(StructWrapper):
    wrapped = elf.Ehdr
    def set_shstrndx(self, val):
        print "Alors on veut changer shstrndx par %r ?" % val
        self.cstr.shstrndx = val

class WSym(StructWrapper):
    wrapped = elf.Sym
    def get_name(self):
        return self.parent.linksection.get_name(self.cstr.name)

class WRel(StructWrapper):
    wrapped = elf.Rel

class WRela(StructWrapper):
    wrapped = elf.Rela

class WShdr(StructWrapper):
    wrapped = elf.Shdr
    def get_name(self):
        return self.parent.parent._shstr.get_name(self.cstr.name)

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
            val = self.parent.seclist.find(val)
        if type(val) is int:
            self.sh.link = val
    linksection = property(get_linksection, set_linksection)
    def get_infosection(self):
        return self.parent[self.sh.info]
    def set_infosection(self, val):
        if isinstance(val, Section):
            val = self.parent.seclist.find(val)
        if type(val) is int:
            self.sh.info = val
    infosection = property(get_infosection, set_infosection)
    
    
    def __init__(self, parent, sh=None):
        self.parent=parent
        self.sh=sh

    
class NullSection(Section):
    sht = elf.SHT_NULL

class ProgBits(Section):
    sht = elf.SHT_PROGBITS

class HashSection(Section):
    sht = elf.SHT_HASH

class Dynamic(Section):
    sht = elf.SHT_DYNAMIC

class NoteSection(Section):
    sht = elf.SHT_NOTE

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
        while c:
            s,c = c[:16],c[16:]
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
        while c:
            s,c = c[:8],c[8:]
            rel = WRel(self,s)
            relname = self.linksection.symtab[rel.sym].name
            self.reltab.append(rel)
            self.rel[relname] = rel
    

### Section List

class SectionList:
    def __init__(self, parent):
        self.parent = parent
        self.seclist = []
        sof1 = self.parent.Ehdr.shoff
        for i in range(self.parent.Ehdr.shnum):
            sof2 = sof1+self.parent.Ehdr.shentsize
            shstr = parent.content[sof1:sof2]
            self.seclist.append( Section(self, shstr=shstr) )
            sof1=sof2
        self._shstr = self.seclist[self.parent.Ehdr.shstrndx]
        for s in self.seclist:
            s._content = parent[s.sh.offset:s.sh.offset+s.sh.size]

        # Follow dependencies when initializing sections
        zero = self.seclist[0]
        todo = self.seclist[1:]
        done = []
        while todo:
            s = todo.pop(0)
            if ( (s.linksection == zero or s.linksection in done)
                 and  (s.infosection == zero or s.infosection in done)):
                done.append(s)
                s.parse_content()
            else:
                todo.append(s)
            
        for s in self.seclist:
            self.do_add_section(s)
        
    def do_add_section(self, section):
        n = section.sh.name
        if n.startswith("."):
            n = n[1:]
        n = n.replace(".","_")
        setattr(self, n, section) #xxx
        
    def append(self, item):
        self.do_add_section(item)
        self.seclist.append(item)
    def __getitem__(self, item):
        return self.seclist[item]
    def __repr__(self):
        rep = ["#  section      offset   size   addr     flags"]
        for i,s in enumerate(self.seclist):
            l = "%(name)-15s %(offset)08x %(size)06x %(addr)08x %(flags)x " % s.sh
            l = ("%2i " % i)+ l + s.__class__.__name__
            rep.append(l)
        return "\n".join(rep)
        


# ELF object

class ELF(object):
    def __init__(self, elfstr):
        self.content = elfstr
    
    content = ContentManager()
    def parse_content(self):
        self.Ehdr = WEhdr(self, self.content)
        self.sections = SectionList(self)
    def __getitem__(self, item):
        return self.content[item]
        
        


if __name__ == "__main__":
    import rlcompleter,readline,pdb
    from pprint import pprint as pp
    readline.parse_and_bind("tab: complete")

    z = ELF(open("/bin/ls").read())
