#! /usr/bin/env python

import struct

import elf
from strpatchwork import StrPatchwork
import logging

log = logging.getLogger("elfparse")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)


class ContentManager(object):
    def __get__(self, owner, x):
        if hasattr(owner, '_content'):
            return owner._content
    def __set__(self, owner, new_content):
        owner.resize(len(owner._content), len(new_content))
        owner._content=StrPatchwork(new_content)
        owner.parse_content()
    def __delete__(self, owner):
        self.__set__(owner, None)


### Sections


def inherit_sex_wsize(self, parent, kargs):
    for f in ['sex', 'wsize']:
        if f in kargs:
            setattr(self, f, kargs[f])
            del kargs[f]
        elif parent != None:
            setattr(self, f, getattr(parent, f))

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
                sh = elf.Shdr(parent = None, content = shstr, sex = parent.sex, wsize = parent.wsize)
                if sh.type in Section.sectypes:
                    cls = Section.sectypes[sh.type]
            i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
            if sh is not None:
                sh._parent=i
            i.__init__(parent, sh)
            return i

    content = ContentManager()
    def resize(self, old, new):
        self.sh.size += new-old
        self.parent.resize(self, new-old)
        if self.phparent:
            self.phparent.resize(self, new-old)
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
        #XXX info may not be in sh list ?!?
        if not self.sh.info in self.parent:
            return None
        return self.parent[self.sh.info]
    def set_infosection(self, val):
        if isinstance(val, Section):
            val = self.parent.shlist.find(val)
        if type(val) is int:
            self.sh.info = val
    infosection = property(get_infosection, set_infosection)
    def __init__(self, parent, sh=None):
        self.parent=parent
        self.phparent=None
        self.sh=sh
        self._content=""
        inherit_sex_wsize(self, parent, {})
    def __repr__(self):
        r = "{%(name)s ofs=%(offset)#x sz=%(size)#x addr=%(addr)#010x}" % self.sh
        return r
    def get_size(self):
        return self.sh.size
    size = property(get_size)
    def get_addr(self):
        return self.sh.addr
    addr = property(get_addr)

class NullSection(Section):
    sht = elf.SHT_NULL
    def get_name(self, ofs):
        # XXX check this
        return ""

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
        # XXX: c may not be aligned?
        while len(c)> 12:
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
            dyn = elf.Dynamic(parent=self, content=s)
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
                log.warning("Missing trailing 0 for string [%s]" % c) # XXX
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
            return self.content.find(name)
        n = len(self.content)
        self.content = str(self.content)+name+"\0"
        return n

    def mod_name(self, name, new_name):
        s = str(self.content)
        if not name in s:
            raise ValueError('unknown name', name)
        s = s.replace('\x00'+name+'\x00', '\x00'+new_name+'\x00')
        self.content = s
        return len(self.content)

class SymTable(Section):
    sht = elf.SHT_SYMTAB
    def parse_content(self):
        Sym = { 32: elf.Sym32, 64: elf.Sym64 }[self.wsize]
        c = self.content
        self.symtab=[]
        self.symbols={}
        sz = self.sh.entsize
        while c:
            s,c = c[:sz],c[sz:]
            sym = Sym(parent=self, content=s)
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
        if self.__class__.sht == elf.SHT_REL:
            Rel = { 32: elf.Rel32,  64: elf.Rel64 }[self.wsize]
        elif self.__class__.sht == elf.SHT_RELA:
            Rel = { 32: elf.Rela32, 64: elf.Rela64 }[self.wsize]
        c = self.content
        self.reltab=[]
        self.rel = {}
        sz = self.sh.entsize
        while c:
            s,c = c[:sz],c[sz:]
            rel = Rel(parent=self, content=s)
            self.reltab.append(rel)
            self.rel[rel.sym] = rel

class RelATable(RelTable):
    sht = elf.SHT_RELA


### Section List

class SHList(object):
    def __init__(self, parent, **kargs):
        self.parent = parent
        inherit_sex_wsize(self, parent, kargs)
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
                s._content = StrPatchwork(parent[s.sh.offset: s.sh.offset+s.sh.size])
        # Follow dependencies when initializing sections
        zero = self.shlist[0]
        todo = self.shlist[1:]
        done = []
        while todo:
            s = todo.pop(0)
            if ( (s.linksection == zero or s.linksection in done)
                 and  (s.infosection in  [zero, None] or s.infosection in done)):
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
    def resize(self, sec, diff):
        for s in self.shlist:
            if s.sh.offset > sec.sh.offset:
                s.sh.offset += diff
        if self.parent.Ehdr.shoff > sec.sh.offset:
            self.parent.Ehdr.shoff += diff
        if self.parent.Ehdr.phoff > sec.sh.offset:
            self.parent.Ehdr.phoff += diff

### Program Header List


class ProgramHeader(object):
    def __init__(self, parent, PHtype, phstr, **kargs):
        self.parent = parent
        inherit_sex_wsize(self, parent, kargs)
        self.ph = PHtype(parent=self, content=phstr)
        self.shlist = []
        for s in self.parent.parent.sh:
            if isinstance(s, NullSection):
                continue
            if ( (   isinstance(s,NoBitsSection)
                     and s.sh.offset == self.ph.offset+self.ph.filesz )
                 or  self.ph.offset <= s.sh.offset < self.ph.offset+self.ph.filesz ):
                s.phparent = self
                self.shlist.append(s)
    def resize(self, sec, diff):
        self.ph.filesz += diff
        self.ph.memsz += diff
        self.parent.resize(sec, diff)
    # get_rvaitem needs addr and size (same names as in the Shdr class)
    # Note that we should always have memsz >= filesz unless memsz == 0
    # Note that paddr is irrelevant for most OS
    def get_size(self):
        return self.ph.memsz
    size = property(get_size)
    def get_addr(self):
        return self.ph.vaddr
    addr = property(get_addr)

class PHList(object):
    def __init__(self, parent, **kargs):
        self.parent = parent
        inherit_sex_wsize(self, parent, kargs)
        self.phlist = []
        ehdr = self.parent.Ehdr
        of1 = ehdr.phoff
        for i in range(ehdr.phnum):
            of2 = of1+ehdr.phentsize
            phstr = parent[of1:of2]
            self.phlist.append(ProgramHeader(self,
                { 32: elf.Phdr32, 64: elf.Phdr64 }[self.wsize],
                phstr))
            of1 = of2

    def __getitem__(self, item):
        return self.phlist[item]

    def __repr__(self):
        r = ["   offset filesz vaddr    memsz"]
        for i,p in enumerate(self.phlist):
            l = "%(offset)07x %(filesz)06x %(vaddr)08x %(memsz)07x %(type)02x"%p.ph
            l = ("%2i " % i)+l
            r.append(l)
            r.append("   "+" ".join([s.sh.name for s in p.shlist]))
        return "\n".join(r)
    def __str__(self):
        c = []
        for p in self.phlist:
            c.append(str(p.ph))
        return "".join(c)
    def resize(self, sec, diff):
        for p in self.phlist:
            if p.ph.offset > sec.sh.offset:
                p.ph.offset += diff
            if p.ph.vaddr > sec.phparent.ph.vaddr+sec.sh.offset:
                p.ph.vaddr += diff
            if p.ph.paddr > sec.phparent.ph.paddr+sec.sh.offset:
                p.ph.paddr += diff


class virt(object):
    def __init__(self, x):
        self.parent = x

    def get_rvaitem(self, item, section = None):
        if item.stop == None:
            s = self.parent.getsectionbyvad(item.start, section)
            return [(s, item.start-s.addr)]

        total_len = item.stop - item.start
        start = item.start
        virt_item = []
        while total_len:
            s = self.parent.getsectionbyvad(start, section)
            if not s:
                raise ValueError('unknown rva address! %x'%start)
            s_start = start - s.addr
            s_stop = item.stop - s.addr
            if s_stop > s.size:
                s_stop =  s.size
            s_len = s_stop - s_start
            if s_len == 0:
                raise ValueError('empty section! %x'%start)
            total_len -= s_len
            start += s_len
            n_item = slice(s_start, s_stop)
            virt_item.append((s, n_item))
        return virt_item


    def __call__(self, ad_start, ad_stop = None, section = None):
        rva_items = self.get_rvaitem(slice(ad_start, ad_stop), section)
        return self.rvaitems2binary(rva_items)

    def __getitem__(self, item):
        rva_items = self.get_rvaitem(item)
        return self.rvaitems2binary(rva_items)

    def rvaitems2binary(self, rva_items):
        data_out = ""
        for s, n_item in rva_items:
            if not isinstance(s, ProgramHeader):
                data_out += s.content[n_item]
                continue
            if not type(n_item) is slice:
                n_item = slice(n_item, n_item+1)
            start = n_item.start + s.ph.offset
            stop  = n_item.stop + s.ph.offset
            n_item = slice(start, stop)
            data_out += self.parent.content[n_item]
        return data_out

    def __setitem__(self, item, data):
        if not type(item) is slice:
            item = slice(item, item+len(data))
        rva_items = self.get_rvaitem(item)
        if not rva_items:
             return
        off = 0
        for s, n_item in rva_items:
            if isinstance(s, ProgBits):
                i = slice(off, n_item.stop+off-n_item.start)

                data_slice = data.__getitem__(i)
                s.content.__setitem__(n_item, data_slice)
                off = i.stop
            else:
                raise ValueError('TODO XXX')

        return

    def __len__(self):
        # the maximum virtual address is found by retrieving the maximum
        # possible virtual address, either from the program entries, and
        # section entries. if there is no such object, raise an error.
        l = 0
        if  self.parent.ph.phlist:
            for phdr in self.parent.ph.phlist:
                l = max(l, phdr.ph.vaddr + phdr.ph.memsz)
        if  self.parent.sh.shlist:
            for shdr in self.parent.sh.shlist:
                l = max(l, shdr.sh.addr  + shdr.sh.size)
        if  not l:
            raise ValueError('maximum virtual address not found !')
        return l

    def is_addr_in(self, ad):
        return self.parent.is_in_virt_address(ad)

    def find(self, pattern, offset = 0):
        sections = []
        for s in self.parent.ph:
            s_max = s.ph.memsz#max(s.ph.filesz, s.ph.memsz)
            if offset < s.ph.vaddr + s_max:
                sections.append(s)

        if not sections:
            return -1
        offset -= sections[0].ph.vaddr
        if offset < 0:
            offset = 0
        for s in sections:
            data = self.parent.content[s.ph.offset:s.ph.offset+s.ph.filesz]
            ret = data.find(pattern, offset)
            if ret != -1:
                return ret  + s.ph.vaddr#self.parent.rva2virt(s.addr + ret)
            offset = 0
        return -1

# ELF object
class ELF(object):
    def __init__(self, elfstr):
        self._content = elfstr
        self.parse_content()

        self._virt = virt(self)

    def get_virt(self):
        return self._virt
    virt = property(get_virt)

    content = ContentManager()
    def parse_content(self):
        h = self.content[:8]
        self.wsize = ord(h[4])*32
        self.sex   = {1:'<', 2:'>'} [ord(h[5])]
        self.Ehdr = elf.Ehdr(parent=self, content=self.content)
        self.sh = SHList(parent=self)
        self.ph = PHList(parent=self)
    def resize(self, old, new):
        pass
    def __getitem__(self, item):
        return self.content[item]

    def build_content(self):
        c = StrPatchwork()
        c[0] = str(self.Ehdr)
        c[self.Ehdr.phoff] = str(self.ph)
        for s in self.sh:
            c[s.sh.offset] = str(s.content)
        c[self.Ehdr.shoff] = str(self.sh)
        return str(c)

    def __str__(self):
        return self.build_content()

    def getsectionbyname(self, name):
        # TODO: many sections may have the same name, e.g. '.group'
        for s in self.sh:
            if s.sh.name.strip('\x00') == name:
                return s
        return None

    def getsectionbyvad(self, ad, section = None):
        if section:
            s = self.getsectionbyname(section)
            if s.sh.addr <= ad < s.sh.addr + s.sh.size:
                return s
        sh = [ s for s in self.sh if s.addr <= ad < s.addr+s.size ]
        ph = [ s for s in self.ph if s.addr <= ad < s.addr+s.size ]
        if len(sh) == 1 and len(ph) == 1:
            # Executable returns a section and a PH
            if not sh[0] in ph[0].shlist:
                raise ValueError("Mismatch: section not in segment")
            return sh[0]
        if len(sh) == 0 and len(ph) == 1:
            # Core returns a PH
            return ph[0]
        if len(ph) == 0 and len(sh) > 1:
            # Relocatable returns many sections, all at address 0
            # The priority given to .text is heuristic
            for s in sh:
                if s.sh.name == '.text':
                    return s
            for s in sh:
                if s.sh.name.startswith('.text'):
                    return s
            return sh[0]
        return None


    def is_in_virt_address(self, ad):
        for s in self.sh:
            if s.sh.addr <= ad < s.sh.addr + s.sh.size:
                return True
        return False

if __name__ == "__main__":
    import rlcompleter,readline,pdb
    from pprint import pprint as pp
    readline.parse_and_bind("tab: complete")

    e = ELF(open("/bin/ls").read())
    print repr(e)
    #o = ELF(open("/tmp/svg-main.o").read())
