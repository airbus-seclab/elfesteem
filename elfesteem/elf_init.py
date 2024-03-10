#! /usr/bin/env python

import struct

from elfesteem import elf
from elfesteem.strpatchwork import StrPatchwork
import logging

log = logging.getLogger("elfparse")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)



### Sections


def inheritsexwsize(self, parent, kargs):
    for f in ['sex', 'wsize']:
        if f in kargs:
            setattr(self, f, kargs[f])
            del kargs[f]
        elif parent != None:
            setattr(self, f, getattr(parent, f))

class SectionMetaclass(type):
    sectypes = {}
    def __new__(cls, name, bases, dct):
        o = type.__new__(cls, name, bases, dct)
        if name != "SectionBase" and o.sht is not None:
            SectionMetaclass.sectypes[o.sht] = o
        return o

SectionBase = SectionMetaclass('SectionBase', (object,), {})

class Section(SectionBase):
    sht = None
    def create(cls, parent, shstr=None):
        if shstr is None:
            sh = None
        else:
            sh = elf.Shdr(parent = None, content = shstr, sex = parent.sex, 
wsize = parent.wsize)
            if sh.type in SectionMetaclass.sectypes:
                cls = SectionMetaclass.sectypes[sh.type]
        i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
        if sh is not None:
            sh.parent=i
        i.__init__(parent, sh)
        return i
    create = classmethod(create)

    def resize(self, old, new):
        self.sh.size += new-old
        self.parent.resize(self, new-old)
        if self.phparent:
            self.phparent.resize(self, new-old)
    def parse_content(self):
        pass
    def pack(self):
        data = self.content
        if type(data) != str: data = data.pack()
        return data
    def get_linksection(self):
        try:
            linksection = self.parent[self.sh.link]
        except IndexError:
            linksection = NoLinkSection
        return linksection
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
    shstrtab = property(lambda _: _.parent._shstrtab)
    def __init__(self, parent, sh=None, **kargs):
        self.parent=parent
        self.phparent=None
        inheritsexwsize(self, parent, {})
        if sh is None:
            sh = elf.Shdr(parent=self, type=self.sht, name_idx=0, **kargs)
        self.sh=sh
        self.content=StrPatchwork()
    def __repr__(self):
        return "%(name)-15s %(offset)08x %(size)06x %(addr)08x %(flags)x" % self.sh
    size = property(lambda _: _.sh.size)
    addr = property(lambda _: _.sh.addr)
    name = property(lambda _: _.sh.name)

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
    def get_flags(self):
        flags, = struct.unpack("I", self.content[:4])
        return flags
    def get_sections(self):
        l = len(self.content)//4 - 1
        sections = struct.unpack("I"*l, self.content[4:])
        return sections
    def set_flags(self, value):
        self.content[0] = struct.pack("I", value)
    def set_sections(self, value):
        for idx in self.sections:
            self.parent.shlist[idx].sh.flags &= ~elf.SHF_GROUP
        for idx in value:
            self.parent.shlist[idx].sh.flags |= elf.SHF_GROUP
            self.parent.shlist[idx].sh.addralign = 1
        self.content[4] = struct.pack("I"*len(value), *value)
    flags = property(get_flags, set_flags)
    sections = property(get_sections, set_sections)
    def readelf_display(self):
        if self.flags == elf.GRP_COMDAT: flags = 'COMDAT'
        else:                            flags = ''
        symbol = self.parent.parent.sh[self.sh.link]
        if not symbol.sh.type == elf.SHT_SYMTAB:
            return "readelf: Error: Bad sh_link in group section `%s'"%self.sh.name
        symbol = symbol[self.sh.info].name
        rep = [ "%s group section [%4d] `%s' [%s] contains %d sections:" % (
            flags,
            self.parent.parent.sh.shlist.index(self),
            self.sh.name,
            symbol,
            len(self.sections)) ]
        format = "   [%5s]   %s"
        rep.append(format % ('Index',' Name'))
        for s_idx in self.sections:
            s = self.parent.parent.sh[s_idx].sh
            rep.append(format % (s_idx,s.name))
            if not (s.flags & elf.SHF_GROUP):
                rep.append("No SHF_GROUP in %s" % s.name)
        return "\n".join(rep)


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
        Dyn = { 32: elf.Dyn32, 64: elf.Dyn64 }[self.wsize]
        c = self.content
        self.dyntab = []
        self.dynamic = {}
        sz = self.sh.entsize
        if sz == 0:
            sz = self.wsize // 4
        idx = 0
        while len(c) > sz*idx:
            s = c[sz*idx:sz*(idx+1)]
            idx += 1
            dyn = Dyn(parent=self, content=s)
            self.dyntab.append(dyn)
            if type(dyn.name) is str:
                self.dynamic[dyn.name] = dyn
    def __getitem__(self,item):
        if type(item) is str:
            return self.dynamic[item]
        return self.dyntab[item]

from elfesteem.cstruct import data_null, bytes_to_name, name_to_bytes

class StrTable(Section):
    sht = elf.SHT_STRTAB

    def get_name(self, idx):
        n = self.content[idx:self.content.find(data_null, idx)]
        return bytes_to_name(n)

    def add_name(self, name):
        name = name_to_bytes(name)
        if data_null+name+data_null in self.content:
            return self.content.find(name)
        idx = len(self.content)
        self.content[idx] = name+data_null
        for sh in self.parent.shlist:
            if sh.sh.offset > self.sh.offset:
                sh.sh.offset += len(name)+1
        return idx

    def mod_name(self, idx, name):
        name = name_to_bytes(name)
        n = self.content[idx:self.content.find(data_null, idx)]
        dif = len(name) - len(n)
        if dif != 0:
            for sh in self.parent.shlist:
                if sh.sh.name_idx > idx:
                    sh.sh.name_idx += dif
                if sh.sh.offset > self.sh.offset:
                    sh.sh.offset += dif
        return idx

class SymTable(Section):
    sht = elf.SHT_SYMTAB
    def __init__(self, *args, **kargs):
        Section.__init__(self, *args, **kargs)
        self.symtab=[]
        self.symbols={}
    def parse_content(self):
        Sym = { 32: elf.Sym32, 64: elf.Sym64 }[self.wsize]
        c = self.content
        sz = Sym(self).bytelen
        if sz != self.sh.entsize:
            log.error("SymTable has invalid entsize %d instead of %d",
                self.sh.entsize, sz)
        idx = 0
        while len(c) > sz*idx:
            s = c[sz*idx:sz*(idx+1)]
            idx += 1
            sym = Sym(parent=self, content=s)
            self.symtab.append(sym)
            self.symbols[sym.name] = sym
    def __len__(self):
        return len(self.symtab)
    def __getitem__(self,item):
        if type(item) is str:
            return self.symbols[item]
        return self.symtab[item]
    def __setitem__(self,item,val):
        if not isinstance(val, elf.Sym32):
            raise ValueError("Cannot set SymTable item to %r"%val)
        if item >= len(self.symtab):
            self.symtab.extend([None for i in range(item+1-len(self.symtab))])
        self.symtab[item] = val
        self.symbols[val.name] = val
        self.content[item*self.sh.entsize] = val.pack()
        if val.info>>4 == elf.STB_LOCAL and item >= self.sh.info:
            # One greater than the symbol table index of the last local symbol
            self.sh.info = item+1
    def readelf_display(self):
        rep = [ "Symbol table '%s' contains %d entries:"
                % (self.sh.name, len(self.symtab)) ]
        if self.wsize == 32:
            rep.append("   Num:    Value  Size Type    Bind   Vis      Ndx Name")
        elif self.wsize == 64:
            rep.append("   Num:    Value          Size Type    Bind   Vis      Ndx Name")
        rep.extend([ _.readelf_display() for _ in self.symtab ])
        return "\n".join(rep)


class DynSymTable(SymTable):
    sht = elf.SHT_DYNSYM


class RelTable(Section):
    sht = elf.SHT_REL
    def parse_content(self):
        if self.__class__.sht == elf.SHT_REL:
            Rel = { 32: elf.Rel32,  64: elf.Rel64 }[self.wsize]
        elif self.__class__.sht == elf.SHT_RELA:
            Rel = { 32: elf.Rela32, 64: elf.Rela64 }[self.wsize]
        if self.parent.parent.Ehdr.machine == elf.EM_MIPS and self.wsize == 64:
            Rel = elf.Rel64MIPS
        c = self.content
        self.reltab=[]
        self.rel = {}
        sz = self.sh.entsize
        idx = 0
        while len(c) > sz*idx:
            s = c[sz*idx:sz*(idx+1)]
            idx += 1
            rel = Rel(parent=self, content=s)
            self.reltab.append(rel)
            self.rel[rel.sym] = rel
    def readelf_display(self):
        ret = "Relocation section %r at offset 0x%x contains %d entries:" % (
            self.sh.name,
            self.sh.offset,
            len(self.reltab))
        if self.wsize == 32:
            ret += "\n Offset     Info    Type            Sym.Value  Sym. Name"
        elif self.wsize == 64:
            ret += "\n  Offset          Info           Type           Sym. Value    Sym. Name"
        if self.sht == elf.SHT_RELA:
            ret += " + Addend"
        for r in self.reltab:
            ret += "\n" + r.readelf_display()
        return ret

class RelATable(RelTable):
    sht = elf.SHT_RELA


### Section List

class SHList(object):
    def __init__(self, parent, **kargs):
        self.parent = parent
        inheritsexwsize(self, parent, kargs)
        self.shlist = []
        ehdr = self.parent.Ehdr
        of1 = ehdr.shoff
        if not of1: # No SH table
            return
        filesize = len(parent.content)
        if of1 > filesize:
            log.error("Offset to section headers after end of file")
            return
        if of1+ehdr.shnum*ehdr.shentsize > filesize:
            log.error("Offset to end of section headers after end of file")
            return
        for i in range(ehdr.shnum):
            of2 = of1+ehdr.shentsize
            shstr = parent[of1:of2]
            self.shlist.append( Section.create(self, shstr=shstr) )
            of1=of2
        assert len(self.shlist) == ehdr.shnum
        # The shstrtab section is not always valid :-(
        if 0 <= ehdr.shstrndx < ehdr.shnum:
            self._shstrtab = self.shlist[ehdr.shstrndx]
        else:
            self._shstrtab = None
        if not isinstance(self._shstrtab, StrTable):
            class NoStrTab(object):
                def get_name(self, idx):
                    return "<no-name>"
            self._shstrtab = NoStrTab()

        if ehdr.shnum == 0: return

        for s in self.shlist:
            if not isinstance(s, NoBitsSection):
                if s.sh.offset > filesize:
                    log.error("Offset to section %d after end of file",
                              self.shlist.index(s))
                    continue
                if s.sh.offset+s.sh.size > filesize:
                    log.error("Offset to end of section %d after end of file",
                              self.shlist.index(s))
                    continue
                s.content = StrPatchwork(parent[s.sh.offset: s.sh.offset+s.sh.size])
        # Follow dependencies when initializing sections
        zero = self.shlist[0]
        todo = self.shlist[1:]
        done = []
        while todo:
            s = todo.pop(0)
            if ( (s.linksection in done + [zero, NoLinkSection]) and
                 (s.infosection in done + [zero, None]) ):
                done.append(s)
                s.parse_content()
            else:
                todo.append(s)
    def append(self, item):
        self.shlist.append(item)
    def __len__(self):
        return len(self.shlist)
    def __getitem__(self, item):
        return self.shlist[item]
    def __repr__(self):
        rep = ["#  section         offset   size   addr     flags"]
        for i,s in enumerate(self.shlist):
            rep.append("%2i %r %s" % (i, s, s.__class__.__name__))
        return "\n".join(rep)
    def readelf_display(self):
        rep = [ "There are %d section headers, starting at offset %#x:"
                % (len(self.shlist), self.parent.Ehdr.shoff),
                "",
                "Section Headers:" ]
        if self.wsize == 32:
            rep.append( "  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al" )
        elif self.wsize == 64:
            rep.extend(["  [Nr] Name              Type             Address           Offset","       Size              EntSize          Flags  Link  Info  Align"])
        rep.extend([ _.sh.readelf_display() for _ in self ])
        rep.extend([ # Footer
"Key to Flags:",
"  W (write), A (alloc), X (execute), M (merge), S (strings)",
"  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)",
"  O (extra OS processing required) o (OS specific), p (processor specific)",
            ])
        return "\n".join(rep)
    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    def pack(self):
        c = struct.pack("")
        for s in self.shlist:
            c += s.sh.pack()
        return c
    def resize(self, sec, diff):
        for s in self.shlist:
            if s.sh.offset > sec.sh.offset:
                s.sh.offset += diff
        if self.parent.Ehdr.shoff > sec.sh.offset:
            self.parent.Ehdr.shoff += diff
        if self.parent.Ehdr.phoff > sec.sh.offset:
            self.parent.Ehdr.phoff += diff

class NoLinkSection(object):
    get_name = lambda s,i:None
    add_name = lambda s,n:None
    mod_name = lambda s,i,n:None
NoLinkSection = NoLinkSection()

### Program Header List


class ProgramHeader(object):
    def __init__(self, parent, PHtype, phstr, **kargs):
        self.parent = parent
        inheritsexwsize(self, parent, kargs)
        self.ph = PHtype(parent=self, content=phstr)
        self.shlist = [] # based on readelf's "Section to Segment mapping"
        self.shlist_partial = [] # These are other sections of interest
        ph_file_end = self.ph.offset+self.ph.filesz
        ph_mem_end  = self.ph.vaddr+self.ph.memsz
        for s in self.parent.parent.sh:
            if isinstance(s, NullSection):
                continue
            if self.ph.type != elf.PT_TLS and (
               (s.sh.flags & elf.SHF_TLS) and s.sh.type == elf.SHT_NOBITS):
                # .tbss is special.  It doesn't contribute memory space
                # to normal segments.
                continue
            if s.sh.flags & elf.SHF_ALLOC:
                if   (self.ph.vaddr <= s.sh.addr) and \
                     (s.sh.addr+s.sh.size <= ph_mem_end):
                    s.phparent = self
                    self.shlist.append(s)
            else:
                if   (self.ph.offset <= s.sh.offset) and \
                     (s.sh.offset+s.sh.size <= ph_file_end):
                    s.phparent = self
                    self.shlist.append(s)
            if s in self.shlist:
                continue
            if   self.ph.offset <= s.sh.offset           < ph_file_end:
                # Section start in Segment
                self.shlist_partial.append(s)
            elif self.ph.offset < s.sh.offset+s.sh.size <= ph_file_end:
                # Section end in Segment
                self.shlist_partial.append(s)
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
        inheritsexwsize(self, parent, kargs)
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
            l = "%(offset)07x %(filesz)06x %(vaddr)08x %(memsz)07x %(type)02x %(flags)01x"%p.ph
            l = ("%2i " % i)+l
            r.append(l)
            r.append("   "+" ".join([s.sh.name for s in p.shlist]))
        return "\n".join(r)
    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    def pack(self):
        c = struct.pack("")
        for p in self.phlist:
            c += p.ph.pack()
        return c
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
        if item.stop is None:
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
    def get(self, start, end):
        # Deprecated API
        return self[start:end]

    def rvaitems2binary(self, rva_items):
        data_out = struct.pack("")
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
        # __len__ should not be used: Python returns an int object, which
        # will cap values to 0x7FFFFFFF on 32 bit systems. A binary can have
        # a base address higher than this, resulting in the impossibility to
        # handle such programs.
        log.warning("__len__ deprecated")
        return self.max_addr()
    def max_addr(self):
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
                return ret  + s.ph.vaddr
            offset = 0
        return -1

def elf_default_content(self, **kargs):
    if self.Ehdr.type == elf.ET_REL:
        elf_default_content_reloc(self, **kargs)

def elf_default_content_reloc(self, **kargs):
    # Create the Section header string table, which contains the names
    # of the sections
    self.sh._shstrtab = StrTable(self.sh, addralign = 1)
    self.sh._shstrtab.content[0] = '\0'
    symtab = SymTable(self.sh, addralign = 4, entsize = 16)
    strtab = StrTable(self.sh, addralign = 1)
    symtab.sh.name = ".symtab"
    strtab.sh.name = ".strtab"
    self.sh._shstrtab.sh.name = ".shstrtab"
    # Create the Section Header List
    sections = kargs.get('sections',[".text"])
    relocs = kargs.get('relocs',[])
    self.sh.shlist.append(NullSection(self.sh))
    for name in sections:
        flags = {}
        if name.startswith(".text"):
            SectionType = ProgBits
            flags['addralign'] = 4
            flags['flags'] = elf.SHF_ALLOC|elf.SHF_EXECINSTR
            if name.startswith(".text.startup"):
                flags['addralign'] = 16
        if name.startswith(".data"):
            SectionType = ProgBits
            flags['addralign'] = 4
            flags['flags'] = elf.SHF_ALLOC|elf.SHF_WRITE
        if name.startswith(".bss"):
            SectionType = NoBitsSection
            flags['addralign'] = 4
            flags['flags'] = elf.SHF_ALLOC|elf.SHF_WRITE
        if name.startswith(".rodata"):
            SectionType = ProgBits
            flags['addralign'] = 1
            flags['flags'] = elf.SHF_ALLOC
            if name.startswith(".rodata."):
                flags['flags'] |= elf.SHF_MERGE
            if name.startswith(".rodata.str"):
                flags['flags'] |= elf.SHF_STRINGS
                flags['entsize'] = 1
            if name.startswith(".rodata.str1.4"):
                flags['addralign'] = 4
            if name.startswith(".rodata.cst4"):
                flags['entsize'] = 4
                flags['addralign'] = 4
        if name == ".eh_frame":
            SectionType = ProgBits
            flags['addralign'] = 4
            flags['flags'] = elf.SHF_ALLOC
        if name == ".comment":
            SectionType = ProgBits
            flags['addralign'] = 1
            flags['entsize'] = 1
            flags['flags'] = elf.SHF_MERGE|elf.SHF_STRINGS
        if name == ".note.GNU-stack":
            SectionType = ProgBits
            flags['addralign'] = 1
        if name == ".group":
            SectionType = GroupSection
            flags['addralign'] = 4
            flags['entsize'] = 4
        if not name in relocs:
            flags['name'] = name
        self.sh.shlist.append(SectionType(self.sh, **flags))
        if name in relocs:
            flags = { 'name': ".rel"+name, 'addralign': 4, 'entsize': 8 }
            flags['info'] = len(self.sh.shlist)-1
            self.sh.shlist.append(RelTable(self.sh, **flags))
            self.sh.shlist[-2].sh.name_idx = self.sh.shlist[-1].sh.name_idx+4
    self.sh.shlist.append(self.sh._shstrtab)
    self.sh.shlist.append(symtab)
    self.sh.shlist.append(strtab)
    # Automatically generate some values
    self.Ehdr.shstrndx = self.sh.shlist.index(self.sh._shstrtab)
    self.Ehdr.shnum = len(self.sh.shlist)
    symtab.sh.link = self.sh.shlist.index(strtab)
    for s in self.sh.shlist:
        if isinstance(s, RelTable) or isinstance(s, GroupSection):
            s.sh.link = self.sh.shlist.index(symtab)
    # Note that all sections are empty, and therefore the section offsets
    # and sizes are invalid
    # elf_set_offsets() should take care of that

def elf_set_offsets(self):
    if self.Ehdr.type != elf.ET_REL:
        # TODO
        return
    # Set offsets; the standard section layout is not the order of the shlist
    s = self.getsectionbyname("")
    s.sh.offset = 0
    pos = self.Ehdr.ehsize
    section_layout = [".group", ".text", ".data", ".bss"]
    section_layout += [ s.sh.name for s in self.sh.shlist if s.sh.name.startswith(".rodata") ]
    section_layout += [ s.sh.name for s in self.sh.shlist if s.sh.name.startswith(".data.") ]
    section_layout += [ s.sh.name for s in self.sh.shlist if s.sh.name.startswith(".text.") ]
    section_layout += [ ".comment", ".note.GNU-stack", ".eh_frame" ]
    section_layout = section_layout \
        + [ ".shstrtab", None, ".symtab", ".strtab"] \
        + [ ".rel"+name for name in section_layout ]
    for name in section_layout:
        if name is None:
            pos = ((pos + 3)//4)*4
            self.Ehdr.shoff = pos
            self.Ehdr.shentsize = self.sh._shstrtab.sh.bytelen
            pos += self.Ehdr.shnum * self.Ehdr.shentsize
            continue
        for s in self.getsectionsbyname(name):
            align = s.sh.addralign
            s.sh.offset = ((pos + align-1)//align)*align
            s.sh.size = len(s.content)
            pos = s.sh.offset
            if name != ".bss": pos += s.sh.size
    for s in self.sh.shlist[1:]:
        if s.sh.offset == 0:
            align = s.sh.addralign
            s.sh.offset = ((pos + align-1)//align)*align
            s.sh.size = len(s.content)
            pos = s.sh.offset
        

# ELF object
class ELF(object):
    # API shared by all/most binary containers
    architecture = property(lambda _:elf.constants['EM'].get(_.Ehdr.machine,'UNKNOWN(%d)'%_.Ehdr.machine))
    entrypoint = property(lambda _:_.Ehdr.entry)
    sections = property(lambda _:_.sh)
    symbols = property(lambda _:_.getsectionbytype(elf.SHT_SYMTAB))
    dynsyms = property(lambda _:_.getsectionbytype(elf.SHT_DYNSYM))

    def __init__(self, elfstr = None, **kargs):
        self._virt = virt(self)
        if elfstr is None:
            # Create an ELF file, with default header values
            # kargs can supersede these default values
            self.wsize = kargs.get('wsize', 32)
            self.sex = kargs.get('sex', '<')
            self.Ehdr = elf.Ehdr(parent=self)
            self.Ehdr.ident = struct.pack("16B",
                0x7f,0x45,0x4c,0x46, # magic number, \x7fELF
                {32:1, 64:2}[self.wsize], # EI_CLASS
                {'<':1,'>':2}[self.sex],  # EI_DATA
                1, # EI_VERSION
                0, # EI_OSABI
                0, # EI_ABIVERSION
                0,0,0,0,0,0,0)
            self.Ehdr.version = 1
            self.Ehdr.type = kargs.get('e_type', elf.ET_REL)
            self.Ehdr.machine = kargs.get('e_machine', elf.EM_386)
            self.Ehdr.ehsize = self.Ehdr.bytelen
            self.sh = SHList(self)
            self.ph = PHList(self)
            elf_default_content(self, **kargs)
            return
        self.content = StrPatchwork(elfstr)
        self.parse_content()
        try:
            self.check_coherency()
        except ValueError:
            # Report the exception message in a way compatible with most
            # versions of python.
            import sys
            log.error(str(sys.exc_info()[1]))

    def get_virt(self):
        return self._virt
    virt = property(get_virt)

    def parse_content(self):
        h = struct.unpack("B"*8, self.content[:8])
        if h[:4] != ( 0x7f,0x45,0x4c,0x46 ): # magic number, \x7fELF
            raise ValueError("Not an ELF")
        self.wsize = h[4]*32
        self.sex   = {1:'<', 2:'>'} .get(h[5], '')
        if self.sex == '':
            log.error("Invalid ELF, endianess defined to %d", h[5])
        if not self.wsize in (32, 64):
            log.error("Invalid ELF, wordsize defined to %d", self.wsize)
            self.wsize = 32
        self.Ehdr = elf.Ehdr(parent=self, content=self.content)
        self.sh = SHList(self)
        self.ph = PHList(self)
    def resize(self, old, new):
        pass
    def __getitem__(self, item):
        return self.content[item]

    def build_content(self):
        if self.Ehdr.shoff == 0:
            elf_set_offsets(self)
        c = StrPatchwork()
        c[0] = self.Ehdr.pack()
        c[self.Ehdr.phoff] = self.ph.pack()
        for s in self.sh:
            c[s.sh.offset] = s.pack()
        sh = self.sh.pack()
        if len(sh):
            # When 'shoff' is invalid, 'sh' is empty, but the line below
            # is very slow because strpatchwork extends the file.
            c[self.Ehdr.shoff] = sh
        return c.pack()

    def check_coherency(self):
        if self.Ehdr.version != 1:
            raise ValueError("Ehdr version is %d instead of 1"%self.Ehdr.version)
        symtab_count, dynsym_count, hash_count = 0, 0, 0
        for sh in self.sh:
            if sh.sh.type == elf.SHT_SYMTAB:
                symtab_count += 1
            if sh.sh.type == elf.SHT_DYNSYM:
                dynsym_count += 1
            if sh.sh.type == elf.SHT_HASH:
                hash_count += 1
        if symtab_count > 1:
            raise ValueError("Has more than one (%d) sections SYMTAB"% symtab_count)
        if dynsym_count > 1:
            raise ValueError("Has more than one (%d) sections DYNSYM"% dynsym_count)
        if hash_count > 1:
            raise ValueError("Has more than one (%d) sections HASH"% hash_count)
        if self.Ehdr.shstrndx == elf.SHN_UNDEF:
            log.warning("No section (e.g. core file)")
        else:
            if self.Ehdr.shstrndx >= len(self.sh):
                raise ValueError("No section of index shstrndx=%d"%self.Ehdr.shstrndx)
            elif self.sh[self.Ehdr.shstrndx].sh.type != elf.SHT_STRTAB:
                raise ValueError("Section of index shstrndx is of type %d instead of %d"%(self.sh[self.Ehdr.shstrndx].sh.type, elf.SHT_STRTAB))
            elif self.sh[self.Ehdr.shstrndx].sh.name != '.shstrtab':
                raise ValueError("Section of index shstrndx is of name '%s' instead of '%s'"%(self.sh[self.Ehdr.shstrndx].sh.name, '.shstrtab'))

    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    def pack(self):
        return self.build_content()

    def getsectionsbytype(self, sectiontype):
        return [s for s in self.sh if s.sh.type == sectiontype]
    def getsectionbytype(self, sectiontype):
        s = self.getsectionsbytype(sectiontype)
        if len(s) == 0: return ()
        return s[0]
    def getsectionsbyname(self, name):
        if ',' in name: name = name[:name.index(',')]
        return [s for s in self.sh if s.sh.name.strip('\x00') == name]
    def getsectionbyname(self, name):
        s = self.getsectionsbyname(name)
        if len(s) == 0: return None
        return s[0]

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
        if len(sh) == 1 and len(ph) > 1:
            # Executable may also return a section and many PH
            # e.g. the start of the .got section
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

    def has_relocatable_sections(self):
        return self.Ehdr.type == elf.ET_REL

    def is_in_virt_address(self, ad):
        for s in self.sh:
            if s.sh.addr <= ad < s.sh.addr + s.sh.size:
                return True
        return False

    # Old API, needed by miasm2
    size = property(lambda _:_.wsize)
    _content = property(lambda _:_.content)

if __name__ == "__main__":
    import readline
    readline.parse_and_bind("tab: complete")

    fd = open("/bin/ls")
    try:
        raw = fd.read()
    finally:
        fd.close()
    e = ELF(raw)
    print (repr(e))
    #o = ELF(open("/tmp/svg-main.o").read())
