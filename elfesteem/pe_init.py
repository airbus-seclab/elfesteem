#! /usr/bin/env python

import struct, array
from elfesteem import pe
from elfesteem.strpatchwork import StrPatchwork
import logging
log = logging.getLogger("peparse")
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
        owner._content=new_content
        #owner.parse_content()
    def __delete__(self, owner):
        self.__set__(owner, None)


class drva(object):
    def __init__(self, x):
        self.parent = x
    def get_slice_raw(self, item):
        if not type(item) is slice:
            return None
        rva_items = self.get_rvaitem(item.start, item.stop, item.step)
        if rva_items is None:
             return
        data_out = ""
        for s, n_item in rva_items:
            if s:
                data_out += s.data.__getitem__(n_item)
            else:
                data_out += self.parent.__getitem__(n_item)
        return data_out

    def get_rvaitem(self, start, stop = None, step = None):
        if self.parent.SHList is None:
            return [(None, start)]
        if stop == None:
            s = self.parent.getsectionbyrva(start)
            if s is None:
                return [(None, start)]
            start = start-s.vaddr
            return [(s, start)]
        total_len = stop - start
        s_min = self.parent.SHList[0].vaddr
        if hasattr(self.parent, 'NThdr'):
            s_min = min(s_min, self.parent.NThdr.sizeofheaders)
        rva_items = []
        while total_len:
            # special case if look at pe hdr address
            if 0 <= start < s_min:
                s_start = start
                s_stop = stop
                s_max = s_min
                s = None
            else:
                s = self.parent.getsectionbyrva(start)
                if s is None:
                    log.warn('unknown rva address! %x'%start)
                    return []
                s_max = s.rawsize
                if hasattr(self.parent, 'NThdr'):
                    # PE, not COFF
                    # paddr contains the virtual size
                    s_max = max(s.paddr, s_max)
                s_start = start - s.vaddr
                s_stop = stop - s.vaddr
            if s_stop >s_max:
                s_stop = s_max
            s_len = s_stop - s_start
            total_len -= s_len
            start += s_len
            n_item = slice(s_start, s_stop, step)
            rva_items.append((s, n_item))
            if s_len <= 0:
                break
        return rva_items

    def __getitem__(self, item):
        return self.get_slice_raw(item)
    def __setitem__(self, item, data):
        if not type(item) is slice:
            item = slice(item, item+len(data), None)
        rva_items = self.get_rvaitem(item.start, item.stop, item.step)
        if rva_items is None:
             return
        off = 0
        for s, n_item in rva_items:
            i = slice(off, n_item.stop+off-n_item.start, n_item.step)
            data_slice = data.__getitem__(i)
            s.data.__setitem__(n_item, data_slice)
            off = i.stop
            #XXX test patch content
            file_off = self.parent.rva2off(s.vaddr+n_item.start)
            if self.parent.content:
                self.parent.content = self.parent.content[:file_off]+ data_slice + self.parent.content[file_off+len(data_slice):]
        return #s.data.__setitem__(n_item, data)


class virt(object):
    def __init__(self, x):
        self.parent = x

    def item_virt2rva(self, item):
        if not type(item) is slice:#integer
            rva = self.parent.virt2rva(item)
            return slice(rva, None, None)
        start = self.parent.virt2rva(item.start)
        stop  = self.parent.virt2rva(item.stop)
        step  = item.step
        return slice(start, stop, step)

    def __getitem__(self, item):
        rva_item = self.item_virt2rva(item)
        return self.parent.drva.__getitem__(rva_item)

    def __setitem__(self, item, data):
        if not type(item) is slice:
            item = slice(item, item+len(data), None)
        rva_item = self.item_virt2rva(item)
        self.parent.drva.__setitem__(rva_item, data)

    def __len__(self):
        # __len__ should not be used: Python returns an int object, which
        # will cap values to 0x7FFFFFFF on 32 bit systems. A binary can have
        # a base address higher than this, resulting in the impossibility to
        # handle such programs.
        log.warn("__len__ deprecated")
        return self.max_addr()
    def max_addr(self):
        l = 0
        for s in self.parent.SHList:
            l = max(l, s.vaddr+s.size)
        if hasattr(self.parent, 'NThdr'):
            l += self.parent.NThdr.ImageBase
        return int(l)

    def find(self, pattern, start = 0, end = None):
        if start != 0:
            start = self.parent.virt2rva(start)
        if end != None:
            end = self.parent.virt2rva(end)

        sections = []
        for s in self.parent.SHList:
            s_max = max(s.size, s.rawsize)
            if s.vaddr+s_max <= start:
                continue
            if end == None or s.vaddr < end:
                sections.append(s)

        if not sections:
            return -1
        for s in sections:
            if s.vaddr < start:
                off = start - s.vaddr
            else:
                off = 0
            ret = s.data.find(pattern, off)
            if ret == -1:
                continue
            if end != None and s.vaddr + ret >= end:
                return -1
            return self.parent.rva2virt(s.vaddr + ret)
        return -1

    def rfind(self, pattern, start = 0, end = None):
        if start != 0:
            start = self.parent.virt2rva(start)
        if end != None:
            end = self.parent.virt2rva(end)

        sections = []
        for s in self.parent.SHList:
            s_max = max(s.size, s.rawsize)
            if s.vaddr+s_max <= start:
                continue
            if end == None or s.vaddr < end:
                sections.append(s)
        if not sections:
            return -1

        for s in reversed(sections):
            if s.vaddr < start:
                off = start - s.vaddr
            else:
                off = 0
            if end == None:
                ret = s.data.rfind(pattern, off)
            else:
                ret = s.data.rfind(pattern, off, end-s.vaddr)
            if ret == -1:
                continue
            return self.parent.rva2virt(s.vaddr + ret)
        return -1

    def is_addr_in(self, ad):
        return self.parent.is_in_virt_address(ad)

    def __call__(self, ad_start, ad_stop = None, ad_step = None, section = None):
        ad_start = self.parent.virt2rva(ad_start)
        if ad_stop != None:
            ad_stop = self.parent.virt2rva(ad_stop)

        rva_items = self.parent.drva.get_rvaitem(ad_start, ad_stop, ad_step)
        data_out = pe.data_empty
        for s, n_item in rva_items:
            if s is None:
                data_out += self.parent.__getitem__(n_item)
            else:
                data_out += s.data.__getitem__(n_item)

        return data_out

class StrTable(object):
    def __init__(self, c):
        self.res = {}
        self.names = {}
        self.trail = pe.data_empty
        self.len = 0
        while c:
            p = c.find(pe.data_null)
            if p < 0:
                self.trail = c
                break
            self.res[self.len] = c[:p]
            self.names[c[:p]] = self.len
            self.len += p+1
            c = c[p+1:]
    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    def pack(self):
        res = pe.data_empty
        k = sorted(self.res.keys())
        for s in k:
            if len(res) != s:
                raise ValueError("StrTable is incoherent : %r != %r"%(len(res),s))
            res += self.res[s] + pe.data_null
        return res + self.trail
    def add(self, name):
        if name in self.names:
            return self.names[name]
        self.res[self.len] = name
        self.names[name] = self.len
        self.len += len(name)+1
    def rem(self, name):
        TODO
    def getby_name(self, name):
        return self.names[name]
    def getby_offset(self, of):
        return self.res.get(of, "")

class CoffSymbols(object):
    def __init__(self, strpwk, of, numberofsymbols, parent):
        self._sex = 0
        self._wsize = 32
        self.parent_head = parent
        self.symbols = []
        if numberofsymbols == 0:
            return
        end = of + 18 * numberofsymbols
        while of < end:
            s = pe.CoffSymbol.unpack(strpwk, of, self)
            self.symbols.append(s)
            of += 18 * (1 + s.numberofauxsymbols)
    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    def pack(self):
        rep = data_empty
        for s in self.symbols:
            rep += s.pack()
        return rep

# PE object

class PE(object):
    content = ContentManager()
    def __init__(self, pestr = None,
                 loadfrommem=False,
                 parse_resources = True,
                 parse_delay = True,
                 parse_reloc = True,
                 wsize = 32):
        self._drva = drva(self)
        self._virt = virt(self)
        if pestr == None:
            self._content = StrPatchwork()
            self._sex = 0
            self._wsize = wsize
            self.Doshdr = pe.Doshdr(self)
            self.NTsig = pe.NTsig(self)
            self.Coffhdr = pe.Coffhdr(self)

            if self._wsize == 32:
                Opthdr = pe.Opthdr32
            else:
                Opthdr = pe.Opthdr64

            self.Opthdr = Opthdr(self)
            self.NThdr = pe.NThdr(self)
            self.NThdr.optentries = [pe.Optehdr(self) for x in xrange(0x10)]
            self.NThdr.CheckSum = 0
            self.SHList = pe.SHList(self)
            self.SHList.shlist = []

            self.DirImport = pe.DirImport(self)
            self.DirExport = pe.DirExport(self)
            self.DirDelay = pe.DirDelay(self)
            self.DirReloc = pe.DirReloc(self)
            self.DirRes = pe.DirRes(self)

            self.Doshdr.magic = 0x5a4d
            self.Doshdr.lfanew = 0xe0

            if wsize == 32:
                self.Opthdr.magic = pe.IMAGE_NT_OPTIONAL_HDR32_MAGIC
            elif wsize == 64:
                self.Opthdr.magic = pe.IMAGE_NT_OPTIONAL_HDR64_MAGIC
            else:
                raise ValueError('unknown pe size %r'%wsize)

            self.Opthdr.majorlinkerversion = 0x7
            self.Opthdr.minorlinkerversion = 0x0
            self.NThdr.filealignment = 0x1000
            self.NThdr.sectionalignment = 0x1000
            self.NThdr.majoroperatingsystemversion = 0x5
            self.NThdr.minoroperatingsystemversion = 0x1
            self.NThdr.MajorImageVersion = 0x5
            self.NThdr.MinorImageVersion = 0x1
            self.NThdr.majorsubsystemversion = 0x4
            self.NThdr.minorsubsystemversion = 0x0
            self.NThdr.subsystem = 0x3
            self.NThdr.dllcharacteristics = 0x8000

            #for createthread
            self.NThdr.sizeofstackreserve = 0x200000
            self.NThdr.sizeofstackcommit = 0x1000
            self.NThdr.sizeofheapreserve = 0x100000
            self.NThdr.sizeofheapcommit = 0x1000

            self.NThdr.ImageBase = 0x400000
            self.NThdr.sizeofheaders = 0x1000
            self.NThdr.numberofrvaandsizes = 0x10

            self.NTsig.signature = 0x4550

            if wsize == 32:
                self.Coffhdr.machine = 0x14c
            elif wsize == 64:
                self.Coffhdr.machine = 0x8664
            else:
                raise ValueError('unknown pe size %r'%wsize)
            if wsize == 32:
                self.Coffhdr.characteristics = 0x10f
                self.Coffhdr.sizeofoptionalheader = 0xe0
            else:
                self.Coffhdr.characteristics = 0x22
                self.Coffhdr.sizeofoptionalheader = 0xf0

        else:
            self._content = StrPatchwork(pestr)
            self.loadfrommem = loadfrommem
            self.parse_content(parse_resources = parse_resources,
                               parse_delay = parse_delay,
                               parse_reloc = parse_reloc)

    def isPE(self):
        if not hasattr(self, 'NTsig') or self.NTsig is None:
            return False
        return self.NTsig.signature == 0x4550

    def parse_content(self,
                      parse_resources = True,
                      parse_delay = True,
                      parse_reloc = True):
        of = 0
        self._sex = 0
        self._wsize = 32
        self.Doshdr = pe.Doshdr.unpack(self.content, of, self)
        #print(repr(self.Doshdr))
        of = self.Doshdr.lfanew
        if of > len(self.content):
            log.warn('ntsig after eof!')
            self.NTsig = None
            return
        self.NTsig = pe.NTsig.unpack(self.content,
                                     of, self)
        self.DirImport = None
        self.DirExport = None
        self.DirDelay = None
        self.DirReloc = None
        self.DirRes = None


        if self.NTsig.signature != 0x4550:
            log.warn('not a valid pe!')
            return
        of += len(self.NTsig)
        self.Coffhdr, l = pe.Coffhdr.unpack_l(self.content,
                                              of,
                                              self)

        of += l
        m = struct.unpack('H', self.content[of:of+2])[0]
        m = (m>>8)*32
        self._wsize = m

        # Even if the NT header has 64-bit pointers, in 64-bit PE files
        # the Section headers have 32-bit pointers (it is a 32-bit COFF
        # in a 64-bit PE).
        if self._wsize == 32:
            Opthdr = pe.Opthdr32
        else:
            Opthdr = pe.Opthdr64

        self.Opthdr, l = Opthdr.unpack_l(self.content, of, self)
        #print(hex(of+len(self.Opthdr)))
        self.NThdr = pe.NThdr.unpack(self.content, of+l, self)
        #print(repr(self.NThdr.optentries))
        self._wsize = 32
        of += self.Coffhdr.sizeofoptionalheader
        self.SHList = pe.SHList.unpack(self.content, of, self)
        #print(repr(self.SHList))

        # load section data
        filealignment = self.NThdr.filealignment
        for s in self.SHList.shlist:
            s.data = StrPatchwork()
            s.data[0] = self.content[s.scnptr:s.scnptr+s.rsize]
        try:
            self.DirImport = pe.DirImport.unpack(self.content,
                                                 self.NThdr.optentries[pe.DIRECTORY_ENTRY_IMPORT].rva,
                                                 self)
        except pe.InvalidOffset:
            log.warning('cannot parse DirImport, skipping')
            self.DirImport = pe.DirImport(self)

        try:
            self.DirExport = pe.DirExport.unpack(self.content,
                                                 self.NThdr.optentries[pe.DIRECTORY_ENTRY_EXPORT].rva,
                                                 self)
        except pe.InvalidOffset:
            log.warning('cannot parse DirExport, skipping')
            self.DirExport = pe.DirExport(self)

        if len(self.NThdr.optentries) > pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            self.DirDelay = pe.DirDelay(self)
            if parse_delay:
                try:
                    self.DirDelay = pe.DirDelay.unpack(self.content,
                                                       self.NThdr.optentries[pe.DIRECTORY_ENTRY_DELAY_IMPORT].rva,
                                                       self)
                except pe.InvalidOffset:
                    log.warning('cannot parse DirDelay, skipping')
        if len(self.NThdr.optentries) > pe.DIRECTORY_ENTRY_BASERELOC:
            self.DirReloc = pe.DirReloc(self)
            if parse_reloc:
                try:
                    self.DirReloc = pe.DirReloc.unpack(self.content,
                                                       self.NThdr.optentries[pe.DIRECTORY_ENTRY_BASERELOC].rva,
                                                       self)
                except pe.InvalidOffset:
                    log.warning('cannot parse DirReloc, skipping')
        if len(self.NThdr.optentries) > pe.DIRECTORY_ENTRY_RESOURCE:
            self.DirRes = pe.DirRes(self)
            if parse_resources:
                try:
                    self.DirRes = pe.DirRes.unpack(self.content,
                                                   self.NThdr.optentries[pe.DIRECTORY_ENTRY_RESOURCE].rva,
                                                   self)
                except pe.InvalidOffset:
                    log.warning('cannot parse DirRes, skipping')

        if self.Coffhdr.pointertosymboltable != 0:
            of = self.Coffhdr.pointertosymboltable
            of += 18 * self.Coffhdr.numberofsymbols
            sz, = struct.unpack('<>'[self._sex]+'I',self.content[of:of+4])
            if len(self.content) < of+sz:
                log.warning('File too short for StrTable')
                sz = len(self.content) - of
            self.SymbolStrings = StrTable(self.content[of:of+sz])
            self.Symbols = CoffSymbols(self.content,
                                       self.Coffhdr.pointertosymboltable,
                                       self.Coffhdr.numberofsymbols,
                                       self)
            """
            # Consistency check
            if self.SymbolStrings.pack() == self.content[
                                       self.Coffhdr.pointertosymboltable
                                       + 18 * self.Coffhdr.numberofsymbols:]:
                print("OK for SymbolStrings")
            if self.Symbols.pack() == self.content[
                                       self.Coffhdr.pointertosymboltable:
                                       self.Coffhdr.pointertosymboltable
                                       + 18 * self.Coffhdr.numberofsymbols]:
                print("OK for Symbols")
            """

        #print(repr(self.Doshdr))
        #print(repr(self.Coffhdr))
        #print(repr(self.Opthdr))
        #print(repr(self.SHList))

        #print(repr(self.DirImport))
        #print(repr(self.DirExport))
        #print(repr(self.DirReloc))
        #print(repr(self.DirRes))

    def resize(self, old, new):
        pass
    def __getitem__(self, item):
        return self.content[item]
    def __setitem__(self, item, data):
        self.content.__setitem__(item, data)
        return

    def getsectionbyrva(self, rva):
        if self.SHList is None:
            return None
        for s in self.SHList.shlist:
            if hasattr(self, 'NThdr'): # PE file
                vsize = s.paddr
            else: # COFF file
                vsize = s.rsize
            if s.vaddr <= rva < s.vaddr+vsize:
                return s
        return None

    def getsectionbyvad(self, vad):
        return self.getsectionbyrva(self.virt2rva(vad))

    def getsectionbyoff(self, off):
        if self.SHList is None:
            return None
        for s in self.SHList.shlist:
            if s.scnptr <= off < s.scnptr+s.rsize:
                return s
        return None

    def getsectionbyname(self, name):
        if self.SHList is None:
            return None
        for s in self.SHList:
            if s.name.strip('\x00') ==  name:
                return s
        return None

    def is_rva_ok(self, rva):
        # Some binaries have import rva outside section, but addresses seem
        # to be rounded.
        # Instead of testing s.addr <= rva < (s.addr+s.size+0xfff) & 0xFFFFF000
        # in getsectionbyrva, as implemented by patch 68ac083623ff, it is more
        # robust to call getsectionbyrva with rva & 0xFFFFF000, when parsing
        # import tables.
        # Apparently, when parsing imports, getsectionbyrva is only used by
        # is_rva_ok, which is the only one needing a patch.
        # We need to check that the 0xFFFFF000 mask is not specific to 32-bit
        # PE.
        return  self.getsectionbyrva(rva & 0xFFFFF000) is not None

    def rva2off(self, rva):
        # Special case rva in header
        if rva < self.NThdr.sizeofheaders:
            return rva
        s = self.getsectionbyrva(rva)
        if s is None:
            return
        soff = (s.scnptr//self.NThdr.filealignment)*self.NThdr.filealignment
        return rva-s.vaddr+soff

    def off2rva(self, off):
        s = self.getsectionbyoff(off)
        if s is None:
            return
        return off-s.scnptr+s.vaddr

    def virt2rva(self, virt):
        if virt is None or not hasattr(self, 'NThdr'):
            return virt
        return virt - self.NThdr.ImageBase

    def rva2virt(self, rva):
        if rva is None or not hasattr(self, 'NThdr'):
            return rva
        return rva + self.NThdr.ImageBase

    def virt2off(self, virt):
        return self.rva2off(self.virt2rva(virt))

    def off2virt(self, off):
        return self.rva2virt(self.off2rva(off))

    def is_in_virt_address(self, ad):
        if hasattr(self, 'NThdr') and ad < self.NThdr.ImageBase:
            return False
        ad = self.virt2rva(ad)
        for s in self.SHList.shlist:
            if s.vaddr <= ad < s.vaddr + s.size:
                return True
        return False

    def get_drva(self):
        return self._drva

    drva = property(get_drva)

    def get_virt(self):
        return self._virt

    virt = property(get_virt)

    def patch_crc(self, c, olds):
        s = 0
        data = c[:]
        l = len(data)
        if len(c)%2:
            end = struct.unpack('B', data[-1])[0]
            data = data[:-1]
        if (len(c)&~0x1)%4:
            s+=struct.unpack('H', data[:2])[0]
            data = data[2:]
        data = array.array('I', data)
        for y in data:
            s += y
        s-=olds
        while s>0xFFFFFFFF:
            s = (s>>32)+(s&0xFFFFFFFF)
        while s>0xFFFF:
            s = (s&0xFFFF)+((s>>16)&0xFFFF)
        if len(c)%2:
            s+=end
        s+=l
        return s

    def build_content(self):

        c = StrPatchwork()
        c[0] = self.Doshdr.pack()

        for s in self.SHList.shlist:
            c[s.scnptr:s.scnptr+s.rawsize] = s.data.pack()

        # fix image size
        s_last = self.SHList.shlist[-1]
        size = s_last.vaddr + s_last.rawsize + (self.NThdr.sectionalignment-1)
        size &= ~(self.NThdr.sectionalignment-1)
        self.NThdr.sizeofimage = size

        off = self.Doshdr.lfanew
        c[off] = self.NTsig.pack()
        off += len(self.NTsig)
        c[off] = self.Coffhdr.pack()
        off += len(self.Coffhdr)
        c[off] = self.Opthdr.pack()
        off += len(self.Opthdr)
        c[off] = self.NThdr.pack()
        off += len(self.NThdr)
        #c[off] = self.Optehdr.pack()

        off = self.Doshdr.lfanew+len(self.NTsig)+len(self.Coffhdr)+self.Coffhdr.sizeofoptionalheader
        c[off] = self.SHList.pack()

        for s in self.SHList:
            data = self.SHList.pack()
            if off + len(data) > s.scnptr:
                log.warn("section offset overlap pe hdr 0x%x 0x%x"%(off+len(data), s.scnptr))
        self.DirImport.build_content(c)
        self.DirExport.build_content(c)
        self.DirDelay.build_content(c)
        self.DirReloc.build_content(c)
        self.DirRes.build_content(c)
        s = c.pack()
        # TODO: add symbol table
        if (self.Doshdr.lfanew+len(self.NTsig)+len(self.Coffhdr))%4:
            log.warn("non aligned coffhdr, bad crc calculation")
        crcs = self.patch_crc(s, self.NThdr.CheckSum)
        c[self.Doshdr.lfanew+len(self.NTsig)+len(self.Coffhdr)+64] = struct.pack('I', crcs)
        return c.pack()

    def __str__(self):
        # For compatibility with previous versions of elftesteem
        # But it will not work with python3, because __str__ must
        # return a string, not bytes
        return self.pack()

    def pack(self):
        return self.build_content()

    def export_funcs(self):
        if self.DirExport is None:
            print('no export dir found')
            return None, None

        all_func = {}
        for i, n in enumerate(self.DirExport.f_names):
            all_func[n.name.name] = self.rva2virt(self.DirExport.f_address[self.DirExport.f_nameordinals[i].ordinal].rva)
            all_func[self.DirExport.f_nameordinals[i].ordinal+self.DirExport.expdesc.base] = self.rva2virt(self.DirExport.f_address[self.DirExport.f_nameordinals[i].ordinal].rva)
        #XXX todo: test if redirected export
        return all_func

    def reloc_to(self, imgbase):
        offset = imgbase - self.NThdr.ImageBase
        if self.DirReloc is None:
            log.warn('no relocation found!')
        for rel in self.DirReloc.reldesc:
            rva = rel.rva
            for reloc in rel.rels:
                t, off = reloc.rel
                if t == 0 and off == 0:
                    continue
                if t != 3:
                    raise ValueError('reloc type not impl')
                off += rva
                v = struct.unpack('I', self.drva[off:off+4])[0]
                v += offset
                self.drva[off:off+4] = struct.pack('I', v & 0xFFFFFFFF)
        self.NThdr.ImageBase = imgbase

# The COFF file format happens to have many variants,
# quite different from the COFF embedded in PE files...
class Coff(PE):
    def parse_content(self,
                      parse_resources = True,
                      parse_delay = True,
                      parse_reloc = True):
        of = 0
        # Detect specific cases of COFF Header format, without knowing
        # the endianess
        COFFmachineLE, = struct.unpack("<H", self.content[0:2])
        COFFmachineBE, = struct.unpack(">H", self.content[0:2])
        if   pe.IMAGE_FILE_MACHINE_ALPHA_O in (COFFmachineLE, COFFmachineBE):
            self._wsize = 64
            COFFhdr = pe.Coffhdr
            sizeofoptionalheader = self.content[18:20]
        elif pe.IMAGE_FILE_MACHINE_XCOFF64 in (COFFmachineLE, COFFmachineBE):
            self._wsize = 64
            COFFhdr = pe.XCOFFhdr64
            sizeofoptionalheader = self.content[16:18]
        else:
            self._wsize = 32
            COFFhdr = pe.Coffhdr
            sizeofoptionalheader = self.content[16:18]
        # COFF endianess is tricky to determine, we use the fact
        # that sizeofoptionalheader should be less than 256
        sizeofoptionalheader = struct.unpack("BB", sizeofoptionalheader)
        if   sizeofoptionalheader[1] == 0: self._sex = 0
        else:                              self._sex = 1
        self.Coffhdr, l = COFFhdr.unpack_l(self.content, of, self)
        of += l
        if   self.Coffhdr.machine == pe.IMAGE_FILE_MACHINE_TI:
            m = struct.unpack('H', self.content[of:of+2])[0]
            self.CPU = {
                # COFF for Texas Instruments
                # Cf. http://www.ti.com/lit/an/spraao8/spraao8.pdf
                # and https://gist.github.com/eliotb/1073231
                0x97: 'TMS470',
                0x98: 'TMS320C5400',
                0x99: 'TMS320C6000',
                0x9C: 'TMS320C5500',
                0x9D: 'TMS320C2800',
                0xA0: 'MSP430',
                0xA1: 'TMS320C5500+',
                }.get(m, 'unknown')
            of += 2
            pe.Shdr.set_fields_TI()
        if   self.Coffhdr.sizeofoptionalheader == 28:
            self.Opthdr, l = pe.Opthdr32.unpack_l(self.content, of, self)
        elif self.Coffhdr.sizeofoptionalheader == 36:
            assert self.Coffhdr.machine == pe.IMAGE_FILE_MACHINE_CLIPPER
            self.Opthdr, l = pe.OpthdrClipper.unpack_l(self.content, of, self)
        elif self.Coffhdr.sizeofoptionalheader == 44:
            assert self.Coffhdr.machine == pe.IMAGE_FILE_MACHINE_APOLLOM68K
            self.Opthdr, l = pe.OpthdrApollo.unpack_l(self.content, of, self)
        elif self.Coffhdr.sizeofoptionalheader == 80:
            assert self.Coffhdr.machine == pe.IMAGE_FILE_MACHINE_ALPHA_O
            self.Opthdr, l = pe.OpthdrOSF1.unpack_l(self.content, of, self)
        elif self.Coffhdr.sizeofoptionalheader == 72:
            self.Opthdr, l = pe.OpthdrXCOFF32.unpack_l(self.content, of, self)
        elif self.Coffhdr.sizeofoptionalheader == 110:
            self.Opthdr, l = pe.OpthdrXCOFF64.unpack_l(self.content, of, self)
        elif self.Coffhdr.sizeofoptionalheader == 0:
            from elfesteem.pe import CStruct
            class NullHdr(CStruct):
                _fields = [ ]
            self.Opthdr, l = NullHdr(), 0
        elif (self.Coffhdr.sizeofoptionalheader % 4) == 0:
            # All known OptHdr start with a 2-byte magic and 2-byte vstamp
            from elfesteem.pe import CStruct
            class OpthdrUnknown(CStruct):
                _fields = [ ("magic", "u16"), ("vstamp", "u16") ] \
                        + [ ("f%d"%_, "u32")
                    for _ in range(1, self.Coffhdr.sizeofoptionalheader // 4) ]
            self.Opthdr, l = OpthdrUnknown.unpack_l(self.content, of, self)
            machine_name = pe.constants['IMAGE_FILE_MACHINE'].get(
                self.Coffhdr.machine, '%#x'%self.Coffhdr.machine)
            log.warn("Unknown Option Header format of size %d for machine %s:\n%r",
                self.Coffhdr.sizeofoptionalheader, machine_name, self.Opthdr)
        else:
            log.debug("COFF %r", self.Coffhdr)
            self.Opthdr, l = None, self.Coffhdr.sizeofoptionalheader
        
        of += l
        if of + self.Coffhdr.numberofsections * 40 > len(self.content):
            # Probably not a COFF!
            self.SHList = pe.SHList.unpack(struct.pack(""), of, self)
        else:
            self.SHList = pe.SHList.unpack(self.content, of, self)
        pe.Shdr.set_fields_reset()
        
        if self.Coffhdr.pointertosymboltable != 0:
            of = self.Coffhdr.pointertosymboltable
            of += 18 * self.Coffhdr.numberofsymbols
            sz, = struct.unpack('<>'[self._sex]+'I',self.content[of:of+4])
            if len(self.content) < of+sz:
                log.warning('File too short for StrTable')
                sz = len(self.content) - of
            self.SymbolStrings = StrTable(self.content[of:of+sz])
            self.Symbols = CoffSymbols(self.content,
                                       self.Coffhdr.pointertosymboltable,
                                       self.Coffhdr.numberofsymbols,
                                       self)



if __name__ == "__main__":
    import rlcompleter,readline,pdb, sys
    from pprint import pprint as pp
    readline.parse_and_bind("tab: complete")

    data = open(sys.argv[1]).read()
    print("Read file of len %d"%len(data))
    e = PE(data)
    e_str = e.pack()
    print("Packed file of len %d"%len(e_str))
    open('out.packed.bin', 'wb').write(e_str)
    if hasattr(e, 'DirImport'): print(repr(e.DirImport))
    if hasattr(e, 'DirExport'): print(repr(e.DirExport))
    if hasattr(e, 'DirDelay'):  print(repr(e.DirDelay))
    if hasattr(e, 'DirReloc'):  print(repr(e.DirReloc))
    if hasattr(e, 'DirRes'):    print(repr(e.DirRes))

    # Remove Bound Import directory
    # Usually, its content is not stored in any section... that's
    # a future version of elfesteem will need to manage this
    # specific directory in a specific way.
    e.NThdr.optentries[pe.DIRECTORY_ENTRY_BOUND_IMPORT].rva = 0
    e.NThdr.optentries[pe.DIRECTORY_ENTRY_BOUND_IMPORT].size = 0

    # Create new sections with all zero content
    s_redir = e.SHList.add_section(name = "redir", size = 0x1000)
    s_test  = e.SHList.add_section(name = "test",  size = 0x1000)
    s_rel   = e.SHList.add_section(name = "rel",   size = 0x5000)
    e_str = e.pack()
    open('out.sect.bin', 'wb').write(e_str)
    print("WROTE out.sect.bin with added sections")



    new_dll = [({"name":"kernel32.dll",
                 "firstthunk":s_test.vaddr},
                ["CreateFileA",
                 "SetFilePointer",
                 "WriteFile",
                 "CloseHandle",
                 ]
                ),
               ({"name":"USER32.dll",
                 "firstthunk":None},
                ["SetDlgItemInt",
                 "GetMenu",
                 "HideCaret",
                 ]
                )
               ]
    e.DirImport.add_dlldesc(new_dll)

    if e.DirExport.expdesc is None:
        e.DirExport.create()
        e.DirExport.add_name("coco")

    s_myimp = e.SHList.add_section(name = "myimp", size = len(e.DirImport))
    s_myexp = e.SHList.add_section(name = "myexp", size = len(e.DirExport))
    s_mydel = e.SHList.add_section(name = "mydel", size = len(e.DirDelay))
    s_myrel = e.SHList.add_section(name = "myrel", size = len(e.DirReloc))
    s_myres = e.SHList.add_section(name = "myres", size = len(e.DirRes))

    """
    for s in e.SHList.shlist:
        s.offset+=0xC00
    """

    e.SHList.align_sections(0x1000, 0x1000)

    e.DirImport.set_rva(s_myimp.addr)
    e.DirExport.set_rva(s_myexp.addr)
    if e.DirDelay.delaydesc:
        e.DirDelay.set_rva(s_mydel.addr)
    if e.DirReloc.reldesc:
        e.DirReloc.set_rva(s_myrel.addr)
    if e.DirRes.resdesc:
        e.DirRes.set_rva(s_myres.addr)

    e_str = e.pack()
    print("f1 %s" % e.DirImport.get_funcvirt('LoadStringW'))
    print("f2 %s" % e.DirExport.get_funcvirt('SetUserGeoID'))
    open('out.bin', 'wb').write(e_str)
    #o = Coff(open('main.obj').read())
    #print(repr(o.Coffhdr))
    #print(repr(o.Opthdr))
    #print(repr(o.SHList))
    #print('numsymb %x'%o.Coffhdr.Coffhdr.numberofsymbols)
    #print('offset %x'%o.Coffhdr.Coffhdr.pointertosymboltable)
    #
    #print(repr(o.Symbols))

    f = PE()
    open('uu.bin', 'wb').write(f.pack())
