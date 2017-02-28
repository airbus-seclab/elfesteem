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
            if s is not None:
                data_out += s.data.__getitem__(n_item)
            else:
                data_out += self.parent.__getitem__(n_item)
        return data_out

    def get_rvaitem(self, start, stop = None, section = None):
        if self.parent.SHList is None:
            return [(None, start)]
        if stop == None:
            s = self.parent.getsectionbyrva(start, section)
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
                s = self.parent.getsectionbyrva(start, section)
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
            n_item = slice(s_start, s_stop)
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

    def __call__(self, ad_start, ad_stop = None, section = None):
        ad_start = self.parent.virt2rva(ad_start)
        if ad_stop != None:
            ad_stop = self.parent.virt2rva(ad_stop)

        rva_items = self.parent.drva.get_rvaitem(ad_start, ad_stop, section)
        data_out = pe.data_empty
        for s, n_item in rva_items:
            if s is None:
                data_out += self.parent.__getitem__(n_item)
            else:
                data_out += s.data.data.__getitem__(n_item)

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

# PE object

class PE(object):
    content = ContentManager()
    Coffhdr = property(lambda self: self.COFFhdr) # Older API
    Doshdr  = property(lambda self: self.DOShdr) # Older API
    def __init__(self, pestr = None,
                 parse_resources = True,
                 parse_delay = True,
                 parse_reloc = True,
                 wsize = 32):
        self._drva = drva(self)
        self._virt = virt(self)
        if pestr == None:
            self.sex = '<'
            self.wsize = wsize
            self._content = StrPatchwork()
            self.DOShdr = pe.DOShdr(parent=self)
            self.NTsig = pe.NTsig(parent=self)
            self.COFFhdr = pe.COFFhdr(parent=self)
            self.Opthdr = {32: pe.Opthdr32, 64: pe.Opthdr64}[wsize](parent=self)
            self.NThdr = pe.NThdr(parent=self)
            self.SHList = pe.SHList(parent=self)

            self.DirImport = pe.DirImport(parent=self)
            self.DirExport = pe.DirExport(parent=self)
            self.DirDelay = pe.DirDelay(parent=self)
            self.DirReloc = pe.DirReloc(parent=self)
            self.DirRes = pe.DirRes(parent=self)

            self.DOShdr.magic = 0x5a4d
            self.DOShdr.lfanew = 0xe0

            if wsize == 32:
                self.COFFhdr.machine = pe.IMAGE_FILE_MACHINE_I386
                self.COFFhdr.characteristics = 0x10f
                self.COFFhdr.sizeofoptionalheader = 0xe0
                self.Opthdr.magic = pe.IMAGE_NT_OPTIONAL_HDR32_MAGIC
            elif wsize == 64:
                self.COFFhdr.machine = pe.IMAGE_FILE_MACHINE_AMD64
                self.COFFhdr.characteristics = 0x22
                self.COFFhdr.sizeofoptionalheader = 0xf0
                self.Opthdr.magic = pe.IMAGE_NT_OPTIONAL_HDR64_MAGIC
            #self.Opthdr.majorlinkerversion = 0x7
            #self.Opthdr.minorlinkerversion = 0x0

            self.NThdr.ImageBase = 0x400000
            self.NThdr.sectionalignment = 0x1000
            self.NThdr.filealignment = 0x200
            #self.NThdr.majoroperatingsystemversion = 0x5
            #self.NThdr.minoroperatingsystemversion = 0x1
            #self.NThdr.MajorImageVersion = 0x5
            #self.NThdr.MinorImageVersion = 0x1
            #self.NThdr.majorsubsystemversion = 0x4
            #self.NThdr.minorsubsystemversion = 0x0
            #self.NThdr.subsystem = 0x3
            #self.NThdr.dllcharacteristics = 0x8000
            #self.NThdr.sizeofstackreserve = 0x200000
            #self.NThdr.sizeofstackcommit = 0x1000
            #self.NThdr.sizeofheapreserve = 0x100000
            #self.NThdr.sizeofheapcommit = 0x1000
            #self.NThdr.sizeofheaders = 0x1000
            self.NThdr.numberofrvaandsizes = 0x10
            self.NThdr.optentries = pe.OptNThdrs(parent=self)
            self.NThdr.CheckSum = 0

            self.NTsig.signature = 0x4550

        else:
            self._content = StrPatchwork(pestr)
            self.parse_content(parse_resources = parse_resources,
                               parse_delay = parse_delay,
                               parse_reloc = parse_reloc)
        # For API compatibility with previous versions of elfesteem
        self._sex = '<>'.index(self.sex)
        self._wsize = self.wsize

    def isPE(self):
        if not hasattr(self, 'NTsig') or self.NTsig is None:
            return False
        return self.NTsig.signature == 0x4550

    def has_relocatable_sections(self):
        # Typically .obj COFF object files for Windows.
        # All sections start at vaddr==0 because they are relocated by
        # the linker.
        return self.COFFhdr.characteristics & pe.IMAGE_FILE_FLAG_EXECUTABLE_IMAGE == 0

    def parse_content(self,
                      parse_resources = True,
                      parse_delay = True,
                      parse_reloc = True):
        of = 0
        self.sex = '<'
        self.wsize = 32
        self.DOShdr = pe.DOShdr(parent=self, content=self.content, start=of)
        of = self.DOShdr.lfanew
        if of > len(self.content):
            log.warn('ntsig after eof!')
            self.NTsig = None
            return
        self.NTsig = pe.NTsig(parent=self, content=self.content, start=of)


        if self.NTsig.signature != 0x4550:
            log.warn('not a valid pe!')
            return
        of += self.NTsig.bytelen
        self.COFFhdr = pe.COFFhdr(parent=self, content=self.content, start=of)
        of += self.COFFhdr.bytelen
        magic, = struct.unpack('H', self.content[of:of+2])
        self.wsize = (magic>>8)*32
        self.Opthdr = {32: pe.Opthdr32, 64: pe.Opthdr64}[self.wsize](parent=self, content=self.content, start=of)
        l = self.Opthdr.bytelen
        self.NThdr = pe.NThdr(parent=self, content=self.content, start=of+l)
        of += self.COFFhdr.sizeofoptionalheader
        if self.NThdr.numberofrvaandsizes < 13:
            log.warn('Windows 8 needs at least 13 directories, %d found',
                self.NThdr.numberofrvaandsizes)
        # Even if the NT header has 64-bit pointers, in 64-bit PE files
        # the Section headers have 32-bit pointers (it is a 32-bit COFF
        # in a 64-bit PE).
        self.SHList = pe.SHList(parent=self, content=self.content, start=of,
            wsize=32)

        # Directory parsing.
        # 'start' is None, because the offset is computed from the RVA
        # in the NT header
        kargs = { 'parent':self, 'content':self.content, 'start':None }
        self.DirImport = pe.DirImport(**kargs)
        self.DirExport = pe.DirExport(**kargs)
        if parse_delay:     self.DirDelay = pe.DirDelay(**kargs)
        if parse_reloc:     self.DirReloc = pe.DirReloc(**kargs)
        if parse_resources: self.DirRes   = pe.DirRes  (**kargs)

        if self.COFFhdr.pointertosymboltable != 0:
            if self.COFFhdr.pointertosymboltable + 18 * self.COFFhdr.numberofsymbols > len(self.content):
                log.warning('Too many symbols: %d', self.COFFhdr.numberofsymbols)
            else:
                self.Symbols = pe.CoffSymbols(**kargs)
        if hasattr(self, 'Symbols'):
            of = self.COFFhdr.pointertosymboltable + self.Symbols.bytelen
            sz, = struct.unpack(self.sex+'I',self.content[of:of+4])
            if len(self.content) < of+sz:
                log.warning('File too short for StrTable %#x != %#x' % (
                    len(self.content)-of, sz))
                sz = len(self.content) - of
            self.SymbolStrings = StrTable(self.content[of:of+sz])

    def resize(self, old, new):
        pass
    def __getitem__(self, item):
        return self.content[item]
    def __setitem__(self, item, data):
        self.content.__setitem__(item, data)

    def getsectionbyrva(self, rva, section = None):
        if self.SHList is None:
            return None
        if section:
            return self.getsectionbyname(section)
        for s in self.SHList.shlist:
            if s.vaddr <= rva < s.vaddr+s.size:
                return s
        return None

    def getsectionbyvad(self, vad, section = None):
        return self.getsectionbyrva(self.virt2rva(vad), section)

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

    def rva2off(self, rva, section = None):
        if section is None and self.has_relocatable_sections():
            # TODO: .obj cannot convert rva2off without knowing the section
            return None
        s = self.getsectionbyrva(rva, section)
        if s is None:
            # e.g. Ange Albertini's tinyW7_3264.exe where sizeofheaders is 0
            # therefore the import table is in no section but not detected as
            # in the headers.
            # The test rva < self.NThdr.sizeofheaders from older elfesteem
            # seems redundant with this one.
            return rva
        return rva-s.vaddr+s.scn_baseoff

    def off2rva(self, off):
        s = self.getsectionbyoff(off)
        if s is None:
            return None
        return off-s.scn_baseoff+s.vaddr

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

    def build_headers(self, c):
        off = self.DOShdr.lfanew
        c[off] = self.NTsig.pack()
        off += self.NTsig.bytelen
        c[off] = self.COFFhdr.pack()
        off += self.COFFhdr.bytelen
        c[off] = self.Opthdr.pack()
        off += self.Opthdr.bytelen
        c[off] = self.NThdr.pack()
        off += self.NThdr.bytelen

    def build_content(self):
        c = StrPatchwork()
        c[0] = self.DOShdr.pack()

        # fix image size
        if len(self.SHList):
            s_last = self.SHList.shlist[-1]
            size = s_last.vaddr + s_last.rsize + (self.NThdr.sectionalignment-1)
            size &= ~(self.NThdr.sectionalignment-1)
            self.NThdr.sizeofimage = size

        # headers
        self.build_headers(c)

        # section headers
        off = self.DOShdr.lfanew \
            + self.NTsig.bytelen \
            + self.COFFhdr.bytelen \
            + self.COFFhdr.sizeofoptionalheader
        c[off] = self.SHList.pack()
        off += self.SHList.bytelen
        end_of_headers = off

        # section data
        # note that the content of directories should have been already
        # included section data, which is possible because position and
        # size of sections are known at this point
        for s in sorted(self.SHList, key=lambda _:_.scnptr):
            if s.rawsize == 0:
                continue
            if end_of_headers > s.scnptr:
                log.warn("section %s offset %#x overlap pe hdr %#x",
                    s.name, s.scnptr, off)
            elif off > s.scnptr:
                log.warn("section %s offset %#x overlap previous section",
                    s.name, s.scnptr)
            off = s.scnptr+s.rawsize
            c[s.scnptr:off] = s.data.data.pack()

        # symbols and strings
        if self.COFFhdr.numberofsymbols:
            self.COFFhdr.pointertosymboltable = off
            c[off] = self.Symbols.pack()
            assert self.Symbols.bytelen == 18 * self.COFFhdr.numberofsymbols
            off += self.Symbols.bytelen
            c[off] = self.SymbolStrings.pack()

        # some headers may have been updated when building sections or symbols
        self.build_headers(c)

        # final verifications
        l = self.DOShdr.lfanew + self.NTsig.bytelen + self.COFFhdr.bytelen
        if l%4:
            log.warn("non aligned coffhdr, bad crc calculation")
        crcs = self.patch_crc(c.pack(), self.NThdr.CheckSum)
        c[l+64] = struct.pack('I', crcs)
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
        # Note that there is no "magic number" to recognize COFF files.
        # Therefore, the usual way to know if a file is COFF is to parse
        # its content with this method. If it is not a COFF, then an
        # exception is raised, of type ValueError
        of = 0
        # Detect specific cases of COFF Header format, without knowing
        # the endianess
        COFFmachineLE, = struct.unpack("<H", self.content[0:2])
        COFFmachineBE, = struct.unpack(">H", self.content[0:2])
        if   pe.IMAGE_FILE_MACHINE_ALPHA_O in (COFFmachineLE, COFFmachineBE):
            self.wsize = 64
            COFFhdr = pe.COFFhdr
            sizeofoptionalheader = self.content[18:20]
        elif pe.IMAGE_FILE_MACHINE_XCOFF64 in (COFFmachineLE, COFFmachineBE):
            self.wsize = 64
            COFFhdr = pe.XCOFFhdr64
            sizeofoptionalheader = self.content[16:18]
        else:
            self.wsize = 32
            COFFhdr = pe.COFFhdr
            sizeofoptionalheader = self.content[16:18]
        # COFF endianess is tricky to determine, we use the fact
        # that sizeofoptionalheader should be less than 256
        sizeofoptionalheader = struct.unpack("BB", sizeofoptionalheader)
        if not 0 in sizeofoptionalheader:
            raise ValueError("Not COFF: OptHdr size too big")
        if   sizeofoptionalheader[1] == 0: self.sex = '<'
        else:                              self.sex = '>'
        self.COFFhdr = COFFhdr(parent=self, content=self.content, start=of)
        of += self.COFFhdr.bytelen
        if   self.COFFhdr.machine == pe.IMAGE_FILE_MACHINE_TI:
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
        kargs = { 'parent': self, 'content': self.content, 'start': of }
        if   self.COFFhdr.sizeofoptionalheader == 28:
            self.Opthdr = pe.Opthdr32(**kargs)
        elif self.COFFhdr.sizeofoptionalheader == 36:
            assert self.COFFhdr.machine == pe.IMAGE_FILE_MACHINE_CLIPPER
            self.Opthdr = pe.OpthdrClipper(**kargs)
        elif self.COFFhdr.sizeofoptionalheader == 44:
            assert self.COFFhdr.machine == pe.IMAGE_FILE_MACHINE_APOLLOM68K
            self.Opthdr = pe.OpthdrApollo(**kargs)
        elif self.COFFhdr.sizeofoptionalheader == 80:
            assert self.COFFhdr.machine == pe.IMAGE_FILE_MACHINE_ALPHA_O
            self.Opthdr = pe.OpthdrOSF1(**kargs)
        elif self.COFFhdr.sizeofoptionalheader == 72:
            self.Opthdr = pe.OpthdrXCOFF32(**kargs)
        elif self.COFFhdr.sizeofoptionalheader == 110:
            self.Opthdr = pe.OpthdrXCOFF64(**kargs)
        elif self.COFFhdr.sizeofoptionalheader == 0:
            from elfesteem.pe import CStruct
            class NullHdr(CStruct):
                _fields = [ ]
            self.Opthdr = NullHdr(**kargs)
        elif (self.COFFhdr.sizeofoptionalheader % 4) == 0:
            # All known OptHdr start with a 2-byte magic and 2-byte vstamp
            from elfesteem.pe import CStruct
            class OpthdrUnknown(CStruct):
                _fields = [ ("magic", "u16"), ("vstamp", "u16") ] \
                        + [ ("f%d"%_, "u32")
                    for _ in range(1, self.COFFhdr.sizeofoptionalheader // 4) ]
            self.Opthdr = OpthdrUnknown(**kargs)
        else:
            # Size of COFF optional header should probably be a multiple of 4
            raise ValueError("COFF SZOPT %d"%self.COFFhdr.sizeofoptionalheader)
        
        of += self.COFFhdr.sizeofoptionalheader
        filesz = len(self.content)
        if self.COFFhdr.numberofsections == 0:
            raise ValueError("COFF cannot have no sections")
        if self.COFFhdr.numberofsections > 0x1000:
            raise ValueError("COFF too many sections %d"%self.COFFhdr.numberofsections)
        if of + self.COFFhdr.numberofsections * 40 > filesz:
            raise ValueError("COFF too many sections %d"%self.COFFhdr.numberofsections)
        if self.COFFhdr.pointertosymboltable > filesz:
            raise ValueError("COFF invalid ptr to symbol table")
        self.SHList = pe.SHList(parent=self, content=self.content, start=of)
        
        of = self.COFFhdr.pointertosymboltable
        if self.COFFhdr.machine == pe.IMAGE_FILE_MACHINE_ALPHA_O \
                and of != 0 \
                and struct.unpack('<H',self.content[of:of+2])[0] == 0x1992:
            self.OSF1Symbols = pe.CoffOSF1Symbols(
                                       parent=self,
                                       content=self.content,
                                       start=self.COFFhdr.pointertosymboltable,
                                       )
        elif of != 0 and self.COFFhdr.numberofsymbols != 0:
            self.Symbols = pe.CoffSymbols(
                                       parent=self,
                                       content=self.content,
                                       start=None,
                                       )
        if hasattr(self, 'Symbols'):
            of = self.COFFhdr.pointertosymboltable + self.Symbols.bytelen
            sz, = struct.unpack(self.sex+'I',self.content[of:of+4])
            if len(self.content) < of+sz:
                log.warning('File too short for StrTable %#x != %#x' % (
                    len(self.content)-of, sz))
                sz = len(self.content) - of
            self.SymbolStrings = StrTable(self.content[of:of+sz])
        
        if self.Opthdr.__class__.__name__ == 'OpthdrUnknown':
            log.warn("Unknown Option Header format of size %d for machine %s:",
                self.COFFhdr.sizeofoptionalheader,
                pe.constants['IMAGE_FILE_MACHINE'].get(
                      self.COFFhdr.machine, '%#x'%self.COFFhdr.machine))
            log.warn('%r', self.Opthdr)


if __name__ == "__main__":
    import rlcompleter,readline,pdb, sys
    from pprint import pprint as pp
    readline.parse_and_bind("tab: complete")

    data = open(sys.argv[1]).read()
    print("Read file of len %d"%len(data))
    e = PE(data)
    # Packed file is not identical :-(
    # Are missing:
    # - the data between the end of DOS header and the start of PE header
    # - the padding after the list of sections, before the first section
    # - many parts of directories
    e_str = e.pack()
    print("Packed file of len %d"%len(e_str))
    open('out.packed.bin', 'wb').write(e_str)

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

    e = PE(data)
    # Delete the last sections => OK
    for _ in range(2):
        del e.SHList._array[-1]
        e.SHList._size -= 40
        e.COFFhdr.numberofsections -= 1
    # Add two Descriptors in the Import Directory
    e.DirImport.add_dlldesc(
              [({"name":"kernel32.dll",
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
              )
    e_str = e.pack()
    open('out.import.bin', 'wb').write(e_str)
    print("WROTE out.import.bin with new imports")

    print("f0 %s" % e.DirImport.get_funcvirt('ExitProcess'))
    print("f1 %s" % e.DirImport.get_funcvirt('LoadStringW'))
    print("f2 %s" % e.DirExport.get_funcvirt('SetUserGeoID'))

    if e.DirExport.expdesc is None:
        e.DirExport.create(['coco'])

    e_str = e.pack()
    open('out.export.bin', 'wb').write(e_str)
    print("WROTE out.export.bin with new exports")

    f = PE()
    open('uu.bin', 'wb').write(f.pack())
