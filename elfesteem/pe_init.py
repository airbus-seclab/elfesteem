#! /usr/bin/env python

import struct
import array
import pe
from strpatchwork import StrPatchwork
import logging
from collections import defaultdict
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
        owner._content = new_content
        # owner.parse_content()

    def __delete__(self, owner):
        self.__set__(owner, None)


class drva:

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

    def get_rvaitem(self, start, stop=None, step=None):
        if self.parent.SHList is None:
            return [(None, start)]
        if stop == None:
            s = self.parent.getsectionbyrva(start)
            if s is None:
                return [(None, start)]
            start = start - s.addr
            return [(s, start)]
        total_len = stop - start
        rva_items = []
        while total_len:
            # Special case if look at pe hdr address
            if 0 <= start < min(self.parent.SHList[0].addr,
                                self.parent.NThdr.sizeofheaders):
                s_start = start
                s_stop = stop
                s_max = min(self.parent.SHList[0].addr,
                            self.parent.NThdr.sizeofheaders)
                s = None
            else:
                s = self.parent.getsectionbyrva(start)
                if s is None:
                    log.warn('unknown rva address! %x' % start)
                    return []
                s_max = max(s.size, s.rawsize)
                s_start = start - s.addr
                s_stop = stop - s.addr
            # print hex(s_stop), hex(s_start)
            if s_stop > s_max:
                # print 'yy'
                # raise ValueError('lack data %d, %d'%(stop, s_max))
                s_stop = s_max
            # print hex(s_start), hex(s_stop)
            s_len = s_stop - s_start
            total_len -= s_len
            start += s_len
            n_item = slice(s_start, s_stop, step)
            rva_items.append((s, n_item))
        return rva_items

    def __getitem__(self, item):
        return self.get_slice_raw(item)

    def __setitem__(self, item, data):
        if not type(item) is slice:
            item = slice(item, item + len(data), None)
        rva_items = self.get_rvaitem(item.start, item.stop, item.step)
        if rva_items is None:
            return
        off = 0
        for s, n_item in rva_items:
            i = slice(off, n_item.stop + off - n_item.start, n_item.step)
            data_slice = data.__getitem__(i)
            s.data.__setitem__(n_item, data_slice)
            off = i.stop
            # XXX test patch content
            file_off = self.parent.rva2off(s.addr + n_item.start)
            if self.parent.content:
                self.parent.content = self.parent.content[
                    :file_off] + data_slice + self.parent.content[file_off + len(data_slice):]
        return  # s.data.__setitem__(n_item, data)


class virt:

    def __init__(self, x):
        self.parent = x

    def item_virt2rva(self, item):
        if not type(item) is slice:  # integer
            rva = self.parent.virt2rva(item)
            return slice(rva, None, None)
        start = self.parent.virt2rva(item.start)
        stop = self.parent.virt2rva(item.stop)
        step = item.step
        return slice(start, stop, step)

    def __getitem__(self, item):
        raise DeprecationWarning("xx(start, [stop, step])")
        print 'ii'
        rva_item = self.item_virt2rva(item)
        return self.parent.drva.__getitem__(rva_item)

    def __setitem__(self, item, data):
        if not type(item) is slice:
            item = slice(item, item + len(data), None)
        rva_item = self.item_virt2rva(item)
        self.parent.drva.__setitem__(rva_item, data)

    def max_addr(self):
        s = self.parent.SHList[-1]
        l = s.addr + s.size + self.parent.NThdr.ImageBase
        return int(l)

    def find(self, pattern, start=0, end=None):
        if start != 0:
            start = self.parent.virt2rva(start)
        if end != None:
            end = self.parent.virt2rva(end)

        sections = []
        for s in self.parent.SHList:
            s_max = max(s.size, s.rawsize)
            if s.addr + s_max <= start:
                continue
            if end == None or s.addr < end:
                sections.append(s)

        if not sections:
            return -1
        for s in sections:
            if s.addr < start:
                off = start - s.addr
            else:
                off = 0
            ret = s.data.find(pattern, off)
            if ret == -1:
                continue
            if end != None and s.addr + ret >= end:
                return -1
            return self.parent.rva2virt(s.addr + ret)
        return -1

    def rfind(self, pattern, start=0, end=None):
        if start != 0:
            start = self.parent.virt2rva(start)
        if end != None:
            end = self.parent.virt2rva(end)

        sections = []
        for s in self.parent.SHList:
            s_max = max(s.size, s.rawsize)
            if s.addr + s_max <= start:
                continue
            if end == None or s.addr < end:
                sections.append(s)
        if not sections:
            return -1

        for s in reversed(sections):
            if s.addr < start:
                off = start - s.addr
            else:
                off = 0
            if end == None:
                ret = s.data.rfind(pattern, off)
            else:
                ret = s.data.rfind(pattern, off, end - s.addr)
            if ret == -1:
                continue
            return self.parent.rva2virt(s.addr + ret)
        return -1

    def is_addr_in(self, ad):
        return self.parent.is_in_virt_address(ad)

    def __call__(self, ad_start, ad_stop=None, ad_step=None):
        ad_start = self.parent.virt2rva(ad_start)
        if ad_stop != None:
            ad_stop = self.parent.virt2rva(ad_stop)

        rva_items = self.parent.drva.get_rvaitem(ad_start, ad_stop, ad_step)
        data_out = ""
        for s, n_item in rva_items:
            if s is None:
                data_out += self.parent.__getitem__(n_item)
            else:
                data_out += s.data.__getitem__(n_item)

        return data_out

# PE object


class PE(object):
    content = ContentManager()

    def __init__(self, pestr=None,
                 loadfrommem=False,
                 parse_resources=True,
                 parse_delay=True,
                 parse_reloc=True,
                 wsize=32):
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

            self.NTsig.signature = 0x4550
            if wsize == 32:
                self.Opthdr.magic = 0x10b
            elif wsize == 64:
                self.Opthdr.magic = 0x20b
            else:
                raise ValueError('unknown pe size %r' % wsize)
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
            if wsize == 32:
                self.NThdr.dllcharacteristics = 0x8000
            else:
                self.NThdr.dllcharacteristics = 0x8000

            # for createthread
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
                raise ValueError('unknown pe size %r' % wsize)
            if wsize == 32:
                self.Coffhdr.characteristics = 0x10f
                self.Coffhdr.sizeofoptionalheader = 0xe0
            else:
                self.Coffhdr.characteristics = 0x22  # 0x2f
                self.Coffhdr.sizeofoptionalheader = 0xf0

        else:
            self._content = StrPatchwork(pestr)
            self.loadfrommem = loadfrommem
            self.parse_content(parse_resources=parse_resources,
                               parse_delay=parse_delay,
                               parse_reloc=parse_reloc)

    def isPE(self):
        if self.NTsig is None:
            return False
        return self.NTsig.signature == 0x4550

    def parse_content(self,
                      parse_resources=True,
                      parse_delay=True,
                      parse_reloc=True):
        of = 0
        self._sex = 0
        self._wsize = 32
        self.Doshdr = pe.Doshdr.unpack(self.content, of, self)
        # print repr(self.Doshdr)
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
        m = struct.unpack('H', self.content[of:of + 2])[0]
        m = (m >> 8) * 32
        self._wsize = m

        if self._wsize == 32:
            Opthdr = pe.Opthdr32
        else:
            Opthdr = pe.Opthdr64

        self.Opthdr, l = Opthdr.unpack_l(self.content, of, self)
        # print hex(of+len(self.Opthdr))
        self.NThdr = pe.NThdr.unpack(self.content, of + l, self)
        # print repr(self.NThdr.optentries)
        of += self.Coffhdr.sizeofoptionalheader
        self.SHList = pe.SHList.unpack(self.content, of, self)
        # print repr(self.SHList)

        # load section data
        filealignment = self.NThdr.filealignment
        for s in self.SHList.shlist:
            if self.loadfrommem:
                s.offset = s.addr
            if filealignment == 0:
                raw_off = s.offset
            else:
                raw_off = filealignment * (s.offset / filealignment)
            if raw_off != s.offset:
                log.warn('unaligned raw section!')
            s.data = StrPatchwork()
            # min section is 0x1000???
            if s.rawsize == 0:
                mm = 0
            else:
                if s.rawsize % filealignment:
                    rs = (s.rawsize / filealignment + 1) * filealignment
                else:
                    rs = s.rawsize
                mm = max(rs, 0x1000)
            s.data[0] = self.content[raw_off:raw_off + mm]
        try:
            self.DirImport = pe.DirImport.unpack(self.content,
                                                 self.NThdr.optentries[
                                                     pe.DIRECTORY_ENTRY_IMPORT].rva,
                                                 self)
        except pe.InvalidOffset:
            log.warning('cannot parse DirImport, skipping')
            self.DirImport = pe.DirImport(self)

        try:
            self.DirExport = pe.DirExport.unpack(self.content,
                                                 self.NThdr.optentries[
                                                     pe.DIRECTORY_ENTRY_EXPORT].rva,
                                                 self)
        except pe.InvalidOffset:
            log.warning('cannot parse DirExport, skipping')
            self.DirExport = pe.DirExport(self)

        if len(self.NThdr.optentries) > pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            self.DirDelay = pe.DirDelay(self)
            if parse_delay:
                try:
                    self.DirDelay = pe.DirDelay.unpack(self.content,
                                                       self.NThdr.optentries[
                                                           pe.DIRECTORY_ENTRY_DELAY_IMPORT].rva,
                                                       self)
                except pe.InvalidOffset:
                    log.warning('cannot parse DirDelay, skipping')
        if len(self.NThdr.optentries) > pe.DIRECTORY_ENTRY_BASERELOC:
            self.DirReloc = pe.DirReloc(self)
            if parse_reloc:
                try:
                    self.DirReloc = pe.DirReloc.unpack(self.content,
                                                       self.NThdr.optentries[
                                                       pe.DIRECTORY_ENTRY_BASERELOC].rva,
                                                       self)
                except pe.InvalidOffset:
                    log.warning('cannot parse DirReloc, skipping')
        if len(self.NThdr.optentries) > pe.DIRECTORY_ENTRY_RESOURCE:
            self.DirRes = pe.DirRes(self)
            if parse_resources:
                self.DirRes = pe.DirRes(self)
                try:
                    self.DirRes = pe.DirRes.unpack(self.content,
                                                   self.NThdr.optentries[
                                                       pe.DIRECTORY_ENTRY_RESOURCE].rva,
                                                   self)
                except pe.InvalidOffset:
                    log.warning('cannot parse DirRes, skipping')
        # self.Symbols = ClassArray(self, WSymb,
        # self.Coffhdr.Coffhdr.pointertosymboltable,
        # self.Coffhdr.Coffhdr.numberofsymbols)

        # print repr(self.Doshdr)
        # print repr(self.Coffhdr)
        # print repr(self.Opthdr)
        # print repr(self.SHList)

        # print repr(self.DirImport)
        # print repr(self.DirExport)
        # print repr(self.DirReloc)
        # print repr(self.DirRes)

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
            """
            TODO CHECK:
            some binaries have import rva outside section, but addresses
            seems to be rounded
            """
            if s.addr <= rva < (s.addr + s.size + 0xfff) & 0xFFFFF000:
                return s
        return None

    def getsectionbyvad(self, vad):
        return self.getsectionbyrva(self.virt2rva(vad))

    def getsectionbyoff(self, off):
        if self.SHList is None:
            return None
        for s in self.SHList.shlist:
            if s.offset <= off < s.offset + s.rawsize:
                return s
        return None

    def getsectionbyname(self, name):
        if self.SHList is None:
            return None
        for s in self.SHList:
            if s.name.strip('\x00') == name:
                return s
        return None

    def is_rva_ok(self, rva):
        return self.getsectionbyrva(rva) is not None

    def rva2off(self, rva):
        # Special case rva in header
        if rva < self.NThdr.sizeofheaders:
            return rva
        s = self.getsectionbyrva(rva)
        if s is None:
            raise pe.InvalidOffset('cannot get offset for 0x%X' % rva)
            return
        soff = (s.offset / self.NThdr.filealignment) * self.NThdr.filealignment
        return rva - s.addr + soff

    def off2rva(self, off):
        s = self.getsectionbyoff(off)
        if s is None:
            return
        return off - s.offset + s.addr

    def virt2rva(self, virt):
        if virt == None:
            return
        return virt - self.NThdr.ImageBase

    def rva2virt(self, rva):
        if rva == None:
            return
        return rva + self.NThdr.ImageBase

    def virt2off(self, virt):
        return self.rva2off(self.virt2rva(virt))

    def off2virt(self, off):
        return self.rva2virt(self.off2rva(off))

    def is_in_virt_address(self, ad):
        if ad < self.NThdr.ImageBase:
            return False
        ad = self.virt2rva(ad)
        for s in self.SHList.shlist:
            if s.addr <= ad < s.addr + s.size:
                return True
        return False

    def get_drva(self):
        return self._drva

    drva = property(get_drva)

    def get_virt(self):
        return self._virt

    virt = property(get_virt)

    def patch_crc(self, c, olds):
        s = 0L
        data = c[:]
        l = len(data)
        if len(c) % 2:
            end = struct.unpack('B', data[-1])[0]
            data = data[:-1]
        if (len(c) & ~0x1) % 4:
            s += struct.unpack('H', data[:2])[0]
            data = data[2:]
        data = array.array('I', data)
        s = reduce(lambda x, y: x + y, data, s)
        s -= olds
        while s > 0xFFFFFFFF:
            s = (s >> 32) + (s & 0xFFFFFFFF)
        while s > 0xFFFF:
            s = (s & 0xFFFF) + ((s >> 16) & 0xFFFF)
        if len(c) % 2:
            s += end
        s += l
        return s

    def build_content(self):

        c = StrPatchwork()
        c[0] = str(self.Doshdr)

        for s in self.SHList.shlist:
            c[s.offset:s.offset + s.rawsize] = str(s.data)

        # fix image size
        s_last = self.SHList.shlist[-1]
        size = s_last.addr + s_last.size + (self.NThdr.sectionalignment - 1)
        size &= ~(self.NThdr.sectionalignment - 1)
        self.NThdr.sizeofimage = size

        off = self.Doshdr.lfanew
        c[off] = str(self.NTsig)
        off += len(self.NTsig)
        c[off] = str(self.Coffhdr)
        off += len(self.Coffhdr)
        c[off] = str(self.Opthdr)
        off += len(self.Opthdr)
        c[off] = str(self.NThdr)
        off += len(self.NThdr)
        # c[off] = str(self.Optehdr)

        off = self.Doshdr.lfanew + \
            len(self.NTsig) + len(self.Coffhdr) + \
            self.Coffhdr.sizeofoptionalheader
        c[off] = str(self.SHList)

        for s in self.SHList:
            if off + len(str(self.SHList)) > s.offset:
                log.warn("section offset overlap pe hdr 0x%x 0x%x" %
                         (off + len(str(self.SHList)), s.offset))
        self.DirImport.build_content(c)
        self.DirExport.build_content(c)
        self.DirDelay.build_content(c)
        self.DirReloc.build_content(c)
        self.DirRes.build_content(c)
        s = str(c)
        if (self.Doshdr.lfanew + len(self.NTsig) + len(self.Coffhdr)) % 4:
            log.warn("non aligned coffhdr, bad crc calculation")
        crcs = self.patch_crc(s, self.NThdr.CheckSum)
        c[self.Doshdr.lfanew + len(self.NTsig) + len(
            self.Coffhdr) + 64] = struct.pack('I', crcs)
        return str(c)

    def __str__(self):
        return self.build_content()

    def export_funcs(self):
        if self.DirExport is None:
            print 'no export dir found'
            return None, None

        all_func = {}
        for i, n in enumerate(self.DirExport.f_names):
            all_func[n.name.name] = self.rva2virt(
                self.DirExport.f_address[self.DirExport.f_nameordinals[i].ordinal].rva)
            all_func[self.DirExport.f_nameordinals[i].ordinal + self.DirExport.expdesc.base] = self.rva2virt(
                self.DirExport.f_address[self.DirExport.f_nameordinals[i].ordinal].rva)
        # XXX todo: test if redirected export
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
                v = struct.unpack('I', self.drva[off:off + 4])[0]
                v += offset
                self.drva[off:off + 4] = struct.pack('I', v & 0xFFFFFFFF)
        self.NThdr.ImageBase = imgbase


class Coff(PE):

    def parse_content(self):
        self.Coffhdr = Coffhdr(self, 0)
        self.Opthdr = Opthdr(self, pe.Coffhdr._size)
        self.SHList = SHList(
            self, pe.Coffhdr._size + self.Coffhdr.Coffhdr.sizeofoptionalheader)

        self.Symbols = ClassArray(
            self, WSymb, self.Coffhdr.Coffhdr.pointertosymboltable, self.Coffhdr.Coffhdr.numberofsymbols)


if __name__ == "__main__":
    import rlcompleter
    import readline
    import pdb
    import sys
    from pprint import pprint as pp
    readline.parse_and_bind("tab: complete")

    e = PE(open(sys.argv[1]).read())
    print repr(e.DirImport)
    print repr(e.DirExport)
    print repr(e.DirDelay)
    print repr(e.DirReloc)
    print repr(e.DirRes)

    # XXX patch boundimport /!\
    e.NThdr.optentries[pe.DIRECTORY_ENTRY_BOUND_IMPORT].rva = 0
    e.NThdr.optentries[pe.DIRECTORY_ENTRY_BOUND_IMPORT].size = 0

    s_redir = e.SHList.add_section(name="redir", rawsize=0x1000)
    s_test = e.SHList.add_section(name="test", rawsize=0x1000)
    s_rel = e.SHList.add_section(name="rel", rawsize=0x5000)

    new_dll = [({"name": "kernel32.dll",
                 "firstthunk": s_test.addr},
                ["CreateFileA",
                 "SetFilePointer",
                 "WriteFile",
                 "CloseHandle",
                 ]
                ),
               ({"name": "USER32.dll",
                 "firstthunk": None},
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

    s_myimp = e.SHList.add_section(name="myimp", rawsize=len(e.DirImport))
    s_myexp = e.SHList.add_section(name="myexp", rawsize=len(e.DirExport))
    s_mydel = e.SHList.add_section(name="mydel", rawsize=len(e.DirDelay))
    s_myrel = e.SHList.add_section(name="myrel", rawsize=len(e.DirReloc))
    s_myres = e.SHList.add_section(name="myres", rawsize=len(e.DirRes))

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

    e_str = str(e)
    print "f1", e.DirImport.get_funcvirt('LoadStringW')
    print "f2", e.DirExport.get_funcvirt('SetUserGeoID')
    open('out.bin', 'wb').write(e_str)
    # o = Coff(open('main.obj').read())
    # print repr(o.Coffhdr)
    # print repr(o.Opthdr)
    # print repr(o.SHList)
    # print 'numsymb', hex(o.Coffhdr.Coffhdr.numberofsymbols)
    # print 'offset', hex(o.Coffhdr.Coffhdr.pointertosymboltable)
    #
    # print repr(o.Symbols)

    f = PE()
    open('uu.bin', 'w').write(str(f))
