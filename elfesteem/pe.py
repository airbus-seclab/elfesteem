#! /usr/bin/env python

from new_cstruct import CStruct
from strpatchwork import StrPatchwork
import struct
import logging

log = logging.getLogger("pepy")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)

class Doshdr(CStruct):
    _fields = [ ("magic", "u16"),
                ("cblp","u16"),
                ("cp","u16"),
                ("crlc","u16"),
                ("cparhdr","u16"),
                ("minalloc","u16"),
                ("maxalloc","u16"),
                ("ss","u16"),
                ("sp","u16"),
                ("csum","u16"),
                ("ip","u16"),
                ("cs","u16"),
                ("lfarlc","u16"),
                ("ovno","u16"),
                ("res","8s"),
                ("oemid","u16"),
                ("oeminfo","u16"),
                ("res2","20s"),
                ("lfanew","u32") ]

class NTsig(CStruct):
    _fields = [ ("signature","u32"),
                ]

class Coffhdr(CStruct):
    _fields = [ ("machine","u16"),
                ("numberofsections","u16"),
                ("timedatestamp","u32"),
                ("pointertosymboltable","u32"),
                ("numberofsymbols","u32"),
                ("sizeofoptionalheader","u16"),
                ("characteristics","u16") ]

class Optehdr(CStruct):
    _fields = [ ("rva","u32"),
                ("size","u32") ]

def get_optehdr_num(o):
    numberofrva = o.numberofrvaandsizes
    size_e = 8
    if o.parent_head.Coffhdr.sizeofoptionalheader < numberofrva * size_e+ len(o.parent_head.Opthdr):
        numberofrva = (o.parent_head.Coffhdr.sizeofoptionalheader-len(o.parent_head.Opthdr))/size_e
        log.warn('bad number of rva.. using default %d'%numberofrva)
        numberofrva = 0x10
    return numberofrva

class Opthdr32(CStruct):
    _fields = [ ("magic","u16"),
                ("majorlinkerversion","u08"),
                ("minorlinkerversion","u08"),
                ("SizeOfCode","u32"),
                ("sizeofinitializeddata","u32"),
                ("sizeofuninitializeddata","u32"),
                ("AddressOfEntryPoint","u32"),
                ("BaseOfCode","u32"),
                ("BaseOfData","u32"),
                ]

class Opthdr64(CStruct):
    _fields = [ ("magic","u16"),
                ("majorlinkerversion","u08"),
                ("minorlinkerversion","u08"),
                ("SizeOfCode","u32"),
                ("sizeofinitializeddata","u32"),
                ("sizeofuninitializeddata","u32"),
                ("AddressOfEntryPoint","u32"),
                ("BaseOfCode","u32"),
                ]

class NThdr(CStruct):
    _fields = [ ("ImageBase","ptr"),
                ("sectionalignment","u32"),
                ("filealignment","u32"),
                ("majoroperatingsystemversion","u16"),
                ("minoroperatingsystemversion","u16"),
                ("MajorImageVersion","u16"),
                ("MinorImageVersion","u16"),
                ("majorsubsystemversion","u16"),
                ("minorsubsystemversion","u16"),
                ("Reserved1","u32"),
                ("sizeofimage","u32"),
                ("sizeofheaders","u32"),
                ("CheckSum","u32"),
                ("subsystem","u16"),
                ("dllcharacteristics","u16"),
                ("sizeofstackreserve","ptr"),
                ("sizeofstackcommit","ptr"),
                ("sizeofheapreserve","ptr"),
                ("sizeofheapcommit","ptr"),
                ("loaderflags","u32"),
                ("numberofrvaandsizes","u32"),
                ("optentries", "Optehdr", lambda c:get_optehdr_num(c))
                ]


class Shdr(CStruct):
    _fields = [ ("name","8s"),
                ("size","u32"),
                ("addr","u32"),
                ("rawsize","u32"),
                ("offset","u32"),
                ("pointertorelocations","u32"),
                ("pointertolinenumbers","u32"),
                ("numberofrelocations","u16"),
                ("numberoflinenumbers","u16"),
                ("flags","u32") ]


class SHList(CStruct):
    _fields = [ ("shlist", "Shdr", lambda c:c.parent_head.Coffhdr.numberofsections)]

    def add_section(self, name="default", data = "", **args):
        s_align = self.parent_head.NThdr.sectionalignment
        s_align = max(0x1000, s_align)

        f_align = self.parent_head.NThdr.filealignment
        f_align = max(0x200, f_align)
        size = len(data)
        rawsize = len(data)
        if len(self):
            addr = self[-1].addr+self[-1].size
            s_last = self[0]
            for s in self:
                if s_last.offset+s_last.rawsize<s.offset+s.rawsize:
                    s_last = s
            offset = s_last.offset+s_last.rawsize
        else:
            offset = self.parent_head.Doshdr.lfanew+len(self.parent_head.NTsig)+len(self.parent_head.Coffhdr)+self.parent_head.Coffhdr.sizeofoptionalheader
            addr = 0x2000
        #round addr
        addr = (addr+(s_align-1))&~(s_align-1)
        offset = (offset+(f_align-1))&~(f_align-1)

        f = {"name":name, "size":size,
             "addr":addr, "rawsize":rawsize,
             "offset": offset,
             "pointertorelocations":0,
             "pointertolinenumbers":0,
             "numberofrelocations":0,
             "numberoflinenumbers":0,
             "flags":0xE0000020,
             "data":data
             }
        f.update(args)
        s = Shdr(_sex = self.parent_head._sex, _wsize = self.parent_head._wsize, **f)
        s.data = data

        if s.rawsize > len(data):
            s.data = s.data+'\x00'*(s.rawsize-len(data))
            s.size = s.rawsize
        c = StrPatchwork()
        c[0] = s.data
        s.data = c
        s.size = max(s_align, s.size)

        self.append(s)
        self.parent_head.Coffhdr.numberofsections = len(self)

        l = (s.addr+s.size+(s_align-1))&~(s_align-1)
        self.parent_head.NThdr.sizeofimage = l
        return s



    def align_sections(self, f_align = None, s_align = None):
        if f_align == None:
            f_align = self.parent_head.NThdr.filealignment
            f_align = max(0x200, f_align)
        if s_align == None:
            s_align = self.parent_head.NThdr.sectionalignment
            s_align = max(0x1000, s_align)

        if not self:
            return

        addr = self[0].offset
        for s in self:
            raw_off = f_align*((addr+f_align-1)/f_align)
            s.offset = raw_off
            s.rawsize = len(s.data)
            addr = raw_off+s.rawsize

    def __repr__(self):
        rep = ["#  section         offset   size   addr     flags   rawsize  "]
        for i,s in enumerate(self):
            l = "%-15s"%s.name.strip('\x00')
            l+="%(offset)08x %(size)06x %(addr)08x %(flags)08x %(rawsize)08x" % s
            l = ("%2i " % i)+ l
            rep.append(l)
        return "\n".join(rep)

    def __getitem__(self, item):
        return self.shlist[item]
    def __len__(self):
        return len(self.shlist)

    def append(self, s):
        self.shlist.append(s)

class Rva(CStruct):
    _fields = [ ("rva","ptr"),
                ]

class DescName(CStruct):
    _fields = [ ("name", (lambda c, s, of:c.gets(s, of),
                          lambda c, value:c.sets(value)))
                ]
    def gets(self, s, of):
        if of < 0x1000:
            log.warn("desname in pe hdr, used as offset")
            ofname = of
        else:
            ofname = self.parent_head.rva2off(of)
        name = self.parent_head[ofname:self.parent_head._content.find('\x00', ofname)]
        return name, of+len(name)+1
    def sets(self, value):
        return str(value)+"\x00"

class ImportByName(CStruct):
    _fields = [ ("hint", "u16"),
                ("name", (lambda c, s, of:c.gets(s, of),
                          lambda c, value:c.sets(value)))
                ]
    def gets(self, s, of):
        name = self.parent_head[of:self.parent_head._content.find('\x00', of)]
        return name, of+len(name)+1
    def sets(self, value):
        return str(value)+"\x00"

class ImpDesc_e(CStruct):
    _fields = [ ("originalfirstthunk","u32"),
                ("timestamp","u32"),
                ("forwarderchain","u32"),
                ("name","u32"),
                ("firstthunk","u32")
              ]


class struct_array(object):
    def __init__(self, c, s, of, cstr, num = None):
        self.l = []
        self.cls = c
        self.end = None
        i = 0
        if not s:
            return

        while (not num) or (num and i <num):
            e = cstr.unpack(s, of, c.parent_head, c.parent_head._sex, c.parent_head._wsize)
            x = str(e)
            if num == None:
                if x == '\x00'*len(x):
                    self.end = x
                    break
            self.l.append(e)
            of += len(x)
            i += 1

    def __str__(self):
        out = "".join([str(x) for x in self.l])
        if self.end != None:
            out += self.end
        return out

    def __getitem__(self, item):
        return self.l.__getitem__(item)

    def __len__(self):
        return len(self.l)

    def append(self, a):
        self.l.append(a)
    def insert(self, index, i):
        self.l.insert(index, i)

class DirImport(CStruct):
    _fields = [ ("impdesc", (lambda c, s, of:c.gete(s, of),
                             lambda c, value:c.sete(value)))]
    def gete(self, s, of):
        if not of:
            return [], of
        of = self.parent_head.rva2off(of)
        out = struct_array(self, s, of, ImpDesc_e)
        if self.parent_head._wsize == 32:
            mask_ptr = 0x80000000
        elif self.parent_head._wsize == 64:
            mask_ptr = 0x8000000000000000L

        for i, d in enumerate(out):
            d.dlldescname = DescName.unpack(s, d.name, self.parent_head)
            if d.originalfirstthunk:
                d.originalfirstthunks = struct_array(self, s,
                                                     self.parent_head.rva2off(d.originalfirstthunk),
                                                     Rva)
            else:
                d.originalfirstthunks = None

            if d.firstthunk:
                d.firstthunks = struct_array(self, s,
                                             self.parent_head.rva2off(d.firstthunk), 
                                             Rva)
            else:
                d.firstthunks = None
            d.impbynames = []
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise ValueError("no thunk!!")
            for i in xrange(len(tmp_thunk)):
                if tmp_thunk[i].rva&mask_ptr == 0:
                    try:
                        n = ImportByName.unpack(s,
                                                self.parent_head.rva2off(tmp_thunk[i].rva),
                                                self.parent_head)
                    except:
                        log.warning('cannot import from add %s'%str(tmp_thunk[i].rva))
                        n = 0
                    d.impbynames.append(n)
                else:
                    d.impbynames.append(tmp_thunk[i].rva&(mask_ptr-1))
        return out, of

    def sete(self, v):
        c = "".join([str(x) for x in v])+"\x00"*(4*5) #ImdDesc_e
        return c


    def __len__(self):
        l = (len(self.impdesc)+1)*(5*4) #ImpDesc_e size
        for i, d in enumerate(self.impdesc):
            l+=len(d.dlldescname)
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                l+=(len(d.originalfirstthunks)+1)*self.parent_head._wsize/8 #Rva size
            if d.firstthunk:
                l+=(len(d.firstthunks)+1)*self.parent_head._wsize/8 #Rva size
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            """
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            """
            for i, imp in enumerate(d.impbynames):
                if isinstance(imp, ImportByName):
                    l+=len(imp)
        return l


    def set_rva(self, rva, size = None):
        self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_IMPORT].rva = rva
        if not size:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_IMPORT].size= len(self)
        else:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_IMPORT].size= size
        rva+=(len(self.impdesc)+1)*5*4 # ImpDesc size
        for i, d in enumerate(self.impdesc):
            d.name = rva
            rva+=len(d.dlldescname)
            if d.originalfirstthunk:# and self.parent_head.rva2off(d.originalfirstthunk):
                d.originalfirstthunk = rva
                rva+=(len(d.originalfirstthunks)+1)*self.parent_head._wsize/8 # rva size
            #XXX rva fthunk not patched => keep original func addr
            #if d.firstthunk:
            #    d.firstthunk = rva
            #    rva+=(len(d.firstthunks)+1)*self.parent_head._wsize/8 # Rva size
            if d.originalfirstthunk and d.firstthunk:
                if isinstance(d.originalfirstthunk, struct_array):
                    tmp_thunk = d.originalfirstthunks
                elif isinstance(d.firstthunks, struct_array):
                    tmp_thunk = d.firstthunks
                else:
                    raise "no thunk!!"
            elif d.originalfirstthunk:# and self.parent_head.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"

            if tmp_thunk == d.originalfirstthunks:
                d.firstthunks = tmp_thunk
            else:
                d.originalfirstthunks = tmp_thunk
            for i, imp in enumerate(d.impbynames):
                if isinstance(imp, ImportByName):
                    tmp_thunk[i].rva = rva
                    rva+=len(imp)

    def build_content(self, c):
        dirimp = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_IMPORT]
        of1 = dirimp.rva
        if not of1: # No Import
            return
        x = str(self.impdesc)
        c[self.parent_head.rva2off(of1)] = str(self)
        for i, d in enumerate(self.impdesc):
            c[self.parent_head.rva2off(d.name)] = str(d.dlldescname)
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                c[self.parent_head.rva2off(d.originalfirstthunk)] = str(d.originalfirstthunks)
            if d.firstthunk:
                c[self.parent_head.rva2off(d.firstthunk)] = str(d.firstthunks)
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            for j, imp in enumerate(d.impbynames):
                if isinstance(imp, ImportByName):
                    c[self.parent_head.rva2off(tmp_thunk[j].rva)] = str(imp)


    def __repr__(self):
        rep = ["<%s>"%self.__class__.__name__]
        for i,s in enumerate(self.impdesc):
            l = "%2d %-25s %s"%(i, repr(s.dlldescname) ,repr(s))
            rep.append(l)
            for ii, f in enumerate(s.impbynames):
                l = "    %2d %-16s"%(ii, repr(f))
                rep.append(l)
        return "\n".join(rep)

    def add_dlldesc(self, new_dll):
        if self.parent_head._wsize == 32:
            mask_ptr = 0x80000000
        elif self.parent_head._wsize == 64:
            mask_ptr = 0x8000000000000000L
        new_impdesc = []
        of1 = None
        for nd, fcts in new_dll:
            for x in ["timestamp", "forwarderchain", "originalfirstthunk"]:
                if not x in nd:
                    nd[x] = 0
            d = ImpDesc_e(self.parent_head, **nd)
            if d.firstthunk!=None:
                of1 = d.firstthunk
            elif of1 == None:
                raise "set fthunk"
            else:
                d.firstthunk = of1
            d.dlldescname = DescName(self.parent_head, name = d.name)
            d.originalfirstthunk = True
            d.originalfirstthunks = struct_array(self, None,
                                                 None,
                                                 Rva)
            d.firstthunks = struct_array(self, None,
                                         None,
                                         Rva)

            impbynames = []
            for nf in fcts:
                f = Rva(self.parent_head)
                if type(nf) in [int, long]:
                    f.rva = mask_ptr+nf
                    ibn = None
                elif type(nf) in [str]:
                    f.rva = True
                    ibn = ImportByName(self.parent_head)
                    ibn.name = nf
                    ibn.hint = 0
                else:
                    raise 'unknown func type %s'%str(nf)
                impbynames.append(ibn)
                d.originalfirstthunks.append(f)
                ff = Rva(self.parent_head)
                if ibn != None:
                    ff.rva = 0xDEADBEEF #default func addr
                else:
                    #ord ?XXX?
                    ff.rva = f.rva
                d.firstthunks.append(ff)
                of1+=self.parent_head._wsize/8
            #for null thunk
            of1+=self.parent_head._wsize/8
            d.impbynames = impbynames
            new_impdesc.append(d)
        if not self.impdesc:
            self.impdesc = struct_array(self, None,
                                        None,
                                        Impdesc)
            self.impdesc.l = new_impdesc
        else:
            for d in new_impdesc:
                self.impdesc.append(d)

    def get_funcrva(self, f):
        for i, d in enumerate(self.impdesc):
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            if type(f) is str:
                for j, imp in enumerate(d.impbynames):
                    if isinstance(imp, ImportByName):
                        if f == imp.name:
                            return d.firstthunk+j*4
            elif type(f) in (int, long):
                for j, imp in enumerate(d.impbynames):
                    if not isinstance(imp, ImportByName):
                        if tmp_thunk[j].rva&0x7FFFFFFF == f:
                            return d.firstthunk+j*4
            else:
                raise ValueError('unknown func tpye %s'%str(f))
    def get_funcvirt(self, f):
        rva = self.get_funcrva(f)
        if rva==None:
            return
        return self.parent_head.rva2virt(rva)


class ExpDesc_e(CStruct):
    _fields = [ ("characteristics","u32"),
                ("timestamp","u32"),
                ("majorv","u16"),
                ("minorv","u16"),
                ("name","u32"),
                ("base","u32"),
                ("numberoffunctions","u32"),
                ("numberofnames","u32"),
                ("addressoffunctions","u32"),
                ("addressofnames","u32"),
                ("addressofordinals","u32"),
              ]

class DirExport(CStruct):
    _fields = [ ("expdesc", (lambda c, s, of:c.gete(s, of),
                             lambda c, value:c.sete(value)))]
    def gete(self, s, of):
        if not of:
            return None, of
        of = self.parent_head.rva2off(of)
        of_sav = of
        expdesc = ExpDesc_e.unpack(s,
                                   of,
                                   self.parent_head)
        self.dlldescname = DescName.unpack(s, expdesc.name, self.parent_head)
        self.f_address = struct_array(self, s,
                                      self.parent_head.rva2off(expdesc.addressoffunctions), 
                                      Rva, expdesc.numberoffunctions)
        self.f_names = struct_array(self, s,
                                    self.parent_head.rva2off(expdesc.addressofnames), 
                                    Rva, expdesc.numberofnames)
        self.f_nameordinals = struct_array(self, s,
                                           self.parent_head.rva2off(expdesc.addressofordinals), 
                                           Ordinal, expdesc.numberofnames)
        for n in self.f_names:
            n.name = DescName.unpack(s, n.rva, self.parent_head)
        return expdesc, of_sav

    def sete(self, v):
        c = str(self.expdesc)
        return c

    def build_content(self, c):
        direxp = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_EXPORT]
        of1 = direxp.rva
        if not self.expdesc: # No Export
            return
        c[self.parent_head.rva2off(of1)] = str(self.expdesc)
        c[self.parent_head.rva2off(self.expdesc.name)] = str(self.dlldescname)
        c[self.parent_head.rva2off(self.expdesc.addressoffunctions)] = str(self.f_address)
        if self.expdesc.addressofnames!=0:
            c[self.parent_head.rva2off(self.expdesc.addressofnames)] = str(self.f_names)
        if self.expdesc.addressofordinals!=0:
            c[self.parent_head.rva2off(self.expdesc.addressofordinals)] = str(self.f_nameordinals)
        for n in self.f_names:
            c[self.parent_head.rva2off(n.rva)] = str(n.name)

        # XXX BUG names must be alphanumeric ordered
        names = [n.name for n in self.f_names]
        names_ = names[:]
        if names != names_:
            log.warn("unsorted export names, may bug")

    def set_rva(self, rva, size = None):
        if not self.expdesc:
            return
        self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_EXPORT].rva = rva
        if not size:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_EXPORT].size= len(self)
        else:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_EXPORT].size= size
        rva+=len(self.expdesc)
        self.expdesc.name = rva
        rva+=len(self.dlldescname)
        self.expdesc.addressoffunctions = rva
        rva+=len(self.f_address)*self.parent_head._wsize/8# Rva size
        self.expdesc.addressofnames = rva
        rva+=len(self.f_names)*self.parent_head._wsize/8# Rva size
        self.expdesc.addressofordinals = rva
        rva+=len(self.f_nameordinals)*2# Ordinal size
        for n in self.f_names:
            n.rva = rva
            rva+=len(n.name)

    def __len__(self):
        l = 0
        if not self.expdesc:
            return l
        l+=len(self.expdesc)
        l+=len(self.dlldescname)
        l+=len(self.f_address)*self.parent_head._wsize/8# Rva size
        l+=len(self.f_names)*self.parent_head._wsize/8# Rva size
        l+=len(self.f_nameordinals)*2# Ordinal size
        for n in self.f_names:
            l+=len(n.name)
        return l

    def __repr__(self):
        rep = ["<%s>"%self.__class__.__name__]
        if not self.expdesc:
            return "\n".join(rep)

        rep = ["<%s %d (%s) %s>"%(self.__class__.__name__,
                                  self.expdesc.numberoffunctions, self.dlldescname, repr(self.expdesc))]
        tmp_names = [[] for x in xrange(self.expdesc.numberoffunctions)]
        for i, n in enumerate(self.f_names):
            tmp_names[self.f_nameordinals[i].ordinal].append(n.name)
        for i,s in enumerate(self.f_address):
            tmpn = []
            if not s.rva:
                continue
            l = "%2d %.8X %s"%(i+self.expdesc.base, s.rva ,repr(tmp_names[i]))
            rep.append(l)
        return "\n".join(rep)

    def create(self, name = 'default.dll'):
        self.expdesc = ExpDesc_e(self.parent_head)
        for x in [ "characteristics",
                   "timestamp",
                   "majorv",
                   "minorv",
                   "name",
                   "base",
                   "numberoffunctions",
                   "numberofnames",
                   "addressoffunctions",
                   "addressofnames",
                   "addressofordinals",
                   ]:
            setattr(self.expdesc, x, 0)

        self.dlldescname = DescName(self.parent_head)
        self.dlldescname.name = name
        self.f_address = struct_array(self, None,
                                      None,
                                      Rva)
        self.f_names = struct_array(self, None,
                                    None,
                                    Rva)
        self.f_nameordinals = struct_array(self, None,
                                           None,
                                           Ordinal)
        self.expdesc.base = 1


    def add_name(self, name, rva = 0xdeadc0fe):
        if not self.expdesc:
            return
        l = len(self.f_names)
        names = [n.name.name for n in self.f_names]
        names_s = names[:]
        names_s.sort()
        if names_s != names:
            log.warn('tab names was not sorted may bug')
        names.append(name)
        names.sort()
        index = names.index(name)
        descname = DescName(self.parent_head)

        descname.name = name
        wname = Rva(self.parent_head)

        wname.name = descname
        woffset = Rva(self.parent_head)
        woffset.rva = rva
        wordinal = Ordinal(self.parent_head)
        #func is append to list
        wordinal.ordinal = len(self.f_address)
        self.f_address.append(woffset)
        #self.f_names.insert(index, wname)
        #self.f_nameordinals.insert(index, wordinal)
        self.f_names.insert(index, wname)
        self.f_nameordinals.insert(index, wordinal)
        self.expdesc.numberofnames+=1
        self.expdesc.numberoffunctions+=1

    def get_funcrva(self, f_str):
        if not self.expdesc:
            return None
        for i, f in enumerate(self.f_names):
            if f_str != f.name.name:
                continue
            o = self.f_nameordinals[i].ordinal
            rva = self.f_address[o].rva
            return rva
        return None

    def get_funcvirt(self, f):
        rva = self.get_funcrva(f)
        if rva==None:
            return
        return self.parent_head.rva2virt(rva)


class Delaydesc_e(CStruct):
    _fields = [ ("attrs","u32"),
                ("name","u32"),
                ("hmod","u32"),
                ("firstthunk","u32"),
                ("originalfirstthunk","u32"),
                ("boundiat","u32"),
                ("unloadiat","u32"),
                ("timestamp","u32"),
              ]

class DirDelay(CStruct):
    _fields = [ ("delaydesc", (lambda c, s, of:c.gete(s, of),
                               lambda c, value:c.sete(value)))]

    def gete(self, s, of):
        if not of:
            return [], of
        of = self.parent_head.rva2off(of)
        out = struct_array(self, s, of, Delaydesc_e)
        if self.parent_head._wsize == 32:
            mask_ptr = 0x80000000
        elif self.parent_head._wsize == 64:
            mask_ptr = 0x8000000000000000L

        parent = self.parent_head
        for i, d in enumerate(out):
            isfromva = (d.attrs & 1) == 0
            if isfromva:
                isfromva = lambda x:parent.virt2rva(x)
            else:
                isfromva = lambda x:x
            d.dlldescname = DescName.unpack(s, isfromva(d.name),
                                            self.parent_head)
            if d.originalfirstthunk:
                d.originalfirstthunks = struct_array(self, s,
                                                     self.parent_head.rva2off(isfromva(d.originalfirstthunk)),
                                                     Rva)
            else:
                d.originalfirstthunks

            if d.firstthunk:
                d.firstthunks = struct_array(self, s,
                                             self.parent_head.rva2off(isfromva(d.firstthunk)),
                                             Rva)
            else:
                d.firstthunk = None

            d.impbynames = []
            if d.originalfirstthunk and self.parent_head.rva2off(isfromva(d.originalfirstthunk)):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                print  ValueError("no thunk in delay dir!! ")
                return
            for i in xrange(len(tmp_thunk)):
                if tmp_thunk[i].rva&mask_ptr == 0:
                    n = ImportByName.unpack(s,
                                            self.parent_head.rva2off(isfromva(tmp_thunk[i].rva)),
                                            self.parent_head)
                    d.impbynames.append(n)
                else:
                    d.impbynames.append(isfromva(tmp_thunk[i].rva&(mask_ptr-1)))
                    #print repr(d[-1])
                    #raise ValueError('XXX to check')
        return out, of

    def sete(self, v):
        c = "".join([str(x) for x in v])+"\x00"*(4*8) #DelayDesc_e
        return c


    def __len__(self):
        l = (len(self.delaydesc)+1)*(4*8) #DelayDesc_e
        for i, d in enumerate(self.delaydesc):
            l+=len(d.dlldescname)
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                l+=(len(d.originalfirstthunks)+1)*self.parent_head._wsize/8 #Rva size
            if d.firstthunk:
                l+=(len(d.firstthunks)+1)*self.parent_head._wsize/8 #Rva size
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            """
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            """
            for i, imp in enumerate(d.impbynames):
                if isinstance(imp, ImportByName):
                    l+=len(imp)
        return l

    def set_rva(self, rva, size = None):
        self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_DELAY_IMPORT].rva = rva
        if not size:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_DELAY_IMPORT].size= len(self)
        else:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_DELAY_IMPORT].size= size
        rva+=(len(self.delaydesc)+1)*(4*8) #DelayDesc_e
        parent = self.parent_head
        for i, d in enumerate(self.delaydesc):
            isfromva = (d.attrs & 1) == 0
            if isfromva:
                isfromva = lambda x:self.parent_head.rva2virt(x)
            else:
                isfromva = lambda x:x

            d.name = isfromva(rva)
            rva+=len(d.dlldescname)
            if d.originalfirstthunk:# and self.parent_head.rva2off(d.originalfirstthunk):
                d.originalfirstthunk = isfromva(rva)
                rva+=(len(d.originalfirstthunks)+1)*self.parent_head._wsize/8 # rva size
            #XXX rva fthunk not patched => fun addr
            #if d.firstthunk:
            #    d.firstthunk = rva
            #    rva+=(len(d.firstthunks)+1)*pe.Rva._size
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            for i, imp in enumerate(d.impbynames):
                if isinstance(imp, ImportByName):
                    tmp_thunk[i].rva = isfromva(rva)
                    rva+=len(imp)

    def build_content(self, c):
        dirdelay = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_DELAY_IMPORT]
        of1 = dirdelay.rva
        if not of1: # No Delay Import
            return
        c[self.parent_head.rva2off(of1)] = str(self)
        for i, d in enumerate(self.delaydesc):
            c[self.parent_head.rva2off(d.name)] = str(d.dlldescname)
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                c[self.parent_head.rva2off(d.originalfirstthunk)] = str(d.originalfirstthunks)
            if d.firstthunk:
                c[self.parent_head.rva2off(d.firstthunk)] = str(d.firstthunks)
            if d.originalfirstthunk and self.parent_head.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            for j, imp in enumerate(d.impbynames):
                if isinstance(imp, ImportByName):
                    c[self.parent_head.rva2off(tmp_thunk[j].rva)] = str(imp)

    def __repr__(self):
        rep = ["<%s>"%self.__class__.__name__]
        for i,s in enumerate(self.delaydesc):
            l = "%2d %-25s %s"%(i, repr(s.dlldescname) ,repr(s))
            rep.append(l)
            for ii, f in enumerate(s.impbynames):
                l = "    %2d %-16s"%(ii, repr(f))
                rep.append(l)
        return "\n".join(rep)

    def add_dlldesc(self, new_dll):
        if self.parent_head._wsize == 32:
            mask_ptr = 0x80000000
        elif self.parent_head._wsize == 64:
            mask_ptr = 0x8000000000000000L
        new_impdesc = []
        of1 = None
        for nd, fcts in new_dll:
            for x in ["attrs","name","hmod","firstthunk","originalfirstthunk","boundiat","unloadiat","timestamp"]:
                if not x in nd:
                    nd[x] = 0
            d = DelayDesc_e(self.parent_head,**nd)
            #d.cstr.__dict__.update(nd)
            if d.firstthunk!=None:
                of1 = d.firstthunk
            elif of1 == None:
                raise "set fthunk"
            else:
                d.firstthunk = of1
            d.dlldescname = DescName(self.parent_head, name = d.name)
            d.originalfirstthunk = True
            d.originalfirstthunks = struct_array(self, None,
                                                 None,
                                                 Rva)
            d.firstthunks = struct_array(self, None,
                                         None,
                                         Rva)

            impbynames = []
            for nf in fcts:
                f = Rva(self.parent_head)
                if type(nf) in [int, long]:
                    f.rva = mask_ptr+nf
                    ibn = None
                elif type(nf) in [str]:
                    f.rva = True
                    ibn = ImportByName(self.parent_head)
                    ibn.name = nf
                    ibn.hint = 0
                else:
                    raise 'unknown func type %s'%str(nf)
                impbynames.append(ibn)
                d.originalfirstthunks.append(f)

                ff = Rva(self.parent_head)
                if ibn != None:
                    ff.rva = 0xDEADBEEF #default func addr
                else:
                    #ord ?XXX?
                    ff.rva = f.rva
                d.firstthunks.append(ff)
                of1+=4
            #for null thunk
            of1+=4
            d.impbynames = impbynames
            new_delaydesc.append(d)
        if not self.delaydesc:
            self.delaydesc = struct_array(self, None,
                                          None,
                                          Delaydesc)
            self.delaydesc.l = new_delaydesc
        else:
            for d in new_delaydesc:
                self.delaydesc.append(d)

    def get_funcrva(self, f):
        for i, d in enumerate(self.delaydesc):
            isfromva = (d.attrs & 1) == 0
            if isfromva:
                isfromva = lambda x:self.parent_head.virt2rva(x)
            else:
                isfromva = lambda x:x
            if d.originalfirstthunk and self.parent_head.rva2off(isfromva(d.originalfirstthunk)):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            if type(f) is str:
                for j, imp in enumerate(d.impbynames):
                    if isinstance(imp, ImportByName):
                        if f == imp.name:
                            return isfromva(d.firstthunk)+j*4
            elif type(f) in (int, long):
                for j, imp in enumerate(d.impbynames):
                    if not isinstance(imp, ImportByName):
                        if isfromva(tmp_thunk[j].rva&0x7FFFFFFF) == f:
                            return isfromva(d.firstthunk)+j*4
            else:
                raise ValueError('unknown func tpye %s'%str(f))
    def get_funcvirt(self, f):
        rva = self.get_funcrva(f)
        if rva==None:
            return
        return self.parent_head.rva2virt(rva)


class Rel(CStruct):
    _fields = [ ("rva","u32"),
                ("size","u32")
                ]

class Reloc(CStruct):
    _fields = [ ("rel",(lambda c, s, of:c.gete(s, of),
                        lambda c, value:c.sete(value))) ]
    def gete(self, s, of):
        rel = struct.unpack('H', s[of:of+2])[0]
        return (rel>>12, rel&0xfff), of+2
    def sete(self, value):
        return struct.pack('H', (value[0]<<12) | value[1])
    def __repr__(self):
        return '<%d %d>'%(self.rel[0], self.rel[1])

class DirReloc(CStruct):
    _fields = [ ("reldesc", (lambda c, s, of:c.gete(s, of),
                             lambda c, value:c.sete(value)))]

    def gete(self, s, of):
        if not of:
            return [], of

        of1 = self.parent_head.rva2off(of)
        ofend = of1+self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_BASERELOC].size
        out = []
        while of1 < ofend:
            reldesc = Rel.unpack(s,
                                 of1,
                                 self.parent_head)
            if reldesc.size == 0:
                log.warn('warning null reldesc')
                reldesc.size = len(reldesc)
                break
            of2 = of1 + len(reldesc)
            reldesc.rels = struct_array(self, s,
                                        of2,
                                        Reloc,
                                        (reldesc.size-len(reldesc))/2) # / Reloc size

            reldesc.patchrel = False
            out.append(reldesc)
            of1+=reldesc.size
        return out, of

    def sete(self, v):
        rep = []
        for n in v:
            rep.append(str(n))
            rep.append(str(n.rels))
        return "".join(rep)

    def set_rva(self, rva, size = None):
        if not self.reldesc:
            return
        self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_BASERELOC].rva = rva
        if not size:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_BASERELOC].size= len(self)
        else:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_BASERELOC].size= size

    def build_content(self, c):
        dirrel = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_BASERELOC]
        dirrel.size  = len(self)
        of1 = dirrel.rva
        if not self.reldesc: # No Reloc
            return
        c[self.parent_head.rva2off(of1)] = str(self)

    def __len__(self):
        if not self.reldesc:
            return 0
        l = 0
        for n in self.reldesc:
            l+=n.size
        return l

    def __str__(self):
        rep = []
        for n in self.reldesc:
            rep.append(str(n))
            rep.append(str(n.rels))
        return "".join(rep)


    def __repr__(self):
        rep = ["<%s>"%self.__class__.__name__]
        if not self.reldesc:
            return "\n".join(rep)
        for i, n in enumerate(self.reldesc):
            l = "%2d %s"%(i, repr(n) )
            rep.append(l)
            """
            #display too many lines...
            for ii, m in enumerate(n.rels):
                l = "\t%2d %s"%(ii, repr(m) )
                rep.append(l)
            """
            l = "\t%2d rels..."%(len(n.rels))
            rep.append(l)
        return "\n".join(rep)

    def add_reloc(self, rels, rtype = 3, patchrel = True):
        dirrel = self.parent_head.NThdr.optentries[pe.DIRECTORY_ENTRY_BASERELOC]
        if not rels:
            return
        rels.sort()
        all_base_ad = set([x & 0xFFFFF000 for x in rels])
        all_base_ad = list(all_base_ad)
        all_base_ad.sort()
        rels_by_base = defaultdict(list)
        while rels:
            r = rels.pop()
            if r >= all_base_ad[-1]:
                rels_by_base[all_base_ad[-1]].append(r)
            else:
                all_base_ad.pop()
                rels_by_base[all_base_ad[-1]].append(r)
        rels_by_base = [x for x in rels_by_base.items()]
        rels_by_base.sort()
        for o_init, rels in rels_by_base:
            #o_init = rels[0]&0xFFFFF000
            offsets = struct_array(self, None, None, Reloc, 0)
            for o in rels:
                if (o&0xFFFFF000) !=o_init:
                    raise "relocs must be in same range"
                r = Reloc(self.parent_head)
                r.rel = (rtype, o-o_init)
                #print repr(r.rel)
                offsets.append(r)
            while len(offsets) &3:
                r = Reloc(self.parent_head)
                r.rel = (0, 0)
                offsets.append(r)
            reldesc = Reloc(self.parent_head)
            reldesc.rva = o_init
            reldesc.size = (len(offsets)*2+8)
            reldesc.rels = offsets
            reldesc.patchrel = patchrel
            if not self.reldesc:
                self.reldesc = []
            self.reldesc.append(reldesc)
            dirrel.size+=reldesc.size

    def del_reloc(self, taboffset):
        if not self.reldesc:
            return
        for rel in self.reldesc:
            of1 = rel.rva
            i = 0
            while i < len(rel.rels):
                r = rel.rels[i]
                if r.rel[0] != 0 and r.rel[1]+of1 in taboffset:
                    print 'del reloc', hex(r.rel[1]+of1)
                    del rel.rels[i]
                    rel.size-=Reloc._size
                else:
                    i+=1


class DirRes(CStruct):
    _fields = [ ("resdesc", (lambda c, s, of:c.gete(s, of),
                             lambda c, value:c.sete(value)))]

    def gete(self, s, of):
        if not of:
            return [], of
        of1 = self.parent_head.rva2off(of)
        resdesc = ResDesc_e.unpack(s,
                                   of1,
                                   self.parent_head)

        nbr = resdesc.numberofnamedentries + resdesc.numberofidentries
        if 1:#try:
            resdesc.resentries = struct_array(self, s,
                                              of1 + len(resdesc),
                                              ResEntry,
                                              nbr)
        if 0:#except:
            log.warning('cannot parse resources')
            resdesc.resentries = struct_array(self, s,
                                              of1 + len(resdesc),
                                              ResEntry,
                                              0)
        dir_todo = {of1:resdesc}
        dir_done = {}
        while dir_todo:
            of1, my_dir = dir_todo.popitem()
            dir_done[of1] = my_dir
            for e in my_dir.resentries:
                of1 = e.offsettosubdir
                if not of1:
                    #data dir
                    of1 = e.offsettodata
                    data = ResDataEntry.unpack(s,
                                               self.parent_head.rva2off(of1),
                                               self.parent_head)
                    of1 = data.offsettodata
                    c =  StrPatchwork()
                    c[0] = self.parent_head.drva[of1:of1+data.size]
                    data.s = c
                    e.data = data
                    continue
                #subdir
                if of1 in dir_done:
                    log.warn('warning recusif subdir')
                    fdds
                    continue
                subdir = ResDesc_e.unpack(s,
                                          self.parent_head.rva2off(of1),
                                          self.parent_head)
                nbr = subdir.numberofnamedentries + subdir.numberofidentries
                subdir.resentries = struct_array(self, s,
                                                 self.parent_head.rva2off(of1 + len(subdir)),
                                                 ResEntry,
                                                 nbr)

                e.subdir = subdir
                dir_todo[of1] = e.subdir
        return resdesc, of

    def build_content(self, c):
        if not self.resdesc:
            return
        of1 = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva
        c[self.parent_head.rva2off(of1)] = str(self.resdesc)
        dir_todo = {self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva:self.resdesc}
        dir_done = {}
        while dir_todo:
            of1, my_dir = dir_todo.popitem()
            dir_done[of1] = my_dir
            c[self.parent_head.rva2off(of1)] = str(my_dir)
            c[self.parent_head.rva2off(of1+len(my_dir))] = str(my_dir.resentries)
            for e in my_dir.resentries:
                if e.name_s:
                    c[self.parent_head.rva2off(e.name)] = str(e.name_s)
                of1 = e.offsettosubdir
                if not of1:
                    c[self.parent_head.rva2off(e.offsettodata)] = str(e.data)
                    c[self.parent_head.rva2off(e.data.offsettodata)] = str(e.data.s)
                    continue
                dir_todo[of1] = e.subdir


    def __len__(self):
        l = 0
        if not self.resdesc:
            return l
        dir_todo = [self.resdesc]
        dir_done = []
        while dir_todo:
            my_dir = dir_todo.pop()
            if not my_dir in dir_done:
                dir_done.append(my_dir)
            else:
                raise 'recursif dir'
            l+=len(my_dir)
            l+=len(my_dir.resentries)*8 # ResEntry size
            for e in my_dir.resentries:
                if not e.offsettosubdir:
                    continue
                if not e.subdir in dir_todo:
                    dir_todo.append(e.subdir)
                else:
                    raise "recursive dir"
                    fds
                    continue

        dir_todo = dir_done
        while dir_todo:
            my_dir = dir_todo.pop()
            for e in my_dir.resentries:
                if e.name_s:
                    l+=len(e.name_s)
                of1 = e.offsettosubdir
                if not of1:
                    l+=4*4 # WResDataEntry size
                    #XXX because rva may be even rounded
                    l+=1
                    l+=e.data.size
                    continue
        return l

    def set_rva(self, rva, size = None):
        if not self.resdesc:
            return
        self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva = rva
        if not size:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].size = len(self)
        else:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].size = size
        dir_todo = [self.resdesc]
        dir_done = {}
        while dir_todo:
            my_dir = dir_todo.pop()
            dir_done[rva] = my_dir
            rva+=len(my_dir)
            rva+=len(my_dir.resentries)*8 # ResEntry size
            for e in my_dir.resentries:
                if not e.offsettosubdir:
                    continue
                if not e.subdir in dir_todo:
                    dir_todo.append(e.subdir)
                else:
                    raise "recursive dir"
                    fds
                    continue
        dir_todo = dir_done
        dir_inv = dict(map(lambda x:(x[1], x[0]), dir_todo.items()))
        while dir_todo:
            rva_tmp, my_dir = dir_todo.popitem()
            for e in my_dir.resentries:
                if e.name_s:
                    e.name = rva
                    rva+=len(e.name_s)
                of1 = e.offsettosubdir
                if not of1:
                    e.offsettodata = rva
                    rva+=4*4 # ResDataEntry size
                    #XXX menu rsrc must be even aligned?
                    if rva%2:rva+=1
                    e.data.offsettodata = rva
                    rva+=e.data.size
                    continue
                e.offsettosubdir = dir_inv[e.subdir]

    def __repr__(self):
        rep = ["<%s>"%(self.__class__.__name__ )]
        if not self.resdesc:
            return "\n".join(rep)
        dir_todo = [self.resdesc]
        out = []
        index = -1
        while dir_todo:
            a = dir_todo.pop(0)
            if isinstance(a, int):
                index+=a
            elif isinstance(a, ResDesc_e):
                #out.append((index, repr(a)))
                dir_todo=[1]+a.resentries.l+[-1]+dir_todo
            elif isinstance(a, ResEntry):
                if a.offsettosubdir:
                    out.append((index, repr(a)))
                    dir_todo = [a.subdir]+dir_todo
                else:
                    out.append((index, repr(a)))
            else:
                raise "zarb"
        for i, c in out:
            rep.append(' '*4*i+c)
        return "\n".join(rep)

class Ordinal(CStruct):
    _fields = [ ("ordinal","u16"),
                ]



class ResDesc_e(CStruct):
    _fields = [ ("characteristics","u32"),
                ("timestamp","u32"),
                ("majorv","u16"),
                ("minorv","u16"),
                ("numberofnamedentries","u16"),
                ("numberofidentries","u16")
              ]

class SUnicode(CStruct):
    _fields = [ ("length", "u16"),
                ("value", (lambda c, s, of:c.gets(s, of),
                           lambda c, value:c.sets(value)))
                ]
    def gets(self, s, of):
        v = s[of:of+self.length*2]
        return v, of+self.length
    def sets(self, value):
        return struct.pack('H', self.length)+self.value

class ResEntry(CStruct):
    _fields = [ ("name",(lambda c, s, of:c.getn(s, of),
                         lambda c, value:c.setn(value))),
                ("offsettodata",(lambda c, s, of:c.geto(s, of),
                                 lambda c, value:c.seto(value)))
                ]

    def getn(self, s, of):
        self.data = None
        #of = self.parent_head.rva2off(of)
        name = struct.unpack('I', s[of:of+4])[0]
        self.name_s = None
        if name & 0x80000000:
            name = (name & 0x7FFFFFFF) + self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva # XXX res rva??
            name &= 0x7FFFFFFF
            self.name_s = SUnicode.unpack(s,
                                          self.parent_head.rva2off(name),
                                          self.parent_head)
        return name, of+4

    def setn(self, v):
        name = v
        if self.name_s:
            name=(self.name-self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva)+0x80000000L
        return struct.pack('I', name)

    def geto(self, s, of):
        self.offsettosubdir = None
        offsettodata_o = struct.unpack('I', s[of:of+4])[0]
        offsettodata = (offsettodata_o & 0x7FFFFFFF) + self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva #XXX res rva??
        if offsettodata_o & 0x80000000:
            self.offsettosubdir = offsettodata
        return offsettodata, of+4
    def seto(self, v):
        offsettodata = v - self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva
        if self.offsettosubdir:
            offsettodata=(self.offsettosubdir-self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva)+0x80000000
        return struct.pack('I', offsettodata)

    def __repr__(self):
        if self.name_s:
            nameid = "%s"%repr(self.name_s)
        else:
            if self.name in RT:# and not self.offsettosubdir:
                nameid = "ID %s"%RT[self.name]
            else:
                nameid = "ID %d"%self.name
        if self.offsettosubdir:
            offsettodata = "subdir: %x"%self.offsettosubdir
        else:
            offsettodata = "data: %x"%self.offsettodata
        return "<%s %s>"%(nameid, offsettodata)



class ResDataEntry(CStruct):
    _fields = [ ("offsettodata","u32"),
                ("size","u32"),
                ("codepage","u32"),
                ("reserved","u32"),
                ]


class Symb(CStruct):
    _fields = [ ("name","8s"),
                ("res1","u32"),
                ("res2","u32"),
                ("res3","u16")]


DIRECTORY_ENTRY_EXPORT           = 0
DIRECTORY_ENTRY_IMPORT           = 1
DIRECTORY_ENTRY_RESOURCE         = 2
DIRECTORY_ENTRY_EXCEPTION        = 3
DIRECTORY_ENTRY_SECURITY         = 4
DIRECTORY_ENTRY_BASERELOC        = 5
DIRECTORY_ENTRY_DEBUG            = 6
DIRECTORY_ENTRY_COPYRIGHT        = 7
DIRECTORY_ENTRY_GLOBALPTR        = 8
DIRECTORY_ENTRY_TLS              = 9
DIRECTORY_ENTRY_LOAD_CONFIG      = 10
DIRECTORY_ENTRY_BOUND_IMPORT     = 11
DIRECTORY_ENTRY_IAT              = 12
DIRECTORY_ENTRY_DELAY_IMPORT     = 13
DIRECTORY_ENTRY_COM_DESCRIPTOR   = 14
DIRECTORY_ENTRY_RESERVED         = 15


RT_CURSOR                        = 1
RT_BITMAP                        = 2
RT_ICON                          = 3
RT_MENU                          = 4
RT_DIALOG                        = 5
RT_STRING                        = 6
RT_FONTDIR                       = 7
RT_FONT                          = 8
RT_ACCELERATOR                   = 9
RT_RCDATA                        = 10
RT_MESSAGETABLE                  = 11
RT_GROUP_CURSOR                  = 12
RT_GROUP_ICON                    = 14
RT_VERSION                       = 16
RT_DLGINCLUDE                    = 17
RT_PLUGPLAY                      = 19
RT_VXD                           = 20
RT_ANICURSOR                     = 21
RT_ANIICON                       = 22
RT_HTML                          = 23
RT_MANIFEST                      = 24


RT = {
    RT_CURSOR       :"RT_CURSOR",
    RT_BITMAP       :"RT_BITMAP",
    RT_ICON         :"RT_ICON",
    RT_MENU         :"RT_MENU",
    RT_DIALOG       :"RT_DIALOG",
    RT_STRING       :"RT_STRING",
    RT_FONTDIR      :"RT_FONTDIR",
    RT_FONT         :"RT_FONT",
    RT_ACCELERATOR  :"RT_ACCELERATOR",
    RT_RCDATA       :"RT_RCDATA",
    RT_MESSAGETABLE :"RT_MESSAGETABLE",
    RT_GROUP_CURSOR :"RT_GROUP_CURSOR",
    RT_GROUP_ICON   :"RT_GROUP_ICON",
    RT_VERSION      :"RT_VERSION",
    RT_DLGINCLUDE   :"RT_DLGINCLUDE",
    RT_PLUGPLAY     :"RT_PLUGPLAY",
    RT_VXD          :"RT_VXD",
    RT_ANICURSOR    :"RT_ANICURSOR",
    RT_ANIICON      :"RT_ANIICON",
    RT_HTML         :"RT_HTML",
    RT_MANIFEST     :"RT_MANIFEST",
    }



if __name__ == "__main__":
    import sys
    PEFILE = sys.stdin
    if len(sys.argv) > 1:
        PEFILE = open(sys.argv[1])
    dhdr = Doshdr._from_file(PEFILE)
    print repr(dhdr)
    print "sigMZ:", hex(dhdr.magic),hex(len(dhdr))

    PEFILE.seek(dhdr.lfanew)
    nthdr = NThdr._from_file(PEFILE)
    print repr(nthdr)
    print "sigPE:", hex(nthdr.signature),hex(len(nthdr))

    PEFILE.seek(dhdr.lfanew+len(nthdr))
    opthdr = Opthdr._from_file(PEFILE)
    print repr(opthdr)
    print "sigHDR:",hex(opthdr.magic),hex(len(opthdr))

    PEFILE.seek(dhdr.lfanew+len(nthdr)+len(opthdr))
    for i in xrange(opthdr.numberofrvaandsizes):
        optehdr = Optehdr._from_file(PEFILE)
        print repr(optehdr)
        


    print hex(dhdr.lfanew+len(nthdr)+nthdr.sizeofoptionalheader)
    PEFILE.seek(dhdr.lfanew+len(nthdr)+nthdr.sizeofoptionalheader)
    for i in xrange(nthdr.numberofsections):
        #PEFILE.seek(dhdr.lfanew+len(nthdr))
        shdr = Shdr._from_file(PEFILE)
        print repr(shdr)
        print "name:",shdr.name,hex(len(shdr))
