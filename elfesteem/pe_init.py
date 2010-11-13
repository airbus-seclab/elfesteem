#! /usr/bin/env python

import struct, array
import pe
from strpatchwork import StrPatchwork
import logging
log = logging.getLogger("peparse")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)


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


class WDoshdr(StructWrapper):
    wrapped = pe.Doshdr

class WNTsig(StructWrapper):
    wrapped = pe.NTsig

class WCoffhdr(StructWrapper):
    wrapped = pe.Coffhdr

class NTsig:
    def __init__(self, parent, of1 = None):
        self.parent = parent
        if of1 == None: # No Coffhdr
            self.NTsig = pe.NTsig()
            return
        of2 = of1+pe.NTsig._size
        strntsig = parent[of1:of2]
        self.NTsig = pe.NTsig(strntsig)

    def __str__(self):
        return str(self.NTsig)
    
    def __repr__(self):
        return repr(self.NTsig)



class Coffhdr:
    def __init__(self, parent, of1 = None):
        self.parent = parent
        if of1 == None: # No Coffhdr
            self.Coffhdr = pe.Coffhdr()
            return
        of2 = of1+pe.Coffhdr._size
        strcoffhdr = parent[of1:of2]
        self.Coffhdr = pe.Coffhdr(strcoffhdr)

    def __str__(self):
        return str(self.Coffhdr)
    
    def __repr__(self):
        return repr(self.Coffhdr)

class WOptehdr(StructWrapper):
    wrapped = pe.Optehdr
    _size = pe.Optehdr._size

class WSymb(StructWrapper):
    wrapped = pe.Symb
    _size = pe.Symb._size


class Opthdr:
    def __init__(self, parent, of1 = None):
        self.parent = parent
        if of1 == None or self.parent.Coffhdr.Coffhdr.sizeofoptionalheader == 0: # No Coffhdr
            self.Opthdr = pe.Opthdr()
            self.Optehdr = ClassArray(self.parent, WOptehdr, None, 16)
            return
        of2 = of1+pe.Opthdr._size
        stropthdr = parent[of1:of2]
        self.Opthdr = pe.Opthdr(stropthdr)
        numberofrva = self.Opthdr.numberofrvaandsizes
        if self.parent.Coffhdr.Coffhdr.sizeofoptionalheader<numberofrva*pe.Optehdr._size+pe.Opthdr._size:
            #numberofrva = (self.parent.Coffhdr.Coffhdr.sizeofoptionalheader-pe.Opthdr._size)/pe.Optehdr._size
            log.warn('bad number of rva.. using default %d'%numberofrva)
            numberofrva = 0x10

        self.Optehdr = ClassArray(self.parent, WOptehdr, of2, numberofrva)
    def __str__(self):
        return str(self.Opthdr)+str(self.Optehdr)

    def __repr__(self):
        return "<Opthdr>\n"+repr(self.Optehdr)



class WShdr(StructWrapper):
    wrapped = pe.Shdr
    _size = pe.Shdr._size

class WImpDesc(StructWrapper):
    wrapped = pe.ImpDesc
    _size = pe.ImpDesc._size

class WDelayDesc(StructWrapper):
    wrapped = pe.DelayDesc
    _size = pe.DelayDesc._size

class WRva(StructWrapper):
    wrapped = pe.Rva
    _size = pe.Rva._size

class WOrdinal(StructWrapper):
    wrapped = pe.Ordinal
    _size = pe.Ordinal._size

class WResEntry(StructWrapper):
    wrapped = pe.ResEntry
    _size = pe.ResEntry._size


#if not num => null class terminated
class ClassArray:
    def __init__(self, parent, cls, of1, num = None):
        self.parent = parent
        self.cls = cls
        self.list = []
        self.null_str = '\x00'*self.cls._size
        self.num = num
        if not of1:
            if num!=None:
                self.list = [self.cls(parent, self.null_str) for x in xrange(num)]
            return
        index = -1
        while True:
            index+=1
            of2 = of1+self.cls._size
            cls_str = self.parent[of1:of2]
            if num==None:
                if cls_str == self.null_str:
                    break
            elif index==num:
                break
            self.list.append(self.cls(parent, cls_str))
            of1 = of2
    @classmethod            
    def from_cls(cls, parent, clst, num = None):
        cls = cls(parent, clst, None, num)
        cls.list = []
        return cls
    
    def __str__(self):
        c = []
        for s in self.list:
            c.append(str(s))
        if self.num==None:
            c.append(self.null_str)
        return "".join(c)
    def __repr__(self):
        rep = []
        for i,s in enumerate(self.list):
            l = ("%2i " % i)+ repr(s) + s.__class__.__name__
            rep.append(l)
        return "\n".join(rep)
    def __getitem__(self, item):
        return self.list.__getitem__(item)
    def __delitem__(self, item):
        self.list.__delitem__(item)
        if self.num!=None:
            self.num = len(self.list)
            
    def insert(self, index, o):
        self.list.insert(index, o)
        if self.num!=None:
            self.num+=1
    def __len__(self):
        return len(self.list)

    def append(self, a):
        self.list.append(a)
        if self.num!=None:
            self.num+=1
            
        
class SHList:
    def __init__(self, parent, of1 = None):
        self.parent = parent
        if of1 == None: # No shlist
            self.shlist = ClassArray(self.parent, WShdr, None, 0)
            return
        coffhdr = self.parent.Coffhdr.Coffhdr
        self.shlist = ClassArray(self.parent, WShdr, of1, coffhdr.numberofsections)
        filealignment = self.parent.Opthdr.Opthdr.filealignment
        for s in self.shlist:
            if self.parent.loadfrommem:
                s.offset = s.addr
            if filealignment ==0:
                raw_off = s.offset
            else:
                raw_off = filealignment*(s.offset/filealignment)
            if raw_off != s.offset:
                log.warn('unaligned raw section!')
            s.data = StrPatchwork()
            s.data[0] = self.parent[raw_off:raw_off+s.rawsize]

    def __getitem__(self, item):
        return self.shlist[item]
    def __len__(self):
        return len(self.shlist)
    def __str__(self):
        c = []
        for s in self.shlist:
            c.append(str(s))
        return "".join(c)
    def __repr__(self):
        rep = ["#  section         offset   size   addr     flags   rawsize  "]
        for i,s in enumerate(self.shlist):
            l = "%-15s"%s.name.strip('\x00')
            l+="%(offset)08x %(size)06x %(addr)08x %(flags)08x %(rawsize)08x" % s
            l = ("%2i " % i)+ l
            rep.append(l)
        return "\n".join(rep)

    def add_section(self, name="default", data = "", **args):
        s_align = self.parent.Opthdr.Opthdr.sectionalignment
        s_align = max(0x1000, s_align)

        f_align = self.parent.Opthdr.Opthdr.filealignment
        f_align = max(0x200, f_align)
        size = len(data)
        rawsize = len(data)
        if len(self.shlist):
            addr = self.shlist[-1].addr+self.shlist[-1].size
            s_last = self.shlist[0]
            for s in self.shlist:
                if s_last.offset+s_last.rawsize<s.offset+s.rawsize:
                    s_last = s
    
                
            offset = s_last.offset+s_last.rawsize
        else:
            offset = self.parent.Doshdr.lfanew+pe.NTsig._size+pe.Coffhdr._size+self.parent.Coffhdr.Coffhdr.sizeofoptionalheader
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
        s = pe.Shdr(**f)

        if s.rawsize > len(data):
            s.data = s.data+'\x00'*(s.rawsize-len(data))
            s.size = s.rawsize
            
        c = StrPatchwork()
        c[0] = s.data
        s.data = c
    
        s.size = max(s_align, s.size)

        self.shlist.append(s)
        self.parent.Coffhdr.Coffhdr.numberofsections = len(self.shlist)

        l = (s.addr+s.size+(s_align-1))&~(s_align-1)
        self.parent.Opthdr.Opthdr.sizeofimage = l
        return s



    def align_sections(self, f_align = None, s_align = None):
        if f_align == None:
            f_align = self.parent.Opthdr.Opthdr.filealignment
            f_align = max(0x200, f_align)
        if s_align == None:
            s_align = self.parent.Opthdr.Opthdr.sectionalignment
            s_align = max(0x1000, s_align)

        if not self.shlist:
            return

        addr = self.shlist[0].offset
        
        for s in self.shlist:
            raw_off = f_align*((addr+f_align-1)/f_align)
            s.offset = raw_off
            s.rawsize = len(s.data)
            
            addr = raw_off+s.rawsize
            
            
class ImportByName:
    def __init__(self, parent, of1 = None):
        self.parent = parent
        self.of1 = of1
        self.hint = 0
        self.name = None
        if not of1:
            return
        ofname = self.parent.rva2off(of1+2)
        self.hint = struct.unpack('H', self.parent.drva[of1:of1+2])[0]
        self.name = self.parent[ofname:self.parent._content.find('\x00', ofname)]
    def __str__(self):
        return struct.pack('H', self.hint)+ self.name+'\x00'
    def __repr__(self):
        return '<%d, %s>'%(self.hint, self.name)
    def __len__(self):
        return 2+len(self.name)+1

class DescName:
    def __init__(self, parent, of1 = None):
        self.parent = parent
        self.of1 = of1
        self.name = None
        if not of1:
            return
        ofname = self.parent.rva2off(of1)
        self.name = self.parent[ofname:self.parent._content.find('\x00', ofname)]
    def __str__(self):
        return self.name+'\x00'
    def __repr__(self):
        return '<%s>'%(self.name)
    def __len__(self):
        return len(self.name)+1

class Directory(object):
    dirname = 'Default Dir'
    def parse_content(self):
        pass
    def build_content(self, c):
        pass
    def __str__(self):
        return ""
    def __repr__(self):
        return "<%s>"%self.dirname

class Reloc:
    _size = 2
    def __init__(self, parent, s = None):
        self.parent = parent
        self.s = s
        if not s:
            return
        rel = struct.unpack('H', s)[0]
        self.rel = (rel>>12, rel&0xfff)
    def __str__(self):
        return struct.pack('H', (self.rel[0]<<12) | self.rel[1])
    def __repr__(self):
        return '<%d %d>'%(self.rel[0], self.rel[1])
    def __len__(self):
        return self._size


class SUnicode:
    def __init__(self, parent, of1):
        self.parent = parent
        self.of1 = of1
        self.s = None
        self.size = 0
        if not of1:
            return
        of2 = of1+2
        self.size = struct.unpack('H', self.parent.drva[of1:of2])[0]
        self.s = self.parent.drva[of2:of2+self.size*2]
    def __str__(self):
        return struct.pack('H', self.size)+self.s
    def __repr__(self):
        if not self.s:
            return "<>"
        s = self.s[0:-1:2]
        return "<%d %s>"%(self.size, s)
    def __len__(self):
        return 2+self.size*2
        
class ResEntry:
    _size = 8
    def __init__(self, parent, s):
        self.parent = parent
        self.s = s
        if not s:
            return
        self.id, self.name = None, None
        name, offsettodata = struct.unpack('LL', s)
        self.name = name
        self.name_s = None
        self.offsettodata = (offsettodata & 0x7FFFFFFF) + self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_RESOURCE].rva #XXX res rva??
        self.offsettosubdir = None
        self.data = None
        if name & 0x80000000:
            self.name = (name & 0x7FFFFFFF) + self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_RESOURCE].rva #XXX res rva??
            self.name_s = SUnicode(parent, self.name) #XXX res rva??
        if offsettodata & 0x80000000:
            self.offsettosubdir = self.offsettodata
                
        #self.offsettodata = offsettodata
    def __str__(self):
        name = self.name
        offsettodata = self.offsettodata - self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_RESOURCE].rva
        if self.name_s:
            name=(self.name-self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_RESOURCE].rva)+0x80000000L
        if self.offsettosubdir:
            offsettodata=(self.offsettosubdir-self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_RESOURCE].rva)+0x80000000L
        return struct.pack('LL', name, offsettodata)
        
    def __repr__(self):
        if self.name_s:
            nameid = "%s"%repr(self.name_s)
        else:
            if self.name in pe.RT:# and not self.offsettosubdir:
                nameid = "ID %s"%pe.RT[self.name]
            else:
                nameid = "ID %d"%self.name
        if self.offsettosubdir:
            offsettodata = "subdir: %d"%self.offsettosubdir
        else:
            offsettodata = "data: %d"%self.offsettodata
        return "<%s %s %s>"%(nameid, offsettodata, repr(self.data))
    def __len__(self):
        return self._size


class DirDelay(Directory):
    dirname = 'Directory Delay'
    def __init__(self, parent):
        self.parent = parent
        if not len(self.parent.Opthdr.Optehdr):
            self.delaydesc = ClassArray(self.parent, WDelayDesc, None)
            return
        dirdelay = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_DELAY_IMPORT]
        of1 = dirdelay.rva
        if not of1: # No Delay
            self.delaydesc = ClassArray(self.parent, WDelayDesc, None)
            return
        self.delaydesc = ClassArray(self.parent, WDelayDesc, self.parent.rva2off(of1))
        for i, d in enumerate(self.delaydesc):
            d.dlldescname = DescName(self.parent, d.name)
            d.originalfirstthunks = ClassArray(self.parent, WRva, self.parent.rva2off(d.originalfirstthunk))
            d.firstthunks = ClassArray(self.parent, WRva, self.parent.rva2off(d.firstthunk))

            d.impbynames = []
            if d.originalfirstthunk and self.parent.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            for i in xrange(len(tmp_thunk)):
                if tmp_thunk[i].rva&0x80000000 == 0:
                    d.impbynames.append(ImportByName(self.parent, tmp_thunk[i].rva))
                else:
                    d.impbynames.append(tmp_thunk[i].rva&0x7fffffff)

    def build_content(self, c):
        dirdelay = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_DELAY_IMPORT]
        of1 = dirdelay.rva
        if not of1: # No Delay Import
            return
        c[self.parent.rva2off(of1)] = str(self.delaydesc)
        for i, d in enumerate(self.delaydesc):
            c[self.parent.rva2off(d.name)] = str(d.dlldescname)
            if d.originalfirstthunk and self.parent.rva2off(d.originalfirstthunk):
                c[self.parent.rva2off(d.originalfirstthunk)] = str(d.originalfirstthunks)
            if d.firstthunk:
                c[self.parent.rva2off(d.firstthunk)] = str(d.firstthunks)
            if d.originalfirstthunk and self.parent.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            for j, imp in enumerate(d.impbynames):
                if isinstance(imp, ImportByName):
                    c[self.parent.rva2off(tmp_thunk[j].rva)] = str(imp)

    def get_funcrva(self, f):
        for i, d in enumerate(self.delaydesc):
            if d.originalfirstthunk and self.parent.rva2off(d.originalfirstthunk):
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
        return self.parent.rva2virt(rva)
        
    def __str__(self):
        c = []
        for s in self.delaydesc:
            c.append(str(s))
        return "".join(c)

    def __len__(self):
        l = (len(self.delaydesc)+1)*pe.Delaydesc._size
        for i, d in enumerate(self.delaydesc):
            l+=len(d.dlldescname)
            if d.originalfirstthunk and self.parent.rva2off(d.originalfirstthunk):
                l+=(len(d.originalfirstthunks)+1)*pe.Rva._size
            if d.firstthunk:
                l+=(len(d.firstthunks)+1)*pe.Rva._size
            if d.originalfirstthunk and self.parent.rva2off(d.originalfirstthunk):
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
        self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_IMPORT].rva = rva
        if not size:
            self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_IMPORT].size= len(self)
        else:
            self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_IMPORT].size= size
        rva+=(len(self.delaydesc)+1)*pe.Delaydesc._size
        for i, d in enumerate(self.delaydesc):
            d.name = rva
            rva+=len(d.dlldescname)
            if d.originalfirstthunk:# and self.parent.rva2off(d.originalfirstthunk):
                d.originalfirstthunk = rva
                rva+=(len(d.originalfirstthunks)+1)*pe.Rva._size
            #XXX rva fthunk not patched => fun addr
            #if d.firstthunk:
            #    d.firstthunk = rva
            #    rva+=(len(d.firstthunks)+1)*pe.Rva._size
            if d.originalfirstthunk and self.parent.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            
            for i, imp in enumerate(d.impbynames):
                if isinstance(imp, ImportByName):
                    tmp_thunk[i].rva = rva
                    rva+=len(imp)

    def add_dlldesc(self, new_dll):
        new_delaydesc = []
        of1 = None
        for nd, fcts in new_dll:
            d = pe.Delaydesc()
            d.__dict__.update(nd)
            if d.firstthunk!=None:
                of1 = d.firstthunk
            elif of1 == None:
                raise "set fthunk"
            else:
                d.firstthunk = of1
            d.dlldescname = DescName(self.parent)
            d.dlldescname.name = d.name
            d.originalfirstthunk = True
            d.originalfirstthunks = ClassArray.from_cls(self.parent, WRva(self.parent))
            d.firstthunks = ClassArray.from_cls(self.parent, WRva(self.parent))
            impbynames = []
            for nf in fcts:
                f = pe.Rva()
                if type(nf) in [int, long]:
                    f.rva = 0x80000000+nf
                    ibn = None
                elif type(nf) in [str]:
                    f.rva = True
                    ibn = ImportByName(self.parent)
                    ibn.name = nf
                else:
                    raise 'unknown func type %s'%str(nf)
                impbynames.append(ibn)
                d.originalfirstthunks.append(f)

                ff = pe.Rva()
                ff.rva = 0xDEADBEEF #default func addr
                d.firstthunks.append(ff)
                of1+=4
            #for null thunk
            of1+=4
            d.impbynames = impbynames
            new_delaydesc.append(d)
        if not self.delaydesc:
            #(parent, cls_tab, num = None):
            self.delaydesc = ClassArray.from_cls(self.parent, WDelaydesc(self.parent))
            self.delaydesc.list = new_delaydesc
        else:
            for d in new_delaydesc:
                self.delaydesc.append(d)

    def __repr__(self):
        rep = ["<%s>"%self.dirname]
        for i,s in enumerate(self.delaydesc):
            l = "%2d %-25s %s"%(i, repr(s.dlldescname) ,repr(s))
            rep.append(l)
            for ii, f in enumerate(s.impbynames):
                l = "    %2d %-16s"%(ii, repr(f))
                rep.append(l)
        return "\n".join(rep)

class DirImport(Directory):
    dirname = 'Directory Import'
    def __init__(self, parent):
        self.parent = parent
        if not len(self.parent.Opthdr.Optehdr):
            self.impdesc = ClassArray(self.parent, WImpDesc, None)
            return
        dirimp = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_IMPORT]
        of1 = dirimp.rva
        if not of1: # No Import
            self.impdesc = ClassArray(self.parent, WImpDesc, None)
            return
        self.impdesc = ClassArray(self.parent, WImpDesc, self.parent.rva2off(of1))
        for i, d in enumerate(self.impdesc):
            d.dlldescname = DescName(self.parent, d.name)
            d.originalfirstthunks = ClassArray(self.parent, WRva, self.parent.rva2off(d.originalfirstthunk))
            d.firstthunks = ClassArray(self.parent, WRva, self.parent.rva2off(d.firstthunk))

            d.impbynames = []
            if d.originalfirstthunk and self.parent.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            for i in xrange(len(tmp_thunk)):
                if tmp_thunk[i].rva&0x80000000 == 0:
                    try:
                        n = ImportByName(self.parent, tmp_thunk[i].rva)
                    except:
                        log.warning('cannot import from add %s'%str(tmp_thunk[i].rva))
                        n = 0
                    d.impbynames.append(n)
                else:
                    d.impbynames.append(tmp_thunk[i].rva&0x7fffffff)

    
    def build_content(self, c):
        dirimp = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_IMPORT]
        of1 = dirimp.rva
        if not of1: # No Import
            return
        c[self.parent.rva2off(of1)] = str(self.impdesc)
        for i, d in enumerate(self.impdesc):
            c[self.parent.rva2off(d.name)] = str(d.dlldescname)
            if d.originalfirstthunk and self.parent.rva2off(d.originalfirstthunk):
                c[self.parent.rva2off(d.originalfirstthunk)] = str(d.originalfirstthunks)
            if d.firstthunk:
                c[self.parent.rva2off(d.firstthunk)] = str(d.firstthunks)
            if d.originalfirstthunk and self.parent.rva2off(d.originalfirstthunk):
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            for j, imp in enumerate(d.impbynames):
                if isinstance(imp, ImportByName):
                    c[self.parent.rva2off(tmp_thunk[j].rva)] = str(imp)

    def get_funcrva(self, f):
        for i, d in enumerate(self.impdesc):
            if d.originalfirstthunk and self.parent.rva2off(d.originalfirstthunk):
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
        return self.parent.rva2virt(rva)
        
    def __str__(self):
        c = []
        for s in self.impdesc:
            c.append(str(s))
        return "".join(c)

    def __len__(self):
        l = (len(self.impdesc)+1)*pe.ImpDesc._size
        for i, d in enumerate(self.impdesc):
            l+=len(d.dlldescname)
            if d.originalfirstthunk and self.parent.rva2off(d.originalfirstthunk):
                l+=(len(d.originalfirstthunks)+1)*pe.Rva._size
            if d.firstthunk:
                l+=(len(d.firstthunks)+1)*pe.Rva._size
            if d.originalfirstthunk and self.parent.rva2off(d.originalfirstthunk):
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
        self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_IMPORT].rva = rva
        if not size:
            self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_IMPORT].size= len(self)
        else:
            self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_IMPORT].size= size
        rva+=(len(self.impdesc)+1)*pe.ImpDesc._size
        for i, d in enumerate(self.impdesc):
            d.name = rva
            rva+=len(d.dlldescname)
            if d.originalfirstthunk:# and self.parent.rva2off(d.originalfirstthunk):
                d.originalfirstthunk = rva
                rva+=(len(d.originalfirstthunks)+1)*pe.Rva._size
            #XXX rva fthunk not patched => fun addr
            #if d.firstthunk:
            #    d.firstthunk = rva
            #    rva+=(len(d.firstthunks)+1)*pe.Rva._size
            if d.originalfirstthunk and d.firstthunk:
                if isinstance(d.originalfirstthunk, ClassArray):
                    tmp_thunk = d.originalfirstthunks
                elif isinstance(d.firstthunks, ClassArray):
                    tmp_thunk = d.firstthunks
                else:
                    fdsf
            elif d.originalfirstthunk:# and self.parent.rva2off(d.originalfirstthunk):
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

    def add_dlldesc(self, new_dll):
        new_impdesc = []
        of1 = None
        for nd, fcts in new_dll:
            d = pe.ImpDesc()
            d.__dict__.update(nd)
            if d.firstthunk!=None:
                of1 = d.firstthunk
            elif of1 == None:
                raise "set fthunk"
            else:
                d.firstthunk = of1
            d.dlldescname = DescName(self.parent)
            d.dlldescname.name = d.name
            d.originalfirstthunk = True
            d.originalfirstthunks = ClassArray.from_cls(self.parent, WRva(self.parent))
            d.firstthunks = ClassArray.from_cls(self.parent, WRva(self.parent))
            impbynames = []
            for nf in fcts:
                f = pe.Rva()
                if type(nf) in [int, long]:
                    f.rva = 0x80000000+nf
                    ibn = None
                elif type(nf) in [str]:
                    f.rva = True
                    ibn = ImportByName(self.parent)
                    ibn.name = nf
                else:
                    raise 'unknown func type %s'%str(nf)
                impbynames.append(ibn)
                d.originalfirstthunks.append(f)

                ff = pe.Rva()
                if ibn:
                    ff.rva = 0xDEADBEEF #default func addr
                else:
                    #ord ?XXX?
                    ff.rva = f.rva
                d.firstthunks.append(ff)
                of1+=4
            #for null thunk
            of1+=4
            d.impbynames = impbynames
            new_impdesc.append(d)
        if not self.impdesc:
            #(parent, cls_tab, num = None):
            self.impdesc = ClassArray.from_cls(self.parent, WImpDesc(self.parent))
            self.impdesc.list = new_impdesc
        else:
            for d in new_impdesc:
                self.impdesc.append(d)

    def __repr__(self):
        rep = ["<%s>"%self.dirname]
        for i,s in enumerate(self.impdesc):
            l = "%2d %-25s %s"%(i, repr(s.dlldescname) ,repr(s))
            rep.append(l)
            for ii, f in enumerate(s.impbynames):
                l = "    %2d %-16s"%(ii, repr(f))
                rep.append(l)
        return "\n".join(rep)
        

class DirExport(Directory):
    dirname = 'Directory Export'
    def __init__(self, parent):
        self.parent = parent
        if not len(self.parent.Opthdr.Optehdr):
            return
        direxp = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_EXPORT]
        self.expdesc = None
        of1 = direxp.rva
        if not of1: # No Export
            return
        of2 = of1+pe.ExpDesc._size
        self.expdesc = pe.ExpDesc(self.parent.drva[of1:of2])
        self.dlldescname = DescName(self.parent, self.expdesc.name)
        self.f_address = ClassArray(self.parent, WRva, self.parent.rva2off(self.expdesc.addressoffunctions), self.expdesc.numberoffunctions)
        self.f_names = ClassArray(self.parent, WRva, self.parent.rva2off(self.expdesc.addressofnames), self.expdesc.numberofnames)
        self.f_nameordinals = ClassArray(self.parent, WOrdinal, self.parent.rva2off(self.expdesc.addressofordinals), self.expdesc.numberofnames)
        for n in self.f_names:
            n.name = DescName(self.parent, n.rva)


    def build_content(self, c):
        direxp = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_EXPORT]
        of1 = direxp.rva
        if not self.expdesc: # No Export
            return
        c[self.parent.rva2off(of1)] = str(self.expdesc)
        c[self.parent.rva2off(self.expdesc.name)] = str(self.dlldescname)
        c[self.parent.rva2off(self.expdesc.addressoffunctions)] = str(self.f_address)
        if self.expdesc.addressofnames!=0:
            c[self.parent.rva2off(self.expdesc.addressofnames)] = str(self.f_names)
        if self.expdesc.addressofordinals!=0:
            c[self.parent.rva2off(self.expdesc.addressofordinals)] = str(self.f_nameordinals)
        for n in self.f_names:
            c[self.parent.rva2off(n.rva)] = str(n.name)

        #XXX BUG names must be alphanumeric ordered
        names = [n.name for n in self.f_names]
        names_ = names[:]
        if names != names_:
            log.warn("unsorted export names, may bug")
            
    def set_rva(self, rva, size = None):
        if not self.expdesc:
            return
        self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_EXPORT].rva = rva
        if not size:
            self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_EXPORT].size= len(self)
        else:
            self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_EXPORT].size= size
        rva+=pe.ExpDesc._size
        self.expdesc.name = rva
        rva+=len(self.dlldescname)
        self.expdesc.addressoffunctions = rva
        rva+=len(self.f_address)*pe.Rva._size
        self.expdesc.addressofnames = rva
        rva+=len(self.f_names)*pe.Rva._size
        self.expdesc.addressofordinals = rva
        rva+=len(self.f_nameordinals)*pe.Ordinal._size
        for n in self.f_names:
            n.rva = rva
            rva+=len(n.name)


    def create(self, name = 'default.dll'):
        self.expdesc = pe.ExpDesc()
        self.dlldescname = DescName(self.parent)
        self.dlldescname.name = name
        self.f_address = ClassArray(self.parent, WRva, None, 0)
        self.f_names = ClassArray(self.parent, WRva, None, 0)
        self.f_nameordinals = ClassArray(self.parent, WOrdinal, None, 0)
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
        
        descname = DescName(self.parent)
        descname.name = name

        wname = WRva(self.parent)
        wname.name = descname

        woffset = WRva(self.parent)
        woffset.rva = rva
        
        wordinal = WOrdinal(self.parent)
        


        #func is append to list
        wordinal.ordinal = len(self.f_address)
    
        self.f_address.append(woffset)
        #self.f_names.insert(index, wname)
        #self.f_nameordinals.insert(index, wordinal)
        self.f_names.insert(index, wname)
        self.f_nameordinals.insert(index, wordinal)


        self.expdesc.numberofnames+=1
        self.expdesc.numberoffunctions+=1
        
        
    def __len__(self):
        l = 0
        if not self.expdesc:
            return l
        l+=pe.ExpDesc._size
        l+=len(self.dlldescname)
        l+=len(self.f_address)*pe.Rva._size
        l+=len(self.f_names)*pe.Rva._size
        l+=len(self.f_nameordinals)*pe.Ordinal._size
        for n in self.f_names:
            l+=len(n.name)
        return l
    
    def __str__(self):
        return str(self.expdesc)

    def __repr__(self):
        if not self.expdesc:
            return Directory.__repr__(self)
        rep = ["<%s %d (%s) %s>"%(self.dirname, self.expdesc.numberoffunctions, self.dlldescname, repr(self.expdesc))]
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
        return self.parent.rva2virt(rva)

class DirReloc(Directory):
    dirname = 'Directory Relocation'
    def __init__(self, parent):
        self.parent = parent
        if not len(self.parent.Opthdr.Optehdr):
            return
        dirrel = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_BASERELOC]
        self.reldesc = None
        of1 = dirrel.rva
        if not of1: # No Reloc
            return
        ofend = of1+dirrel.size
        print hex(of1), hex(ofend)
        self.reldesc = []
        while of1 < ofend:
            of2=of1+pe.Rel._size
            reldesc = pe.Rel(self.parent.drva[of1:of2])
            if reldesc.size == 0:
                log.warn('warning null reldesc')
                reldesc.size = pe.Rel._size
                break
                
            reldesc.rels = ClassArray(self.parent, Reloc, self.parent.rva2off(of2), (reldesc.size-pe.Rel._size)/Reloc._size)
            reldesc.patchrel = False
            self.reldesc.append(reldesc)
            of1+=reldesc.size

    def set_rva(self, rva, size = None):
        if not self.reldesc:
            return
        self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_BASERELOC].rva = rva
        if not size:
            self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_BASERELOC].size= len(self)
        else:
            self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_BASERELOC].size= size
        

    def add_reloc(self, rels, rtype = 3, patchrel = True):
        dirrel = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_BASERELOC]
        o_init = rels[0]&0xFFFFF000
        offsets = ClassArray(self.parent, Reloc, None, num=0)
        for o in rels:
            if (o&0xFFFFF000) !=o_init:
                raise "relocs must be in same range"
            r = Reloc(self.parent)
            r.rel = (rtype, o-o_init)
            #print repr(r.rel)
            offsets.append(r)

        while len(offsets) &3:
            r = Reloc(self.parent)
            r.rel = (0, 0)
            offsets.append(r)

        reldesc = pe.Rel()
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

    def build_content(self, c):
        dirrel = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_BASERELOC]
        dirrel.size  = len(self)
        of1 = dirrel.rva
        if not self.reldesc: # No Reloc
            return
        c[self.parent.rva2off(of1)] = str(self)

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
        if not self.reldesc:
            return Directory.__repr__(self)
        rep = ["<%s>"%(self.dirname )]
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


class DirRes(Directory):
    dirname = 'Directory Resource'
    def __init__(self, parent):
        self.parent = parent
        if not len(self.parent.Opthdr.Optehdr):
            return
        dirres = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_RESOURCE]
        self.resdesc = None
        of1 = dirres.rva
        if not of1: # No Resources
            return
        of2 = of1+pe.ResDesc._size
        self.resdesc = pe.ResDesc(self.parent.drva[of1:of2])

        nbr = self.resdesc.numberofnamedentries + self.resdesc.numberofidentries
        try:
            self.resdesc.resentries = ClassArray(self.parent, ResEntry, self.parent.rva2off(of2), nbr)
        except:
            log.warning('cannot parse resources')
            self.resdesc.resentries = ClassArray(self.parent, ResEntry, None, 0)
        dir_todo = {of1:self.resdesc}
        dir_done = {}
        
        while dir_todo:
            of1, my_dir = dir_todo.popitem()
            dir_done[of1] = my_dir
            for e in my_dir.resentries:
                of1 = e.offsettosubdir
                if not of1:
                    #data dir
                    of1 = e.offsettodata
                    of2 = of1+pe.ResDataEntry._size
                    data = pe.ResDataEntry(self.parent.drva[of1:of2])
                    of1 = data.offsettodata
                    c =  StrPatchwork()                    
                    c[0] = self.parent.drva[of1:of1+data.size]
                    data.s = c
                    e.data = data
                    continue
                    
                #subdir
                if of1 in dir_done:
                    log.warn('warning recusif subdir')
                    fdds
                    continue
                of2 = of1+pe.ResDesc._size
                subdir = pe.ResDesc(self.parent.drva[of1:of2])
                nbr = subdir.numberofnamedentries + subdir.numberofidentries
                subdir.resentries = ClassArray(self.parent, ResEntry, self.parent.rva2off(of2), nbr)
                e.subdir = subdir
                dir_todo[of1] = e.subdir
                
                

    def set_rva(self, rva, size = None):
        if not self.resdesc:
            return
        self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_RESOURCE].rva = rva
        if not size:
            self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_RESOURCE].size = len(self)
        else:
            self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_RESOURCE].size = size
        dir_todo = [self.resdesc]
        dir_done = {}
        while dir_todo:
            my_dir = dir_todo.pop()
            dir_done[rva] = my_dir
            rva+=my_dir._size
            rva+=len(my_dir.resentries)*ResEntry._size
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
                    rva+=pe.ResDataEntry._size
                    #XXX menu rsrc must be even aligned?
                    if rva%2:rva+=1
                    e.data.offsettodata = rva
                    rva+=e.data.size
                    continue
                e.offsettosubdir = dir_inv[e.subdir]

    def build_content(self, c):
        if not self.resdesc:
            return
        of1 = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_RESOURCE].rva
        c[self.parent.rva2off(of1)] = str(self.resdesc)
        
        dir_todo = {self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_RESOURCE].rva:self.resdesc}
        dir_done = {}
        while dir_todo:
            of1, my_dir = dir_todo.popitem()
            dir_done[of1] = my_dir
            c[self.parent.rva2off(of1)] = str(my_dir)
            c[self.parent.rva2off(of1+len(my_dir))] = str(my_dir.resentries)
            
            for e in my_dir.resentries:
                if e.name_s:
                    c[self.parent.rva2off(e.name)] = str(e.name_s)
                of1 = e.offsettosubdir
                if not of1:
                    c[self.parent.rva2off(e.offsettodata)] = str(e.data)
                    c[self.parent.rva2off(e.data.offsettodata)] = str(e.data.s)
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
            l+=my_dir._size
            l+=len(my_dir.resentries)*ResEntry._size
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
                    l+=pe.ResDataEntry._size
                    #XXX because rva may be even rounded
                    l+=1
                    l+=e.data.size
                    continue
        return l

    def __repr__(self):
        if not self.resdesc:
            return Directory.__repr__(self)
        rep = ["<%s>"%(self.dirname )]
        dir_todo = [self.resdesc]
        out = []
        index = -1
        while dir_todo:
            a = dir_todo.pop(0)
            if isinstance(a, int):
                index+=a
            elif isinstance(a, pe.ResDesc):
                #out.append((index, repr(a)))
                dir_todo=[1]+a.resentries.list+[-1]+dir_todo
            elif isinstance(a, ResEntry):
                if a.offsettosubdir:
                    out.append((index, repr(a)))
                    dir_todo = [a.subdir]+dir_todo
                else:
                    out.append((index, repr(a)))
            else:
                raise "zarb"
        rep = []
        for i, c in out:
            rep.append(' '*4*i+c)
        
                
        return "\n".join(rep)


class drva:
    def __init__(self, x):
        self.parent = x
    def get_slice_raw(self, item):
        if not type(item) is slice:
            return None
        start = self.parent.rva2off(item.start)
        s = self.parent.getsectionbyrva(item.start)
        if not s:
            fds
            return
        stop = item.stop
        if stop == s.addr+s.size:
            stop = stop-s.addr+s.offset
        else:
            stop = self.parent.rva2off(stop)
        step = item.step
        if not start or not stop:
            return
        n_item = slice(start, stop, step)
        return n_item
    
    def __getitem__(self, item):
        n_item = self.get_slice_raw(item)
        return self.parent.__getitem__(n_item)
    def __setitem__(self, item, data):
        n_item = self.get_slice_raw(item)
        return self.parent.__setitem__(n_item, data)
    

class virt:
    def __init__(self, x):
        self.parent = x

    def item2virtitem(self, item):
        if not type(item) is slice:#integer
            rva = item-self.parent.Opthdr.Opthdr.ImageBase
            s = self.parent.getsectionbyrva(rva)
            if not s:
                return None, None
            start = rva-s.addr
            return [(s, start)]
        #if not type(item) is slice:
        #    return None
        start = item.start - self.parent.Opthdr.Opthdr.ImageBase
        stop  = item.stop - self.parent.Opthdr.Opthdr.ImageBase
        step  = item.step



        total_len = stop - start

        virt_item = []
        while total_len:
            
            s = self.parent.getsectionbyrva(start)
            s_max = max(s.size, s.rawsize)                        
            #print repr(s)
            #print "%(name)s %(offset)08x %(size)06x %(addr)08x %(flags)08x %(rawsize)08x" % s
            #print 'virtitem', hex(start), hex(stop), hex(total_len), hex(s_max)

            if not s:
                log.warn('unknown virt address!')
                return


            s_start = start - s.addr
            s_stop = stop - s.addr
            #print hex(s_stop), hex(s_start)
            if s_stop >s_max:
                #print 'yy'
                #raise ValueError('lack data %d, %d'%(stop, s_max))
                s_stop = s_max

            #print hex(s_start), hex(s_stop)
                
            s_len = s_stop - s_start
            
            total_len -= s_len
            start += s_len
                
            n_item = slice(s_start, s_stop, step)
            virt_item.append((s, n_item))
        
        return virt_item
         
    def __getitem__(self, item):
        virt_item = self.item2virtitem(item)
        if not virt_item:
             return
        data_out = ""
        for s, n_item in virt_item:
            data_out += s.data.__getitem__(n_item)
        return data_out
 
    def __setitem__(self, item, data):
        if not type(item) is slice:
            item = slice(item, item+len(data), None)
            
        virt_item = self.item2virtitem(item)
        if not virt_item:
             return
        off = 0
        for s, n_item in virt_item:
            i = slice(off, n_item.stop+off-n_item.start, n_item.step)

            data_slice = data.__getitem__(i)
            s.data.__setitem__(n_item, data_slice)
            off = i.stop

            #XXX test patch content
            file_off = self.parent.rva2off(s.addr+n_item.start)
            if self.parent.content:
                self.parent.content = self.parent.content[:file_off]+ data_slice + self.parent.content[file_off+len(data_slice):]
            
            
        return #s.data.__setitem__(n_item, data)
 
    def __len__(self):
         s = self.parent.SHList[-1]
         l = s.addr+s.size+self.parent.Opthdr.Opthdr.ImageBase
         return int(l)
 
    def find(self, pattern, offset = 0):
        if offset != 0:
            offset = self.parent.virt2rva(offset)

        sections = []
        for s in self.parent.SHList:
            s_max = max(s.size, s.rawsize)
            if offset < s.addr + s_max:
                sections.append(s)

        if not sections:
            return -1
        offset -= sections[0].addr
        if offset < 0:
            offset = 0
        for s in sections:
            ret = s.data.find(pattern, offset)
            if ret != -1:
                return self.parent.rva2virt(s.addr + ret)
            offset = 0
        return -1


# PE object

class PE(object):
    def __init__(self, pestr = None, loadfrommem=False):
        self._drva = drva(self)
        self._virt = virt(self)
        
        self._content = pestr
        if pestr == None:
            self.Doshdr = pe.Doshdr()
            self.NTsig = pe.NTsig()
            self.Coffhdr = Coffhdr(self)
            self.Opthdr = Opthdr(self)
            self.SHList = SHList(self)
            self.DirImport = DirImport(self)
            self.DirExport = DirExport(self)
            self.DirDelay = DirDelay(self)
            self.DirReloc = DirReloc(self)
            self.DirRes = DirRes(self)

            self.Doshdr.magic = 0x5a4d
            self.Doshdr.lfanew = 0x200

            self.Opthdr.Opthdr.magic = 0x10b
            self.Opthdr.Opthdr.majorlinkerversion = 0x7
            self.Opthdr.Opthdr.minorlinkerversion = 0x0
            self.Opthdr.Opthdr.filealignment = 0x1000
            self.Opthdr.Opthdr.sectionalignment = 0x1000
            self.Opthdr.Opthdr.majoroperatingsystemversion = 0x5
            self.Opthdr.Opthdr.minoroperatingsystemversion = 0x1
            self.Opthdr.Opthdr.MajorImageVersion = 0x5
            self.Opthdr.Opthdr.MinorImageVersion = 0x1
            self.Opthdr.Opthdr.majorsubsystemversion = 0x4
            self.Opthdr.Opthdr.minorsubsystemversion = 0x0
            self.Opthdr.Opthdr.subsystem = 0x2
            self.Opthdr.Opthdr.dllcharacteristics = 0x8000

            #for createthread 
            self.Opthdr.Opthdr.sizeofstackreserve = 0x200000
            self.Opthdr.Opthdr.sizeofstackcommit = 0x1000
            self.Opthdr.Opthdr.sizeofheapreserve = 0x100000
            self.Opthdr.Opthdr.sizeofheapcommit = 0x1000
            

            self.Opthdr.Opthdr.ImageBase = 0x400000
            self.Opthdr.Opthdr.sizeofheaders = 0x400
            self.Opthdr.Opthdr.numberofrvaandsizes = 0x10
            
            


            self.NTsig.signature = 0x4550
            self.Coffhdr.Coffhdr.machine = 0x14c
            self.Coffhdr.Coffhdr.sizeofoptionalheader = 0xe0
            self.Coffhdr.Coffhdr.characteristics = 0x10f
            
            

        else:
            self.loadfrommem = loadfrommem
            self.parse_content()
    
    content = ContentManager()

    def isPE(self):
        return self.NTsig.NTsig.signature == 0x4550
    
    def parse_content(self):
        self.Doshdr = WDoshdr(self, self.content)
        self.NTsig = NTsig(self, self.Doshdr.lfanew)


        self.DirImport = None
        self.DirExport = None
        self.DirDelay = None
        self.DirReloc = None
        self.DirRes = None


        if self.NTsig.NTsig.signature != 0x4550:
            return
        self.Coffhdr = Coffhdr(self, self.Doshdr.lfanew+pe.NTsig._size)
        self.Opthdr = Opthdr(self, self.Doshdr.lfanew+pe.NTsig._size+pe.Coffhdr._size)
        self.SHList = SHList(self, self.Doshdr.lfanew+pe.NTsig._size+pe.Coffhdr._size+self.Coffhdr.Coffhdr.sizeofoptionalheader)
        
        self.DirImport = DirImport(self)
        self.DirExport = DirExport(self)
        self.DirDelay = DirDelay(self)
        self.DirReloc = DirReloc(self)
        self.DirRes = DirRes(self)

        #self.Symbols = ClassArray(self, WSymb, self.Coffhdr.Coffhdr.pointertosymboltable, self.Coffhdr.Coffhdr.numberofsymbols)

        #print repr(self.Doshdr)
        #print repr(self.Coffhdr)
        #print repr(self.Opthdr)
        print repr(self.SHList)

        #print repr(self.DirImport)
        #print repr(self.DirExport)
        #print repr(self.DirReloc)
        #print repr(self.DirRes)
        

    def resize(self, old, new):
        pass
    def __getitem__(self, item):
        return self.content[item]
    def __setitem__(self, item, data):
        self.content.__setitem__(item, data)
        return 

    def getsectionbyrva(self, rva):
        if not self.SHList:
            return
        for s in self.SHList:
            if s.addr <= rva < s.addr+s.size:
                return s

    def getsectionbyoff(self, off):
        if not self.SHList:
            return
        for s in self.SHList:
            if s.offset <= off < s.offset+s.rawsize:
                return s
            
    def getsectionbyname(self, name):
        if not self.SHList:
            return
        for s in self.SHList:
            if s.name.strip('\x00') ==  name:
                return s
        return None
            
            
    def rva2off(self, rva):
        s = self.getsectionbyrva(rva)
        if not s:
            return
        return rva-s.addr+s.offset

    def off2rva(self, off):
        s = self.getsectionbyoff(off)
        if not s:
            return
        return off-s.offset+s.addr

    def virt2rva(self, virt):
        if virt == None:
            return
        return virt - self.Opthdr.Opthdr.ImageBase

    def rva2virt(self, rva):
        if rva == None:
            return
        return rva + self.Opthdr.Opthdr.ImageBase

    def virt2off(self, virt):
        return self.rva2off(self.virt2rva(virt))

    def off2virt(self, off):
        return self.rva2virt(self.off2rva(off))

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
        if len(c)%2:
            end = struct.unpack('B', data[-1])[0]
            data = data[:-1]
        if (len(c)&~0x1)%4:
            s+=struct.unpack('H', data[:2])[0]
            data = data[2:]
        
        data = array.array('I', data)
        s = reduce(lambda x,y:x+y, data, s)
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
        c[0] = str(self.Doshdr)

        for s in self.SHList:
            c[s.offset:s.offset+s.rawsize] = str(s.data)

        c[self.Doshdr.lfanew] = str(self.NTsig)
        c[self.Doshdr.lfanew+pe.NTsig._size] = str(self.Coffhdr)
        c[self.Doshdr.lfanew+pe.NTsig._size+pe.Coffhdr._size] = str(self.Opthdr)
        c[self.Doshdr.lfanew+pe.NTsig._size+pe.Coffhdr._size+self.Coffhdr.Coffhdr.sizeofoptionalheader] = str(self.SHList)

        self.DirImport.build_content(c)
        self.DirExport.build_content(c)
        self.DirReloc.build_content(c)
        self.DirRes.build_content(c)

        
        s = str(c)
        if (self.Doshdr.lfanew+pe.NTsig._size+pe.Coffhdr._size)%4:
            log.warn("non aligned coffhdr, bad crc calculation")
        crcs = self.patch_crc(s, self.Opthdr.Opthdr.CheckSum)
        c[self.Doshdr.lfanew+pe.NTsig._size+pe.Coffhdr._size+64] = struct.pack('I', crcs)
        return str(c)

    def __str__(self):
        return self.build_content()

    def export_funcs(self):
        if not self.DirExport:
            print 'no export dir found'
            return None, None

        all_func = {}
        for i, n in enumerate(self.DirExport.f_names):
            all_func[n.name.name] = self.rva2virt(self.DirExport.f_address[self.DirExport.f_nameordinals[i].ordinal].rva)
    
            all_func[self.DirExport.f_nameordinals[i].ordinal+self.DirExport.expdesc.base] = self.rva2virt(self.DirExport.f_address[self.DirExport.f_nameordinals[i].ordinal].rva)
    
        #XXX todo: test if redirected export
        return all_func
    


class Coff(PE):
    def parse_content(self):
        self.Coffhdr = Coffhdr(self, 0)
        self.Opthdr = Opthdr(self, pe.Coffhdr._size)
        self.SHList = SHList(self, pe.Coffhdr._size+self.Coffhdr.Coffhdr.sizeofoptionalheader)

        self.Symbols = ClassArray(self, WSymb, self.Coffhdr.Coffhdr.pointertosymboltable, self.Coffhdr.Coffhdr.numberofsymbols)



if __name__ == "__main__":
    import rlcompleter,readline,pdb, sys
    from pprint import pprint as pp
    readline.parse_and_bind("tab: complete")

    e = PE(open(sys.argv[1]).read())
    ###TEST XXX###
    #XXX patch boundimport /!\
    e.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_BOUND_IMPORT].rva = 0
    e.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_BOUND_IMPORT].size = 0
        

    s_redir = e.SHList.add_section(name = "redir", rawsize = 0x1000)
    s_test = e.SHList.add_section(name = "test", rawsize = 0x1000)
    s_rel = e.SHList.add_section(name = "rel", rawsize = 0x1000)

    new_dll = [({"name":"kernel32.dll",
                 "firstthunk":s_test.addr},
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

    s_myimp = e.SHList.add_section(name = "myimp", rawsize = len(e.DirImport))
    s_myexp = e.SHList.add_section(name = "myexp", rawsize = len(e.DirExport))
    s_myrel = e.SHList.add_section(name = "myrel", rawsize = len(e.DirReloc))
    s_myres = e.SHList.add_section(name = "myres", rawsize = len(e.DirRes))
    
                    
    for s in e.SHList:
        s.offset+=0xC00

    e.DirImport.set_rva(s_myimp.addr)
    e.DirExport.set_rva(s_myexp.addr)
    e.DirReloc.set_rva(s_myrel.addr)
    e.DirRes.set_rva(s_myres.addr)

    e_str = str(e)
    
    
    open('out.bin', 'wb').write(e_str)
    o = Coff(open('main.obj').read())
    print repr(o.Coffhdr)
    print repr(o.Opthdr)
    print repr(o.SHList)
    print 'numsymb', hex(o.Coffhdr.Coffhdr.numberofsymbols)
    print 'offset', hex(o.Coffhdr.Coffhdr.pointertosymboltable)
    
    print repr(o.Symbols)
