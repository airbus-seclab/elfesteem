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
        owner.parse_content()
    def __delete__(self, owner):
        self.__set__(owner, None)


class WDoshdr(StructWrapper):
    wrapped = pe.Doshdr


class NThdr:
    def __init__(self, parent):
        self.parent = parent
        dhdr = self.parent.Doshdr
        of1 = dhdr.lfanew
        if not of1: # No NThdr
            return
        of2 = of1+pe.NThdr._size
        strnthdr = parent[of1:of2]
        self.NThdr = pe.NThdr(strnthdr)

    def __str__(self):
        return str(self.NThdr)
    
    def __repr__(self):
        return repr(self.NThdr)


class Opthdr:
    def __init__(self, parent):
        self.parent = parent
        dhdr = self.parent.Doshdr
        of1 = dhdr.lfanew+pe.NThdr._size
        if not of1: # No NThdr 
            return
        of2 = of1+pe.Opthdr._size
        stropthdr = parent[of1:of2]
        self.Opthdr = pe.Opthdr(stropthdr)
        self.Optehdr = []
        numberofrva = self.Opthdr.numberofrvaandsizes
        if self.parent.NThdr.NThdr.sizeofoptionalheader<numberofrva*pe.Optehdr._size+pe.Opthdr._size:
            numberofrva = (self.parent.NThdr.NThdr.sizeofoptionalheader-pe.Opthdr._size)/pe.Optehdr._size
            log.warn('bad number of rva.. using default %d'%numberofrva)
            
        for i in xrange(numberofrva):
            of1 = of2
            of2 += pe.Optehdr._size
            optehdr = pe.Optehdr(parent[of1:of2])
            self.Optehdr.append(optehdr)
        
    def __str__(self):
        c = [str(self.Opthdr)]
        for s in self.Optehdr:
            c.append(str(s))
        return "".join(c)

    def __repr__(self):
        o = repr(self.Opthdr)
        for c in self.Optehdr:
            o+='\n    '+repr(c)
        return o



class WShdr(StructWrapper):
    wrapped = pe.Shdr
    _size = pe.Shdr._size

class WImpDesc(StructWrapper):
    wrapped = pe.ImpDesc
    _size = pe.ImpDesc._size

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
    def __init__(self, parent):
        self.parent = parent
        dhdr = self.parent.Doshdr
        nthdr = self.parent.NThdr.NThdr
        of1 = dhdr.lfanew+pe.NThdr._size+nthdr.sizeofoptionalheader
        if not of1: # No shlist
            return
        self.shlist = ClassArray(self.parent, WShdr, of1, nthdr.numberofsections)
        filealignment = self.parent.Opthdr.Opthdr.filealignment
        for s in self.shlist:
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
    def __str__(self):
        c = []
        for s in self.shlist:
            c.append(str(s))
        return "".join(c)
    def __repr__(self):
        rep = ["#  section         offset   size   addr     flags"]
        for i,s in enumerate(self.shlist):
            l = "%(name)-15s %(offset)08x %(size)06x %(addr)08x %(flags)x " % s
            l = ("%2i " % i)+ l + s.__class__.__name__
            rep.append(l)
        return "\n".join(rep)


    def add_section(self, name="default", data = "", **args):
        s_align = self.parent.Opthdr.Opthdr.sectionalignment
        s_align = max(0x1000, s_align)

        f_align = self.parent.Opthdr.Opthdr.filealignment
        f_align = max(0x200, f_align)
        
        addr = self.shlist[-1].addr+self.shlist[-1].size
        s_last = self.shlist[0]
        for s in self.shlist:
            if s_last.offset+s_last.rawsize<s.offset+s.rawsize:
                s_last = s

        size = len(data)
        rawsize = len(data)
            
        offset = s_last.offset+s_last.rawsize
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
        self.parent.NThdr.NThdr.numberofsections = len(self.shlist)

        l = (s.addr+s.size+(s_align-1))&~(s_align-1)
        self.parent.Opthdr.Opthdr.sizeofimage = l
        return s

            
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
    def __init__(self, parent, s):
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



class DirImport(Directory):
    dirname = 'Directory Import'
    def __init__(self, parent):
        self.parent = parent
        dirimp = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_IMPORT]
        of1 = dirimp.rva
        if not of1: # No Import
            return
        self.impdesc = ClassArray(self.parent, WImpDesc, self.parent.rva2off(of1))
        for i, d in enumerate(self.impdesc):
            d.dlldescname = DescName(self.parent, d.name)
            d.originalfirstthunks = ClassArray(self.parent, WRva, self.parent.rva2off(d.originalfirstthunk))
            d.firstthunks = ClassArray(self.parent, WRva, self.parent.rva2off(d.firstthunk))

            d.impbynames = []
            if d.originalfirstthunk:
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
        dirimp = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_IMPORT]
        of1 = dirimp.rva
        if not of1: # No Import
            return
        c[self.parent.rva2off(of1)] = str(self.impdesc)
        for i, d in enumerate(self.impdesc):
            c[self.parent.rva2off(d.name)] = str(d.dlldescname)
            if d.originalfirstthunk:
                c[self.parent.rva2off(d.originalfirstthunk)] = str(d.originalfirstthunks)
            if d.firstthunk:
                c[self.parent.rva2off(d.firstthunk)] = str(d.firstthunks)
            if d.originalfirstthunk:
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            for i, imp in enumerate(d.impbynames):
                if isinstance(imp, ImportByName):
                    c[self.parent.rva2off(tmp_thunk[i].rva)] = str(imp)
                    
    def __str__(self):
        c = []
        for s in self.impdesc:
            c.append(str(s))
        return "".join(c)

    def __len__(self):
        l = (len(self.impdesc)+1)*pe.ImpDesc._size
        for i, d in enumerate(self.impdesc):
            l+=len(d.dlldescname)
            if d.originalfirstthunk:
                l+=(len(d.originalfirstthunks)+1)*pe.Rva._size
            if d.firstthunk:
                l+=(len(d.firstthunks)+1)*pe.Rva._size
            if d.originalfirstthunk:
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
            if d.originalfirstthunk:
                d.originalfirstthunk = rva
                rva+=(len(d.originalfirstthunks)+1)*pe.Rva._size
            #XXX rva fthunk not patched => fun addr
            #if d.firstthunk:
            #    d.firstthunk = rva
            #    rva+=(len(d.firstthunks)+1)*pe.Rva._size
            if d.originalfirstthunk:
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
                if nf[0]:
                    f.rva = 0x80000000+nf[0]
                else:
                    f.rva = True
                    ibn = ImportByName(self.parent)
                    ibn.name = nf[1]
                    impbynames.append(ibn)
                d.originalfirstthunks.append(f)

                ff = pe.Rva()
                ff.rva = 0xDEADBEEF #default func addr
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
        direxp = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_EXPORT]
        self.expdesc = None
        of1 = direxp.rva
        if not of1: # No Export
            return
        of2 = of1+pe.ExpDesc._size
        self.expdesc = pe.ExpDesc(self.parent.drva[of1:of2])
        self.dlldescname = DescName(self.parent, self.expdesc.name)
        self.functions = ClassArray(self.parent, WRva, self.parent.rva2off(self.expdesc.addressoffunctions), self.expdesc.numberoffunctions)
        self.functionsnames = ClassArray(self.parent, WRva, self.parent.rva2off(self.expdesc.addressofnames), self.expdesc.numberofnames)
        self.functionsordinals = ClassArray(self.parent, WOrdinal, self.parent.rva2off(self.expdesc.addressofordinals), self.expdesc.numberofnames)
        for n in self.functionsnames:
            n.name = DescName(self.parent, n.rva)


    def build_content(self, c):
        direxp = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_EXPORT]
        of1 = direxp.rva
        if not self.expdesc: # No Export
            return
        c[self.parent.rva2off(of1)] = str(self.expdesc)
        c[self.parent.rva2off(self.expdesc.name)] = str(self.dlldescname)
        c[self.parent.rva2off(self.expdesc.addressoffunctions)] = str(self.functions)
        c[self.parent.rva2off(self.expdesc.addressofnames)] = str(self.functionsnames)
        c[self.parent.rva2off(self.expdesc.addressofordinals)] = str(self.functionsordinals)
        for n in self.functionsnames:
            c[self.parent.rva2off(n.rva)] = str(n.name)

        #XXX BUG names must be alphanumeric ordered
        names = [n.name for n in self.functionsnames]
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
        rva+=len(self.functions)*pe.Rva._size
        self.expdesc.addressofnames = rva
        rva+=len(self.functionsnames)*pe.Rva._size
        self.expdesc.addressofordinals = rva
        rva+=len(self.functionsordinals)*pe.Ordinal._size
        for n in self.functionsnames:
            n.rva = rva
            rva+=len(n.name)

    def add_name(self, name, ordinal):
        if not self.expdesc:
            return
        l = len(self.functionsnames)
        names = [n.name.name for n in self.functionsnames]
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

        wordinal = WOrdinal(self.parent)
        wordinal.ordinal = ordinal
        
        self.functionsnames.insert(index, wname)
        self.functionsordinals.insert(index, wordinal)

        self.expdesc.numberofnames+=1        
        
        
    def __len__(self):
        l = 0
        if not self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_EXPORT].rva:
            return l
        l+=pe.ExpDesc._size
        l+=len(self.dlldescname)
        l+=len(self.functions)*pe.Rva._size
        l+=len(self.functionsnames)*pe.Rva._size
        l+=len(self.functionsordinals)*pe.Ordinal._size
        for n in self.functionsnames:
            l+=len(n.name)
        return l
    
    def __str__(self):
        return str(self.expdesc)

    def __repr__(self):
        if not self.expdesc:
            return Directory.__repr__(self)
        rep = ["<%s %d (%s) %s>"%(self.dirname, self.expdesc.numberoffunctions, self.dlldescname, repr(self.expdesc))]
        tmp_names = [[] for x in xrange(self.expdesc.numberoffunctions)]
        
        for i, n in enumerate(self.functionsnames):
            tmp_names[self.functionsordinals[i].ordinal].append(n.name)

        for i,s in enumerate(self.functions):
            tmpn = []
            if not s.rva:
                continue
            l = "%2d %.8X %s"%(i+self.expdesc.base, s.rva ,repr(tmp_names[i]))
            rep.append(l)
        return "\n".join(rep)

class DirReloc(Directory):
    dirname = 'Directory Relocation'
    def __init__(self, parent):
        self.parent = parent
        dirrel = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_BASERELOC]
        self.reldesc = None
        of1 = dirrel.rva
        if not of1: # No Reloc
            return
        ofend = of1+dirrel.size
        self.reldesc = []
        while of1 < ofend:
            of2=of1+pe.Rel._size
            reldesc = pe.Rel(self.parent.drva[of1:of2])
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
        

    def add_reloc(self, rels, tpye = 3, patchrel = True):
        dirrel = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_BASERELOC]
        o_init = rels[0]&0xFFFF000
        offsets = ClassArray(self.parent, Reloc(parent), num=0)
        for o in rels:
            if (o&0xFFFF000) !=o_init:
                raise "relocs must be in same range"
            r = Reloc()
            r.rel = (type, x-o_init)
            offsets.append(r)

        reldesc = pe.Rel()
        reldesc.rva = o_init
        reldesc.size = len(rels)*2+8
        reldesc.rels = offsets
        reldesc.patchrel = patchrel
        self.reldesc.append(reldesc)
        dirrel.size+=reldesc.size
  
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
        dirres = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_RESOURCE]
        self.resdesc = None
        of1 = dirres.rva
        if not of1: # No Resources
            return
        of2 = of1+pe.ResDesc._size
        self.resdesc = pe.ResDesc(self.parent.drva[of1:of2])

        nbr = self.resdesc.numberofnamedentries + self.resdesc.numberofidentries
        self.resdesc.resentries = ClassArray(self.parent, ResEntry, self.parent.rva2off(of2), nbr)
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
    def __getitem__(self, item):
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
        return self.parent.__getitem__(n_item)
    

# PE object

class PE(object):
    def __init__(self, pestr):
        self._drva = drva(self)
        self._content = pestr
        self.parse_content()
    
    content = ContentManager()
    def parse_content(self):
        self.Doshdr = WDoshdr(self, self.content)
        self.NThdr = NThdr(self)
        self.Opthdr = Opthdr(self)
        self.SHList = SHList(self)

        self.DirImport = DirImport(self)
        self.DirExport = DirExport(self)
        self.DirReloc = DirReloc(self)
        self.DirRes = DirRes(self)

        print repr(self.Doshdr)
        print repr(self.NThdr)
        print repr(self.Opthdr)
        print repr(self.SHList)

        print repr(self.DirImport)
        print repr(self.DirExport)
        print repr(self.DirReloc)
        print repr(self.DirRes)
        

    def resize(self, old, new):
        pass
    def __getitem__(self, item):
        return self.content[item]

    def getsectionbyrva(self, rva):
        if not self.SHList:
            return
        for s in self.SHList:
            if s.addr <= rva < s.addr+s.size:
                return s
            
    def rva2off(self, rva):
        s = self.getsectionbyrva(rva)
        if not s:
            return
        return rva-s.addr+s.offset

    def get_drva(self):
        return self._drva

    drva = property(get_drva)


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

        c[self.Doshdr.lfanew] = str(self.NThdr)
        c[self.Doshdr.lfanew+pe.NThdr._size] = str(self.Opthdr)
        c[self.Doshdr.lfanew+pe.NThdr._size+self.NThdr.NThdr.sizeofoptionalheader] = str(self.SHList)

        self.DirImport.build_content(c)
        self.DirExport.build_content(c)
        self.DirReloc.build_content(c)
        self.DirRes.build_content(c)

        
        s = str(c)
        if (self.Doshdr.lfanew+pe.NThdr._size)%4:
            log.warn("non aligned nthdr, bad crc calculation")
        crcs = self.patch_crc(s, self.Opthdr.Opthdr.CheckSum)
        c[self.Doshdr.lfanew+pe.NThdr._size+64] = struct.pack('I', crcs)
        return str(c)

    def __str__(self):
        return self.build_content()


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
                [(None, "CreateFileA"),
                 (None, "SetFilePointer"),
                 (None, "WriteFile"),
                 (None, "CloseHandle"),
                 ]
                ),
               ({"name":"USER32.dll",
                 "firstthunk":None},
                [(None, "SetDlgItemInt"),
                 (None, "GetMenu"),
                 (None, "HideCaret"),
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
