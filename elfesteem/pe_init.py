#! /usr/bin/env python

import struct
import pe
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
        



"""
class WEhdr(StructWrapper):
    wrapped = elf.Ehdr
    def set_shstrndx(self, val):
        self.cstr.shstrndx = val
"""

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
        for i in xrange(self.Opthdr.numberofrvaandsizes):
            of1 = of2
            of2 += pe.Optehdr._size
            optehdr = pe.Optehdr(parent[of1:of2])
            self.Optehdr.append(optehdr)
        
    def __str__(self):
        c = []
        c.append(str(self.Opthdr))
        for s in self.Optehdr:
            c.append(str(s))
        return "".join(c)

    def __repr__(self):
        o = repr(self.Opthdr)
        for c in self.Optehdr:
            o+='\n\t'+repr(c)
        return o


class SList:
    def __init__(self, parent):
        self.parent = parent
        dhdr = self.parent.Doshdr
        nthdr = self.parent.NThdr.NThdr
        of1 = dhdr.lfanew+pe.NThdr._size+nthdr.sizeofoptionalheader
        if not of1: # No NThdr
            return
        self.shlist = []
        for i in xrange(nthdr.numberofsections):
            of2 = of1+pe.Shdr._size
            shdrstr = parent[of1:of2]
            self.shlist.append(pe.Shdr(shdrstr))
            of1 = of2
    def __str__(self):
        c = []
        for s in self.shlist:
            c.append(str(s))
        return "".join(c)
    def __repr__(self):
        rep = ["#  section         offset   size   addr     flags"]
        for i,s in enumerate(self.shlist):
            #l = "%(name)-15s %(offset)08x %(size)06x %(addr)08x %(flags)x " % s.sh
            #l = ("%2i " % i)+ l + s.__class__.__name__
            l = "%(name)-15s %(offset)08x %(size)06x %(addr)08x %(flags)x " % s
            l = ("%2i " % i)+ l + s.__class__.__name__
            rep.append(l)
        return "\n".join(rep)

class ClassArray:
    def __init__(self, parent, cls, of1):
        self.parent = parent
        self.cls = cls
        self.list = []
        self.null_str = '\x00'*self.cls._size
        if of1 == 0:
            return
        while True:
            of2 = of1+self.cls._size
            cls_str = self.parent.drva[of1:of2]
            if cls_str == self.null_str:
                break
            self.list.append(self.cls(cls_str))
            of1 = of2
    def __str__(self):
        c = []
        for s in self.list:
            c.append(str(s))
        return "".join(c)+self.null_str
    def __repr__(self):
        rep = []
        for i,s in enumerate(self.list):
            l = ("%2i " % i)+ repr(s) + s.__class__.__name__
            rep.append(l)
        return "\n".join(rep)
    def __getitem__(self, item):
        return self.list.__getitem__(item)
    def __len__(self):
        return len(self.list)
        
            
class ImportByName:
    def __init__(self, parent, of1):
        self.parent = parent
        self.of1 = of1
        
        ofname = self.parent.rva2offset(of1+2)
        self.hint = struct.unpack('H', self.parent.drva[of1:of1+2])[0]
        self.name = self.parent[ofname:ofname+self.parent[ofname:].find('\x00')]
    def __str__(self):
        return struct.pack('H', self.hint)+ self.name+'\x00'
    def __repr__(self):
        return '<%d, %s>'%(self.hint, self.name)

class DllDescName:
    def __init__(self, parent, of1):
        self.parent = parent
        self.of1 = of1
        
        ofname = self.parent.rva2offset(of1)
        self.name = self.parent[ofname:ofname+self.parent[ofname:].find('\x00')]
    def __str__(self):
        return self.name+'\x00'
    def __repr__(self):
        return '<%s>'%(self.name)

        
class DirImport:
    def __init__(self, parent):
        self.parent = parent
        dirimp = self.parent.Opthdr.Optehdr[pe.DIRECTORY_ENTRY_IMPORT]
        of1 = dirimp.rva
        if not of1: # No Import
            return
        self.impdesc = ClassArray(self.parent, pe.ImpDesc, of1)
        for i, d in enumerate(self.impdesc):
            d.dlldescname = DllDescName(self.parent, d.name)
            d.originalfirstthunks = ClassArray(self.parent, pe.Rva, d.originalfirstthunk)
            d.firstthunks = ClassArray(self.parent, pe.Rva, d.firstthunk)

            d.impbynames = []
            if d.originalfirstthunk:
                tmp_thunk = d.originalfirstthunks
            elif d.firstthunk:
                tmp_thunk = d.firstthunks
            else:
                raise "no thunk!!"
            for i in xrange(len(tmp_thunk)):
                d.impbynames.append(ImportByName(self.parent, tmp_thunk[i].rva))

    def __str__(self):
        c = []
        for s in self.impdesc:
            c.append(str(s))
        return "".join(c)

    def __repr__(self):
        rep = []
        for i,s in enumerate(self.impdesc):
            l = "%2d %-25s %s"%(i, repr(s.dlldescname) ,repr(s))
            rep.append(l)
            for ii, f in enumerate(s.impbynames):
                l = "\t%2d %-16s %-14s"%(ii, repr(f), repr(s.impbynames[ii]))
                rep.append(l)
        return "\n".join(rep)
        
        
        
                               
            
            
            
        


class drva:
    def __init__(self, x):
        self.parent = x
    def __getitem__(self, item):
        if not type(item) is slice:
            return None
        start = self.parent.rva2offset(item.start)
        stop = self.parent.rva2offset(item.stop)
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
        self.SList = SList(self)

        self.DirImport = DirImport(self)
        

        print repr(self.Doshdr)
        print repr(self.NThdr)
        print repr(self.Opthdr)
        print repr(self.SList)

        #print self.getsectionbyrva(0x1100)
        #print repr(self.drva[0x1000:0x1100])
        print repr(self.DirImport)

        

    def resize(self, old, new):
        pass
    def __getitem__(self, item):
        return self.content[item]

    def getsectionbyrva(self, rva):
        if not self.SList.shlist:
            return
        for s in self.SList.shlist:
            if s.addr <= rva < s.addr+s.size:
                return s
            
    def rva2offset(self, rva):
        s = self.getsectionbyrva(rva)
        if not s:
            return
        return rva-s.addr+s.offset

    def get_drva(self):
        return self._drva

    drva = property(get_drva)
    
    def build_content(self):
        c = StrPatchwork()
        c[0] = str(self.Ehdr)
        c[self.Ehdr.phoff] = str(self.ph)
        for s in self.sh:
            c[s.sh.offset] = s.content
        c[self.Ehdr.shoff] = str(self.sh)
        return str(c)

    def __str__(self):
        return self.build_content()


if __name__ == "__main__":
    import rlcompleter,readline,pdb, sys
    from pprint import pprint as pp
    readline.parse_and_bind("tab: complete")

    e = PE(open(sys.argv[1]).read())
