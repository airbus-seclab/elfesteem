#! /usr/bin/env python

import struct

from elfesteem import cstruct
from elfesteem import macho
from elfesteem.macho import data_bytes
from elfesteem.cstruct import data_empty, data_null
from elfesteem.strpatchwork import StrPatchwork
from elfesteem import intervals
import copy
#import traceback

def inherit_sex_wsize(self, parent, kargs):
    for f in ['sex', 'wsize']:
        if f in kargs:
            setattr(self, f, kargs[f])
            del kargs[f]
        elif parent != None:
            setattr(self, f, getattr(parent, f))
    self.parent = parent

class ContentManager(object):
    def __get__(self, owner, x):
        if hasattr(owner, '_content'):
            return owner._content
    def __set__(self, owner, new_content):
        owner.resize(len(owner._content), len(new_content))
        owner._content=StrPatchwork(new_content)
        owner.parse_content(owner.sex, owner.wsize)
    def __delete__(self, owner):
        self.__set__(owner, None)

def type_to_format(type, val):
    if len(type) > 2 and type[-1] == 's' and int(type[:-1]) > 0:
        val = val.strip('\0')
        type = 's'
    return {
        's': '%r',
        'u32': '%.8X',
        'u64': '%.8X',
        }[type] % val

class LoaderMetaclass(type):
    loadtypes = {}
    def __new__(cls,name,bases,dct):
        dct_glob = {}
        for d in reversed([dct]+[b.__dict__ for b in bases]):
            dct_glob.update(d)
        for fname, ftype in macho.Lhdr._fields:
            dct[fname] = property(
                dct_glob.pop("get_"+fname,
                    lambda self, fname=fname: getattr(self.lh,fname)),
                dct_glob.pop("set_"+fname,
                    lambda self,v, fname=fname: setattr(self.lh,fname,v)),
                dct_glob.pop("del_"+fname, None))
        lhc = dct_glob.pop('lhc', None)
        if name != "LoaderBase" and lhc is not None:
            for fname, ftype in lhc._fields:
                dct[fname] = property(
                    dct_glob.pop("get_"+fname,
                        lambda self, fname=fname: getattr(self.lhc,fname)),
                    dct_glob.pop("set_"+fname,
                        lambda self,v, fname=fname: setattr(self.lhc,fname,v)),
                    dct_glob.pop("del_"+fname, None))
        o = type.__new__(cls, name, bases, dct)
        if 'lht' in dct:
            LoaderMetaclass.loadtypes[o.lht] = o
        return o

LoaderBase = LoaderMetaclass('LoaderBase', (object,), {})

class Loader(LoaderBase):
    lhc = None
    @classmethod
    def create(cls, **kargs):
        if not 'content' in kargs:
            lh = macho.Lhdr(content=data_empty,**kargs)
            lh.cmd = cls.lht
        else:
            lh = macho.Lhdr(**kargs)
        if lh.cmd in LoaderMetaclass.loadtypes:
            cls = LoaderMetaclass.loadtypes[lh.cmd]
        i = cls.__new__(cls,cls.__name__,cls.__bases__,cls.__dict__)
        kargs['parent'] = lh
        i.__init__(**kargs)
        return i

    content = ContentManager()
    def parse_content(self, **kargs):
        if self.__class__.lhc == None:
            self._repr_fields = []
        else:
            self.lhc = self.__class__.lhc(**kargs)
            self._repr_fields = self.lhc._fields[:]
        self._parse_content()
    def _parse_content(self):
        pass
    def __init__(self, **kargs):
        if 'parent' in kargs:
            self.lh = kargs['parent']
            self.parent = self.lh
        else :
            raise ValueError("No lh given in Loader __init__")
        inherit_sex_wsize(self, self.parent, kargs)
        self._content = StrPatchwork()
        self.parse_content(**kargs)
    def __repr__(self):
        return "<" + self.__class__.__name__ + " " + ' '.join(map(lambda f:f[0]+" "+type_to_format(f[1],getattr(self,f[0])),self._repr_fields)) + ">"
    def pack(self):
        s = self.lh.pack()
        if self.lhc != None: s += self.lhc.pack()
        if hasattr(self,'_str_additional_data'):
            s += self._str_additional_data()
        if self.__class__.__name__ == "Loader":
            s += self.content.pack()
        self.lh.cmdsize = len(s)
        return s
    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    def changeOffsets(self, decalage, min_offset=None):
        pass

def isOffsetChangeable(offset, min_offset):
    return (min_offset == None or offset >= min_offset) and offset != 0

class LoaderLinkEditDataCommand(Loader):
    lhc = macho.linkedit_data_command
    def changeOffsets(self, decalage, min_offset=None):
        if isOffsetChangeable(self.data_off, min_offset):
            self.data_off += decalage
    def sectionsToAdd(self, raw):
        self.sect = []
        if self.data_size != 0:
            c = raw[self.data_off:self.data_off + self.data_size]
            self.sect.append(self.sect_class(self,c, type='data'))
        return self.sect

class LoaderSegmentBase(Loader):
    def _parse_content(self):
        self.sh = []
        a = len(self.lhc.pack())
        b = self.lh_size
        for i in range(self.lhc.nsects):
            self.sh.append(self.sh_type(parent=self,content=self.content[a+b*i:a+b*(i+1)]))
    def _str_additional_data(self):
        data = data_empty
        for sh in self.sh:
            data += sh.pack()
        return data
    def addSH(self, s):
        maxoff = self.fileoff
        if not hasattr(self, 'sect'):
            self.sect = []
            offset = 0
            size = 0 
        if len(self.sect)>0:
            offset = 0
            size = 0
            for se in self.sect:
                if offset < se.offset :
                    offset = se.offset
                    size = se.size
            maxoff = offset + size
        self.nsects += 1
        self.cmdsize += len(str(s.sh))
        s.sh.parent = self
        s.sh.offset = maxoff 
        s.sh.addr = self.vmaddr - self.fileoff + s.sh.offset
        s.sh.align = 4
        # Values and positions by default
        self.sh.append(s.sh)
        self.sect.append(s)
        s.sh.size = len(str(s))
        s.sh.offset = maxoff
        if offset + size > self.fileoff + self.filesize :
            raise ValueError("not enough space in segment")
            #self.parent.extendSegment(self, 0x1000*(s.sh.size/0x1000 +1))
        else :
            self.filesize += len(str(s))
            self.vmsize += len(str(s))   
    def changeOffsets(self, decalage, min_offset=None):
        for sh in self.sh:
            sh.changeOffsets(decalage, min_offset)
        if isOffsetChangeable(self.fileoff, min_offset):
            self.fileoff += decalage
    def sectionsToAdd(self, raw):
        self.sect = []
        for sh in self.sh:
            if sh.type == macho.S_ZEROFILL:
                c = data_empty
            else :
                c = raw[sh.offset:sh.offset+sh.size]
            if sh.type == macho.S_SYMBOL_STUBS:
                cls = SymbolStubList
            elif sh.type == macho.S_NON_LAZY_SYMBOL_POINTERS:
                cls = NLSymbolPtrList
            elif sh.type == macho.S_LAZY_SYMBOL_POINTERS:
                cls = LASymbolPtrList
            else:
                cls = Section
            sh.sect = cls(self, sh=sh, content=c)
            self.sect.append(sh.sect)
        for sh in self.sh:
            if sh.reloff != 0:
                c = raw[sh.reloff:sh.reloff+sh.nreloc*8]
                sh.reloc = Reloc(self, sh=sh, content=c)
                self.sect.append(sh.reloc)
        return self.sect
    def get_segname(self):
        return self.lhc.segname.strip(data_null)
    def set_segname(self, val):
        padding = len(self.lhc.segname) - len(val)
        if (padding < 0) : raise ValueError("segname is too long for the structure")
        self.lhc.segname = val + data_null*padding
        for sh in self.sh:
            sh.segname = val
    def is_text_segment(self):
        return self.segname == data_bytes("__TEXT")

class LoaderSegment(LoaderSegmentBase):
    lht = macho.LC_SEGMENT
    lhc = macho.segment_command
    sh_type = macho.sectionHeader
    lh_size = 68

class LoaderSegment_64(LoaderSegmentBase):
    lht = macho.LC_SEGMENT_64
    lhc = macho.segment_command_64
    sh_type = macho.sectionHeader_64
    lh_size = 80

class LoaderSymTab(Loader):
    lht = macho.LC_SYMTAB
    lhc = macho.symtab_command
    def sectionsMappedInMemory(self):
        return [self]
    def changeOffsets(self, decalage, min_offset=None):
        if isOffsetChangeable(self.str_off, min_offset):
            self.str_off += decalage
        if isOffsetChangeable(self.sym_off, min_offset):
            self.sym_off += decalage
    def sectionsToAdd(self, raw):
        if self.wsize == 32 : sizesym = 12
        if self.wsize == 64 : sizesym = 16
        self.sect = []
        self.sym_size = self.nsyms*sizesym
        if self.sym_off != 0:
            c = raw[self.sym_off:self.sym_off + self.sym_size]
            self.sect.append(SymbolTable(self,c, type='sym'))
        if self.str_off != 0:
            c = raw[self.str_off:self.str_off + self.str_size]
            self.sect.append(StringTable(self,c, type='str'))
        return self.sect

class LoaderDysymTab(Loader):
    lht = macho.LC_DYSYMTAB
    lhc = macho.dysymtab_command
    subtypes = ['toc', 'modtab', 'extrefsym', 'indirectsym', 'extrel', 'locrel']
    symbolsize = {'toc':2*4, 'modtab':{32: 13*4, 64: 12*4+8}[32], 'extrefsym':4, 'indirectsym':4, 'extrel':2*4, 'locrel':2*4}
    symbolsize_64 = {'toc':2*4, 'modtab':{32: 13*4, 64: 12*4+8}[64], 'extrefsym':4, 'indirectsym':4, 'extrel':2*4, 'locrel':2*4}
    def changeOffsets(self, decalage, min_offset=None):
        for type in LoaderDysymTab.subtypes:
            of = getattr(self,type+'_off')
            if isOffsetChangeable(of, min_offset):
                setattr(self, type+'_off', of + decalage)
    def sectionsToAdd(self, raw):
        self.sect = []
        for type in LoaderDysymTab.subtypes:
            if self.wsize == 32:
                setattr(self, type+'_size',getattr(self,'n'+type)*LoaderDysymTab.symbolsize[type])
            elif self.wsize == 64:
                setattr(self, type+'_size',getattr(self,'n'+type)*LoaderDysymTab.symbolsize_64[type])

        for type in LoaderDysymTab.subtypes:
            of = getattr(self,type+'_off')
            if of != 0:
                size = getattr(self,type+'_size')
                c = raw[of:of + size]
                self.sect.append(DySymbolTable(self,c, type=type))
        return self.sect

class LoaderLib(Loader):
    def _parse_content(self):
        self.name = self.content[self.lhc.stroffset-8:].strip(data_null)
        self.padding = self.lh.cmdsize - len(self.lh.pack()) - len(self.lhc.pack()) - len(self.name)
        self._repr_fields[0] = ("name", "s")
    def _str_additional_data(self):
        return self.name+data_null*self.padding

class LoaderLoadDylib(LoaderLib):
    lht = macho.LC_LOAD_DYLIB
    lhc = macho.dylib_command

class LoaderIDDylib(LoaderLib):
    lht = macho.LC_ID_DYLIB
    lhc = macho.dylib_command

class LoaderDylinker(LoaderLib):
    lht = macho.LC_LOAD_DYLINKER
    lhc = macho.dylinker_command

class LoaderUUID(Loader):
    lht = macho.LC_UUID
    lhc = None
    def _parse_content(self):
        data = self.content.pack()
        if data == data_empty: data = data_null * 16
        self.uuid = struct.unpack(">IHHHHI", data)
    def _str_additional_data(self):
        return struct.pack(">IHHHHI", *self.uuid)
    def __repr__(self):
        return '<LoaderUUID %.8X-%.4X-%.4X-%.4X-%.4X%.8X>' % self.uuid
    def changeUUID(self, uuid):
        s = struct.pack("B"*16, *[int(uuid[2*i:2*i+2],16) for i in range(int(len(uuid)/2))])
        self.uuid = struct.unpack(">IHHHHI", s)

class LoaderTwoLevelHints(Loader):
    lht = macho.LC_TWOLEVEL_HINTS
    lhc = macho.twolevel_hints_command
    def changeOffsets(self, decalage, min_offset=None):
        if isOffsetChangeable(self.twolevelhints_off, min_offset):
            self.twolevelhints_off += decalage
    def sectionsToAdd(self, raw):
        self.sect = []
        size_of_hint = 4
        if self.twolevelhints_off != 0:
            self.twolevelhints_size = size_of_hint*self.nhints
            c = raw[self.twolevelhints_off:self.twolevelhints_off + self.twolevelhints_size]
            self.sect.append(Hint(self,c, type='twolevelhints'))
        return self.sect

class LoaderPrebindCksum(Loader):
    lht = macho.LC_PREBIND_CKSUM
    lhc = macho.prebind_cksum_command

class LoaderEncryption(Loader):
    lht = macho.LC_ENCRYPTION_INFO
    lhc = macho.encryption_command
    def changeOffsets(self, decalage, min_offset=None):
        if isOffsetChangeable(self.crypt_off, min_offset):
            self.crypt_off += decalage
        if isOffsetChangeable(self.crypt_size, min_offset):
            self.crypt_size += decalage
        if isOffsetChangeable(self.crypt_id, min_offset):
            self.crypt_id += decalage
    def sectionsToAdd(self, raw):
        self.sect = []
        if self.crypt_off != 0:
            c = raw[self.crypt_off:self.crypt_off + self.crypt_size]
            self.sect.append(Encryption(self,c, type='crypt'))
        return self.sect

class LoaderDYLDInfo(Loader):
    lht = macho.LC_DYLD_INFO
    lhc = macho.dyld_info_command
    subtypes = ['rebase', 'bind', 'weak_bind', 'lazy_bind', 'export']
    def sectionsToAdd(self, raw):
        self.sect = []
        for type in LoaderDYLDInfo.subtypes:
            of = getattr(self,type+'_off')
            if of != 0:
                c = raw[of:of + getattr(self,type+'_size')]
                self.sect.append(DynamicLoaderInfo(self,c, type=type))
        return self.sect
    
    def changeOffsets(self, decalage, min_offset=None):
        if isOffsetChangeable(self.rebase_off, min_offset):
            self.rebase_off += decalage
        if isOffsetChangeable(self.bind_off, min_offset):
            self.bind_off += decalage
        if isOffsetChangeable(self.weak_bind_off, min_offset):
            self.weak_bind_off += decalage
        if isOffsetChangeable(self.lazy_bind_off, min_offset):
            self.lazy_bind_off += decalage
        if isOffsetChangeable(self.export_off, min_offset):
            self.export_off += decalage


class LoaderDYLDInfoOnly(Loader):
    lht = macho.LC_DYLD_INFO_ONLY
    lhc = macho.dyld_info_command
    subtypes = ['rebase', 'bind', 'weak_bind', 'lazy_bind', 'export']
    def sectionsToAdd(self, raw):
        self.sect = []
        for type in LoaderDYLDInfoOnly.subtypes:
            of = getattr(self,type+'_off')
            if of != 0:
                c = raw[of:of + getattr(self,type+'_size')]
                self.sect.append(DynamicLoaderInfo(self,c, type=type))
        return self.sect
    
    def changeOffsets(self, decalage, min_offset=None):
        if isOffsetChangeable(self.rebase_off, min_offset):
            self.rebase_off += decalage
        if isOffsetChangeable(self.bind_off, min_offset):
            self.bind_off += decalage
        if isOffsetChangeable(self.weak_bind_off, min_offset):
            self.weak_bind_off += decalage
        if isOffsetChangeable(self.lazy_bind_off, min_offset):
            self.lazy_bind_off += decalage
        if isOffsetChangeable(self.export_off, min_offset):
            self.export_off += decalage

class LoaderVersion(Loader):
    lht = macho.LC_VERSION_MIN_MACOSX
    lhc = macho.version_min_command

class LoaderEntryPoint(Loader):
    lht = macho.LC_MAIN
    lhc = macho.entry_point_command
    def changeOffsets(self, decalage, min_offset=None):
        if isOffsetChangeable(self.entryoff, min_offset):
            self.entryoff += decalage

threadStateParameters = { # flavor, count, regsize in 32-bit words
    macho.CPU_TYPE_I386:    (1, 16, 1),
    macho.CPU_TYPE_X86_64:  (4, 42, 2),
    macho.CPU_TYPE_POWERPC: (1, 40, 1),
    macho.CPU_TYPE_ARM:     (1, 17, 1),
    }
class LoaderUnixthread(Loader):
    lht = macho.LC_UNIXTHREAD
    lhc = macho.unixthread_command
    data = data_empty
    def set_entrypoint(self, val):
        registerInstructionPointer = {
            macho.CPU_TYPE_I386: 10,
            macho.CPU_TYPE_X86_64: 16,
            }
        self.data[registerInstructionPointer[self.cputype]] = val
    entrypoint = property(None, set_entrypoint)
    def _parse_content(self):
        if type(self.parent._parent) == dict: self.cputype = self.parent._parent['cputype']
        else:                                self.cputype = self.parent._parent.parent.Mhdr.cputype
        if self.content == data_empty:
            self.lhc.flavor, self.lhc.count, self.regsize = threadStateParameters[self.cputype]
            self.lh.cmdsize += self.lhc.count*4
            data = data_null * (self.lhc.count*4)
        else:
            flavor, count, self.regsize = threadStateParameters[self.cputype]
            if self.lhc.flavor != flavor: FLAVOR_ERROR
            if self.lhc.count  != count:  COUNT_ERROR
            data = self.content[8:8+(self.lhc.count)*4]
        #print "THREAD_STATE %d COUNT %d" % (self.lhc.flavor, self.lhc.count)
        self.packstring = "%s%d%s" % (
            self.sex,
            int(self.lhc.count/self.regsize),
            "Q" if self.regsize == 2 else "I",
            )
        self.data = list(struct.unpack(self.packstring, data))
    def _str_additional_data(self):
        return struct.pack(self.packstring, *self.data)

class LoaderSourceVersion(Loader):
    lht = macho.LC_SOURCE_VERSION
    lhc = macho.source_version_command

class LHList(object):
    def __init__(self, parent, **kargs):
        inherit_sex_wsize(self, parent, kargs)
        self.lhlist = []
        mhdr = self.parent.Mhdr
        of = len(mhdr.pack())
        for i in range(mhdr.ncmds):
            lhstr = parent[of:of+8]
            lh = Loader.create(parent=self, content=lhstr)
            lh._content = StrPatchwork(parent[of+8:of+lh.lh.cmdsize])
            lh.parse_content(parent=self, content=lh._content)
            self.lhlist.append(lh)
            if parent.interval is not None :
                if not parent.interval.contains(of,of+len(lh.pack())):
                    raise ValueError("This part of file has already been parsed")
                #print "LHList interval before", parent.interval
                #print " ---- to delete ---",of,"-",of+len(str(lh)),"/",hex(of),"-",hex(of+len(str(lh)))
                parent.interval.delete(of,of+len(lh.pack()))
            of += lh.lh.cmdsize
        #print "LHList interval after", parent.interval
        #print "'''''''''''''''''''''''''''''''''''''''''"
    def append(self, lh):
        self.lhlist.append(lh)
        self.parent.Mhdr.ncmds += 1
        self.parent.Mhdr.sizeofcmds += len(lh.pack())
    def getpos(self, lht):
        poslist = []
        for lc in self.lhlist:
            if lc.lht == lht :
                poslist.append(self.lhlist.index(lc))
        return poslist
    def removepos(self, pos):
        self.parent.Mhdr.sizeofcmds -= len(self.lhlist[pos].pack())
        self.parent.Mhdr.ncmds-=1
        self.lhlist.remove(self.lhlist[pos])
    def changeOffsets(self, decalage, min_offset=None):
        for lc in self.lhlist:
            lc.changeOffsets(decalage, min_offset)
    
    def addSH(self, s):
        for lc in self.lhlist:
            if isinstance(lc, LoaderSegment) and lc.segname == s.sh.segname:
                lc.addSH(s)
                return True
            if isinstance(lc, LoaderSegment_64) and lc.segname == s.sh.segname:
                lc.addSH(s)
                return True
        return False
    
    def __getitem__(self, item):
        return self.lhlist[item]
    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    def pack(self):
        data = data_empty
        for lc in self.lhlist:
            data += lc.pack()
        return data
    def extendSegment(self,lc,size):
        if lc.maxprot == 0:
            raise ValueError('Maximum Protection is 0')
        lc.filesize += size 
        lc.vmsize += size
        for lco in self.lhlist:
             if hasattr(lco,'segname'):
                if lco.fileoff > lc.fileoff:
                    lco.fileoff += size
                    lco.vmaddr += size
                    if hasattr(lco,'sect'):
                        for s in lco.sect:
                            if not s.offset == 0 :
                                s.offset += size
                            if not s.addr == 0 :
                                s.addr += size
             else :
                if not lco.cmd == 0x80000028:
                    lco.changeOffsets(size)

    def findlctext(self):
        for lc in self.lhlist:
            if lc.cmd == macho.LC_SEGMENT or lc.cmd == macho.LC_SEGMENT_64:
                if lc.is_text_segment():
                    return lc


class FarchList(object):
    def __init__(self, parent, **kargs):
        inherit_sex_wsize(self, parent, kargs)
        self.farchlist = []
        fhdr = self.parent.Fhdr
        of = len(fhdr.pack())
        for i in range(fhdr.nfat_arch):
            fhstr = parent[of+20*i:of+20*(i+1)]
            farch = macho.Farch(parent=self, content=fhstr)
            self.farchlist.append(farch)
            if parent.interval is not None :
                if not parent.interval.contains(of+20*i,of+20*(i+1)):
                    raise ValueError("This part of file has already been parsed")
                parent.interval.delete(of+20*i,of+20*(i+1))
                #print "Farchlist", parent.interval
    def __getitem__(self, item):
        return self.farchlist[item]
    def __str__(self):
        c = []
        for farch in self.farchlist:
            c.append(str(farch))
        return "".join(c)

class MachoList(object):
    def __init__(self, parent, **kargs):
        inherit_sex_wsize(self, parent, kargs)
        self.macholist = []
        for farch in parent.fh:
            macho = MACHO(parent[farch.offset:farch.offset+farch.size],
                          intervals.Intervals().add(0,farch.size))
            macho.offset = farch.offset
            self.macholist.append(macho)
            inverse = intervals.Intervals().add(0,farch.size)
            for j in macho.interval.ranges:
                inverse.delete(j.start,j.stop)
            if not self.parent.interval == None:
                for j in inverse.ranges:
                    if not parent.interval.contains(farch.offset+j.start,farch.offset+j.stop):
                        raise ValueError("This part of file has already been parsed")
                    parent.interval.delete(farch.offset+j.start,farch.offset+j.stop)
    def __getitem__(self, item):
        return self.macholist[item]
    def __str__(self):
        c = []
        for macho in self.macholist:
            c.append(str(macho))
        return "".join(c)

class MachoData(object):
    def get_offset(self):
        return 0
    def set_offset(self, val):
        pass
    def get_addr(self):
        return 0
    def get_size(self):
        return 0
    offset = property(get_offset, set_offset)
    addr = property(get_addr)
    size = property(get_size)

class Section(MachoData):
    def __init__(self, parent, content=None, sh=None, **kargs):
        inherit_sex_wsize(self, parent, kargs)
        self.content = StrPatchwork(content)
        if sh != None:
            self.sh = sh
        else:
            if self.wsize==32 : self.sh = macho.sectionHeader(parent=self,content=None,**kargs)
            if self.wsize==64 : self.sh = macho.sectionHeader_64(parent=self,content=None,**kargs)   
        self._parsecontent()
    def get_offset(self):
        return self.sh.offset
    def set_offset(self, val):
        self.sh.offset = val
    offset = property(get_offset, set_offset)
    def get_addr(self):
        return self.sh.addr
    def set_addr(self,val):
        self.sh.addr = val
    def get_size(self):
        return self.sh.size
    addr = property(get_addr, set_addr)
    size = property(get_size)
    def get_segname(self):
        return self.sh.segname.strip(data_null)
    def set_segname(self, val):
        padding = len(str(self.sh.segname)) - len(val)
        if (padding < 0) : raise ValueError("segname is too long for the structure")
        self.sh.segname = val + data_null*padding
    segname = property(get_segname, set_segname)
    def _parsecontent(self):
        pass
    def pack(self):
        return self.content.pack()
    def __str__(self):
        raise AttributeError("Use pack() instead of str()")

class BaseSymbol(object):
    def pack(self):
        return self.content
    def __str__(self):
        NEVER

class SymbolStub(BaseSymbol):
    def __init__(self, content, address, len_stub, sizeofstubs, adoff_64=0):
        self.content = content
        self.addr = address
        if self.content[0:2] == struct.pack("BB",0xFF,0x25):
            self.off, = struct.unpack("<I",self.content[2:6])
            self.off += adoff_64
    def get_address(self):
        return self.addr
    def set_address(self, val):
        self.addr = val
    def get_offset(self):
        if hasattr(self, 'off'):
            return self.off
        else:
            raise ValueError("Cannot find link between symbol stub and lazy symbol pointers")        
    address = property(get_address, set_address)
    offset = property(get_offset)

class NLSymbolPtr(BaseSymbol):
    def __init__(self, parent, content, off):
        self.content = content
        self.offset = off

class LASymbolPtr(BaseSymbol):
    def __init__(self, parent, content, off):
        self.content = content
        self.offset = off

class SymbolList(Section):
    def __getitem__(self, off):
        for sy in self.list:
            if sy.offset == off:
                return sy
        raise ValueError("Cannot find symbol with the offset")
    def __iter__(self):
        return self.list.__iter__()
    def pack(self):
        data = data_empty
        for x in self.list:
            data += x.pack()
        return data

class SymbolStubList(SymbolList):
    def _parsecontent(self):
        self.list = []
        len_stub=self.sh.reserved2
        #print "self.content", repr(self.content)
        for i in range(int(self.sh.size/len_stub)):
            addr = self.sh.addr + i*len_stub
            if self.wsize == 32:
                self.list.append(SymbolStub(self.content[i*len_stub:(i+1)*len_stub], addr, len_stub, self.sh.size))
            elif self.wsize == 64: #FF25 is an indirect relative jump for 64 bits
                off_next_stub = self.sh.offset + (i+1)*len_stub + self.sh._parent.vmaddr - self.sh._parent.fileoff #function off2addr
                self.list.append(SymbolStub(self.content[i*len_stub:(i+1)*len_stub], addr, len_stub, self.sh.size, off_next_stub))

class NLSymbolPtrList(SymbolList):
    def _parsecontent(self):
        self.list = []
        len_ptr={32: 4, 64: 8}[self.wsize]
        for i in range(int(self.sh.size/len_ptr)):
            self.list.append(NLSymbolPtr(self, self.content[i*len_ptr:(i+1)*len_ptr], self.sh.offset + i*len_ptr))

class LASymbolPtrList(SymbolList):
    def _parsecontent(self):
        self.list = []
        len_ptr={32: 4, 64: 8}[self.wsize]
        for i in range(int(self.sh.size/len_ptr)):
            self.list.append(LASymbolPtr(self, self.content[i*len_ptr:(i+1)*len_ptr], self.sh.offset + i*len_ptr))

class Reloc(Section):
    def _parsecontent(self):
        self.reloclist = []
        len_sym_rel = 8
        for i in range(self.sh.nreloc):
            relocSym = macho.relocationSymbol(parent = self, content = self.content[i*len_sym_rel:(i+1)*len_sym_rel])
            relocSym.offset = i*len_sym_rel
            #print repr(relocSym)
            self.reloclist.append(relocSym)
    def get_offset(self):
        return self.sh.reloff
    def set_offset(self, val):
        self.sh.reloff = val
    offset = property(get_offset, set_offset)
    def pack(self):
        data = StrPatchwork()
        for s in self.reloclist:
            data[s.offset] = s.pack()
        return data.pack()

class LinkEditSection(MachoData):
    def __init__(self, parent, c, type = None):
        inherit_sex_wsize(self, parent, {})
        self.content = StrPatchwork(c)
        self.lc = parent
        self.type = type
        self._parsecontent()
    def _parsecontent(self):
        pass
    def get_offset(self):
        return getattr(self.lc,self.type+'_off')
    def set_offset(self, val):
        setattr(self.lc,self.type+'_off', val)
    offset = property(get_offset, set_offset)
    def get_size(self):
        return getattr(self.lc,self.type+'_size')
    def set_size(self, val):
        setattr(self.lc,self.type+'_size', val)
    size = property(get_size, set_size)
    def pack(self):
        return self.content.pack()
    def __str__(self):
        raise AttributeError("Use pack() instead of str()")

"""
class BindSymbolOpcode(object):
    def __init__(self, content):
        pass
"""

class SymbolOpcode(object):
    def __init__(self, content, parent):
        self.offset = 0
        self.opsize = 0
        content = StrPatchwork(content)
        self.segment, = struct.unpack("B",content[self.opsize:self.opsize+1])
        self.opsize += 1
        """
        self.startuleb = self.opsize
        """
        uleb128termination = False
        while not uleb128termination:
            ulebbyte, = struct.unpack("B",content[self.opsize:self.opsize+1])
            uleb128termination = (ulebbyte < 128)
            self.offset += (ulebbyte % 128) * 128**(self.opsize-1)
            self.opsize += 1
        """
        self.enduleb = self.opsize
        self.uleb = content[self.startuleb:self.enduleb]
        """
        self.dylib, = struct.unpack("B",content[self.opsize:self.opsize+1])
        self.opsize += 1
        if self.dylib == macho.BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            self.libraryOrdinal, = struct.unpack("B",content[self.opsize:self.opsize+1])
            self.opsize += 1
        self.flags,  = struct.unpack("B",content[self.opsize:self.opsize+1])
        self.opsize += 1
        self.name = content[self.opsize:self.opsize+content[self.opsize:].find(data_null)]
        self.opsize += len(self.name)+1
        self.doBind,self.done, = struct.unpack("BB",content[self.opsize:self.opsize+2])
        self.opsize += 2
        #print repr(self)
        self.addr = self.offset + parent.parent.parent._parent.parent.lh.lhlist[self.segment & 0x0f].vmaddr
        self.realoffset = self.offset + parent.parent.parent._parent.parent.lh.lhlist[self.segment & 0x0f].fileoff
        if (self.doBind, self.done) != (0x90, 0):
            self.opsize = 0
            return

    def __repr__(self):
        fields = [ "segment", "offset", "dylib" ]
        if hasattr(self, 'libraryOrdinal'):
            fields.append("libraryOrdinal")
        fields.extend(["flags", "doBind", "done"])
        return "<" + self.__class__.__name__ + " " + " -- ".join([x + " " + hex(getattr(self,x)) for x in fields]) + " -- " + "name" + " " + self.name + ">"

    def __str__(self):
        NEVER

    def pack(self):
        val = self.offset
        uleb = data_empty
        uleb128termination = False
        while not uleb128termination:
            byte = val%128
            val = int(val/128)
            uleb128termination = (val == 0)
            if not uleb128termination:
                byte += 128
            uleb += struct.pack("B", byte)
        if hasattr(self, 'libraryOrdinal'):
            return struct.pack("B",self.segment) + uleb + struct.pack("B",self.dylib) + struct.pack("B",self.libraryOrdinal) + struct.pack("B",self.flags) + self.name+data_null + struct.pack("B",self.doBind) + struct.pack("B",self.done)
        else:
            return struct.pack("B",self.segment) + uleb + struct.pack("B",self.dylib) + struct.pack("B",self.flags) + self.name+data_null + struct.pack("B",self.doBind) + struct.pack("B",self.done)
    def __len__(self):
        return self.opsize

class DynamicLoaderInfo(LinkEditSection):
    def _parsecontent(self):
        """
        if self.type == 'bind':
            of = getattr(self.parent,self.type+'_off')
            if of != 0:
                self.BindSymbolOpcodeList = []
                #print "self.content", repr(self.content)
                offset = 0
                size = len(str(self.content))
                bindSymbolOpcode = BindSymbolOpcode(self.content)
                while bindSymbolOpcode:
                    self.BindSymbolOpcodeList.append(bindSymbolOpcode)
                    offset += len(bindSymbolOpcode)
                    bindSymbolOpcode = BindSymbolOpcode(self.content[offset:])
                print(self.BindSymbolOpcodeList)
        """
        if self.type == 'lazy_bind':
            #print self.type
            of = getattr(self.parent,self.type+'_off')
            #print "offset DynamicLoaderInfo", of
            if of != 0:
                self.SymbolOpcodeList = []
                #print "self.content", repr(self.content)
                offset = 0
                size = len(self.content.pack())
                symbolOpcode = SymbolOpcode(self.content, self)
                while symbolOpcode:
                    self.SymbolOpcodeList.append(symbolOpcode)
                    #print "symbolOpcode", repr(symbolOpcode)
                    offset += len(symbolOpcode)
                    symbolOpcode = SymbolOpcode(self.content[offset:], self)
                #print "self.SymbolOpcodeList", self.SymbolOpcodeList
    def pack(self):
        if self.type == 'lazy_bind':
            data = data_empty
            for x in self.SymbolOpcodeList:
                data += x.pack()
            return data
        else:
            return self.content.pack()

class SymbolTable(LinkEditSection):
    def _parsecontent(self):
        self.symbols = []
        self.symbols_from_name = {}
        of = 0
        one_sym_size = int(self.lc.sym_size/self.lc.nsyms)
        if self.wsize == 32:
            symbol_type = macho.symbol
        elif self.wsize == 64 :
            symbol_type = macho.symbol_64
        for i in range(self.lc.nsyms):
            symbol=symbol_type(parent=self, content=self.content[of:of+one_sym_size])
            symbol.offset = of
            self.symbols.append(symbol)
            of += one_sym_size
    def __getitem__(self, idx):
        if type(idx) == int:
            return self.symbols[idx]
        else:
            return self.symbols_from_name[idx.strip(data_null)]
        raise ValueError("Cannot find symbol with index %r"%idx)
    def pack(self):
        data = StrPatchwork()
        for s in self.symbols:
            data[s.offset] = s.pack()
        return data.pack()

class StringTable(LinkEditSection):
    def _parsecontent(self):
        self.res = {}
        c = self.content
        q = 0
        while c:
            p = c.find(data_null)
            if p < 0:
                log.warning("Missing trailing 0 for string [%s]" % c) # XXX
                p = len(c)
            self.res[q] = c[:p]
            q += p+1
            c = c[p+1:]
    def pack(self):
        data = StrPatchwork()
        for i, name in self.res.items():
            data[i] = name
        data = data.pack()
        padding = self.lc.str_size - len(data)
        return data + data_null*padding

class DySymbolTable(LinkEditSection):
    pass

class FunctionStarts(LinkEditSection):
    pass

class LoaderFunctionStart(LoaderLinkEditDataCommand):
    lht = macho.LC_FUNCTION_STARTS
    sect_class = FunctionStarts

class DataInCode(LinkEditSection):
    pass

class LoaderDataInCode(LoaderLinkEditDataCommand):
    lht = macho.LC_DATA_IN_CODE
    sect_class = DataInCode

class DylibCodeSign(LinkEditSection):
    pass
    """
    def _parsecontent(self):
        self.blobs = []
        of = 0
        while self.content[of:of+2] == '\xfa\xde':
            self.blobs.append(self.content[of:of+20])
            of += 20
        self.string = self.content[of:of+16]
        self.int = self.content[of+16:of+20]
        self.end = self.content[of+20:] # need to be improved
    def __str__(self):
        #if self.wsize == 32:
        return ''.join([str(x) for x in self.blobs]) + self.string + self.int + self.end
        #if self.wsize == 64:
        #    return ''.join([str(x) for x in self.blobs]) + self.string + self.int + '\x00\x00\x00\x00'
    """

class LoaderDylibCodeSign(LoaderLinkEditDataCommand):
    lht = macho.LC_DYLIB_CODE_SIGN_DRS
    sect_class = DylibCodeSign

class CodeSignature(LinkEditSection):
    pass

class LoaderCodeSignature(LoaderLinkEditDataCommand):
    lht = macho.LC_CODE_SIGNATURE
    sect_class = CodeSignature

class Hint(LinkEditSection):
    pass

class Encryption(LinkEditSection):
    pass

class SectionList(object):
    def __init__(self, parent):
        self.parent = parent
        self.sect = []
        for lc in parent.lh:
            if hasattr(lc, 'sectionsToAdd'):
                list=lc.sectionsToAdd(self.parent)
                self.sect.extend(list)
                if not hasattr(lc,'segname'):
                    for s in list:
                        for loco in parent.lh:
                            if hasattr(loco,'segname'):# searching in parent.lh of LC_segment
                                if loco.fileoff < s.offset and s.offset < loco.fileoff + loco.filesize :
                                    loco.sect.append(s)# ajout a sect
                if parent.interval is not None :
                    for s in list:
                        if not (hasattr(s, 'sh') and s.sh.type == macho.S_ZEROFILL):
                            if s.__class__.__name__== 'Encryption':
                                if parent.verbose == True : print("Some encrypted text is not parsed with the section headers of LC_SEGMENT(__TEXT)")
                            else:
                                #print "SectionList interval before", parent.interval
                                #print "-- section --", s.__class__.__name__
                                #print " ---- to delete ---",s.offset,"-",s.offset+len(str(s)),"/",hex(s.offset),"-",hex(s.offset+len(str(s)))
                                if not parent.interval.contains(s.offset,s.offset+len(s.pack())):
                                    raise ValueError("This part of file has already been parsed")
                                parent.interval.delete(s.offset,s.offset+len(s.pack()))
    def add(self, s):
        # looking in s.lc to know where to insert
        pos = 0
        for lc in self.parent.lh:
            if not hasattr(lc, 'sect'):
                pass
            elif s in lc.sect:
                pos += lc.sect.index(s)
                self.sect[pos:pos] = [s]
                break
            else:
                pos += len(lc.sect)

    def getpos(self, section):
        poslist = []
        for i, s in enumerate(self.sect):
            if s == section :
                poslist.append(i)
        return poslist
    def removepos(self, pos):
        self.sect.remove(self.sect[pos])
    def __iter__(self):
        return self.sect
    def __repr__(self):
        return "".join(str(self.sect))
    def __str__(self):
        raise ValueError('class Section cannot be output as a bytestream')

class virt(object):
    def __init__(self, x):
        self.parent = x

    def __call__(self, ad_start, ad_stop = None, section = None):
        rva_items = self.get_rvaitem(slice(ad_start, ad_stop), section)
        data_out = ""
        for s, n_item in rva_items:
            data_out += s.content[n_item]
        return data_out
    
    def __getitem__(self, item):
        rva_items = self.get_rvaitem(item)
        data_out = ""
        for s, n_item in rva_items:
            data_out += s.content[n_item]
        return data_out
    
    def __setitem__(self, item, data):
        if not type(item) is slice:
            item = slice(item, item+len(data))
        rva_items = self.get_rvaitem(item)
        off = 0
        for s, n_item in rva_items:
            #print "s", s, "n_item", n_item
            i = slice(off,n_item.stop + off - n_item.start)
            data_slice = data[i]
            s.content[n_item] = data_slice
            #print "s.content[n_item]", s.content[n_item]
            off = i.stop
    
    def get_rvaitem(self, item, section_name = None):
        if item.step != None:
            raise ValueError("pas de step")
        if item.stop == None:
            s = self.parent.getsectbyvad(item.start, section_name)
            if not s:
                raise ValueError('unknown rva address! 0x%x'%item.start)
            s_start = item.start - s.addr
            n_item = slice(s_start, s.size)
            return [ (s, n_item) ]
        total_len = item.stop - item.start
        virt_item = []
        start = item.start
        while total_len:
            s = self.parent.getsectbyvad(start, section_name)
            if not s:
                raise ValueError('unknown rva address! 0x%x'%start)
            s_start = start - s.addr
            s_stop = item.stop - s.addr
            if s_stop > s.size:
                s_stop =  s.size
            s_len = s_stop - s_start
            if s_len == 0:
                print("GETRVAITEM %r %s %s" % (s, hex(s.addr), s.size))
                raise ValueError('empty section at address 0x%x'%start)
            total_len -= s_len
            start += s_len
            n_item = slice(s_start, s_stop)
            virt_item.append((s, n_item))
        return virt_item

    def __len__(self):
        l=0
        for lc in self.parent.lh.lhlist:
            if hasattr(lc, 'vmaddr'):
                l = max(l, lc.vmaddr+lc.vmsize)
        if  not l:
            raise ValueError('maximum virtual address not found !')
        return l


# MACHO object
class MACHO(object):
    def __init__(self, machostr, interval=None, verbose=False, parseSymbols=True):
        self.interval = interval
        self.verbose = verbose
        self._content = machostr
        self.parse_content()
        if parseSymbols and hasattr(self, 'Mhdr'):
            self.parse_symbols()
        self._virt = virt(self)
    def get_virt(self):
        return self._virt
    virt = property(get_virt)
    
    content = ContentManager()
    def parse_content(self):
        magic, = struct.unpack("<I",self.content[0:4])
        if  magic == macho.MH_MAGIC:
            self.sex = '<'
            self.wsize = 32
            self.Mhdr = macho.Mhdr(parent=self, content=self.content)
        if  magic == macho.MH_CIGAM:
            self.sex = '>'
            self.wsize = 32
            self.Mhdr = macho.Mhdr(parent=self, content=self.content)
        if  magic == macho.MH_MAGIC_64:
            self.sex = '<'
            self.wsize = 64
            self.Mhdr = macho.Mhdr_64(parent=self, content=self.content)
        if  magic == macho.MH_CIGAM_64:
            self.sex = '>'
            self.wsize = 64
            self.Mhdr = macho.Mhdr_64(parent=self, content=self.content)
        if  magic == macho.FAT_MAGIC or magic == macho.FAT_CIGAM:
            self.sex = '<' if magic == macho.FAT_MAGIC else '>'
            self.wsize = 0
            self.Fhdr = macho.Fhdr(parent=self, content=self.content)
            if self.verbose: print("FHDR is %r" % self.Fhdr)
            self.fh = FarchList(self)
            self.arch = MachoList(self)
            self.rawdata = []
            return
        if self.verbose: print("MHDR is %r" % self.Mhdr)
        self.lh = LHList(self)
        self.sect = SectionList(self)
        for sect in self.sect.sect:
            if type(sect) != SymbolTable:
                continue
            for symbol in sect.symbols:
                sect.symbols_from_name[symbol.name] = symbol
        self.rawdata = []

    def parse_symbols(self):
        lctext = self.lh.findlctext()
        if self.Mhdr.cputype == macho.CPU_TYPE_I386 or self.Mhdr.cputype == macho.CPU_TYPE_X86_64:
            if lctext != None and lctext.flags == macho.SG_PROTECTED_VERSION_1:
                if self.verbose: print("cannot parse dynamic symbols because of encryption")
            else:
                self.parse_dynamic_symbols()
        else:
            if self.verbose: print("parse_dynamic_symbols() can only be used with x86 architectures")

    def __getitem__(self, item):
        return self.content[item]
    
    def pack(self):
        if hasattr(self,'Mhdr'):
            c = StrPatchwork()
            mhdr = self.Mhdr.pack()
            c[0] = mhdr
            offset = len(mhdr)
            c[offset] = self.lh.pack()
            for s in self.sect.sect:
                if not s.__class__.__name__== 'Encryption':
                    c[s.offset] = s.pack()
            for offset, data in self.rawdata:
                c[offset] = data
            return c.pack()
        elif hasattr(self,'Fhdr'):
            c = StrPatchwork()
            fhdr = self.Fhdr.pack()
            c[0] = fhdr
            offset = len(fhdr)
            c[offset] = self.fh.pack()
            for macho in self.arch.macholist:
                c[macho.offset] = macho.pack()
            for offset, data in self.rawdata:
                c[offset] = data
            return c.pack()
    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    
    def getsectbyname(self, name):
        for s in self.sect.sect:
            if s.sectname.strip(data_null) == name:
                return s
        return None

    def getsectbyvad(self, ad, section_name = None):
        if section_name:
            s = self.getsectbyname(section_name)
            if s.addr <= ad < s.addr+s.size:
                return s
        f = []
        for s in self.sect.sect:
            if s.addr <= ad < s.addr+s.size:
                f.append(s)
        return f[0]

    def getsegment_byoffset(self, of):
        f = []
        for lc in self.lh.lhlist:
            if hasattr(lc,'fileoff'):
                if lc.fileoff <= of < lc.fileoff + lc.filesize:
                    f.append(lc)
        return f[0]

    def off2ad(self, of):
        lc = self.getsegment_byoffset(of)
        return of - lc.fileoff + lc.vmaddr
    
    def mem2file(self, ad):
        f = []
        for s in self.sect.sect:
            if s.addr <= ad < s.addr+s.size:
                f.append(ad-s.addr+s.offset)
        return f
    
    def add(self, *args, **kargs):
        if args:
            s= args[0]
            if hasattr(self,'fh'):
                for f in self.fh.farchlist:
                    if f._content.wsize == s.wsize:
                        f._content.add(s)
                return
            if isinstance(s, Section):
                if not self.lh.addSH(s):
                    print("s.content %s" % s.content)
                    print("s.sex %s" % s.sex)
                    print("s.wsize %s" % s.wsize)
                    print("s.sh %r" % s.sh)
                    print("s.sh.segname %r" % s.sh.segname)
                    raise ValueError('addSH failed')
                if not s.sh.size == len(str(s)) : raise ValueError("s.sh.size and len(str(s)) differ")
                self.sect.add(s)
                self.Mhdr.sizeofcmds += len(str(s.sh))
            if isinstance(s, Loader):
                s.cmdsize = len(str(s))
                self.Mhdr.sizeofcmds += len(str(s))
                self.Mhdr.ncmds += 1
                if hasattr(s, 'segname'):
                    fileoff = 0
                    vmaddr = 0x1000
                    diff = 0
                    for lc in self.lh.lhlist:
                        if hasattr(lc, 'segname'):
                            if not lc.fileoff == fileoff:
                                diff = lc.fileoff-fileoff
                            fileoff = lc.fileoff
                            vmaddr = lc.vmaddr
                    s.fileoff = fileoff + diff
                    s.vmaddr = vmaddr + diff
                self.lh.lhlist.append(s)
        elif kargs:
            if 'parent' in kargs:
                parent = kargs['parent']
            else:
                parent = None
            if 'sex' in kargs:
                sex = kargs['sex']
            else:
                sex = self.sex
            if 'wsize' in kargs:
                wsize = kargs['wsize']
            else:
                wsize= self.wsize
            type = kargs['type']
            nwlc = Loader.create(parent=parent,sex=sex,wsize=wsize, content=struct.pack("<II",type.lht,0))
            if 'segname' in kargs :
                nwlc.segname = kargs['segname']
            else:
                nwlc.segname = None
            if 'initprot' in kargs :
                nwlc.initprot = kargs['initprot']
            if 'maxprot' in kargs :
                nwlc.maxprot = kargs['maxprot']
            else :
                nwlc.maxprot = macho.SEGMENT_READ|macho.SEGMENT_WRITE|macho.SEGMENT_EXECUTE            
            if 'content' in kargs :
                content = kargs['content']
                nwsh = Section(self, sex=sex, wsize=wsize, content=content)
                if not nwlc.segname==None:
                    nwsh.sh.segname = nwlc.segname
            self.add(nwlc)
            self.add(nwsh)

    def changeUUID(self, uuid):
        for lc in self.lh.lhlist:
            if hasattr(lc, 'changeUUID'):
                lc.changeUUID(uuid)

    def changeStart(self):
        self.sect.sect[0].content[0]='\0'

    def incompletedPosVal(self):
        result = []
        if hasattr(self,'Fhdr'):
            for arch in self.arch.macholist:
                result.extend([(pos+macho.offset, val) for (pos, val) in arch.incompletedPosVal()])
            return result
        if hasattr(self,'Mhdr'):
            for lc in self.lh.lhlist:
                if lc.cmd == macho.LC_SEGMENT_64 and lc.is_text_segment():
                    for s in lc.sh:
                        if s.is_text_section():
                            if s.size%2 == 1 :
                                pos, val = s.offset+s.size, struct.pack("B",0x90)
                                if struct.pack("B",self[pos])==val:
                                    result.append((pos,val))
            return result

    def checkParsedCompleted(self, **kargs):
        if self.interval == None :
            raise ValueError("No interval argument in macho_init call")
        result = []
        for i in self.interval :
            data = self._content[i:i+1]
            if data != data_null :
                result.append((i, data))
        if 'detect_nop' in kargs and kargs['detect_nop']:
            for pos, val in self.incompletedPosVal():
                if (pos,val) in result:
                    self.rawdata.append((pos,val))
                    result.remove((pos,val))

        if 'add_rawdata' in kargs and kargs['add_rawdata']:
            for pos, val in result:
                self.rawdata.append( (pos, val) )
            result = []
        return result

    def get_stringtable(self):
        for strtab in self.sect.sect:
            if hasattr(strtab, 'res'):
                return strtab
    stringtable=property(get_stringtable,None)

    def get_lib(self, val):
        for lc in self.lh.lhlist :
            if lc.cmd == 0x0C:
                val-=1
                if val == 0 :
                    return lc.name
        raise ValueError('cannot find lib')

    def parse_dynamic_symbols(self):
        if not len(self.sect.sect):
            return
        nl_symbol_ptr = None
        for s in self.sect.sect:
            if hasattr(s, 'sh'):
                if s.sh.type == macho.S_NON_LAZY_SYMBOL_POINTERS:
                    nl_symbol_ptr = s
                    break

        for s in self.sect.sect:
            if hasattr(s, 'sh'):
                if s.sh.type == macho.S_LAZY_SYMBOL_POINTERS:
                    la_symbol_ptr = s
                    break

        for s in self.sect.sect:
            if hasattr(s, 'sh') :
                if s.sh.type == macho.S_SYMBOL_STUBS:
                    symbol_stub = s
                    break

        hasDyldLazy = 0
        for s in self.sect.sect:
            if hasattr(s, 'SymbolOpcodeList'):
                #print s.SymbolOpcodeList
                dynamic_loader_info_lazy = s
                hasDyldLazy = 1
                break
        for s in self.sect.sect:
            if hasattr(s, 'BindSymbolOpcodeList'):
                dynamic_loader_info_bind = s
                break

        for s in self.sect.sect:
            if hasattr(s, 'symbols'):
                symbol_table = s
                break
        # modif de symbol_stub pour les decalages dependant de la position de la_symbol_ptr
        hasimport = 0
        for lc in self.lh.lhlist:
            if hasattr(lc, 'segname'):
                if lc.segname == "__IMPORT":
                    hasimport = 1
                    break
        if hasDyldLazy :
            for symbol in dynamic_loader_info_lazy.SymbolOpcodeList:
                symbol.pointer = la_symbol_ptr[symbol.realoffset]
                la_symbol_ptr[symbol.realoffset].binding = symbol
                symbol.stub = symbol_stub[symbol.addr]
                symbol_stub[symbol.addr].binding = symbol
                symbol_table[symbol.name].stub = symbol_stub[symbol.addr]
            """
            for symbol in dynamic_loader_info_bind.BindSymbolOpcodeList:
                if symbol.name.strip('\0') in ['dyld_stub_binder', 'ABSOLUTE']:
                    continue
                # We should probably never get here
                # if we reach this place, then some more analysis of Mach-O is needed
                symbol.pointer = nl_symbol_ptr[symbol.offset]
                nl_symbol_ptr[symbol.offset].binding = symbol
                symbol.stub = stub_helper[symbol.offset]
                stub_helper[symbol.offset].binding = symbol
                symbol_table[symbol.name].stub = stub_helper[symbol.offset]
            """
    
        else :
            if nl_symbol_ptr is not None :
                indstubIndex = 0
                for indstub in nl_symbol_ptr:
                    symbol_table[indstubIndex].stub = indstub
                    indstubIndex += 1
                for indstub in symbol_stub:
                    symbol_table[indstubIndex].stub = indstub
                    indstubIndex += 1
            else:
                pass #should be implemented

    def get_sym_value(self, name):
        for s in self.sect.sect:
            if hasattr(s, 'symbols'):
                symbol_table = s
                break
        #symbol_table = # ...
        #return symbol_table[symbol.name].stub.address
        if hasattr(symbol_table[name], 'stub'):
            return symbol_table[name].stub.address
        else:
            return 0
