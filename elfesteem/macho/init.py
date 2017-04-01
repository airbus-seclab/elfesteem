from elfesteem.macho.sections import *
from elfesteem.macho.loaders import *
from elfesteem import intervals
import struct

#### Source: /usr/include/mach/vm_prot.h

#      Protection values, defined as bits within the vm_prot_t type

VM_PROT_NONE         = 0x00
VM_PROT_READ         = 0x01      # read permission
VM_PROT_WRITE        = 0x02      # write permission
VM_PROT_EXECUTE      = 0x04      # execute permission
# The default protection for newly-created virtual memory
VM_PROT_DEFAULT      = (VM_PROT_READ|VM_PROT_WRITE)
# The maximum privileges possible, for parameter checking.
VM_PROT_ALL          = (VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE)

# An invalid protection value.
# Used only by memory_object_lock_request to indicate no change
# to page locks.  Using -1 here is a bad idea because it
# looks like VM_PROT_ALL and then some.
VM_PROT_NO_CHANGE    = 0x08

# When a caller finds that he cannot obtain write permission on a
# mapped entry, the following flag can be used.  The entry will
# be made "needs copy" effectively copying the object (using COW),
# and write permission will be added to the maximum protections
# for the associated entry. 
VM_PROT_COPY         = 0x10

# Another invalid protection value.
# Used only by memory_object_data_request upon an object
# which has specified a copy_call copy strategy. It is used
# when the kernel wants a page belonging to a copy of the
# object, and is only asking the object as a result of
# following a shadow chain. This solves the race between pages
# being pushed up by the memory manager and the kernel
# walking down the shadow chain.
VM_PROT_WANTS_COPY   = 0x10 # (yes, vm_prot.h puts the same value as above)

# Another invalid protection value.
# Indicates that the other protection bits are to be applied as a mask
# against the actual protection bits of the map entry.
VM_PROT_IS_MASK      = 0x40

# Another invalid protection value to support execute-only protection.
# VM_PROT_STRIP_READ is a special marker that tells mprotect to not
# set VM_PROT_READ. We have to do it this way because existing code
# expects the system to set VM_PROT_READ if VM_PROT_EXECUTE is set.
# VM_PROT_EXECUTE_ONLY is just a convenience value to indicate that
# the memory should be executable and explicitly not readable. It will
# be ignored on platforms that do not support this type of protection.
VM_PROT_STRIP_READ   = 0x80
VM_PROT_EXECUTE_ONLY = (VM_PROT_EXECUTE|VM_PROT_STRIP_READ)


#### Source: /usr/include/mach-o/fat.h

FAT_MAGIC     = 0xcafebabe
FAT_CIGAM     = 0xbebafeca # NXSwapLong(FAT_MAGIC)
# The support for the 64-bit fat file format described here is a work in
# progress and not yet fully supported in all the Apple Developer Tools.
FAT_MAGIC_64  = 0xcafebabf
FAT_CIGAM_64  = 0xbfbafeca # NXSwapLong(FAT_MAGIC_64)

class fat_header(CStruct):
    _fields = [
        ("magic","u32"),     # FAT_MAGIC or FAT_MAGIC_64
        ("nfat_arch","u32"), # number of structs that follow
        ]
    def __init__(self, *args, **kargs):
        CStruct.__init__(self, *args, **kargs)
        if self.parent.interval is not None :
            self.parent.interval.delete(0,8)

class fat_arch(CStruct):
    _fields = [
        ("cputype","u32"),    # cpu specifier (int)
        ("cpusubtype","u32"), # machine specifier (int)
        ("offset","u32"),     # file offset to this object file
        ("size","u32"),       # size of this object file
        ("align","u32"),      # alignment as a power of 2
        ]

class fat_arch_64(CStruct):
    _fields = [
        ("cputype","u32"),    # cpu specifier (int)
        ("cpusubtype","u32"), # machine specifier (int)
        ("offset","u64"),     # file offset to this object file
        ("size","u64"),       # size of this object file
        ("align","u32"),      # alignment as a power of 2
        ("reserved","u32"),
        ]

class FarchList(CArray):
    _cls = fat_arch
    count = lambda _: _.parent.Fhdr.nfat_arch
    # TODO: update self.parent.interval
    #       self.parent.interval.delete(of+20*i,of+20*(i+1))

class MachoList(CBase):
    def unpack(self, c, o):
        self.macholist = []
        for farch in self.parent.fh:
            e = MACHO(c[farch.offset:farch.offset+farch.size],
                      interval=intervals.Intervals().add(0,farch.size),
                      parseSymbols=self.parent.fh.parseSymbols)
            e.offset = farch.offset
            self.macholist.append(e)
            inverse = intervals.Intervals().add(0,farch.size)
            for j in e.interval.ranges:
                inverse.delete(j.start,j.stop)
            if not self.parent.interval == None:
                for j in inverse.ranges:
                    if not self.parent.interval.contains(farch.offset+j.start,farch.offset+j.stop):
                        raise ValueError("This part of file has already been parsed")
                    self.parent.interval.delete(farch.offset+j.start,farch.offset+j.stop)
    def __getitem__(self, item):
        return self.macholist[item]


#### Generic elfesteem data structures

class virt(object):
    def __init__(self, x):
        self.parent = x

    def __call__(self, ad_start, ad_stop = None, section = None):
        rva_items = self.get_rvaitem(slice(ad_start, ad_stop), section = section)
        data_out = data_empty
        for s, n_item in rva_items:
            data_out += s.content[n_item]
        return data_out
    
    def __getitem__(self, item):
        rva_items = self.get_rvaitem(item)
        data_out = data_empty
        for s, n_item in rva_items:
            data_out += s.content[n_item]
        return data_out
    
    def __setitem__(self, item, data):
        if not type(item) is slice:
            item = slice(item, item+len(data))
        rva_items = self.get_rvaitem(item)
        off = 0
        for s, n_item in rva_items:
            i = slice(off,n_item.stop + off - n_item.start)
            data_slice = data[i]
            s.content[n_item] = data_slice
            off = i.stop
    
    def get_rvaitem(self, item, section = None):
        if item.step != None:
            raise ValueError("pas de step")
        if item.stop == None:
            s = self.parent.getsectionbyvad(item.start, section = section)
            if not s:
                raise ValueError('unknown rva address! 0x%x'%item.start)
            s_start = item.start - s.addr
            n_item = slice(s_start, s.size)
            return [ (s, n_item) ]
        total_len = item.stop - item.start
        virt_item = []
        start = item.start
        while total_len:
            s = self.parent.getsectionbyvad(start, section = section)
            if s is None:
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
        # __len__ should not be used: Python returns an int object, which
        # will cap values to 0x7FFFFFFF on 32 bit systems. A binary can have
        # a base address higher than this, resulting in the impossibility to
        # handle such programs.
        log.warn("__len__ deprecated")
        return self.max_addr()
    def max_addr(self):
        l=0
        for lc in self.parent.load:
            if hasattr(lc, 'vmaddr'):
                l = max(l, lc.vmaddr+lc.vmsize)
        return l


# MACHO object
class MACHO(object):
    # Either a FAT file, or a normal Mach-O file (TODO: ar archives)
    # Normal Mach-O file
    #   Mhdr     Header
    #   load     Load commands
    #   sect     Sections (true sections and also chunks in __LINKEDIT)
    #   rawdata  Unanalyzed data
    # FAT file
    #   Fhdr     Header
    #   fh       list of architectures
    #   arch     list of normal Mach-O files
    #   rawdata  Unanalyzed data
    def __init__(self, data, interval=None, parseSymbols=True):
        if interval is True:
            interval = intervals.Intervals().add(0,len(data))
        self.interval = interval
        self.content = StrPatchwork(data)
        self.parse_content(parseSymbols=parseSymbols)
        self._virt = virt(self)
    def get_virt(self):
        return self._virt
    virt = property(get_virt)
    
    def parse_content(self, parseSymbols=True):
        magic, = struct.unpack("<I",self.content[0:4])
        if  magic == FAT_MAGIC or magic == FAT_CIGAM:
            if   magic == FAT_MAGIC: self.sex = '<'
            elif magic == FAT_CIGAM: self.sex = '>'
            self.wsize = 0
            self.Fhdr = fat_header(parent=self, content=self.content)
            of = len(self.Fhdr.pack())
            self.fh = FarchList(parent=self, content=self.content, start=of)
            self.fh.parseSymbols = parseSymbols
            self.arch = MachoList(parent=self, content=self.content)
            self.rawdata = []
        elif  self.content[0:7] == '!<arch>':
            # a Mach-O FAT file may contain ar archives, called "Static
            # archive libraries",
            # cf. https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachOTopics/1-Articles/building_files.html
            # elfesteem does not know how to parse ar archives
            raise ValueError("ar archive")
        elif  magic in (MH_MAGIC, MH_MAGIC_64,
                        MH_CIGAM, MH_CIGAM_64):
            if   magic == MH_MAGIC:    self.sex, self.wsize = '<', 32
            elif magic == MH_CIGAM:    self.sex, self.wsize = '>', 32
            elif magic == MH_MAGIC_64: self.sex, self.wsize = '<', 64
            elif magic == MH_CIGAM_64: self.sex, self.wsize = '>', 64
            self.Mhdr = mach_header(parent=self, content=self.content)
            of = len(self.Mhdr.pack())
            self.load = LoadCommands(parent=self, content=self.content, start=of)
            self.sect = Sections(self)
            for sect in self.sect:
                if type(sect) == SymbolTable:
                    self.symbols = sect
                    break
            else:
                self.symbols = None
            if parseSymbols:
                self.parse_symbols()
            # 'rawdata' is a list of pairs (position, byte) that is used by
            # pack() to reconstruct what was not parsed by analysing the
            # headers. Null padding is not memorized.
            self.rawdata = []
            if self.interval is not None:
                for i in self.interval:
                    data = self.content[i:i+1]
                    if data != data_null:
                        self.rawdata.append( (i, data) )
                if len(self.rawdata):
                    log.warn("Part of the file was not parsed: %d bytes", len(self.rawdata))
        else:
            raise ValueError("Not a Mach-O file")

    def parse_symbols(self):
        lctext = self.load.findlctext()
        if self.Mhdr.cputype in (CPU_TYPE_I386, CPU_TYPE_X86_64):
            if lctext != None and lctext.flags == SG_PROTECTED_VERSION_1:
                log.warn("cannot parse dynamic symbols because of encryption")
            else:
                self.parse_dynamic_symbols()
        else:
            log.warn("parse_dynamic_symbols() can only be used with x86 architectures, not %s", self.Mhdr.cputype)

    def pack(self):
        if hasattr(self,'Mhdr'):
            c = StrPatchwork()
            mhdr = self.Mhdr.pack()
            c[0] = mhdr
            offset = len(mhdr)
            c[offset] = self.load.pack()
            for s in self.sect:
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
            for e in self.arch.macholist:
                c[e.offset] = e.pack()
            for offset, data in self.rawdata:
                c[offset] = data
            return c.pack()
    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    
    def entrypoint(self):
        ep = [ _ for _ in self.load if _.cmd in (LC_MAIN, LC_UNIXTHREAD) ]
        if len(ep) != 1: raise ValueError("Loader with entrypoint %s" % ep)
        if ep[0].cmd == LC_MAIN: return self.off2ad(ep[0].entryoff)
        if ep[0].cmd == LC_UNIXTHREAD: return ep[0].entrypoint
    def set_entrypoint(self, val):
        ep = [ _ for _ in self.load if _.cmd in (LC_MAIN, LC_UNIXTHREAD) ]
        if len(ep) != 1: raise ValueError("Loader with entrypoint %s" % ep)
        if ep[0].cmd == LC_MAIN: ep[0].entryoff = self.ad2off(val)
        if ep[0].cmd == LC_UNIXTHREAD: ep[0].entrypoint = val
    entrypoint = property(entrypoint, set_entrypoint)

    def getsectionbyname(self, name):
        for s in self.sect:
            if hasattr(s, 'sh') and name == "%s,%s"%(s.sh.segname,s.sh.sectname):
                return s
        return None

    def getsectionbyvad(self, ad, section = None):
        if section:
            s = self.getsectionbyname(section)
            if s.addr <= ad < s.addr+s.size:
                return s
        f = []
        for s in self.sect:
            if not hasattr(s, 'name'):
                continue
            if s.addr <= ad < s.addr+s.size:
                f.append(s)
        if len(f) == 0: return None
        return f[0]

    def getsegment_byoffset(self, of):
        f = []
        for lc in self.load:
            if hasattr(lc,'fileoff'):
                if lc.fileoff <= of < lc.fileoff + lc.filesize:
                    f.append(lc)
        return f[0]

    def ad2off(self, ad):
        s = self.getsectionbyvad(ad)
        return ad - s.addr + s.offset
    
    def off2ad(self, of):
        lc = self.getsegment_byoffset(of)
        return of - lc.fileoff + lc.vmaddr
    
    def mem2file(self, ad):
        f = []
        for s in self.sect:
            if s.addr <= ad < s.addr+s.size:
                f.append(ad-s.addr+s.offset)
        return f
    
    def has_relocatable_sections(self):
        return self.Mhdr.filetype == MH_OBJECT
    
    def add(self, *args, **kargs):
        if args:
            s= args[0]
            if hasattr(self,'fh'):
                for f in self.fh:
                    if f.content.wsize == s.wsize:
                        f.content.add(s)
                return
            if isinstance(s, Section):
                if not self.load.addSH(s):
                    print("s.content %s" % s.content.pack())
                    print("s.sex %s" % s.sex)
                    print("s.wsize %s" % s.wsize)
                    print("s.sh %r" % s.sh)
                    print("s.sh.segname %r" % s.sh.segname)
                    raise ValueError('addSH failed')
                if not s.parent.size == len(s.pack()) : raise ValueError("s.parent.size and len(s.pack()) differ")
                self.sect.add(s)
                self.Mhdr.sizeofcmds += len(s.parent.pack())
            if hasattr(s, 'cmd'): # Load Command
                if hasattr(s, 'segname'):
                    fileoff = 0
                    vmaddr = 0x1000
                    diff = 0
                    for lc in self.load:
                        if hasattr(lc, 'segname'):
                            if not lc.fileoff == fileoff:
                                diff = lc.fileoff-fileoff
                            fileoff = lc.fileoff
                            vmaddr = lc.vmaddr
                    s.fileoff = fileoff + diff
                    s.vmaddr = vmaddr + diff
                self.load.append(s)
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
            nwlc = LoadCommand(parent=parent, sex=sex, wsize=wsize, cmd=type)
            if 'segname' in kargs :
                nwlc.segname = kargs['segname']
            else:
                nwlc.segname = None
            if 'initprot' in kargs :
                nwlc.initprot = kargs['initprot']
            if 'maxprot' in kargs :
                nwlc.maxprot = kargs['maxprot']
            else :
                nwlc.maxprot = VM_PROT_ALL
            if 'content' in kargs :
                nwsh = Section(parent=sectionHeader(parent=self.load),
                               content=kargs['content'])
                if not nwlc.segname==None:
                    nwsh.parent.segname = nwlc.segname
            self.add(nwlc)
            self.add(nwsh)

    def changeUUID(self, uuid):
        for lc in self.load:
            if hasattr(lc, 'changeUUID'):
                lc.changeUUID(uuid)

    def changeStart(self):
        self.sect.sect[0].content[0]='\0'

    def incompletedPosVal(self):
        result = []
        if hasattr(self,'Fhdr'):
            for arch in self.arch.macholist:
                result.extend([(pos+arch.offset, val) for (pos, val) in arch.incompletedPosVal()])
            return result
        if hasattr(self,'Mhdr'):
            for lc in self.load:
                if lc.cmd == LC_SEGMENT_64 and lc.is_text_segment():
                    for s in lc.sh:
                        if s.is_text_section():
                            if s.size%2 == 1 :
                                pos, val = s.offset+s.size, struct.pack("B",0x90)
                                if self[pos]==val:
                                    result.append((pos,val))
            return result

    def checkParsedCompleted(self, **kargs):
        if self.interval == None :
            raise ValueError("No interval argument in macho_init call")
        result = []
        for i in self.interval :
            data = self.content[i:i+1]
            if data != data_null :
                result.append((i, data))
        if 'detect_nop' in kargs and kargs['detect_nop']:
            for pos, val in self.incompletedPosVal():
                if (pos,val) in result:
                    self.rawdata.append((pos,val))
                    result.remove((pos,val))
        return result

    def get_lib(self, val):
        for lc in self.load:
            if lc.cmd == 0x0C:
                val-=1
                if val == 0 :
                    return lc.name
        raise ValueError('cannot find lib')

    def parse_dynamic_symbols(self):
        if not len(self.sect):
            return
        for s in self.sect:
            if hasattr(s, 'sh'):
                if s.sh.type == S_NON_LAZY_SYMBOL_POINTERS:
                    nl_symbol_ptr = s
                    break
        else:
            nl_symbol_ptr = None

        for s in self.sect:
            if hasattr(s, 'sh'):
                if s.sh.type == S_LAZY_SYMBOL_POINTERS:
                    la_symbol_ptr = s
                    break
        else:
            la_symbol_ptr = None

        for s in self.sect:
            if hasattr(s, 'sh') :
                if s.sh.type == S_SYMBOL_STUBS:
                    symbol_stub = s
                    break
        else:
            symbol_stub = None

        hasDyldLazy = 0
        for s in self.sect:
            if hasattr(s, 'SymbolOpcodeList'):
                #print s.SymbolOpcodeList
                dynamic_loader_info_lazy = s
                hasDyldLazy = 1
                break
        for s in self.sect:
            if hasattr(s, 'BindSymbolOpcodeList'):
                dynamic_loader_info_bind = s
                break

        for s in self.sect:
            if hasattr(s, 'symbols'):
                symbol_table = s
                break
        # modif de symbol_stub pour les decalages dependant de la position de la_symbol_ptr
        hasimport = 0
        for lc in self.load:
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
        else :
            indstubIndex = 0
            if nl_symbol_ptr is not None :
                for indstub in nl_symbol_ptr:
                    symbol_table[indstubIndex].stub = indstub
                    indstubIndex += 1
            if symbol_stub is not None :
                for indstub in symbol_stub:
                    symbol_table[indstubIndex].stub = indstub
                    indstubIndex += 1

    def get_sym_value(self, name):
        for s in self.sect:
            if hasattr(s, 'symbols'):
                symbol_table = s
                break
        if hasattr(symbol_table[name], 'stub'):
            return symbol_table[name].stub.address
        else:
            return 0
