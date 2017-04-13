# RPRC syntax: firmware format used by rpmsg

# The main source of information on this format is
#  https://github.com/ohadbc/sysbios-rpmsg
# A tool that reads the content of a RPRC .bin file is
#  https://github.com/ohadbc/sysbios-rpmsg/blob/master/src/utils/rprcfmt.h
#  https://github.com/ohadbc/sysbios-rpmsg/blob/master/src/utils/readrprc.c
# But the last version of this tool (tagged "new ABI") does not correspond
# to the RPRC files downloadable at http://goo.gl/4dndeg
# For example, the size of resources is 76 bytes, while in the new ABI it
# is 96 bytes. All examples of output of 'readrprc' that are found in this
# repository and in the following links have 76-bytes long resources.
#  https://github.com/radare/radare2/issues/1602
#  http://omappedia.org/wiki/RPMsg_BIOS_Sources
#  http://www.omappedia.com/wiki/RPMsg_Tesla
#  http://omappedia.org/wiki/Debugging_RPMsg#Readrprc_Utility
#  http://omappedia.org/wiki/RPMsg_BIOS_Sources#SYS.2FBIOS_RPMsg_Customizations
#  http://omappedia.org/wiki/Design_Overview_-_RPMsg#Firmware_Image_Format
# Currently, we don't know if there is a flag that tells when the "new ABI"
# is used, e.g. a value of 'version' greater than 2 in the header.

import struct
from elfesteem.cstruct import CBase, CData, CStruct, data_null, data_empty
from elfesteem.strpatchwork import StrPatchwork

# Section types
FW_RESOURCE    = 0
FW_TEXT        = 1
FW_DATA        = 2

# Resource types (old ABI)
RSC_CARVEOUT    = 0
RSC_DEVMEM      = 1
RSC_DEVICE      = 2
RSC_IRQ         = 3
RSC_TRACE       = 4
RSC_BOOTADDR    = 5
RSC_VRING       = 6

# Resource types (new ABI)
RSC_CARVEOUT    = 0
RSC_DEVMEM      = 1
RSC_TRACE       = 2
RSC_VRING       = 3
RSC_VIRTIO_HDR  = 4
RSC_VIRTIO_CFG  = 5

class Header(CStruct):
    _fields = [ ("magic","4s"), 
                ("version","u32"),
                ("header_len","u32"),
                ("data",CData(lambda _:_.header_len))]
    magic_txt = property(lambda _:_.magic.decode('latin1'))
    def _initialize(self):
        CStruct._initialize(self)
        # Change default values
        self.magic      = 'RPRC'.encode('latin1')
        self.version    = 2
        self.header_len = 1012
        self.data[0]    = data_null * self.header_len
        self._size     += self.header_len
    def display(self):
        rep = []
        rep.append('magic number %(magic_txt)s' % self)
        rep.append('header version %(version)d' % self)
        rep.append('header size %(header_len)d' % self)
        rep.append('header data')
        rep.append(str(self.data))
        return '\n'.join(rep)

# NB: the following definition is taken from
# https://github.com/ohadbc/sysbios-rpmsg/blob/master/src/utils/rprcfmt.h
# It does not correspond to the RPRC files we have
class ResourceNewABI(CStruct):
    _fields = [ ("type","u32"),
                ("id","u32"),
                ("da","u64"),   # Device Address
                ("pa","u64"),   # Physical Address
                ("len","u32"),
                ("flags","u32"),
                ("reserved","16s"),
                ("name","48s"),
                ]

class Resource(CStruct):
    _fields = [ ("type","u32"),
                ("da","u64"),   # Device Address
                ("pa","u64"),   # Physical Address
                ("len","u32"),
                ("flags","u32"),
                ("name","48s"),
                ]
    name_txt = property(lambda _:_.name.strip(data_null).decode('latin1'))
    def unpack(self, c, o):
        CStruct.unpack(self, c, o)
        self.offset = o
    def display(self):
        return 'resource %(type)d, da: %(da)#010x, pa: %(pa)#010x, len: %(len)#010x, name: %(name_txt)s' % self

class Section(CStruct):
    _fields = [ ("type","u32"),
                ("da","u64"),   # Device Address
                ("len","u32"),
                ("data",CData(lambda _:_.len))]
    def unpack(self, c, o):
        CStruct.unpack(self, c, o)
        self.offset = o
        if self.type == FW_RESOURCE:
            self.res_len = Resource(parent=self).bytelen
            if self.data.bytelen % self.res_len != 0:
                raise ValueError('Section data length %#x not multiple of %#x' % (self.data.bytelen, self.res_len))
            of = 0
            self.res = []
            while of + self.res_len <= self.data.bytelen:
                r = Resource(parent=self, content=self.data, start=of)
                self.res.append(r)
                of += self.res_len
    def display(self):
        rep = []
        rep.append('section %(type)d, address: %(da)#010x, size: %(len)#010x' % self)
        if self.type == FW_RESOURCE:
            rep.append('resource table: %d' % self.res_len)
            for r in self.res:
                rep.append(r.display())
        return '\n'.join(rep)
    def __str__(self):
        return 'section %(type)d, address: %(da)#010x, size: %(len)#010x' % self

class Layout(object):
    ''' This class manages the layout of the file when loaded in memory. '''
    def __init__(self, overlap=None):
        ''' Initialize with an empty memory '''
        if   overlap == 'silent':
            pass
        elif overlap == 'warning':
            TODO
        elif overlap == 'error':
            TODO
        else:
            raise ValueError('Define overlap in %s'%self.__class__)
        self.layout = [(0, None)]
    def __setitem__(self, item, data):
        ''' Load 'data' in memory at interval 'item'. '''
        if item.start == item.stop:
            return
        # Find the position in the layout where the data is loaded
        for i, (o, _) in enumerate(self.layout):
            if o >= item.start: break
        else:
            i = len(self.layout)
        # Find the position in the layout where the data loading ends
        for j, (o, _) in enumerate(self.layout):
            if o > item.stop: break
        else:
            j = len(self.layout)
        # Find what is the value after the end
        _, prv_data = self.layout[j-1]
        self.layout[i:j] = [(item.start, data),(item.stop, prv_data)]
    def __getitem__(self, item):
        ''' Return a list of (slice, data) which indicates what is in
            memory at interval 'item'; the slices that are returned
            are contiguous and add up to the whole 'item' slice. '''
        res = []
        for i, (stop, _) in enumerate(self.layout):
            if item.start >= stop:
                continue
            start, data = self.layout[i-1]
            if item.stop <= start:
                continue
            res.append((slice(max(item.start,start),min(item.stop,stop)),data))
        if stop < item.stop:
            _, data = self.layout[-1]
            res.append((slice(stop,item.stop),data))
        return res
    def max_addr(self):
        return self.layout[-1][0]

class Virtual(object):
    # This class manages 'virtual addresses', i.e. the addresses when
    # the RPRC file is loaded in memory.
    # These addresses are the ones used by absolute addressing in the
    # executable code.
    def __init__(self, e):
        self.parent = e
        self.layout = Layout(overlap='silent')
        for s in self.parent.sections:
            self.layout[s.da:s.da+s.len] = s
    def __getitem__(self, item):
        # If 'item' is an integer, we return the byte at this address,
        # else 'item' is a slice and we return the corresponding bytes,
        # padded with zeroes.
        if type(item) is slice:
            assert item.step is None
            start, stop = item.start, item.stop
        else:
            start, stop = item, item+1
        res = data_empty
        for i, s in self.layout[start:stop]:
            if s is None: res += data_null * (i.stop-i.start) # non-mapped
            else: res += s.data[i.start-s.da:i.stop-s.da]
        return res
    def __setitem__(self, item, data):
        # If 'item' is an integer, we write starting from this address
        if type(item) is slice:
            assert item.step is None
            start, stop = item.start, item.stop
            assert len(data) == stop-start
        else:
            start, stop = item, item+len(data)
        l = self.layout[start:stop]
        if None in [ s for _, s in l]:
            raise ValueError('Addresses %#x:%#x not entirely mapped in memory'%(start,stop))
        for i, s in l:
            of = i.start-start
            s.data[i.start-s.da:i.stop-s.da] = data[i.start-s.da+of:i.stop-s.da+of]
    def max_addr(self):
        return self.layout.max_addr()

class RPRC(object):
    # API shared by all/most binary containers
    architecture = property(lambda _:'ARM')
    entrypoint = property(lambda _:-1)
    #sections = property(lambda _:_.SHList.shlist)
    symbols = property(lambda _:())
    dynsyms = property(lambda _:())

    sex = '<'
    wsize = 32
    virt = property(lambda _:_._virt)
    def __init__(self, data = None, **kargs):
        self.sections = []
        if data is not None:
            self.content = StrPatchwork(data)
            self.parse_content()
        else:
            # Create a RPRC file with no section
            self.hdr = Header(parent=self)
        self._virt = Virtual(self)
    def parse_content(self):
        h = struct.unpack("B"*4, self.content[:4])
        if h != ( 0x52,0x50,0x52,0x43 ): # magic number, RPRC
            raise ValueError("Not an RPRC")
        self.hdr = Header(parent=self, content=self.content)
        of = self.hdr.bytelen
        while of < len(self.content):
            s = Section(parent=self, content=self.content, start=of)
            self.sections.append(s)
            of += s.bytelen
    def pack(self):
        c = StrPatchwork()
        c[0] = self.hdr.pack()
        of = self.hdr.bytelen
        for s in self.sections:
            c[of] = s.pack()
            of += s.bytelen
        return c.pack()
    def display(self):
        # Same output as 'readrprc'
        rep = [self.hdr.display()] + [s.display() for s in self.sections]
        return '\n'.join(rep)
    def getsectionbyvad(self, ad):
        # Same API as ELF or PE, but different implementation for accessing
        # data by virtual addresses: a mechanism entirely inside 'virt'
        # rather than split between two classes; future versions of
        # elfesteem should probably do the same for all binary containers.
        return self.virt.layout[ad:ad+1][0][1]

if __name__ == "__main__":
    import sys, code
    if len(sys.argv) > 2:
        for f in sys.argv[1:]:
            print('File: %s'%f)
            e = RPRC(open(f, 'rb').read())
            print (e.display())
        sys.exit(0)
    if len(sys.argv) == 2:
        e = RPRC(open(sys.argv[1], 'rb').read())
    code.interact('Interactive Python Console', None, locals())
