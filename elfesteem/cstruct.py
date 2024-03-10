#! /usr/bin/env python

import struct, re

# To be compatible with python 2 and python 3
data_empty = struct.pack("")
data_null = struct.pack("B",0)

import sys
if sys.version_info[0] < 3:
    bytes_to_name = lambda s: s
    name_to_bytes = lambda s: s
else:
    bytes_to_name = lambda s: s.decode(encoding="latin1")
    name_to_bytes = lambda s: s.encode(encoding="latin1")

class CBase(object):
    """
    This is the base class, used to define CString, CStruct, CArray

    Functions to manipulate a CBase object
      unpack(): two args (c, o) the bytestring and the starting offset
      pack():   creates a byte string from the object content
      bytelen:  length of this byte string
      pprint(): representation of the object, that can be used by pprint
      update(): named args, that change the object content

    Parameters used to create a CBase object from a bytestring:
      parent:  parent object (mandatory)
      content: binary stream to initialize the object
      start:   offset where to start parsing the content
      sex and wsize: endianess and wordsize
    """
    def __init__(self, *args, **kargs):
        if not 'parent' in kargs:
            # Old API of elfesteem
            # e.g. used by miasm2's example/jitter/unpack_upx.py
            kargs['parent'] = args[0]
        self._parent_parse(kargs)
        self._initialize()
        if 'content' in kargs:
            if not 'start' in kargs: kargs['start'] = 0
            if 'count' in kargs:
                self.count = lambda c=kargs['count']: c
                del kargs['count']
            self.unpack(kargs['content'], kargs['start'])
            del kargs['content']
            del kargs['start']
        self.update(**kargs)
    def _parent_parse(self, kargs):
        self.parent = kargs['parent']
        if not 'sex'   in kargs: kargs['sex']   = self.parent.sex
        if not 'wsize' in kargs: kargs['wsize'] = self.parent.wsize
        self.sex   = kargs['sex']
        self.wsize = kargs['wsize']
        del kargs['parent']
        del kargs['sex']
        del kargs['wsize']
    def _initialize(self):
        # For default values
        pass
    def update(self, **kargs):
        pass

    def __len__(self):
        # We don't use __len__ for the length in bytes, because we want to be able
        # to use it for the number of elements of a CArray
        raise AttributeError("__len__ not defined for '%s'"%self.__class__.__name__)
    def bytelen(self):
        return self._size
    bytelen = property(bytelen)

    def _size_align(self, o):
        s = o._size
        if hasattr(self, '_align'):
            s += ((self._align - s % self._align) % self._align)
        return s
    def _pack_align(self, o):
        s = o.pack()
        if hasattr(self, '_align'):
            s += '\0' * ((self._align - o._size % self._align) % self._align)
        return s

class CString(CBase):
    def set_value(self, s):
        self.X = s
        self._size = len(self.X) + 1
    def unpack(self, c, o):
        self.set_value(c[o:c.find(data_null,o)])
        self._off = o
    def update(self, **kargs):
        # If 's' is an argument, then the string value is set to s
        if 's' in kargs:
            self.set_value(kargs['s'])
    def _initialize(self):
        self.set_value(data_empty)
    def pack(self):
        return self.X + data_null
    def __str__(self):
        return bytes_to_name(self.X)
    def __repr__(self):
        return '<CString %r>' % self.X
    def pprint(self):
        return self.X

from elfesteem.strpatchwork import StrPatchwork
class CData(object):
    # Generic class to be used at the end of a CStruct, to implement common
    # cases implemented in C as     struct s { ...; char data[]; }
    # We use StrPatchwork because the data may be very long, and we want to
    # be able to modify it very efficiently.
    def __new__(self, f):
        class CDataInstance(CBase):
            def _initialize(self, f=f):
                self._size = f(self.parent)
                self._data = StrPatchwork()
            def unpack(self, c, o):
                self._data[0] = c[o:o+self._size]
            def pack(self):
                return self._data.pack()
            def __str__(self):
                return self.pack().decode('latin1')
            def __getitem__(self, item):
                return self._data[item]
            def __setitem__(self, item, value):
                self._data[item] = value
        return CDataInstance

type_size = {}
size2type = {}
size2type_s = {}

for t in 'B', 'H', 'I', 'Q':
    s = struct.calcsize(t)
    type_size[t] = s*8
    size2type[s*8] = t

for t in 'b', 'h', 'i', 'q':
    s = struct.calcsize(t)
    type_size[t] = s*8
    size2type_s[s*8] = t

type_size['u08'] = size2type[8]
type_size['u16'] = size2type[16]
type_size['u32'] = size2type[32]
type_size['u64'] = size2type[64]

type_size['s08'] = size2type_s[8]
type_size['s16'] = size2type_s[16]
type_size['s32'] = size2type_s[32]
type_size['s64'] = size2type_s[64]

def convert_size2type(ftype, wsize):
    if not isinstance(ftype, str):
        return ''
    elif re.match(r'\d+s', ftype):
        return ftype
    elif ftype == "ptr":
        return size2type[wsize]
    elif ftype in type_size:
        return type_size[ftype]
    else:
        raise ValueError("unkown CStruct type", ftype)

class CStruct_metaclass(type):
    """
    metaclass, with a syntax compatible with python2 and python3
    """
    _prefix = "_field_" # To avoid namespace collisions
    def __new__(cls, name, bases, dct):
        if '_fields' in dct:
            for fname, _ in dct['_fields']:
                dct[fname] = property(
                    lambda self,fname=fname:   self.getf(fname),
                    lambda self,v,fname=fname: self.setf(fname,v),
                    None)
        return type.__new__(cls, name, bases, dct)

CStruct_base = CStruct_metaclass('CStruct_base', (CBase,), {})
class CStruct(CStruct_base):
    """
    The class CStruct is inherited by classes that simply
    represent a concatenation of typed fields

    How to create a CStruct class:
      _fields list the pairs (field_name, field_type)
      if the last fields are (field_name, class), they are optional
      _align: an optional integer value for alignment of optional fields

    How to create a CStruct object:
      the keywords not used by CBase initialise the object fields

    How to use a CStruct object:
      in addition to the CBase interface, the fields can be modified

    Field types:
      basic types with fixed size (u08, ..., 16s)
      wsize-dependent type (ptr)
    """

    def getf(self, fname):
        return getattr(self,'_0'+fname)
    def setf(self, fname, v):
        return setattr(self,'_0'+fname,v)

    _packformat = ""

    def _parent_parse(self, kargs):
        CBase._parent_parse(self, kargs)
        if self._packformat:
            self.sex = ""
        self._format = {}
        pstr = []
        for fname, ftype in self._fields:
            ftype = convert_size2type(ftype, self.wsize)
            self._format[fname] = ftype
            pstr.append(ftype)
        self._packstring =  self.sex + self._packformat+"".join(pstr)
        self._names = [x[0] for x in self._fields if isinstance(x[1],str)]
        self._opt = [x for x in self._fields if not isinstance(x[1],str)]

    def unpack(self, c, o):
        self._size = struct.calcsize(self._packstring)
        s = c[o:o+self._size]
        s += data_null*(self._size-len(s))
        disas = struct.unpack(self._packstring, s)
        for n,v in zip(self._names,disas):
            setattr(self, n, v)
        # If the last fields are optional data, their types are a class
        for fname, fclass in self._opt:
            v = fclass(parent=self, content=c, start=o+self._size)
            self._size += self._size_align(v)
            self.setf(fname, v)

    def _initialize(self):
        self._size = struct.calcsize(self._packstring)
        for f in self._names:
            # Default values
            if self._format[f].endswith('s'): self.setf(f,data_empty)
            else:                             self.setf(f,0)
        for fname, fclass in self._opt:
            v = fclass(parent=self)
            self._size += self._size_align(v)
            self.setf(fname, v)

    def update(self, **kargs):
        for f in [f for f in kargs if f in self._names]:
            self.setf(f,kargs[f])
        for fname, fclass in self._opt:
            v = self.getf(fname)
            self._size -= self._size_align(v)
            v.update(**kargs)
            self._size += self._size_align(v)

    def pack(self):
        fields = [getattr(self, x) for x in self._names]
        s = struct.pack(self._packstring, *fields)
        for fname, fclass in self._opt:
            s += self._pack_align(self.getf(fname))
        if self.bytelen != len(s):
            raise ValueError("Inconsistent size %d != %d for %r"
                % (self.bytelen,len(s), self.__class__.__name__))
        return s

    def __str__(self):
        raise AttributeError("Use pack() instead of str()")

    def pprint(self):
        rep = { }
        for fname, _ in self._fields:
            rep[fname] = getattr(self, fname)
            if hasattr(rep[fname], 'pprint'):
                rep[fname] = rep[fname].pprint()
        return ( "<%s>" % self.__class__.__name__, rep )

    def __repr__(self):
        return "<%s=%s>" % (self.__class__.__name__,
            "/".join(map(lambda x:repr(getattr(self,x[0])),self._fields)))

    def __getitem__(self, item): # to work with format strings
        return getattr(self, item)

class CStructWithStrTable(CStruct):
    # The attribute 'name' is computed from an integer index 'name_idx'
    # and a link to the string table 'strtab'
    def get_name(self):
        return self.strtab.get_name(self.name_idx)
    def set_name(self, name):
        if self.name_idx == 0:
            self.name_idx = self.strtab.add_name(name)
        else:
            self.strtab.mod_name(self.name_idx, name)
    name = property(get_name, set_name)
    def update(self, **kargs):
        CStruct.update(self, **kargs)
        if 'name' in kargs and 'name_idx' in self._names:
            self.name = kargs['name']

class CArray_metaclass(type):
    """
    metaclass, with a syntax compatible with python2 and python3
    """
    def __new__(cls, name, bases, dct):
        class_defined = '_cls' in dct
        for c in bases:
            class_defined = class_defined or '_cls' in c.__dict__
        if not name.startswith('CArray') and not class_defined:
            raise ValueError("Class %r should define '_cls'"%name)
        return type.__new__(cls, name, bases, dct)

CArray_base = CArray_metaclass('CArray_base', (CBase,), {})
class CArray(CArray_base):
    """
    The class CArray is inherited by classes that represent
    a variable length array of objects of variable length.

    How to create a CArray subclass:
      _cls: the class of the array elements
      count (optional): method that returns the number of elements

    How to use a CArray object:
      in addition to the CBase interface,
      [item] gives access to an element of the array
      len gives the number of elements
      append adds an element to the array
      _array is the whole array
      _last is the terminating element, if count is not defined
    """
    def _initialize(self):
        self._array = [] # Elements of the array
        self._size  = 0
        if not hasattr(self, 'count'):
            # Array end is decided by a terminating element
            # which is detected by 'stop', of by default by
            # comparing with the default value of an object
            # of class _cls
            self._last  = self._cls(parent=self)
            self._size  += self._size_align(self._last)

    def pack(self):
        s = data_empty.join([self._pack_align(o) for o in self._array])
        if hasattr(self, '_last'): s += self._pack_align(self._last)
        if self._size != len(s):
            raise ValueError("Inconsistent size %d != %d for %r"
                % (self._size,len(s), self.__class__.__name__))
        return s

    def stop(self, elt):
        return elt.pack() == self._last.pack()

    def unpack(self, c, o):
        if o is None: return
        self._off = o
        if hasattr(self, 'count'):
            # self.count() is recomputed each time
            # This enables complicated conditions for array termination
            idx = 0
            while idx < self.count():
                if o+self._size >= len(c):
                    break
                elt = self._cls(parent=self, content=c, start=o+self._size)
                self._array.append(elt)
                self._size += self._size_align(elt)
                idx += 1
        else:
            pos = 0
            while True:
                if o+pos >= len(c):
                    break
                elt = self._cls(parent=self, content=c, start=o+pos)
                if self.stop(elt):
                    break
                self._array.append(elt)
                pos += self._size_align(elt)
            self._size += pos

    def __getitem__(self, item):
        return self._array[item]

    def __len__(self):
        return len(self._array)

    def append(self, obj):
        self._array.append(obj)
        self._size += self._size_align(self._array[-1])
        return obj

    def pprint(self):
        return ("<%s>"%self.__class__.__name__,
                [x.pprint() for x in self._array],
               )

    def __repr__(self):
        return "<%s of length %d>" % (self.__class__.__name__, len(self))

# Method that defines constants (as in .h headers) and tables that
# can recover the constant's name from its value.
def Constants(globs = None, table = None,
              name = None, prefix = None,
              no_name = (), **kargs):
    if prefix is None:
        # Use the prefix common to all value names
        for k in kargs:
            if prefix is None:
                prefix = k
            else:
                while not k.startswith(prefix):
                    prefix = prefix[:-1]
    if name is None:
        if prefix.endswith('_'): name = prefix[:-1]
        else:                    name = prefix
    if name != '' and not name in table: table[name] = {}
    for k in kargs:
        globs[k] = kargs[k]
        if name != '':
            if k.startswith(prefix) and not k in no_name:
                if kargs[k] in table[name]:
                    print("Duplicate at %s[%s]=%s; %s"%(name,kargs[k],table[name][kargs[k]],k))
                table[name][kargs[k]] = k[len(prefix):]
