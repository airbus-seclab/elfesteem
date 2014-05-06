#! /usr/bin/env python

import struct

# To be compatible with python 2 and python 3
data_empty = struct.pack("")
data_null = struct.pack("B",0)

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

class CStruct(object):
    """
    The class CStruct is inherited by classes that simply
    represent a concatenation of typed fields

    How to create a CStruct:
      _fields list the pairs (field_name, field_type)
      unpack creates attributes by unpacking a byte string
      pack creates a byte string from the object content

    How to use a CStruct:
      create with the following optional parameters:
      content: binary stream to initialize the object
      parent: parent object
      sex and wsize: endianess and wordsize
    """

    class __metaclass__(type):
        _prefix = "_field_"
        def __new__(cls, name, bases, dct):
            for fname, ftype in dct['_fields']:
                dct[fname] = property(
                    dct.pop("get_"+fname,
                        lambda self,fname=fname:   getattr(self,cls._prefix+fname)),
                    dct.pop("set_"+fname,
                        lambda self,v,fname=fname: setattr(self,cls._prefix+fname,v)),
                    dct.pop("del_"+fname,          None))
            return type.__new__(cls, name, bases, dct)

    _packformat = ""
    _fields = []

    def fix_size(self, wsize):
        out = []
        for name, v in self._fields:
            if v.endswith("s"):
                pass
            elif v == "ptr":
                v = size2type[wsize]
            elif not v in type_size:
                raise ValueError("unkown Cstruct type", v)
            else:
                v = type_size[v]
            out.append((name, v))
        return out

    def __init__(self, *args, **kargs):
        self._parent = kargs.get('parent', None)
        for f in ['sex', 'wsize']:
            if f in kargs:
                setattr(self, f, kargs[f])
            elif self._parent != None:
                setattr(self, f, getattr(self._parent, f))
        sex = self.sex
        wsize = self.wsize
        if self._packformat:
            sex = self._packformat
        pstr = self.fix_size(wsize)
        self._packstring =  sex + "".join(map(lambda x:x[1],pstr))
        self._size = struct.calcsize(self._packstring)

        self._names = [x[0] for x in self._fields]
        if 'content' in kargs:
            s = kargs['content']
            s += data_null*self._size
            s = s[:self._size]            
            self.unpack(s)
        kargs = kargs.copy()
        for f in ['parent', 'sex', 'wsize', 'content']:
            kargs.pop(f, None)
        self.__dict__.update(kargs)

    def unpack(self,s):
        disas = struct.unpack(self._packstring, s)
        for n,v in zip(self._names,disas):
            setattr(self, n, v)
        return self

    def pack(self):
        fields = [getattr(self, x) for x in self._names]
        return struct.pack(self._packstring, *fields)

    def __len__(self):
        return self._size

    def __str__(self):
        raise AttributeError("Use pack() instead of str()")

    def __repr__(self):
        return "<%s=%s>" % (self.__class__.__name__, "/".join(map(lambda x:repr(getattr(self,x[0])),self._fields)))

    def __getitem__(self, item): # to work with format strings
        return getattr(self, item)

