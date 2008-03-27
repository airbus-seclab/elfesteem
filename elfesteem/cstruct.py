#! /usr/bin/env python

import struct

class Cstruct_Metaclass(type):
    def __new__(cls, name, bases, dct):
        o = super(Cstruct_Metaclass, cls).__new__(cls, name, bases, dct)
        o._packstring =  o._packformat+"".join(map(lambda x:x[1],o._fields))
        o._size = struct.calcsize(o._packstring)
        return o
    

class CStruct(object):
    __metaclass__ = Cstruct_Metaclass
    _packformat = ""
    _fields = []

    @classmethod
    def _from_file(cls, f):
        return cls(f.read(cls._size))
    
    def __init__(self, *args, **kargs):
        self._names = map(lambda x:x[0], self._fields)
        if kargs:
            self.__dict__.update(kargs)
        else:
            s=""
            if args:
                s = args[0]
            s += "\x00"*self._size
            s = s[:self._size]            
            self._unpack(s)

    def _unpack(self,s):
        disas = struct.unpack(self._packstring, s)
        for n,v in zip(self._names,disas):
            setattr(self, n, v)

    def _pack(self):
        return struct.pack(self._packstring,
                           *map(lambda x: getattr(self, x), self._names))

    def _spack(self, superstruct, shift=0):
        attr0 = map(lambda x: getattr(self, x), self._names)
        attr = []
        for s in attr0:
            if isinstance(s,CStruct):
                if s in superstruct:
                    s = reduce(lambda x,y: x+len(y),
                               superstruct[:superstruct.index(s)],
                               0)
                    s += shift
                else:
                    raise Exception("%s not un superstructure" % repr(s))
            attr.append(s)
        return struct.pack(self._packstring, *attr)

    def _copy(self):
        return self.__class__(**self.__dict__)

    def __len__(self):
        return self._size

    def __str__(self):
        return self._pack()

    def __repr__(self):
        return "<%s=%s>" % (self.__class__.__name__, "/".join(map(lambda x:repr(getattr(self,x[0])),self._fields)))

    def __getitem__(self, item): # to work with format strings
        return getattr(self, item)

    def _show(self):
        print "##%s:" % self.__class__.__name__
        fmt = "%%-%is = %%r" % max(map(lambda x:len(x[0]), self._fields))
        for fn,ft in self._fields:
            print fmt % (fn,getattr(self,fn))

class CStructStruct:
    def __init__(self, lst, shift=0):
        self._lst = lst
        self._shift = shift
    def __getattr__(self, attr):
        return getattr(self._lst, attr)
    def __str__(self):
        s = []
        for a in self._lst:
            if type(a) is str:
                s.append(a)
            else:
                s.append(a._spack(self._lst, self._shift))
        return "".join(s)
        
        
