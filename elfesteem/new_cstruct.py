#! /usr/bin/env python

import struct
import re

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

type_size['d'] = 'd'
type_size['f'] = 'f'
type_size['q'] = 'q'
type_size['ptr'] = 'ptr'

sex_types = {0:'<', 1:'>'}

def fix_size(fields, wsize):
    out = []
    for name, v in fields:
        if v.endswith("s"):
            pass
        elif v == "ptr":
            v = size2type[wsize]
        elif not v in type_size:
            raise ValueError("unkown Cstruct type", v)
        else:
            v = type_size[v]
        out.append((name, v))
    fields = out
    return fields

def real_fmt(fmt, wsize):
    if fmt == "ptr":
        v = size2type[wsize]
    elif fmt in type_size:
        v = type_size[fmt]
    else:
        v = fmt
    return v

all_cstructs = {}
class Cstruct_Metaclass(type):
    _prefix = "_field_"
    def __new__(cls, name, bases, dct):
        if name == 'CStructBase':
            o = type.__new__(cls, name, bases, dct)
            return o
        for fields in dct['_fields']:
            fname = fields[0]
            if fname in ['parent', 'parent_head']:
                raise ValueError('field name will confuse internal structs',
                                 repr(fname))
            dct[fname] = property(dct.pop("get_"+fname,
                                          lambda self,fname=fname: getattr(self,cls._prefix+fname)),
                                  dct.pop("set_"+fname,
                                          lambda self,v,fname=fname: setattr(self,cls._prefix+fname,v)),
                                  dct.pop("del_"+fname, None))



        o = super(Cstruct_Metaclass, cls).__new__(cls, name, bases, dct)
        if name != "CStruct":
            all_cstructs[name] = o
        return o

    def unpack_l(cls, s, off = 0, parent_head = None, _sex=None, _wsize=None):
        if _sex == None and _wsize == None:
            # get sex and size from parent
            if parent_head:
                _sex = parent_head._sex
                _wsize = parent_head._wsize
            else:
                _sex = 0
                _wsize = 32
        c = cls(_sex = _sex, _wsize = _wsize)
        if parent_head == None:
            parent_head = c
        c.parent_head = parent_head

        of1 = off
        for field in c._fields:
            cpt = None
            if len(field) == 2:
                fname, ffmt = field
            elif len(field) == 3:
                fname, ffmt, cpt = field
            if ffmt in type_size or (isinstance(ffmt, str) and re.match(r'\d+s', ffmt)):
                # basic types
                if cpt:
                    value = []
                    i = 0
                    while i < cpt(c):
                        fmt = real_fmt(ffmt, _wsize)
                        of2 = of1+struct.calcsize(fmt)
                        value.append(struct.unpack(c.sex+fmt, s[of1:of2])[0])
                        of1 = of2
                        i+=1
                else:
                    fmt = real_fmt(ffmt, _wsize)
                    of2 = of1+struct.calcsize(fmt)
                    value = struct.unpack(c.sex+fmt, s[of1:of2])[0]
            elif ffmt == "sz": # null terminated special case
                of2 = s.find(data_null, of1)
                if of2 == -1:
                    raise ValueError('no null char in string!')
                of2 += 1
                value = s[of1:of2-1]
            elif ffmt in all_cstructs:
                # sub structures
                if cpt:
                    value = []
                    i = 0
                    while i < cpt(c):
                        v, l = all_cstructs[ffmt].unpack_l(s, of1, parent_head, _sex, _wsize)
                        v.parent = c
                        value.append(v)
                        of2 = of1 + l
                        of1 = of2
                        i += 1
                else:
                    value, l = all_cstructs[ffmt].unpack_l(s, of1, parent_head, _sex, _wsize)
                    value.parent = c
                    of2 = of1 + l
            elif isinstance(ffmt, tuple):
                f_get, f_set = ffmt
                value, of2 = f_get(c, s, of1)
            else:
                raise ValueError('unknown class', ffmt)
            of1 = of2
            setattr(c, CStruct._prefix+fname, value)

        return c, of2-off

    def unpack(cls, s, off = 0, parent_head = None, _sex=None, _wsize=None):
        c, l = cls.unpack_l(s, off = off,
                            parent_head = parent_head, _sex=_sex, _wsize=_wsize)
        return c

CStructBase = Cstruct_Metaclass('CStructBase', (object,), {})
class CStruct(CStructBase):
    _packformat = ""
    _fields = []

    def __init__(self, parent_head = None, _sex = None, _wsize = None, **kargs):
        self.parent_head = parent_head
        self._size = None
        kargs = dict(kargs)
        #if not sex or size: get the one of the parent
        if _sex == None and _wsize == None:
            if parent_head:
                _sex = parent_head._sex
                _wsize = parent_head._wsize
            else:
                # else default sex & size
                _sex = 0
                _size = 32
        self.sex = _sex
        self.wsize = _wsize
        if self._packformat:
            self.sex = self._packformat
        else:
            self.sex = sex_types[_sex]
        for f in self._fields:
            setattr(self, CStruct._prefix+f[0], None)
        if kargs:
            for k, v in kargs.items():
                self.__dict__[CStruct._prefix+k] = v

    def pack(self):
        out = data_empty
        for field in self._fields:
            cpt = None
            if len(field) == 2:
                fname, ffmt = field
            elif len(field) == 3:
                fname, ffmt, cpt = field

            value = getattr(self, CStruct._prefix+fname)
            if ffmt in type_size or (isinstance(ffmt, str) and re.match(r'\d+s', ffmt)):
                # basic types
                fmt = real_fmt(ffmt, self.wsize)
                if cpt == None:
                    if value == None:
                        o = struct.calcsize(fmt)*data_null
                    else:
                        o = struct.pack(self.sex+fmt, value)
                else:
                    o = data_empty
                    for v in value:
                        if value == None:
                            o += struct.calcsize(fmt)*data_null
                        else:
                            o += struct.pack(self.sex+fmt, v)

            elif ffmt == "sz": # null terminated special case
                o = value+data_null
            elif ffmt in all_cstructs:
                # sub structures
                if cpt == None:
                    o = value.pack()
                else:
                    o = data_empty
                    for v in value:
                        o += v.pack()
            elif isinstance(ffmt, tuple):
                f_get, f_set = ffmt
                o = f_set(self, value)

            else:
                raise ValueError('unknown class', ffmt)
            out += o

        return out

    def __len__(self):
        return len(self.pack())

    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
        return self.pack()

    def __repr__(self):
        return "<%s=%s>" % (self.__class__.__name__, "/".join(map(lambda x:repr(getattr(self,x[0])),self._fields)))

    def __getitem__(self, item): # to work with format strings
        return getattr(self, item)

if __name__ == "__main__":

    """
    Classic C struct
    """
    class c1(CStruct):
        _fields = [("c1_field1", "u16"),
                   ("c1_field2", "u16"),
                   ("c1_field3", "u32"),
                   ]

    """
    Struct with a sub structure as field (here, c1)
    """
    class c2(CStruct):
        _fields = [("c2_field1", "u16"),
                   ("c2_field2", "u16"),
                   ("c2_field3", "u32"),
                   ("c2_c", "c1"),
                   ]

    """
    b field is an array of 2 u16
    c field is an array of a count u16
    """
    class c3(CStruct):
        _fields = [("a", "u16"),
                   ("b", "u16", lambda x:2),
                   ("c", "c1", lambda c:c.a),
                   ("d", "u16"),
                   ]

    """
    e field has its own packing/unpacking custom functions
    """
    class c4(CStruct):
        _fields = [("d", "u16"),
                   ("e", (lambda c, s, of:c.gets(s, of),
                          lambda c, value:c.sets(value))),
                   ("f", "u16"),
                   ]
        def gets(cls, s, of):
            i = 0
            while s[of+i] != "\x00":
                i+=1
            return s[of:of+i], of+i+1
        def sets(cls, value):
            return str(value)+'\x00'

    """
    h field is a 4 len string
    """
    class c5(CStruct):
        _fields = [("g", "u16"),
                   ("h", "4s"),
                   ]

    """
    j field is a nul terminated string
    """
    class c6(CStruct):
        _fields = [("i", "u16"),
                   ("j", "sz"),
                   ("k", "u16"),
                   ]

    print(all_cstructs)

    s1 = struct.pack('HHI', 1111, 2222, 333333333)
    c = c1.unpack(s1)
    print(repr(c))
    assert len(c) == 8
    s2 = c.pack()
    assert s1 == s2
    print(repr(s2))
    print(repr(c1.unpack(s2)))

    s3 = struct.pack('HHI', 4444, 5555, 666666666)+s2
    print(repr(s3))
    assert len(s3) == 16
    c = c2.unpack(s3)
    print(repr(c))
    s4 = c.pack()
    print("%r %r"%(s3,s4))
    assert s3 == s4
    assert c.c2_c.parent_head == c


    s5 = struct.pack('HHH', 2, 5555, 6666)+s1*2+struct.pack('H', 9999)
    c = c3.unpack(s5)
    assert len(c) == 24
    print(repr(c))
    print(c.b)
    print(c.c)
    print(c.c[0].c1_field1)

    s6 = c.pack()
    print("%r %r"%(s5,s6))
    assert s5 == s6

    c = c1()
    c.c1_field1 = 1111
    c.c1_field2 = 2222
    c.c1_field3 = 333333333
    assert c.pack() == s1

    s7 = struct.pack('H', 8888)+"fffff\x00"+struct.pack('H', 9999)
    c = c4.unpack(s7)
    print(repr(c))
    print(repr(c.e))
    print(repr(c.f))

    print(repr(s7))
    print(repr(c.pack()))
    assert s7 == c.pack()

    s8 = struct.pack('H4s', 8888, "abcd")
    c = c5.unpack(s8)
    print(repr(c))
    assert s8 == c.pack()


    s9 = struct.pack('H', 9999)+ "toto\x00" + struct.pack('H', 1010)
    print(repr(s9))
    c = c6.unpack(s9)
    print("%r %r"%(c,c.pack()))
    assert s9 == c.pack()

