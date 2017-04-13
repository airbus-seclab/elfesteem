#! /usr/bin/env python

import struct, array
from strpatchwork import StrPatchwork
from new_cstruct import CStruct
import logging
from collections import defaultdict
from pprint import pprint as pp
log = logging.getLogger("classparse")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)




def gensapce(lvl):
    return '    '*lvl

def out_attrs(o, lvl =  None):
    if lvl == None:
        lvl = 0
    out = ""
    if not isinstance(o, list):
        return gensapce(lvl)+repr(o)+'\n'
    for f, v in o:
        out += gensapce(lvl)+repr(f)
        if isinstance(v, list):
            out +='\n'
            for x in v:
                out += out_attrs(x, lvl+1)
        else:
            out += " "+repr(v)
        out +="\n"
    return out




class CPUtf8(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("length", "u16"),
                ("value", (lambda c, s, of:c.gets(s, of),
                           lambda c, value:c.sets(value)))
                ]
    def gets(self, s, of):
        v = s[of:of+self.length]
        return v, of+self.length
    def sets(self, value):
        return str(value)

    def set_str(self, s):
        self.length = len(s)
        self.value = s
    def pp(self):
        return "%r"%(self.value)

class CPInteger(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("value", "u32")]

class CPFloat(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("value", "f")]

class CPLong(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("value", "q")]

class CPDouble(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("value", "d")]

class CPClass(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("name", "u16")]

    def get_name(self):
        return self.parent_head.get_constant_pool_by_index(self.name_value).value
    def pp(self):
        return "%r"%(self.name)

class CPString(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("value", "u16")]

    def get_value(self):
        return self.parent_head.get_constant_pool_by_index(self.value_value).value
    def set_value(self, v):
        self.parent_head.get_constant_pool_by_index(self.value_value).set_str(v)
    def pp(self):
        s = self.value
        """
        if len(s) > 40:
            s = str(s)[:40]+'...'
        """
        return "%r"%(s)

class CPFieldref(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("name", "u16"),
                ("type", "u16")]

    def get_name(self):
        return self.parent_head.get_constant_pool_by_index(self.name_value).name
    def get_type(self):
        return self.parent_head.get_constant_pool_by_index(self.type_value)
    def pp(self):
        return "%r %r"%(self.name, parse_field_descriptor(self.type.type, self.type.name))

class CPMethodref(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("name", "u16"),
                ("type", "u16")]


    def get_name(self):
        return self.parent_head.get_constant_pool_by_index(self.name_value).name
    def get_type(self):
        return self.parent_head.get_constant_pool_by_index(self.type_value)
    def pp(self):
        return "%r"%(demangle_java_name(self.name, self.type.type, self.type.name))


# From hachoir project
code_to_type_name = {
    'B': "byte",
    'C': "char",
    'D': "double",
    'F': "float",
    'I': "int",
    'J': "long",
    'S': "short",
    'Z': "boolean",
    'V': "void",
}


def demangle_java_name(c_name, c_typetype, c_typename):
    t = c_name.replace('/', '.')
    return parse_method_descriptor(c_typetype, t+'->'+c_typename)


def eat_descriptor(descr):
    """
    Read head of a field/method descriptor.  Returns a pair of strings, where
    the first one is a human-readable string representation of the first found
    type, and the second one is the tail of the parameter.
    """
    array_dim = 0
    while descr[0] == '[':
        array_dim += 1
        descr = descr[1:]
    if (descr[0] == 'L'):
        try: end = descr.find(';')
        except: raise ValueError("Not a valid descriptor string: " + descr)
        type = descr[1:end]
        descr = descr[end:]
    else:
        global code_to_type_name
        try:
            type = code_to_type_name[descr[0]]
        except KeyError:
            raise ValueError("Not a valid descriptor string: %s" % descr)
    return (type.replace("/", ".") + array_dim * "[]", descr[1:])

def parse_field_descriptor(descr, name=None):
    """
    Parse a field descriptor (single type), and returns it as human-readable
    string representation.
    """
    assert descr
    (type, tail) = eat_descriptor(descr)
    assert not tail
    if name:
        return type + " " + name
    else:
        return type

def parse_method_descriptor(descr, name=None):
    """
    Parse a method descriptor (params type and return type), and returns it
    as human-readable string representation.
    """
    assert descr and (descr[0] == '(')
    descr = descr[1:]
    params_list = []
    while descr[0] != ')':
        (param, descr) = eat_descriptor(descr)
        params_list.append(param)
    (type, tail) = eat_descriptor(descr[1:])
    assert not tail
    params = ", ".join(params_list)
    if name:
        return "%s %s(%s)" % (type, name, params)
    else:
        return "%s (%s)" % (type, params)



class CPInterfaceMethodref(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("name", "u16"),
                ("type", "u16")]

    def get_name(self):
        return self.parent_head.get_constant_pool_by_index(self.name_value).name
    def get_type(self):
        return self.parent_head.get_constant_pool_by_index(self.type_value)
    def pp(self):
        return "%r %r %r"%(self.name.replace('/', '.'), self.type.name, self.type.type)

class CPNameandType(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("name", "u16"),
                ("type", "u16")]


    def get_name(self):
        return self.parent_head.get_constant_pool_by_index(self.name_value).value
    def get_type(self):
        return self.parent_head.get_constant_pool_by_index(self.type_value).value

    def pp(self):
        return "%r %r"%(self.type, self.name)


CONSTANT_TYPES = {
    1 : CPUtf8,
    3 : CPInteger,
    4 : CPFloat,
    5 : CPLong,
    6 : CPDouble,
    7 : CPClass,
    8 : CPString,
    9 : CPFieldref,
    10: CPMethodref,
    11: CPInterfaceMethodref,
    12: CPNameandType,
    }

CONSTANT_TYPES_inv = dict([(x[1], x[0]) for x in  CONSTANT_TYPES.items()])


class CPoolfield(CStruct):
    _packformat = ">"
    _fields = [("tag", "u08")]
    @classmethod
    def unpack_l(cls, s, off = 0, parent_head = None, _sex=1, _wsize=32):
        tag = ord(s[off])
        if not tag in CONSTANT_TYPES:
            raise ValueError('unknown type', hex(tag))
        c, l = CONSTANT_TYPES[tag].unpack_l(s, off, parent_head, _sex, _wsize)
        return c, l

    @classmethod
    def unpack(cls, s, off = 0, parent_head = None, _sex=None, _wsize=None):
        c, l = cls.unpack_l(s, off = off,
                            parent_head = parent_head, _sex=_sex, _wsize=_wsize)
        return c


class CException_table(CStruct):
    _packformat = ">"
    _fields = [ ("start_pc", "u16"),
                ("end_pc", "u16"),
                ("handler_pc", "u16"),
                ("catch_type", "u16")
                ]

class CAttribute_code(CStruct):
    _packformat = ">"
    _fields = [ ("name", "u16"),
                ("attribute_length", "u32"),
                ("max_stack", "u16"),
                ("max_locals", "u16"),
                ("code_length", "u32"),
                ("code", (lambda c, s, of:c.getcode(s, of),
                          lambda c, value:c.setcode(value))),
                ("exception_table_length", "u16"),
                ("exception_table", "CException_table", lambda c:c.exception_table_length),
                ("attributes_count", "u16"),
                ("attributes", "CAttributeInfo", lambda c:c.attributes_count),
                ]
    def getcode(self, s, of):
        v = s[of:of+self.code_length]
        return v, of+self.code_length
    def setcode(self, value):
        return str(value)

    def get_name(self):
        return self.parent_head.get_constant_pool_by_index(self.name_value).value

class LineNumberTableEntry(CStruct):
    _packformat = ">"
    _fields = [ ("start_pc", "u16"),
                ("line_number", "u16")
                ]

class CLineNumberTable(CStruct):
    _packformat = ">"
    _fields = [ ("name", "u16"),
                ("attribute_length", "u32"),
                ("line_number_table_length", "u16"),
                ("line_number_table", "LineNumberTableEntry", lambda c:c.line_number_table_length),
                ]
    def get_name(self):
        return self.parent_head.get_constant_pool_by_index(self.name_value).value


class CException(CStruct):
    _packformat = ">"
    _fields = [ ("name", "u16"),
                ("attribute_length", "u32"),
                ("exceptions_count", "u16"),
                ("exceptions", "u16", lambda c:c.exceptions_count),
                ]
    def get_name(self):
        return self.parent_head.get_constant_pool_by_index(self.name_value).value

class CClass(CStruct):
    _packformat = ">"
    _fields = [ ("inner_class_info", "u16"),
                ("outer_class_info", "u16"),
                ("inner_name", "u16"),
                ("inner_class_access_flags", "u16"),
                ]

    def get_inner_class_info(self):
        return self.parent_head.get_constant_pool_by_index(self.inner_value_class_info).name
    def get_outer_class_info(self):
        return self.parent_head.get_constant_pool_by_index(self.outer_value_class_info).name
    def get_inner_name(self):
        return self.parent_head.get_constant_pool_by_index(self.inner_value_name).name

class CInnerClasses(CStruct):
    _packformat = ">"
    _fields = [ ("name", "u16"),
                ("attribute_length", "u32"),
                ("classes_count", "u16"),
                ("classes", "CClass", lambda c:c.classes_count),
                ]

    def get_name(self):
        return self.parent_head.get_constant_pool_by_index(self.name_value).value

class CSourceFile(CStruct):
    _packformat = ">"
    _fields = [ ("name", "u16"),
                ("attribute_length", "u32"),
                ("sourcefile", "u16"),
                ]
    def get_name(self):
        return self.parent_head.get_constant_pool_by_index(self.name_value).value
    def get_sourcefile(self):
        return self.parent_head.get_constant_pool_by_index(self.sourcefile_value).value

class CSynthetic(CStruct):
    _packformat = ">"
    _fields = [ ("name", "u16"),
                ("attribute_length", "u32")
                ]

    def get_name(self):
        return self.parent_head.get_constant_pool_by_index(self.name_value).value

class CAttributeInfo_default(CStruct):
    _packformat = ">"
    _fields = [ ("name", "u16"),
                ("attribute_length", "u32"),
                ("attribute", (lambda c, s, of:c.getcode(s, of),
                                lambda c, value:c.setcode(value))),
                ]

    def get_name(self):
        return self.parent_head.get_constant_pool_by_index(self.name_value).value
    def getcode(self, s, of):
        v = s[of:of+self.attribute_length]
        return v, of+self.attribute_length
    def setcode(self, value):
        return str(value)


class CAttributeInfo(CStruct):
    _packformat = ">"
    _fields = [ ("name", "u16")
                ]
    @classmethod
    def unpack_l(cls, s, off = 0, parent_head = None, _sex=1, _wsize=32):
        tag = struct.unpack('>H', s[off:off+2])[0]
        c = parent_head.get_constant_pool_by_index(tag)
        if not isinstance(c, CPUtf8):
            raise ValueError('Error in parsing, should be string', hex(tag))
        name = c.value
        if name == "Code":
            c, l = CAttribute_code.unpack_l(s, off, parent_head, _sex, _wsize)
        elif name == "LineNumberTable":
            c, l = CLineNumberTable.unpack_l(s, off, parent_head, _sex, _wsize)
        elif name == "Exceptions":
            c, l = CException.unpack_l(s, off, parent_head, _sex, _wsize)
        elif name == "InnerClasses":
            c, l = CInnerClasses.unpack_l(s, off, parent_head, _sex, _wsize)
        elif name == "SourceFile":
            c, l = CSourceFile.unpack_l(s, off, parent_head, _sex, _wsize)
        elif name == "Synthetic":
            c, l = CSynthetic.unpack_l(s, off, parent_head, _sex, _wsize)
        else:
            log.warning("unsupported attribute, skipping:\n%r"%(c))
            c, l = CAttributeInfo_default.unpack_l(s, off, parent_head, _sex, _wsize)
        return c, l

    @classmethod
    def unpack(cls, s, off = 0, parent_head = None, _sex=None, _wsize=None):
        c, l = cls.unpack_l(s, off = off,
                            parent_head = parent_head, _sex=_sex, _wsize=_wsize)
        return c

class CFieldInfo(CStruct):
    _packformat = ">"
    _fields = [ ("access_flags", "u16"),
                ("name", "u16"),
                ("descriptor", "u16"),
                ("attributes_count", "u16"),
                ("attributes", "CAttributeInfo", lambda c:c.attributes_count),
                ]

    def get_name(self):
        return self.parent_head.get_constant_pool_by_index(self.name_value).value

class CMethods(CStruct):
    _packformat = ">"
    _fields = [ ("access_flags", "u16"),
                ("name", "u16"),
                ("descriptor", "u16"),
                ("attributes_count", "u16"),
                ("attributes", "CAttributeInfo", lambda c:c.attributes_count),
                ]
    def get_name(self):
        return self.parent_head.get_constant_pool_by_index(self.name_value).value
    def get_descriptor(self):
        return self.parent_head.get_constant_pool_by_index(self.descriptor_value).value

class Jclass_hdr(CStruct):
    _packformat = ">"
    _fields = [ ("magic", "u32"),
                ("minor_version","u16"),
                ("major_version","u16"),
                ("constants_pool_count","u16"),
                ("constants_pool", (lambda c, s, of:c.gets(s, of),
                                    lambda c, value:c.sets(value))),
                ("bitmask", "u16"),
                ("this","u16"),
                ("super","u16")
                ]

    def gets(self, s, of):
        v = []
        while len(v) < self.constants_pool_count-1:
            c, l = CPoolfield.unpack_l(s, of, self.parent_head)
            v.append(c)
            of += l
            if c.tag in [5, 6]:
                # XXX long objects insert an supplementary object
                v.append(None)
        return v, of
    def sets(self, value):
        out = "".join([str(x) for x in value if x != None])
        return out

class Jclass_description(CStruct):
    _packformat = ">"
    _fields = [ ("interface_count","u16"),
                ("interfaces","u16", lambda c:c.interface_count),
                ("fields_count","u16"),
                ("fields","CFieldInfo", lambda c:c.fields_count),
                ("methods_count","u16"),
                ("methods","CMethods", lambda c:c.methods_count),
                ("attributes_count","u16"),
                ("attributes","CAttributeInfo", lambda c:c.attributes_count),
                ]

    def get_interfaces(self):
        out = [self.parent_head.get_constant_pool_by_index(x).name for x in self.interfaces_value]
        return out


class JCLASS(object):
    def __getitem__(self, item):
        return self.content[item]
    def __setitem__(self, item, data):
        self.content.__setitem__(item, data)
        return

    def __init__(self, pestr = None):
        self._sex = 0
        self._wsize = 32
        self.content = pestr
        self.parse_content()

    def get_constant_pool_by_index(self, index):
        index -=1
        if 0 <= index < len(self.hdr.constants_pool):
            return self.hdr.constants_pool[index]
        return None

    def parse_content(self):
        self.hdr, l = Jclass_hdr.unpack_l(self.content, 0, self, self)
        self.description = Jclass_description.unpack(self.content, l, self, self)

    def __str__(self):
        out = ''
        out += str(self.hdr)
        out += str(self.description)
        return out


    def add_constant(self, c):
        self.hdr.constants_pool.append(c)
        self.hdr.constants_pool_count = len(self.hdr.constants_pool) + 1
        return len(self.hdr.constants_pool)

    def add_integer(self, i):
        c = CPInteger(parent_head = self, value = i)
        c.tag = CONSTANT_TYPES_inv[c.__class__]
        return self.add_constant(c)

    def add_float(self, i):
        c = CPFloat(parent_head = self, value = i)
        c.tag = CONSTANT_TYPES_inv[c.__class__]
        return self.add_constant(c)

    def add_long(self, i):
        c = CPLong(parent_head = self, value = i)
        c.tag = CONSTANT_TYPES_inv[c.__class__]
        return self.add_constant(c)

    def add_double(self, i):
        c = CPDouble(parent_head = self, value = i)
        c.tag = CONSTANT_TYPES_inv[c.__class__]
        return self.add_constant(c)

    def add_utf8(self, i):
        c = CPUtf8(parent_head = self, length = len(i), value = i)
        c.tag = CONSTANT_TYPES_inv[c.__class__]
        return self.add_constant(c)

    def add_string(self, i):
        x = self.add_utf8(i)
        c = CPString(parent_head = self, value = x)
        c.tag = CONSTANT_TYPES_inv[c.__class__]
        return self.add_constant(c)

    def add_nameandtype(self, name, t):
        namei = self.add_utf8(name)
        typei = self.add_utf8(t)
        c = CPNameandType(parent_head = self, name = namei, type = typei)
        c.tag = CONSTANT_TYPES_inv[c.__class__]
        return self.add_constant(c)

    def add_class(self, i):
        x = self.add_utf8(i)
        c = CPClass(parent_head = self, name = x)
        c.tag = CONSTANT_TYPES_inv[c.__class__]
        return self.add_constant(c)

    def add_methodref(self, name, typetype, typename):
        namei = self.add_class(name)
        typei = self.add_nameandtype(typename, typetype)
        c = CPMethodref(parent_head = self, name = namei, type = typei)
        c.tag = CONSTANT_TYPES_inv[c.__class__]
        return self.add_constant(c)

    def add_fieldref(self, name, typetype, typename):
        namei = self.add_class(name)
        typei = self.add_nameandtype(typename, typetype)
        c = CPFieldref(parent_head = self, name = namei, type = typei)
        c.tag = CONSTANT_TYPES_inv[c.__class__]
        return self.add_constant(c)



if __name__ == "__main__":
    import sys
    from pprint import pprint as pp
    data = open(sys.argv[1]).read()
    e = JCLASS(data)
