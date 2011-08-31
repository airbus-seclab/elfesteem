#! /usr/bin/env python

import struct, array
from strpatchwork import StrPatchwork
from new_cstruct import CStruct, StructWrapper
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

class ContentManager(object):
    def __get__(self, owner, x):
        if hasattr(owner, '_content'):
            return owner._content
    def __set__(self, owner, new_content):
        owner.resize(len(owner._content), len(new_content))
        owner._content=new_content
    def __delete__(self, owner):
        self.__set__(owner, None)

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

class CStruct_withnames(CStruct):
    pass
    """
    def __repr__(self, lvli = None):
        if lvli == None:
            lvl = 0
        else:
            lvl = lvli
        out = [('classname', self.__class__)]
        for f in self._fields:
            v = getattr(self, f[0])
            if isinstance(v, list):
                o = []
                for i, x in enumerate(v):
                    o.append(str(i+1))
                    if isinstance(x, CStruct_withnames):
                        o.append(x.__repr__(lvl+1))
                    else:
                        o.append(repr(x))
                v = o
            elif isinstance(v, CStruct_withnames):
                v = v.__repr__(lvl+1)
            else:
                v = repr(v)
            out.append((f[0], v))

        if lvli == None:
            return out_attrs(out)
        return out
    """


class CStruct_pp_f1(CStruct):
    def pp(self):
        fds
        return repr(getattr(self, self._fields[1]))


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

class CPInteger(CStruct_pp_f1):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("value", "u32")]

class CPFloat(CStruct_pp_f1):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("value", "f")]

class CPLong(CStruct_pp_f1):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("value", "q")]

class CPDouble(CStruct_pp_f1):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("value", "d")]

class CPClass(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("name", "u16")]
    def __repr__(self, lvli = None):
        f = self._fields[1]
        v = getattr(self, f[0])
        v = self.parent.get_constant_pool_by_index(v).value

        if lvli == None:
            return "<%s %s:%r>"%(self.__class__, f[0], v)
        else:
            return [(self.__class__, [(f[0], v)])]


class WCPClass(StructWrapper):
    wrapped = CPClass
    def get_name(self):
        return self.parent.get_constant_pool_by_index(self.cstr.name).value
    def pp(self):
        return "%r"%(self.name)

class CPString(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("value", "u16")]

class WCPString(StructWrapper):
    wrapped = CPString
    def get_value(self):
        return self.parent.get_constant_pool_by_index(self.cstr.value).value
    def set_value(self, v):
        self.parent.get_constant_pool_by_index(self.cstr.value).set_str(v)
    def pp(self):
        s = self.value
        if len(s) > 40:
            s = str(s)[:40]+'...'
        return "%r"%(s)

class CPFieldref(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("name", "u16"),
                ("type", "u16")]

class WCPFieldref(StructWrapper):
    wrapped = CPFieldref
    def get_name(self):
        return self.parent.get_constant_pool_by_index(self.cstr.name).name
    def get_type(self):
        return self.parent.get_constant_pool_by_index(self.cstr.type)
    def pp(self):
        return "%r %r"%(self.name, parse_field_descriptor(self.type.type, self.type.name))

class CPMethodref(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("name", "u16"),
                ("type", "u16")]

    def __repr__(self, lvli = None):
        f1 = self._fields[1]
        n = getattr(self, f1[0])
        c = self.parent.get_constant_pool_by_index(n)
        f2 = self._fields[2]
        t = getattr(self, f2[0])
        n = self.parent.get_constant_pool_by_index(t)

        if lvli == None:
            return "<%s %s:%r %s:%r>"%(self.__class__, f1[0], c, f2[0], n)
        else:
            return [(self.__class__, [(f1[0], c), (f2[0], n)])]

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


class WCPMethodref(StructWrapper):
    wrapped = CPMethodref
    def get_name(self):
        return self.parent.get_constant_pool_by_index(self.cstr.name).name
    def get_type(self):
        return self.parent.get_constant_pool_by_index(self.cstr.type)
    def pp(self):
        return "%r"%(demangle_java_name(self.name, self.type.type, self.type.name))


class CPInterfaceMethodref(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("name", "u16"),
                ("type", "u16")]

class WCPInterfaceMethodref(StructWrapper):
    wrapped = CPInterfaceMethodref
    def get_name(self):
        return self.parent.get_constant_pool_by_index(self.cstr.name).value
    def get_type(self):
        return self.parent.get_constant_pool_by_index(self.cstr.type)
    def pp(self):
        return "%r %r %r"%(self.name.replace('/', '.'), self.type.name, self.type.type)

class CPNameandType(CStruct):
    _packformat = ">"
    _fields = [ ("tag", "u08"),
                ("name", "u16"),
                ("type", "u16")]

    def __repr__(self, lvli = None):
        f1 = self._fields[1]
        n = getattr(self, f1[0])
        n = self.parent.get_constant_pool_by_index(n).value
        f2 = self._fields[2]
        t = getattr(self, f2[0])
        t = self.parent.get_constant_pool_by_index(t).value

        if lvli == None:
            return "<%s %s:%r %s:%r>"%(self.__class__, f1[0], n, f2[0], t)
        else:
            return [(self.__class__, [(f1[0], n), (f2[0], t)])]

class WCPNameandType(StructWrapper):
    wrapped = CPNameandType
    def get_name(self):
        return self.parent.get_constant_pool_by_index(self.cstr.name).value
    def get_type(self):
        return self.parent.get_constant_pool_by_index(self.cstr.type).value

    def pp(self):
        return "%r %r"%(self.type, self.name)


CONSTANT_TYPES = {
    1 : CPUtf8,
    3 : CPInteger,
    4 : CPFloat,
    5 : CPLong,
    6 : CPDouble,
    7 : WCPClass,
    8 : WCPString,
    9 : WCPFieldref,
    10: WCPMethodref,
    11: WCPInterfaceMethodref,
    12: WCPNameandType,
    }

class CPoolfield(CStruct):
    _packformat = ">"
    _fields = [("tag", "u08")]
    @classmethod
    def unpack(cls, s, off = 0, parent = None, _sex=1, _wsize=32):
        tag = ord(s[off])
        if not tag in CONSTANT_TYPES:
            raise ValueError('unknown type', hex(tag))
        c = CONSTANT_TYPES[tag].unpack(s, off, parent, _sex, _wsize)
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


class WCAttribute_code(StructWrapper):
    wrapped = CAttribute_code
    def get_name(self):
        return self.parent.get_constant_pool_by_index(self.cstr.name).value

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

class WCLineNumberTable(StructWrapper):
    wrapped = CLineNumberTable
    def get_name(self):
        return self.parent.get_constant_pool_by_index(self.cstr.name).value

class CException(CStruct):
    _packformat = ">"
    _fields = [ ("name", "u16"),
                ("attribute_length", "u32"),
                ("exceptions_count", "u16"),
                ("exceptions", "u16", lambda c:c.exceptions_count),
                ]

class WCException(StructWrapper):
    wrapped = CException
    def get_name(self):
        return self.parent.get_constant_pool_by_index(self.cstr.name).value

class CClass(CStruct):
    _packformat = ">"
    _fields = [ ("inner_class_info", "u16"),
                ("outer_class_info", "u16"),
                ("inner_name", "u16"),
                ("inner_class_access_flags", "u16"),
                ]

class WCClass(StructWrapper):
    wrapped = CClass
    def get_inner_class_info(self):
        return self.parent.get_constant_pool_by_index(self.cstr.inner_class_info).name
    def get_outer_class_info(self):
        return self.parent.get_constant_pool_by_index(self.cstr.outer_class_info).name
    def get_inner_name(self):
        return self.parent.get_constant_pool_by_index(self.cstr.inner_name).name

class CInnerClasses(CStruct):
    _packformat = ">"
    _fields = [ ("name", "u16"),
                ("attribute_length", "u32"),
                ("classes_count", "u16"),
                ("classes", "CClass", lambda c:c.classes_count),
                ]

class WCInnerClasses(StructWrapper):
    wrapped = CInnerClasses
    def get_name(self):
        return self.parent.get_constant_pool_by_index(self.cstr.name).value

class CSourceFile(CStruct):
    _packformat = ">"
    _fields = [ ("name", "u16"),
                ("attribute_length", "u32"),
                ("sourcefile", "u16"),
                ]

class WCSourceFile(StructWrapper):
    wrapped = CSourceFile
    def get_name(self):
        return self.parent.get_constant_pool_by_index(self.cstr.name).value
    def get_sourcefile(self):
        return self.parent.get_constant_pool_by_index(self.cstr.sourcefile).value

class CSynthetic(CStruct):
    _packformat = ">"
    _fields = [ ("name", "u16"),
                ("attribute_length", "u32")
                ]

class WCSynthetic(StructWrapper):
    wrapped = CSynthetic
    def get_name(self):
        return self.parent.get_constant_pool_by_index(self.cstr.name).value

class CAttributeInfo_default(CStruct):
    _packformat = ">"
    _fields = [ ("name", "u16"),
                ("attribute_length", "u32"),
                ("attribute", (lambda c, s, of:c.getcode(s, of),
                                lambda c, value:c.setcode(value))),
                ]

    def getcode(self, s, of):
        v = s[of:of+self.attribute_length]
        return v, of+self.attribute_length
    def setcode(self, value):
        return str(value)

class WCAttributeInfo_default(StructWrapper):
    wrapped = CAttributeInfo_default
    def get_name(self):
        return self.parent.get_constant_pool_by_index(self.cstr.name).value


class CAttributeInfo(CStruct):
    _packformat = ">"
    _fields = [ ("name", "u16")
                ]
    @classmethod
    def unpack(cls, s, off = 0, parent = None, _sex=1, _wsize=32):
        tag = struct.unpack('>H', s[off:off+2])[0]
        c = parent.get_constant_pool_by_index(tag)
        if not isinstance(c, CPUtf8):
            raise ValueError('Error in parsing, should be string', hex(tag))
        name = c.value
        if name == "Code":
            c = WCAttribute_code.unpack(s, off, parent, _sex, _wsize)
        elif name == "LineNumberTable":
            c = WCLineNumberTable.unpack(s, off, parent, _sex, _wsize)
        elif name == "Exceptions":
            c = WCException.unpack(s, off, parent, _sex, _wsize)
        elif name == "InnerClasses":
            c = WCInnerClasses.unpack(s, off, parent, _sex, _wsize)
        elif name == "SourceFile":
            c = WCSourceFile.unpack(s, off, parent, _sex, _wsize)
        elif name == "Synthetic":
            c = WCSynthetic.unpack(s, off, parent, _sex, _wsize)
        else:
            log.warning("unsupported attribute, skipping:\n%r"%(c))
            c = CAttributeInfo_default.unpack(s, off, parent, _sex, _wsize)
        return c
"""
class WCAttributeInfo(StructWrapper):
    wrapped = CAttributeInfo
"""
class CFieldInfo(CStruct):
    _packformat = ">"
    _fields = [ ("access_flags", "u16"),
                ("name", "u16"),
                ("descriptor", "u16"),
                ("attributes_count", "u16"),
                ("attributes", "CAttributeInfo", lambda c:c.attributes_count),
                ]

class WCFieldInfo(StructWrapper):
    wrapped = CFieldInfo
    def get_name(self):
        return self.parent.get_constant_pool_by_index(self.cstr.name).value

class CMethods(CStruct):
    _packformat = ">"
    _fields = [ ("access_flags", "u16"),
                ("name", "u16"),
                ("descriptor", "u16"),
                ("attributes_count", "u16"),
                ("attributes", "CAttributeInfo", lambda c:c.attributes_count),
                ]

class WCMethods(StructWrapper):
    wrapped = CMethods
    def get_name(self):
        return self.parent.get_constant_pool_by_index(self.cstr.name).value
    def get_descriptor(self):
        return self.parent.get_constant_pool_by_index(self.cstr.descriptor).value


class Jclass_hdr(CStruct):
    _packformat = ">"
    _fields = [ ("magic", "u32"),
                ("minor_version","u16"),
                ("major_version","u16"),
                ("constants_pool_count","u16"),
                ("constants_pool", "CPoolfield", lambda c:c.constants_pool_count-1),
                ("bitmask", "u16"),
                ("this","u16"),
                ("super","u16")
                ]

class Jclass_description(CStruct):
    _packformat = ">"
    _fields = [ ("interface_count","u16"),
                ("interfaces","u16", lambda c:c.interface_count),
                ("fields_count","u16"),
                ("fields","WCFieldInfo", lambda c:c.fields_count),
                ("methods_count","u16"),
                ("methods","WCMethods", lambda c:c.methods_count),
                ("attributes_count","u16"),
                ("attributes","CAttributeInfo", lambda c:c.attributes_count),
                ]

class WJclass_description(StructWrapper):
    wrapped = Jclass_description
    def get_interfaces(self, item):
        return self.parent.get_constant_pool_by_index(self.cstr.interfaces.__getitem__(item)).name


class JCLASS(object):
    content = ContentManager()

    def __getitem__(self, item):
        return self.content[item]
    def __setitem__(self, item, data):
        self.content.__setitem__(item, data)
        return

    def __init__(self, pestr = None):
        self.sex = 0
        self.wsize = 32
        self._content = pestr
        self.parse_content()

    def get_constant_pool_by_index(self, index):
        index -=1
        if 0 <= index < len(self.hdr.constants_pool):
            return self.hdr.constants_pool[index]
        return None

    def parse_content(self):
        self.hdr = Jclass_hdr.unpack(self.content, 0, self)
        self.description = Jclass_description.unpack(self.content, len(self.hdr), self)

    def __str__(self):
        out = ''
        out += str(self.hdr)
        out += str(self.description)
        return out
if __name__ == "__main__":
    import sys
    from pprint import pprint as pp

    e = JCLASS(open(sys.argv[1]).read())
