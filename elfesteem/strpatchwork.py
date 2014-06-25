from array import array
# To be compatible with python 2 and python 3
import struct
data_null = struct.pack("B",0)
data_empty = struct.pack("")

class StrPatchwork(object):
    def __init__(self, s=data_empty, paddingbyte=data_null):
        if s == None: s = data_empty
        if isinstance(s, StrPatchwork): s = s.pack()
        self.s = array("B",s)
        # cache s to avoid rebuilding str after each find
        self.s_cache = s
        self.paddingbyte=paddingbyte
    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    def pack(self):
        return self.s.tostring()

    def __getitem__(self, item):
        s = self.s
        if type(item) is slice:
            end = item.stop
            l = len(s)
            if end != None and l < end:
                # This is inefficient but avoids complicated maths if step is not 1
                s = s[:]
                s.extend(array("B",self.paddingbyte*(end-l)))
            r = s[item]
            return r.tostring()

        else:
            if item > len(s):
                return self.paddingbyte
            else:
                return chr(s[item])
    def __setitem__(self, item, val):
        if val == None:
            return
        val = array("B",val)
        if type(item) is not slice:
            item = slice(item, item+len(val))
        end = item.stop
        l = len(self.s)
        if l < end:
            self.s.extend(array("B", self.paddingbyte*(end-l)))
        self.s[item] = val
        self.s_cache = None


    def __repr__(self):
        return "<Patchwork %r>" % self.s.tostring()
    def __len__(self):
        return len(self.s)
    def __contains__(self, val):
        return val in str(self)
    def __iadd__(self, other):
        self.s.extend(array("B", other))
        return self

    def find(self, pattern, offset = 0):
        if not self.s_cache:
            self.s_cache = self.s.tostring()
        return self.s_cache.find(pattern, offset)

