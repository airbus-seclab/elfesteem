from array import array
# To be compatible with python 2 and python 3
import sys
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
            r = s[item]
            end = item.stop
            if end != None and len(s) < end:
                if item.step is not None:
                    TODO
                elif len(r) > 0:
                    # We go beyond the end of 's'
                    r.extend(array("B",self.paddingbyte*(end-len(s))))
                else:
                    # We are entirely after the end of 's'
                    r = array("B",self.paddingbyte*(end-item.start))
            return r.tostring()
        else:
            if item > len(s):
                return self.paddingbyte
            else:
                return chr(s[item])
    def __setitem__(self, item, val):
        if val == None:
            return
        if sys.version_info[0] >= 3 and type(val) == str:
            val = val.encode(encoding="latin1")
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
        return val in self.pack()
    def __iadd__(self, other):
        self.s.extend(array("B", other))
        return self

    def find(self, pattern, offset = 0):
        if not self.s_cache:
            self.s_cache = self.s.tostring()
        return self.s_cache.find(pattern, offset)

    def rfind(self, pattern, start = 0, end = None):
        if not self.s_cache:
            self.s_cache = self.s.tostring()
        return self.s_cache.rfind(pattern, start, end)

