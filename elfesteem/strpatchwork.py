from array import array
# To be compatible with python 2 and python 3
import sys
import struct
data_null = struct.pack("B",0)
data_empty = struct.pack("")

class StrPatchwork(object):
    def __init__(self, s=data_empty, paddingbyte=data_null):
        if s is None: s = data_empty
        if isinstance(s, StrPatchwork): s = s.pack()
        self.s = array("B",s)
        # cache s to avoid rebuilding str after each find
        self.s_cache = s
        self.paddingbyte=paddingbyte
    def __str__(self):
        return self.pack() # Needed for miasm2 :-(
        raise AttributeError("Use pack() instead of str()")
    def pack(self):
        if sys.version_info[0] >= 3:
            return self.s.tobytes()
        else:
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
                    start = item.start
                    if start is None: start = 0
                    r = array("B",self.paddingbyte*(end-start))
        else:
            if item > len(s):
                return self.paddingbyte
            else:
                r = array("B",[s[item]])
        if sys.version_info[0] >= 3:
            return r.tobytes()
        else:
            return r.tostring()
    def __setitem__(self, item, val):
        if val is None:
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
        return "<Patchwork %r>" % self.pack()
    def __len__(self):
        return len(self.s)
    def __contains__(self, val):
        return val in self.pack()
    def __iadd__(self, other):
        self.s.extend(array("B", other))
        return self

    def find(self, pattern, *args):
        if not self.s_cache:
            self.s_cache = self.pack()
        return self.s_cache.find(pattern, *args)

    def rfind(self, pattern, *args):
        if not self.s_cache:
            self.s_cache = self.pack()
        return self.s_cache.rfind(pattern, *args)

