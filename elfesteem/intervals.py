import sys
if sys.version_info[0] >= 3:
    from functools import reduce
if sys.version_info[0:2] == (2, 3):
    from elfesteem.compatibility_python23 import sorted

class Intervals(object):
    '''
    Represent a subset of the integers, to be used to detect which parts
    of the file have been parsed
    '''
    def __init__(self):
        self.ranges = [ ]
    def __str__(self):
        if len(self.ranges) == 0: return "[]"
        return reduce(lambda x, y: x+" "+y,
               map(lambda x: "[%s:%s]"%(x.start,x.stop), self.ranges))
    # Internal methods to make object manipulation easier
    def _split(self, *poslist):
        def _split_slice(l, s):
            for pos in sorted(poslist):
                if s.start < pos < s.stop:
                    l.append(slice(s.start, pos))
                    s = slice(pos, s.stop)
            l.append(s)
            return l
        self.ranges = reduce(_split_slice, self.ranges, [])
    def _merge(self):
        def _merge_two_slices(l, s):
            if len(l) and (l[-1].stop == s.start):
                l[-1] = slice(l[-1].start, s.stop)
            else:
                l.append(s)
            return l
        self.ranges = reduce(_merge_two_slices, self.ranges, [])
    # Interface of the class
    def __iter__(self):
        for s in self.ranges:
            for t in range(s.start, s.stop):
                yield t
    def contains(self, start, stop):
        for s in self.ranges:
            if s.start <= start and stop <= s.stop:
                return True
        return False
    def excludes(self, start, stop):
        if len(self.ranges) == 0:
            return True
        if stop <= self.ranges[0].start:
            return True
        if self.ranges[-1].stop <= start:
            return True
        for i in range(len(self.ranges)-1):
            if self.ranges[i].stop <= start and stop <= self.ranges[i+1].start:
                return True
        return False
    def delete(self, start, stop):
        def _remove_slices(l, s):
            if start > s.start or stop < s.stop:
                l.append(s)
            return l
        self._split(start, stop)
        self.ranges = reduce(_remove_slices, self.ranges, [])
        return self
    def add(self, start, stop):
        if len(self.ranges) == 0:
            self.ranges.append(slice(start, stop))
            return self
        new_ranges = []
        prev_stop = None
        for l in self.ranges:
            if start <= l.start:
                if prev_stop is None:
                    new_ranges.append(slice(start, min(stop,l.start)))
                elif prev_stop < stop:
                    new_ranges.append(slice(max(start,prev_stop), min(stop,l.start)))
            new_ranges.append(l)
            prev_stop = l.stop
        if new_ranges[-1].stop < stop:
            new_ranges.append(slice(max(start,new_ranges[-1].stop), stop))
        self.ranges = new_ranges
        self._merge()
        return self
