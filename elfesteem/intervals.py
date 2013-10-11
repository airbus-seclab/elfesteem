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
        self._split(start, stop)
        def _add_slice(l, s):
            if len(l) and l[-1].start <= start < s.start:
                if l[-1].start == start:
                    l[-1] = slice(start, stop)
                else:
                    l.append(slice(start, stop))
            if s.stop <= start or stop <= s.start:
                l.append(s)
            return l
        self.ranges = reduce(_add_slice, self.ranges, [])
        self._merge()
        return self

if __name__ == "__main__":
    i = Intervals()
    i.add(0, 100)
    print i
    i.delete(8, 25)
    print i
    print i.contains(18, 30)
    print i.contains(30, 50)
    print i.excludes(10, 20)
    print i.excludes(10, 30)
    i.add(12, 16)
    print i
    i.add(11, 14)
    print i
    i.add(1, 11)
    print i
    i.delete(8, 15)
    print i
    i.add(10, 30)
    print i
    i.delete(0, 100)
    print i
    print i.contains(18, 30)
    print i.excludes(10, 30)
    i.add(10, 30)
    print i
    i.delete(14, 27)
    print i
    for k in i:
        print k
