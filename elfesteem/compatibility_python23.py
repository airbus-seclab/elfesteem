import sys
if sys.version_info[0] == 2 and sys.version_info[1] <= 3:
    # Python 2.3 does not know 'sorted' nor 'reversed'
    def sorted(l, key=None, reverse=False):
        l = [_ for _ in l]
        if key is None:
            if reverse: l.sort(lambda x,y: cmp(y,x))
            else:       l.sort()
        else:
            if reverse: l.sort(lambda x,y: cmp(key(y),key(x)))
            else:       l.sort(lambda x,y: cmp(key(x),key(y)))
        return l
    def reversed(l):
        length = len(l)
        return [ l[length-idx] for idx in range(1,length+1) ]
    import warnings
    warnings.simplefilter("ignore", FutureWarning)
