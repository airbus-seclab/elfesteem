#! /usr/bin/env python

from test_all import run_tests, assertion
from elfesteem.intervals import Intervals

def test_intervals(assertion):
    i = Intervals()
    assertion(i.ranges, [],
              'Empty interval')
    i.add(10, 90)
    assertion(i.ranges, [slice(10, 90)],
              'Interval [10:90]')
    i.add(0, 100)
    assertion(i.ranges, [slice(0, 100)],
              'Addition of bigger interval')
    i.add(0, 100)
    assertion(i.ranges, [slice(0, 100)],
              'Addition of identical interval')
    i.delete(8, 25)
    assertion(i.ranges, [slice(0, 8), slice(25, 100)],
              '[0:100] minus [8:25]')
    assertion(False, i.contains(18, 30),
              '[0:8]+[25:100] contains [18:30]')
    assertion(True,  i.contains(30, 30),
              '[0:8]+[25:100] contains [30:30]')
    assertion(True,  i.excludes(10, 20),
              '[0:8]+[25:100] excludes [10:20]')
    assertion(False, i.excludes(10, 30),
              '[0:8]+[25:100] excludes [10:30]')
    assertion(True,  i.excludes(-10, -5),
              '[0:8]+[25:100] excludes [-10:-5]')
    assertion(True,  i.excludes(110, 130),
              '[0:8]+[25:100] excludes [110:130]')
    i.add(12, 16)
    assertion(i.ranges, [slice(0, 8), slice(12, 16), slice(25, 100)],
              'Addition of disjoint interval')
    i.add(11, 14)
    assertion(i.ranges, [slice(0, 8), slice(11, 16), slice(25, 100)],
              'Addition of overlapping interval')
    i.add(1, 11)
    assertion(i.ranges, [slice(0, 16), slice(25, 100)],
              'Addition generating a merge')
    i.delete(8, 15)
    assertion(i.ranges, [slice(0, 8), slice (15, 16), slice(25, 100)],
              'Deletion within an interval')
    i.add(10, 30)
    assertion(i.ranges, [slice(0, 8), slice(10, 100)],
              'Addition of encompassing interval')
    i.delete(0, 100)
    assertion(i.ranges, [],
              'Deletion of everyting')
    assertion(False, i.contains(18, 30),
              'Empty contains [18:30]')
    assertion(True,  i.excludes(10, 30),
              'Empty excludes [10:30]')
    i.add(10, 30)
    i.delete(14, 27)
    assertion(str(i), '[10:14] [27:30]',
              'Display [10:14] [27:30]')
    assertion([_ for _ in i], [10, 11, 12, 13, 27, 28, 29],
              'Enumerate [10:14] [27:30]')

def run_test(assertion):
    for name, value in dict(globals()).items():
        if name.startswith('test_'):
            value(assertion)

if __name__ == "__main__":
    run_tests(run_test)
