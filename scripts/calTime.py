# Import all classification package

import numpy
import random
import os
import sys
import string

if __name__=="__main__":
    fn=sys.argv[1]
    lines=list()
    for line in file(fn).readlines():
        lines.append (float(line.lstrip().rstrip()))

    a = numpy.array([lines])
    print "avg=%f, std=%f, min=%f, max=%f\n" % (numpy.mean(a), numpy.std(a), numpy.min(a), numpy.max(a))

    sys.exit(0)

# hcai: set ts=4 tw=100 sts=4 sw=4
