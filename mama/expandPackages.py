#!/usr/bin/python

import os
import argparse
import sys
import multiprocessing
import math
import string

packages=[]

def readpackages():
    global packages
    with open('Packages.txt') as packseq:
        for line in packseq:
            assert line.startswith('.')
            line = line[1:]
            packages.append(line.replace('\n',''))

    ret=set()
    for pack in packages:
        l = expand(pack)
        for item in l:
            ret.add(item)

    packages = list(ret)
    packages.sort()
    ret=[]
    for item in reversed (packages):
        ret.append (item)
    packages = ret
    packseq.close()


    for item in packages:
        print item

def expand(line):
    ret=list()
    segs = string.split(line, '.')
    n=len(segs)

    if n<2:
        ret.append(line)
        return ret

    s = []
    s.append(segs[0])
    ret.append(segs[0])

    for i in range(1,n):
        s.append(segs[i])
        ret.append('.'.join(s))

    return ret

if __name__ == "__main__":
    readpackages()

    sys.exit (0)

# hcai: set ts=4 tw=120 sts=4 sw=4

