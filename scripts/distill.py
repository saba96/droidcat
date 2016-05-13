#!/usr/bin/python

import os
import string
import sys

def do(fn):
    fh = file(fn,'r')
    if fh==None:
        return
    allines = fh.readlines()
    ret=dict()
    for line in allines:
        items = string.split(line)
        if len(items)!=13:
            continue
        key=(items[0],items[1])
        sum=int(items[9])+int(items[10])
        if key in ret.keys():
            if int(ret[key][0]) < sum:
                ret[key] = (sum, line)
        else:
            ret[key] = (sum, line)
    for key in ret.keys():
        print ret[key][1],

if __name__ == "__main__":
    do(sys.argv[1])

