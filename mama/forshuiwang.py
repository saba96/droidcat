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
    packages.sort()
    ret=[]
    for item in reversed (packages):
        ret.append (item)
    packages = ret
    #print packages
    packseq.close()

def abstract2pack(line):
    global packages
    #print packages
    for pack in packages:
        if  line.lower().startswith( pack.lower() ):
        #if  line.lower() == pack.lower():
            return pack
    return "self_define"

def do_transform(lines):
    for line in lines:
        line = line.replace('\n','')
        line = line.lstrip('<').rstrip('>')
        pair=string.split(line," ==> ",2)
        assert len(pair)==2
        pair[0] = pair[0].lstrip('<').rstrip('>')
        pair[0] = string.split(pair[0], ":")[0]
        pair[1] = pair[1].lstrip('<').rstrip('>')
        pair[1] = string.split(pair[1], ":")[0]

        pair[0] = abstract2pack( pair[0] )
        pair[1] = abstract2pack( pair[1] )

        print line
        print "%s -> %s" % (pair[0], pair[1])
        print

def transform_all(graphdir):
    fnapps = os.listdir(graphdir)
    for fnapp in fnapps:
        with open(graphdir+'/'+fnapp) as callseq:
            specificapp=[]
            for line in callseq:
                specificapp.append(line)
            callseq.close()

        print "for app %s" % (fnapp)
        do_transform( specificapp )

if __name__ == "__main__":
    if len(sys.argv)<2:
        print >> sys.stderr, "usage: %s callgraph-dir" % (sys.argv[0])
        sys.exit(-1)

    readpackages()

    transform_all ( sys.argv[1] )

    sys.exit (0)

# hcai: set ts=4 tw=120 sts=4 sw=4

