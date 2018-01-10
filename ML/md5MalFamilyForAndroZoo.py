# Load features from DroidFax feature statistics files
import numpy
import random
import os
import sys
import string
import subprocess

from configs import *
from os import listdir
from os.path import isfile, join
from handle_io import io

verbose=False

def getsha256(fnapk):
    try:
        sha = subprocess.check_output(['sha256sum', fnapk])
    except Exception,e:
        print >> sys.stderr, "error occurred when executing sha256sum " + fnapk
    ret = string.split(sha.lower().lstrip().rstrip())
    if len(ret) < 2:
        print >> sys.stderr, "error in sha256sum of %s: %s" % (fnapk, sha)
        sys.exit(-1)

    return ret[0]

def getmd5(fnapk):
    return io.get_md5(fnapk)

def getMalwareFamily(resultDir, fnmapping):
    malwareLabels={}

    mapping = dict()
    for line in file (fnmapping, 'r').readlines():
        res = string.split(line.lower().lstrip().rstrip())
        assert len(res)==2
        mapping[res[0]] = res[1]

    for item in os.listdir(resultDir):
        if not (item.endswith(".apk")):
            continue
        apkfn = os.path.abspath(resultDir+'/'+item)
        sha = getsha256 (apkfn)
        md5 = getmd5 (apkfn)

        if sha not in mapping.keys():
            print >> sys.stderr, "family mapping for %s not found" % (apkfn)
            malwareLabels [md5] = "none"
        else:
            malwareLabels [md5] = mapping [sha]

    return malwareLabels

def malwareCatStat(labels):
    l2c={}
    for lab in labels:
        if lab not in l2c.keys():
            l2c[lab]=0
        l2c[lab]=l2c[lab]+1
    return l2c


if __name__=="__main__":
    malwareLabels = getMalwareFamily(sys.argv[1], '/home/hcai/Downloads/AndroZoo/labels/names/fullmapping.txt')

    '''
    labels = malwareLabels.values()
    l2c = malwareCatStat(labels)
    for lab in l2c.keys():
        print "%s\t%s" % (lab, l2c[lab])
    '''

    for app in malwareLabels.keys():
        print >> sys.stdout, "%s\t%s" % (app, malwareLabels[app])

    sys.exit(0)

# hcai: set ts=4 tw=100 sts=4 sw=4
