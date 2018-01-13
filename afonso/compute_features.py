# Compute afonso-apisys features from method call and strace traces
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

import re

verbose=False

g_featureframe=dict()


def getsha256(fnapk):
    try:
        sha = subprocess.check_output(['sha256sum', fnapk])
    except Exception,e:
        print >> sys.stderr, "error occurred when executing sha256sum " + fnapk
    ret = string.split(sha.lstrip().rstrip())
    if len(ret) < 2:
        print >> sys.stderr, "error in sha256sum of %s: %s" % (fnapk, sha)
        sys.exit(-1)

    return ret[0]

def getmd5(fnapk):
    return io.get_md5(fnapk)

def getapkname(fnapk):
    napk=fnapk
    ri = string.rfind(fnapk, '/')
    if ri != -1:
        napk = fnapk[ri+1:]
    ri = string.rfind(napk, '.')
    return napk[:ri]

def buildFeatureFrame(fnAPIList, fnSyscallList):
    global g_featureframe
    for line in file (fnAPIlist).readlines():
        line = line.lstrip().rstrip().replace('/','.')
        g_featureframe[line] = 0.0
    for line in file (fnSyscallList).readlines():
        line = line.lstrip().rstrip()
        g_featureframe[line] = 0.0
    return len(g_featureframe)

def loadFunctionCallTrace(fnFuncTrace):
    fvec = g_featureframe
    pattern = re.compile (r"<(?P<class1>):\s+.*\s+(?P<method1>)\(.*\)>\s+->\s+<(?P<class2>):\s+.*\s+(?P<method2>)\(.*\)>")
    for line in file (fnFuncTrace).readlines():
        line = line.lstrip().rstrip()
        if "->" not in line:
            pass
        res = pattern.match ( line )
        c1 = res.group ("class1")
        m1 = res.group ("method1")
        c2 = res.group ("class2")
        m2 = res.group ("method2")

        k1 = "%s->%s" % (c1, m1)
        k2 = "%s->%s" % (c2, m2)

        print >> sys.stderr, "line: %s => %s\t%s" % (line, k1, k2)

        if k1 in fvec.keys():
            fvec[k1] += 1

        if k2 in fvec.keys():
            fvec[k2] += 1

    return fvec

def newMalwareCategorize(resultDir,obf,prefix=False):
    fullFamilyList=list()
    for mf in file(malwareFamilyListFile).readlines():
        mf = mf.lstrip().rstrip()
        fullFamilyList.append( mf )
    vtRes=dict()
    for item in os.listdir(resultDir):
        if not (item.endswith(".apk") and os.path.isfile(resultDir+"/"+item+".result")):
            continue
        apkfn = os.path.abspath(resultDir+'/'+item)
        resfn = os.path.abspath(resultDir+'/'+item+".result")
        # store VirusTotal results in a map: tool->result
        vtResDetails=dict()
        for res in file(resfn, 'r').readlines():
            res = res.lstrip().rstrip()
            toolres = string.split(res)
            if len(toolres) < 2:
                #raise Exception ("wrong vt result line: %s in %s" % (res, apkfn))
                print >> sys.stderr, "wrong vt result line: %s in %s" % (res, apkfn)
                continue
            vtResDetails[toolres[0]] = toolres[1]
        appname = getpackname(apkfn, prefix)
        if obf==True:
            appname = getapkname(apkfn)
        if appname==None:
            print >> sys.stderr, "unable to figure out package name of " + apkfn
            sys.exit(-1)
        vtRes[appname] = vtResDetails

    ret=dict()
    for app in vtRes.keys():
        finalFam = refineFamily(fullFamilyList, vtRes[app])
        #print >> sys.stdout, "%s\t%s" % (app, finalFam)
        if None==finalFam:
            #print >> sys.stdout, "no family identified for %s -- %s" % (app, vtRes[app])
            print >> sys.stderr, "no family identified for %s" % (app)
            finalFam = majorvote( vtRes[app] )
            if None==finalFam:
                print >> sys.stderr, "cannot find family for %s" % (app)
            else:
                print >> sys.stderr, "will use %s" % (finalFam)
            #sys.exit(-2)
        ret[app] = [finalFam, vtRes[app]]

    return ret


def DrebinMalwareCategorizeMD5(resultDir, fnfamilymap="/home/hcai/Downloads/Drebin/sha256_family.csv"):
    sha2fam=dict()
    for line in file (fnfamilymap).readlines():
        line = line.lstrip().rstrip()
        res = string.split(line,sep=',')
        sha2fam[ res[0] ] = res[1]

    ret=dict()
    for item in os.listdir(resultDir):
        if not (item.endswith(".apk")):
            continue
        apkfn = os.path.abspath(resultDir+'/'+item)
        sha = getsha256 (apkfn)
        md5 = io.get_md5 (apkfn)
        ret[md5] = [ sha2fam[sha], {} ]

    return ret


if __name__=="__main__":
    malwareLabels = getMalwareFamily(sys.argv[1], sys.argv[2].lower()=="true", sys.argv[3].lower()=="true", sys.argv[4].lower()=="true")

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
