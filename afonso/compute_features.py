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

def loadAPICallTrace(fnFuncTrace):
    fvec = g_featureframe
    pattern = re.compile (r"<(?P<class1>):\s+.*\s+(?P<method1>)\(.*\)>\s+->\s+<(?P<class2>):\s+.*\s+(?P<method2>)\(.*\)>")
    for line in file (fnFuncTrace).readlines():
        line = line.lstrip().rstrip()
        if "->" not in line:
            continue
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

def loadAllAPICallTraces(apkDir, traceDir):
    retRes=dict()
    for apk in os.listdir(apkDir):
        if not (item.endswith(".apk")):
            continue
        apkfn = os.path.abspath(apkDir+'/'+apk)
        md5 = get_md5 (apkfn)

        tracefn = os.path.abspath(traceDir+'/'+getapkname(apkfn)+'.logcat')
        if os.path.isfile(tracefn):
            print >> sys.stderr, "no API call trace found for %s under directory %s" % (apkfn, traceDir)
            continue

        fvec = loadAPICallTrace (tracefn)
        retRes [md5] = fvec

    return retRes

def loadSysCallTrace(fnSyscallTrace):
    fvec = g_featureframe
    start=False
    end=False
    iscf = 0 # number of extracted sys-call features
    for line in file (fnSyscallTrace).readlines():
        line = line.lstrip().rstrip()
        #start = ("time     seconds  usecs/call     calls    errors syscall" in line)
        if not start:
            start = ("------ ----------- ----------- --------- --------- ----------------" in line)
            if not start:
                continue
        end = ("------ ----------- ----------- --------- --------- ----------------" in line)
        if end:
            break

        items = string.split (line)
        if len(items) != 6:
            continue

        syscallname = items[5]
        freq = float(items[3])

        if syscallname not in g_featureframe.keys()
            continue

        assert syscallname in fvec.keys()

        fvec [syscallname] = freq
        iscf += 1

    return iscf

def loadAllSysCallTraces(apkDir, traceDir):
    retRes=dict()
    for apk in os.listdir(apkDir):
        if not (item.endswith(".apk")):
            continue
        apkfn = os.path.abspath(apkDir+'/'+apk)
        md5 = get_md5 (apkfn)

        tracefn = os.path.abspath(traceDir+'/'+getapkname(apkfn)+'.logcat')
        if os.path.isfile(tracefn):
            print >> sys.stderr, "no system call trace found for %s under directory %s" % (apkfn, traceDir)
            continue

        fvec = loadSysCallTrace(tracefn)
        retRes [md5] = fvec

    return retRes

if __name__=="__main__":
    if len(sys.argv) < 5:
        print >> sys.stderr, "%s apkDir API-call-trace-dir Sys-call-trace-dir datatag"
        sys.exit(1)

    apkDir = sys.argv[1]
    apitraceDir = sys.argv[2]
    systraceDir = sys.argv[3]
    datatag = sys.argv[4]
    outfn = 'afonso.pickle.' + datatag

    apifvec = loadAllAPICallTraces(apkDir, apitraceDir)
    sysfvec = loadAllSysCallTraces(apkDir, systraceDir)

    finalfvec = apifvec
    finalfvec.update (sysfvec)

    fhpickle = file (outfn, 'wb')
    pickle.dump (finalfvec, fhpickle)
    fhpickle.close()

    print >> sys.stdout, "%d features computed, and dumped to %s" % (len(finalfvec), outfn)

    sys.exit(0)

# hcai: set ts=4 tw=100 sts=4 sw=4
