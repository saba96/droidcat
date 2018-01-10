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

verbose=False


def getpackname(fnapk, prefix=False):
    return getsha256(fnapk)

    appname=None
    try:
        appname = subprocess.check_output([BIN_GETPACKNAME, fnapk])
    except Exception,e:
        print >> sys.stderr, "error occurred when executing getpackage.sh " + fnapk
    ret = string.split(appname.lstrip().rstrip(),'\t')
    if len(ret) < 2:
        print >> sys.stderr, "error in getting package name of %s: %s" % (fnapk, appname)
        sys.exit(-1)

    if not prefix:
        return ret[1]

    napk=fnapk
    ri = string.rfind(fnapk, '/')
    if ri != -1:
        napk = fnapk[ri+1:]
    #napk = napk[0: string.rfind(napk, ".apk")]
    return napk+'.'+ret[1]

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

def getapkname(fnapk):
    napk=fnapk
    ri = string.rfind(fnapk, '/')
    if ri != -1:
        napk = fnapk[ri+1:]
    ri = string.rfind(napk, '.')
    return napk[:ri]

def refineFamily(fullFamilyList, vtres):
    f2n=dict()
    for tool in vtres.keys():
        res = vtres[tool].lower().lstrip("\"").rstrip("\"")
        for fam in fullFamilyList:
            if fam.lower() in res or res in fam.lower():
                if fam not in f2n.keys():
                    f2n[fam]=0
                f2n[fam]=f2n[fam]+1
    winCnt=-sys.maxint
    winFam=None
    for fam in f2n.keys():
        if f2n[fam] > winCnt:
            winCnt = f2n[fam]
            winFam = fam
    return winFam

def majorvote(vtres):
    f2n=dict()
    for tool in vtres.keys():
        res = vtres[tool].lower().lstrip("\"").rstrip("\"")
        if res not in f2n.keys():
            f2n[res]=0
        f2n[res] = f2n[res]+1

    winCnt=-sys.maxint
    winFam=None
    for fam in f2n.keys():
        if f2n[fam] > winCnt:
            winCnt = f2n[fam]
            winFam = fam
    return winFam

def malwareCategorize(resultDir,fnmapping):
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
            vtResDetails[toolres[0]] = toolres[1]
        appname = getpackname(apkfn)
        if appname==None:
            print >> sys.stderr, "unable to figure out package name of " + apkfn
            sys.exit(-1)
        vtRes[appname] = vtResDetails

    familymapping=dict()
    for mp in file(fnmapping).readlines():
        mp = mp.lstrip().rstrip()
        apkfam = string.split(mp)
        apkfn = os.path.abspath(resultDir+'/'+apkfam[0]+'.apk')
        if not os.path.isfile(apkfn):
            continue
        appname = getpackname(apkfn)
        if appname==None:
            print >> sys.stderr, "unable to figure out package name of " + apkfn
            sys.exit(-1)
        _sep=None
        if string.find(apkfam[1],'--')!=-1:
            _sep = '--'
        if string.find(apkfam[1],'_')!=-1:
            _sep = '_'
        if _sep==None:
            print >> sys.stderr, "unknown delimiter for retrieving malware family from "+apkfn
            sys.exit(-1)
        fam = string.split(apkfam[1],sep=_sep)[0]
        familymapping[appname]=fam

    ret=dict()
    '''
    for app in set(vtRes.keys()).intersection( familymapping.keys() ):
        finalFam = refineFamily(fullFamilyList, vtRes[app])
        #print >> sys.stdout, "%s\t%s" % (app, finalFam)
        if None==finalFam:
            finalFam=familymapping[app]
            #print >> sys.stdout, "%s\t%s" % (app, finalFam)
        ret[app] = [finalFam, vtRes[app]]
    '''

    for app in vtRes.keys():
        finalFam = refineFamily(fullFamilyList, vtRes[app])
        #print >> sys.stdout, "%s\t%s" % (app, finalFam)
        if None==finalFam:
            #print >> sys.stdout, "no family identified for %s -- %s" % (app, vtRes[app])
            print >> sys.stdout, "no family identified for %s" % (app)
            finalFam = majorvote( vtRes[app] )
            print >> sys.stdout, "will use %s" % (finalFam)
            #sys.exit(-2)
        ret[app] = [finalFam, vtRes[app]]

    return ret

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
            print >> sys.stdout, "no family identified for %s" % (app)
            finalFam = majorvote( vtRes[app] )
            print >> sys.stdout, "will use %s" % (finalFam)
            #sys.exit(-2)
        ret[app] = [finalFam, vtRes[app]]

    return ret

def DrebinMalwareCategorize(fnfamilymap="/home/hcai/Downloads/Drebin/sha256_family.csv",fnpkg2name="/home/hcai/Downloads/Drebin/pkg2name.txt"):
    name2fam=dict()
    for line in file (fnfamilymap).readlines():
        line = line.lstrip().rstrip()
        res = string.split(line,sep=',')
        name2fam[ res[0] ] = res[1]
    pkg2name=dict()
    for line in file (fnpkg2name).readlines():
        line = line.lstrip().rstrip()
        res = string.split(line,sep='\t')
        pkg2name[ res[0] ] = res[1]

    ret=dict()
    for app in pkg2name.keys():
        ret[app] = [ name2fam[ pkg2name[app] ], {} ]

    return ret

def MalgenomeMalwareCategorize(fnapklist="malgenome_apks.txt",fnfamilylist="malgenome_families.txt"):
    famlist=[]
    for line in file (fnfamilylist).readlines():
        fam = line.lstrip().rstrip()
        famlist.append (fam)
    def getfamily(apkname):
        for fam in famlist:
            if fam.lower() in apkname.lower():
                return fam
        return None

    ret=dict()
    for line in file (fnapklist).readlines():
        app = line.lstrip().rstrip()
        fam = getfamily(app)
        if fam == None:
            raise ValueError("could not find right family for Malgenome app: " + app)
        ret [app] = [ fam, {} ]

    return ret

def getMalwareFamily(\
        malwareResultDir=malwareResultDirNew,
        drebin=False,
        obf=False,
        malgenome=False):

    malFam = None
    if drebin==True:
        malFam = DrebinMalwareCategorize(fnfamilymap=os.path.join(malwareResultDir, 'sha256_family.csv'), fnpkg2name=os.path.join(malwareResultDir,'pkg2name.txt'))
    elif malgenome==True:
        malFam = MalgenomeMalwareCategorize(fnapklist="/home/hcai/gitrepo/droidcat/ML/malgenome_apks.txt", fnfamilylist="/home/hcai/gitrepo/droidcat/ML/malgenome_families.txt")
    else:
        malFam = newMalwareCategorize(malwareResultDir,obf)

    malwareLabels={}

    for app in malFam.keys():
        malwareLabels[app] = str(malFam[app][0]).lower()

    return malwareLabels

def malwareCatStat(labels):
    l2c={}
    for lab in labels:
        if lab not in l2c.keys():
            l2c[lab]=0
        l2c[lab]=l2c[lab]+1
    return l2c


if __name__=="__main__":
    malwareLabels = getMalwareFamily(sys.argv[1], sys.argv[2].lower()=="true", sys.argv[3].lower()=="true", sys.argv[4].lower()=="true")
    labels = malwareLabels.values()

    l2c = malwareCatStat(labels)
    for lab in l2c.keys():
        print "%s\t%s" % (lab, l2c[lab])

    for app in malwareLabels.keys():
        print "%s\t%s" % (app, malwareLabels[app])

    sys.exit(0)

# hcai: set ts=4 tw=100 sts=4 sw=4
