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

'''
feature storage structure:
    {(appname,date):[feature value set 1[feature-value1,feature-value2,...,feature-valueN], feature value set 2[...],...,]}
'''

'''load general features'''
def load_generalFeatures(gfn):
    fh = file(gfn, 'r')
    if fh==None:
        raise IOError("error occurred when opening file " + gfn)
    contents = fh.readlines()
    fh.close()
    gfeatures=dict()
    n=0
    for line in contents:
        line=line.lstrip().rstrip()
        items = string.split(line)
        n=n+1
        '''
        if len(items)!=30:
            print "%s\n%s at line %d" % (gfn, line,n)
            continue
        '''
        assert len(items)==31
        appname = items[0]
        date = items[1]
        if (appname,date) not in gfeatures.keys():
            gfeatures[ (appname,date) ] = list()
        fvs = [float(x) for x in items[2:]]
        gfeatures[ (appname,date) ].append( fvs )
    # for multiple sets of feature values per app, compute and keep the averages only
    for (app,date) in gfeatures.keys():
        allsets = gfeatures[(app,date)]
        if verbose and len(allsets)<2:
            print >> sys.stderr, app + " has one set of general features only!"
            #continue
        for j in range(0, len(allsets[0])):
            for k in range(1,len(allsets)):
                allsets[0][j] += allsets[k][j]
            allsets[0][j] /= (len(allsets)*1.0)
        del gfeatures[(app,date)]
        gfeatures[(app,date)] = allsets[0] #change to mapping: appname -> vector of average (element-wise) feature values
    return gfeatures

'''load ICC features'''
def load_ICCFeatures(iccfn):
    fh = file(iccfn, 'r')
    if fh==None:
        raise IOError("error occurred when opening file " + iccfn)
    contents = fh.readlines()
    fh.close()
    iccfeatures=dict()
    for line in contents:
        line=line.lstrip().rstrip()
        items = string.split(line)
        assert len(items)==9
        appname = items[0]
        date = items[1]
        if (appname,date) not in iccfeatures.keys():
            iccfeatures[ (appname,date) ] = list()
        fvs = [float(x) for x in items[2:]]
        iccfeatures[ (appname,date) ].append( fvs )
    # for multiple sets of feature values per app, compute and keep the averages only
    for (app,date) in iccfeatures.keys():
        allsets = iccfeatures[(app,date)]
        if verbose and len(allsets)<2:
            print >> sys.stderr, app + " has one set of ICC features only!"
            #continue
        for j in range(0, len(allsets[0])):
            for k in range(1,len(allsets)):
                allsets[0][j] += allsets[k][j]
            allsets[0][j] /= (len(allsets)*1.0)
        del iccfeatures[(app,date)]
        iccfeatures[(app,date)] = allsets[0] # change to mapping: appname -> vector of average (element-wise) feature values
    return iccfeatures

'''load security features'''
def load_securityFeatures(secfn):
    fh = file(secfn, 'r')
    if fh==None:
        raise IOError("error occurred when opening file " + secfn)
    contents = fh.readlines()
    fh.close()
    secfeatures=dict()
    n=0
    for line in contents:
        line=line.lstrip().rstrip()
        items = string.split(line)
        '''
        n=n+1
        if len(items)!=87:
            print "%s\n%s at line %d" % (secfn, line,n)
            continue
        '''

        assert len(items)==88
        appname = items[0]
        date = items[1]
        if (appname,date) not in secfeatures.keys():
            secfeatures[ (appname,date) ] = list()
        fvs = [float(x) for x in items[2:]]
        secfeatures[ (appname,date) ].append( fvs )
    # for multiple sets of feature values per app, compute and keep the averages only
    for (app,date) in secfeatures.keys():
        allsets = secfeatures[(app,date)]
        if verbose and len(allsets)<2:
            print >> sys.stderr, app + " has one set of security features only!"
            #continue
        for j in range(0, len(allsets[0])):
            for k in range(1,len(allsets)):
                allsets[0][j] += allsets[k][j]
            allsets[0][j] /= (len(allsets)*1.0)
        del secfeatures[(app,date)]
        secfeatures[(app,date)] = allsets[0] # change to mapping: appname -> vector of average (element-wise) feature values
    return secfeatures

def getpackname(fnapk, prefix=False):
    appname=None
    try:
        appname = subprocess.check_output([BIN_GETPACKNAME, fnapk])
    except Exception,e:
        print >> sys.stderr, "error occurred when executing getpackage.sh " + fnapk
    ret = string.split(appname.lstrip().rstrip(),'\t')
    if len(ret) < 2:
        print >> sys.stderr, "error in getting package name of %s: %s" % (fnapk, appname)
        sys.exit(-1)
        '''
        napk=fnapk
        ri = string.rfind(fnapk, '/')
        if ri != -1:
            napk = fnapk[ri+1:]
        return napk
        '''

    if not prefix:
        return ret[1]

    napk=fnapk
    ri = string.rfind(fnapk, '/')
    if ri != -1:
        napk = fnapk[ri+1:]
    #napk = napk[0: string.rfind(napk, ".apk")]
    return napk+'.'+ret[1]

def getapkname(fnapk):
    napk=fnapk
    ri = string.rfind(fnapk, '/')
    if ri != -1:
        napk = fnapk[ri+1:]
    ri = string.rfind(napk, '.')
    #return napk[:ri]
    return napk[:ri]+'.apk'

def malwareCategorizeRough(resultDir,fnmapping):
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
    for app in set(vtRes.keys()).intersection( familymapping.keys() ):
        ret[app] = [familymapping[app], vtRes[app]]

    return ret

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
            winFam = fam.lower()
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
            winFam = fam.lower()
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
                continue
            vtResDetails[toolres[0]] = toolres[1]
        if obf==True:
            appname = getapkname(apkfn)
        else:
            appname = getpackname(apkfn, prefix)
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
            #print >> sys.stdout, "no family identified for %s" % (app)
            finalFam = majorvote( vtRes[app] )
            #print >> sys.stdout, "will use %s" % (finalFam)
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

def getBenignTrainingData(\
        benign_g=FTXT_BENIGN_G,\
        benign_icc=FTXT_BENIGN_ICC,\
        benign_sec=FTXT_BENIGN_SEC):

    gfeatures_benign = load_generalFeatures(benign_g)
    iccfeatures_benign = load_ICCFeatures(benign_icc)
    secfeatures_benign = load_securityFeatures(benign_sec)

    for app in set(malbenignapps):
        for (_app,date) in gfeatures_benign.keys():
            if app == _app:
                del gfeatures_benign[(_app,date)]
        for (_app,date) in iccfeatures_benign.keys():
            if app == _app:
                del iccfeatures_benign[(_app,date)]
        if (_app,date) in secfeatures_benign.keys():
            if app == _app:
                del secfeatures_benign[(_app,date)]
    allapps_benign = set(gfeatures_benign.keys()).intersection(iccfeatures_benign.keys()).intersection(secfeatures_benign.keys())
    for (app,date) in set(gfeatures_benign.keys()).difference(allapps_benign):
        del gfeatures_benign[(app,date)]
    for (app,date) in set(iccfeatures_benign.keys()).difference(allapps_benign):
        del iccfeatures_benign[(app,date)]
    for (app,date) in set(secfeatures_benign.keys()).difference(allapps_benign):
        del secfeatures_benign[(app,date)]

    assert len(gfeatures_benign)==len(iccfeatures_benign) and len(iccfeatures_benign)==len(secfeatures_benign)

    allfeatures_benign = dict()
    for (app,date) in gfeatures_benign.keys():
        allfeatures_benign[(app,date)] = gfeatures_benign[(app,date)] + iccfeatures_benign[(app,date)] + secfeatures_benign[(app,date)]

    benignLabels={}
    #for j in range(0,len(allfeatures_benign)):
    #    benignLabels.append("BENIGN")
    for (app,date) in allfeatures_benign.keys():
        benignLabels[(app,date)] = "BENIGN"

    for (app,date) in allfeatures_benign.keys():
        if sum(allfeatures_benign[(app,date)]) < 0.00005:
            del allfeatures_benign[(app,date)]
            del benignLabels[(app,date)]

    print str(len(allfeatures_benign)) + " valid benign app training samples to be used."

    return (allfeatures_benign, benignLabels)

def loadBenignData(rootdir):
    return getBenignTrainingData ( os.path.join(rootdir, FTXT_G), os.path.join(rootdir, FTXT_ICC), os.path.join(rootdir, FTXT_SEC) )

'''load malware features without malware family labels'''
def loadMalwareNoFamily(rootdir):
    mal_g = os.path.join(rootdir, FTXT_G)
    mal_icc = os.path.join(rootdir, FTXT_ICC)
    mal_sec = os.path.join(rootdir, FTXT_SEC)
    gfeatures_malware = load_generalFeatures(mal_g)
    iccfeatures_malware = load_ICCFeatures(mal_icc)
    secfeatures_malware = load_securityFeatures(mal_sec)

    allapps_malware = \
        set(gfeatures_malware.keys()).intersection(iccfeatures_malware.keys()).intersection(secfeatures_malware.keys())

    for app in set(gfeatures_malware.keys()).difference(allapps_malware):
        del gfeatures_malware[app]
    for app in set(iccfeatures_malware.keys()).difference(allapps_malware):
        del iccfeatures_malware[app]
    for app in set(secfeatures_malware.keys()).difference(allapps_malware):
        del secfeatures_malware[app]

    assert len(gfeatures_malware)==len(iccfeatures_malware) and len(iccfeatures_malware)==len(secfeatures_malware)

    allfeatures_malware = dict()
    for app in gfeatures_malware.keys():
        allfeatures_malware[app] = gfeatures_malware[app] + iccfeatures_malware[app] + secfeatures_malware[app]

    malwareLabels={}
    for app in allfeatures_malware.keys():
        malwareLabels[app] = 'MALICIOUS'

    for app in allfeatures_malware.keys():
        if sum(allfeatures_malware[app]) < 0.00005:
            del allfeatures_malware[app]
            del malwareLabels[app]

    print str(len(allfeatures_malware)) + " valid malicious app training samples to be used."
    return (allfeatures_malware,malwareLabels)

'''load malware features and associate with each sample the malware family label'''
def loadMalwareData(dichotomous, rootdir, malwareResultDir, pruneMinor, drebin, obf, malgenome=False):
    return getMalwareTestingData(dichotomous, os.path.join(rootdir, FTXT_G), os.path.join(rootdir, FTXT_ICC), os.path.join(rootdir, FTXT_SEC), \
            malwareResultDir, pruneMinor, drebin, obf, malgenome)

def getMalwareTestingData(dichotomous=False, \
        mal_g=FTXT_MALWARE_G_NEW,\
        mal_icc=FTXT_MALWARE_ICC_NEW,\
        mal_sec=FTXT_MALWARE_SEC_NEW,\
        malwareResultDir=malwareResultDirNew,
	pruneMinor=False,
        drebin=False,
        obf=False,
        malgenome=False):

    gfeatures_malware = load_generalFeatures(mal_g)
    iccfeatures_malware = load_ICCFeatures(mal_icc)
    secfeatures_malware = load_securityFeatures(mal_sec)

    malFam = None
    if drebin==True:
        malFam = DrebinMalwareCategorize(fnfamilymap=os.path.join(malwareResultDir, 'sha256_family.csv'), fnpkg2name=os.path.join(malwareResultDir,'pkg2name.txt'))
    elif malgenome==True:
        malFam = MalgenomeMalwareCategorize(fnapklist="/home/hcai/gitrepo/droidcat/ML/malgenome_apks.txt", fnfamilylist="/home/hcai/gitrepo/droidcat/ML/malgenome_families.txt")
    else:
        malFam = newMalwareCategorize(malwareResultDir,obf)

    allapps_malware = \
        set(gfeatures_malware.keys()).intersection(iccfeatures_malware.keys()).intersection(secfeatures_malware.keys())

    #allapps_malware = [app for (app,_) in allapps_malware.keys()].intersection( malFam.keys() )

    toremove=[]
    for (app,date) in allapps_malware:
        if app not in malFam.keys():
            toremove.append( (app,date) )
    for e in toremove:
        allapps_malware.remove(e)

    for app in set(gfeatures_malware.keys()).difference(allapps_malware):
        del gfeatures_malware[app]
    for app in set(iccfeatures_malware.keys()).difference(allapps_malware):
        del iccfeatures_malware[app]
    for app in set(secfeatures_malware.keys()).difference(allapps_malware):
        del secfeatures_malware[app]

    assert len(gfeatures_malware)==len(iccfeatures_malware) and len(iccfeatures_malware)==len(secfeatures_malware)

    allfeatures_malware = dict()
    for app in gfeatures_malware.keys():
        allfeatures_malware[app] = gfeatures_malware[app] + iccfeatures_malware[app] + secfeatures_malware[app]

    malwareLabels={}
    '''
    for app in allfeatures_malware.keys():
        if dichotomous:
            malwareLabels[app] = 'MALICIOUS'
        else:
            malwareLabels[app] = str(malFam[app][0])
    '''
    for app in allfeatures_malware.keys():
        malwareLabels[app] = str(malFam[app[0]][0]).lower()
        #print "%s 's malware label: %s" % (app, malwareLabels[app])

    for app in allfeatures_malware.keys():
        if sum(allfeatures_malware[app]) < 0.00005:
            del allfeatures_malware[app]
            del malwareLabels[app]

    if pruneMinor:
        purelabels = list()
        for app in allfeatures_malware.keys():
            purelabels.append (malwareLabels[app])
        l2c = malwareCatStat(purelabels)
        minorapps = list()
        for app in allfeatures_malware.keys():
            if pruneMinor and l2c[ malwareLabels[app] ] <= PRUNE_THRESHOLD:
                minorapps.append( app )
        for app in minorapps:
            del allfeatures_malware[app]
            del malwareLabels[app]
        print "%d minor apps pruned" % (len(minorapps))


    '''
    big_families=["DroidKungfu", "ProxyTrojan/NotCompatible/NioServ", "GoldDream", "Plankton", "FakeInst"]
    for app in malwareLabels.keys():
        if malwareLabels[app] not in big_families:
            del allfeatures_malware[app]
            del malwareLabels[app]
            #pass
            #malwareLabels[app] = "MALICIOUS"
    '''
    for app in malwareLabels.keys():
        if malwareLabels[app].lower()=="none":
            del allfeatures_malware[app]
            del malwareLabels[app]

    print str(len(allfeatures_malware)) + " valid malicious app testing samples to be used."

    if dichotomous:
        for app in malwareLabels.keys():
            malwareLabels[app] = 'MALICIOUS'

    return (allfeatures_malware,malwareLabels)

def getMalwareTrainingData(dichotomous=False, \
        mal_g=FTXT_MALWARE_G,\
        mal_icc=FTXT_MALWARE_ICC,\
        mal_sec=FTXT_MALWARE_SEC,\
	pruneMinor=False):

    gfeatures_malware = load_generalFeatures(mal_g)
    iccfeatures_malware = load_ICCFeatures(mal_icc)
    secfeatures_malware = load_securityFeatures(mal_sec)

    #malFam = malwareCategorizeRough(malwareResultDir, malwareMappingFile)
    malFam = malwareCategorize(malwareResultDir, malwareMappingFile)


    gfeatures_malware.update ( load_generalFeatures (FTXT_MALWARE_G_NEW) )
    iccfeatures_malware.update ( load_ICCFeatures( FTXT_MALWARE_ICC_NEW) )
    secfeatures_malware.update ( load_securityFeatures (FTXT_MALWARE_SEC_NEW) )
    newmalFam = newMalwareCategorize(malwareResultDirNew, False, True)
    malFam.update (newmalFam)

    allapps_malware = \
        set(gfeatures_malware.keys()).intersection(iccfeatures_malware.keys()).intersection(secfeatures_malware.keys())

    allapps_malware = allapps_malware.intersection( malFam.keys() )

    for app in set(gfeatures_malware.keys()).difference(allapps_malware):
        del gfeatures_malware[app]
    for app in set(iccfeatures_malware.keys()).difference(allapps_malware):
        del iccfeatures_malware[app]
    for app in set(secfeatures_malware.keys()).difference(allapps_malware):
        del secfeatures_malware[app]

    assert len(gfeatures_malware)==len(iccfeatures_malware) and len(iccfeatures_malware)==len(secfeatures_malware)

    allfeatures_malware = dict()
    for app in gfeatures_malware.keys():
        allfeatures_malware[app] = gfeatures_malware[app] + iccfeatures_malware[app] + secfeatures_malware[app]

    malwareLabels={}
    #for app in allfeatures_malware.keys():
    #    malwareLabels.append( str(malFam[app][0]) )
    '''
    for app in allfeatures_malware.keys():
        if dichotomous:
            malwareLabels[app] = 'MALICIOUS'
        else:
            malwareLabels[app] = str(malFam[app][0])
        #print "%s\t%s" % (app, malwareLabels[app])
    '''
    for app in allfeatures_malware.keys():
        malwareLabels[app] = str(malFam[app][0]).lower()

    for app in allfeatures_malware.keys():
        if sum(allfeatures_malware[app]) < 0.00005:
            del allfeatures_malware[app]
            del malwareLabels[app]

    if pruneMinor:
        purelabels = list()
        for app in allfeatures_malware.keys():
            purelabels.append (malwareLabels[app])
        l2c = malwareCatStat(purelabels)
        minorapps = list()
        for app in allfeatures_malware.keys():
            if pruneMinor and l2c[ malwareLabels[app] ] < PRUNE_THRESHOLD:
                minorapps.append( app )
        for app in minorapps:
            del allfeatures_malware[app]
            del malwareLabels[app]
        print "%d minor apps pruned" % (len(minorapps))


    big_families=["DroidKungfu", "ProxyTrojan/NotCompatible/NioServ", "GoldDream", "Plankton", "FakeInst", "MALICIOUS"]
    #big_families=["DroidKungfu", "ProxyTrojan/NotCompatible/NioServ", "GoldDream", "Plankton", "FakeInst"]
    for app in malwareLabels.keys():
        if malwareLabels[app] not in big_families:
            '''
            del allfeatures_malware[app]
            del malwareLabels[app]
            malwareLabels[app] = "MALICIOUS"
            '''
            pass

    _exfamilies=["Malap", "Pjapps", "BackFlash/Crosate"]
    exfamilies=[x.lower for x in _exfamilies]

    for app in malwareLabels.keys():
        if malwareLabels[app] in exfamilies:
            del allfeatures_malware[app]
            del malwareLabels[app]

    if dichotomous:
        for app in malwareLabels.keys():
            malwareLabels[app] = 'MALICIOUS'

    print str(len(allfeatures_malware)) + " valid malicious app training samples to be used."
    return (allfeatures_malware,malwareLabels)

def getTrainingData(dichotomous=False, \
        benign_g=FTXT_BENIGN_G,\
        benign_icc=FTXT_BENIGN_ICC,\
        benign_sec=FTXT_BENIGN_SEC,\
        mal_g=FTXT_MALWARE_G,\
        mal_icc=FTXT_MALWARE_ICC,\
        mal_sec=FTXT_MALWARE_SEC,\
	pruneMinor=False,
        malwareCategorizationOnly=False):

    '''
    1. Assemble benign app features
    '''
    (allfeatures_benign, benignLabels) = getBenignTrainingData(benign_g, benign_icc, benign_sec)

    '''
    2. Assemble malicious app features
    '''
    (allfeatures_malware, malwareLabels) = getMalwareTrainingData(dichotomous, mal_g, mal_icc, mal_sec, pruneMinor)
    #(allfeatures_malware, malwareLabels) = getMalwareTestingData(dichotomous, FTXT_MALWARE_G_NEW, FTXT_MALWARE_ICC_NEW, FTXT_MALWARE_SEC_NEW, pruneMinor)

    #(allfeatures_newmalware, newmalwareLabels) = getMalwareTrainingData(dichotomous, FTXT_MALWARE_G_NEW, FTXT_MALWARE_ICC_NEW, FTXT_MALWARE_SEC_NEW, pruneMinor)


    '''
    3. assemble into the entire training set (as a matrix)
    '''
    allfeatures = dict() #allfeatures_benign.copy()
    if not malwareCategorizationOnly:
        allfeatures = allfeatures_benign.copy()
    allfeatures.update ( allfeatures_malware )
    # sanity check
    r=0
    c=None
    for app in allfeatures.keys():
        r+=1
        if c==None:
            c = len (allfeatures[app])
            print "feature vector length=%d" % (c)
            continue
        if c != len (allfeatures[app]):
            print "inconsistent feature vector length for app: %s --- %d" % (app, len(allfeatures[app]))
        assert c == len (allfeatures[app])

    allLabels = benignLabels.copy()
    allLabels.update ( malwareLabels )

    features = numpy.zeros( shape=(r,c) )
    labels = list()
    k=0
    j=0
    Testfeatures = list() #numpy.zeros( shape=(r/2,c) )
    Testlabels = list()

    # test data: randomly pick 50% of the samples as test cases
    for app in allfeatures.keys():
        features[k] = allfeatures[app]
        labels.append (allLabels[app])
        k+=1

        if j < r/2 and random.Random().randint(1,2)==1:
            Testfeatures.append ( allfeatures[app] )
            Testlabels.append (allLabels[app])
            j+=1

    assert len(Testfeatures)==len(Testlabels)
    assert len(features)==len(labels)

    return (features, labels, Testfeatures, Testlabels)

def adapt (featureDict, labelDict):
    r=0
    c=None
    for app in featureDict.keys():
        r+=1
        if c==None:
            c = len (featureDict[app])
            print "feature vector length=%d" % (c)
            continue
        if c != len (featureDict[app]):
            print "inconsistent feature vector length for app: %s --- %d" % (app, len(featureDict[app]))
        assert c == len (featureDict[app])

    features = numpy.zeros( shape=(r,c) )
    labels = list()
    k=0
    for app in featureDict.keys():
        features[k] = featureDict[app]
        labels.append (labelDict[app])
        k+=1

    return (features, labels)

def getTestingData( app_g, app_icc, app_sec ):
    '''
    1. Assemble app features
    '''
    gfeatures_app = load_generalFeatures(app_g)
    iccfeatures_app = load_ICCFeatures(app_icc)
    secfeatures_app = load_securityFeatures(app_sec)

    allapps_app = set(gfeatures_app.keys()).intersection(iccfeatures_app.keys()).intersection(secfeatures_app.keys())
    for app in set(malbenignapps):
        for (_app,date) in gfeatures_benign.keys():
            if app == _app:
                del gfeatures_benign[(_app,date)]
        for (_app,date) in iccfeatures_benign.keys():
            if app == _app:
                del iccfeatures_benign[(_app,date)]
        if (_app,date) in secfeatures_benign.keys():
            if app == _app:
                del secfeatures_benign[(_app,date)]
    for app in set(gfeatures_app.keys()).difference(allapps_app):
        del gfeatures_app[app]
    for app in set(iccfeatures_app.keys()).difference(allapps_app):
        del iccfeatures_app[app]
    for app in set(secfeatures_app.keys()).difference(allapps_app):
        del secfeatures_app[app]

    assert len(gfeatures_app)==len(iccfeatures_app) and len(iccfeatures_app)==len(secfeatures_app)
    print str(len(gfeatures_app)) + " valid apps for detection..."

    allfeatures_app = dict()
    for app in gfeatures_app.keys():
        allfeatures_app[app] = gfeatures_app[app] + iccfeatures_app[app] + secfeatures_app[app]

    return allfeatures_app

def getFeatureMapping (fn_fmap = featureMappingFile):
    fh = file (fn_fmap, 'r')
    contents = fh.readlines()
    fh.close()
    idx2featurenames=dict()
    for line in contents:
        line=line.lstrip().rstrip()
        items = string.split(line)
        assert len(items)>=3
        idx2featurenames[(int)(items[0])] = (items[1], items[2])
    return idx2featurenames

def malwareCatStat(labels):
    l2c={}
    for lab in labels:
        if lab not in l2c.keys():
            l2c[lab]=0
        l2c[lab]=l2c[lab]+1
    return l2c

def loadMamaFeatures(featurefilesuffix, mode, label):
    print "loading features in %s in %s mode" % (featurefilesuffix, mode)
    featurefile = "features_mama/"+mode+"/"+featurefilesuffix+".csv"
    #prefix=featurefilesuffix+'/'
    prefix=""
    allfeatures = dict()
    #allfiles = [f for f listdir(rootdir) if isfile(join(rootdir, f))]
    fh = file (featurefile, 'r')
    contents = fh.readlines()
    fh.close()
    #del contents[0]
    inv=0

    apklist=[]
    for line in file ('samplelists/apks.'+featurefilesuffix).readlines():
        apklist.append (line.lstrip('\r\n').rstrip('\r\n')+'.txt')

    for line in contents:
        line=line.lstrip().rstrip()
        #print line
        items = string.split(line,sep=", ")
        appname = prefix+items[0].lstrip('\' []').rstrip('\' []')
        if appname not in apklist:
            continue
        try:
            fvs = [float(x.lstrip('\' []').rstrip('\' []')) for x in items[1:]]
        except:
            inv+=1
            continue
        allfeatures[ appname  ] = fvs

    alllabels={}
    for app in allfeatures.keys():
        alllabels[app] = label

    '''
    for app in allfeatures.keys():
        if sum(allfeatures[app]) < 0.00005:
            del allfeatures[app]
            del alllabels[app]
    '''

    print str(inv) + " invalid lines skipped"
    print str(len(allfeatures)) + " valid " + label + " app training samples to be used by MamaDroid."

    return (allfeatures, alllabels)

def pruneMinorMalware(features, labels):
    purelabels = list()
    for app in features.keys():
        purelabels.append (labels[app])
    l2c = malwareCatStat(purelabels)
    minorapps = list()
    for app in features.keys():
        if l2c[ labels[app] ] < PRUNE_THRESHOLD:
            minorapps.append( app )
    for app in minorapps:
        del features[app]
        del labels[app]
    print "%d minor apps pruned" % (len(minorapps))
    return (features,labels)

if __name__=="__main__":
    (features, labels, Testfeatures, Testlabels) = getTrainingData( False, pruneMinor=True)
    #(features, labels) = loadMamaFeatures( featurefile="features_mama/family/benign-2015.csv", label="BENIGN", prefix="benign-2015")
    (features, labels) = loadMamaFeatures( "benign-2014", "family", "BENIGN")

    l2c = malwareCatStat(labels)
    for lab in l2c.keys():
        print "%s\t%s" % (lab, l2c[lab])

    sys.exit(0)

# hcai: set ts=4 tw=100 sts=4 sw=4
