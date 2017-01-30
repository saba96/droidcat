# Load features from DroidFax feature statistics files
import numpy
import random
import os
import sys
import string
import subprocess

from configs import *

verbose=False

'''
feature storage structure:
    {appname:[feature value set 1[feature-value1,feature-value2,...,feature-valueN], feature value set 2[...],...,]}
'''

'''load general features'''
def load_generalFeatures(gfn):
    fh = file(gfn, 'r')
    if fh==None:
        raise IOError("error occurred when opening file " + gfn)
    contents = fh.readlines()
    fh.close()
    gfeatures=dict()
    for line in contents:
        line=line.lstrip().rstrip()
        items = string.split(line)
        assert len(items)==30
        appname = items[0]
        if items[0] not in gfeatures.keys():
            gfeatures[ appname ] = list()
        fvs = [float(x) for x in items[1:]]
        gfeatures[ appname ].append( fvs )
    # for multiple sets of feature values per app, compute and keep the averages only
    for app in gfeatures.keys():
        allsets = gfeatures[app]
        if verbose and len(allsets)<2:
            print >> sys.stderr, app + " has one set of general features only!"
            #continue
        for j in range(0, len(allsets[0])):
            for k in range(1,len(allsets)):
                allsets[0][j] += allsets[k][j]
            allsets[0][j] /= (len(allsets)*1.0)
        del gfeatures[app]
        gfeatures[app] = allsets[0] #change to mapping: appname -> vector of average (element-wise) feature values
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
        assert len(items)==8
        appname = items[0]
        if items[0] not in iccfeatures.keys():
            iccfeatures[ appname ] = list()
        fvs = [float(x) for x in items[1:]]
        iccfeatures[ appname ].append( fvs )
    # for multiple sets of feature values per app, compute and keep the averages only
    for app in iccfeatures.keys():
        allsets = iccfeatures[app]
        if verbose and len(allsets)<2:
            print >> sys.stderr, app + " has one set of ICC features only!"
            #continue
        for j in range(0, len(allsets[0])):
            for k in range(1,len(allsets)):
                allsets[0][j] += allsets[k][j]
            allsets[0][j] /= (len(allsets)*1.0)
        del iccfeatures[app]
        iccfeatures[app] = allsets[0] # change to mapping: appname -> vector of average (element-wise) feature values
    return iccfeatures

'''load security features'''
def load_securityFeatures(secfn):
    fh = file(secfn, 'r')
    if fh==None:
        raise IOError("error occurred when opening file " + secfn)
    contents = fh.readlines()
    fh.close()
    secfeatures=dict()
    for line in contents:
        line=line.lstrip().rstrip()
        items = string.split(line)
        assert len(items)==87
        appname = items[0]
        if items[0] not in secfeatures.keys():
            secfeatures[ appname ] = list()
        fvs = [float(x) for x in items[1:]]
        secfeatures[ appname ].append( fvs )
    # for multiple sets of feature values per app, compute and keep the averages only
    for app in secfeatures.keys():
        allsets = secfeatures[app]
        if verbose and len(allsets)<2:
            print >> sys.stderr, app + " has one set of security features only!"
            #continue
        for j in range(0, len(allsets[0])):
            for k in range(1,len(allsets)):
                allsets[0][j] += allsets[k][j]
            allsets[0][j] /= (len(allsets)*1.0)
        del secfeatures[app]
        secfeatures[app] = allsets[0] # change to mapping: appname -> vector of average (element-wise) feature values
    return secfeatures

def getpackname(fnapk):
    appname=None
    try:
        appname = subprocess.check_output([BIN_GETPACKNAME, fnapk])
    except Exception,e:
        print >> sys.stderr, "error occurred when executing getpackage.sh " + fnapk
    return string.split(appname.lstrip().rstrip(),'\t')[1]

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
        res = vtres[tool].lower()
        for fam in fullFamilyList:
            if fam.lower() in res or res in fam.lower():
                if fam not in f2n.keys():
                    f2n[fam]=1
                f2n[fam]=f2n[fam]+1
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
    for app in set(vtRes.keys()).intersection( familymapping.keys() ):
        finalFam = refineFamily(fullFamilyList, vtRes[app])
        #print >> sys.stdout, "%s\t%s" % (app, finalFam)
        if None==finalFam:
            finalFam=familymapping[app]
            #print >> sys.stdout, "%s\t%s" % (app, finalFam)
        ret[app] = [finalFam, vtRes[app]]

    return ret

def getTrainingData(dichotomous=False, \
        benign_g=FTXT_BENIGN_G,\
        benign_icc=FTXT_BENIGN_ICC,\
        benign_sec=FTXT_BENIGN_SEC,\
        mal_g=FTXT_MALWARE_G,\
        mal_icc=FTXT_MALWARE_ICC,\
        mal_sec=FTXT_MALWARE_SEC,\
	pruneMinor=False):
    '''
    1. Assemble benign app features
    '''

    gfeatures_benign = load_generalFeatures(benign_g)
    iccfeatures_benign = load_ICCFeatures(benign_icc)
    secfeatures_benign = load_securityFeatures(benign_sec)

    allapps_benign = set(gfeatures_benign.keys()).intersection(iccfeatures_benign.keys()).intersection(secfeatures_benign.keys())
    for app in set(malbenignapps):
        if app in gfeatures_benign:
            del gfeatures_benign[app]
        if app in iccfeatures_benign:
            del iccfeatures_benign[app]
        if app in secfeatures_benign:
            del secfeatures_benign[app]
    for app in set(gfeatures_benign.keys()).difference(allapps_benign):
        del gfeatures_benign[app]
    for app in set(iccfeatures_benign.keys()).difference(allapps_benign):
        del iccfeatures_benign[app]
    for app in set(secfeatures_benign.keys()).difference(allapps_benign):
        del secfeatures_benign[app]

    assert len(gfeatures_benign)==len(iccfeatures_benign) and len(iccfeatures_benign)==len(secfeatures_benign)
    print str(len(gfeatures_benign)) + " valid benign app training samples to be used."

    allfeatures_benign = dict()
    for app in gfeatures_benign.keys():
        allfeatures_benign[app] = gfeatures_benign[app] + iccfeatures_benign[app] + secfeatures_benign[app]

    benignLabels={}
    #for j in range(0,len(allfeatures_benign)):
    #    benignLabels.append("BENIGN")
    for app in allfeatures_benign.keys():
        benignLabels[app] = "BENIGN"

    '''
    2. Assemble malicious app features
    '''
    gfeatures_malware = load_generalFeatures(mal_g)
    iccfeatures_malware = load_ICCFeatures(mal_icc)
    secfeatures_malware = load_securityFeatures(mal_sec)

    allapps_malware = \
        set(gfeatures_malware.keys()).intersection(iccfeatures_malware.keys()).intersection(secfeatures_malware.keys())

    #malFam = malwareCategorizeRough(malwareResultDir, malwareMappingFile)
    malFam = malwareCategorize(malwareResultDir, malwareMappingFile)

    allapps_malware = allapps_malware.intersection( malFam.keys() )

    for app in set(gfeatures_malware.keys()).difference(allapps_malware):
        del gfeatures_malware[app]
    for app in set(iccfeatures_malware.keys()).difference(allapps_malware):
        del iccfeatures_malware[app]
    for app in set(secfeatures_malware.keys()).difference(allapps_malware):
        del secfeatures_malware[app]

    assert len(gfeatures_malware)==len(iccfeatures_malware) and len(iccfeatures_malware)==len(secfeatures_malware)
    print str(len(gfeatures_malware)) + " valid malicious app training samples to be used."

    allfeatures_malware = dict()
    for app in gfeatures_malware.keys():
        allfeatures_malware[app] = gfeatures_malware[app] + iccfeatures_malware[app] + secfeatures_malware[app]

    malwareLabels={}
    #for app in allfeatures_malware.keys():
    #    malwareLabels.append( str(malFam[app][0]) )
    for app in allfeatures_malware.keys():
        if dichotomous:
            malwareLabels[app] = 'MALICIOUS'
        else:
            malwareLabels[app] = str(malFam[app][0])

    '''
    3. assemble into the entire training set (as a matrix)
    '''
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

    assert r == len (allLabels)

    if pruneMinor:
        purelabels = list()
        for app in allfeatures.keys():
            purelabels.append (allLabels[app])
        l2c = malwareCatStat(purelabels)
        minorapps = list()
        for app in allfeatures.keys():
            if pruneMinor and l2c[ allLabels[app] ] <= 1:
                minorapps.append( app )
        for app in minorapps:
            del allfeatures[app]
            del allLabels[app]
        print "%d minor apps pruned" % (len(minorapps))
        r -= len(minorapps)

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

    big_families=["DroidKungfu", "ProxyTrojan/NotCompatible/NioServ", "GoldDream", "Plankton", "FakeInst", "BENIGN", "MALICIOUS"]
    for j in range(0, len(labels)):
        if labels[j] not in big_families:
            labels[j] = "MALICIOUS"

    for app in allLabels.keys():
        if allLabels[app] not in big_families:
            allLabels[app] = "MALICIOUS"

    pnnfeatures = numpy.zeros( shape=(27,c) )
    dkfeatures = numpy.zeros( shape=(5,c) )
    gdfeatures = numpy.zeros( shape=(11,c) )
    pkfeatures = numpy.zeros( shape=(8,c) )
    fifeatures = numpy.zeros( shape=(33,c) )
    malfeatures = numpy.zeros( shape=(41,c) )
    bgnfeatures = numpy.zeros( shape=(136,c) )
    k1=0; k2=0; k3=0; k4=0; k5=0; k6=0; k7=0

    n=-1
    pnnsamplefeature = numpy.zeros( shape=(1,c) )
    pnnsample2feature = numpy.zeros( shape=(1,c) )
    for app in allfeatures.keys():
        n+=1
        if n==8:
            assert allLabels[app] == "ProxyTrojan/NotCompatible/NioServ"
            print "sample PNN app: %s " % (app)
            pnnsamplefeature[0] = allfeatures[app]
        if n==12:
            assert allLabels[app] == "ProxyTrojan/NotCompatible/NioServ"
            print "sample PNN app 2: %s " % (app)
            pnnsample2feature[0] = allfeatures[app]
        if allLabels[app] == "ProxyTrojan/NotCompatible/NioServ":
            #print "%s \t %s" % (app, allLabels[app])
            pnnfeatures[k1] = allfeatures[app]
            k1+=1
        elif allLabels[app] == "DroidKungfu":
            #print "%s \t %s" % (app, allLabels[app])
            dkfeatures[k2] = allfeatures[app]
            k2+=1
        elif allLabels[app] == "GoldDream":
            #print "%s \t %s" % (app, allLabels[app])
            gdfeatures[k3] = allfeatures[app]
            k3+=1
        elif allLabels[app] == "Plankton":
            #print "%s \t %s" % (app, allLabels[app])
            pkfeatures[k4] = allfeatures[app]
            k4+=1
        elif allLabels[app] == "FakeInst":
            #print "%s \t %s" % (app, allLabels[app])
            fifeatures[k5] = allfeatures[app]
            k5+=1
        elif allLabels[app] == "MALICIOUS":
            #print "%s \t %s" % (app, allLabels[app])
            malfeatures[k6] = allfeatures[app]
            k6+=1
        elif allLabels[app] == "BENIGN":
            bgnfeatures[k7] = allfeatures[app]
            k7+=1

    def selectFeatures(features, selection):
        featureSelect=[idx-1 for idx in selection]
        selectedfeatures=list()
        for featureRow in features:
            selectedfeatures.append ( featureRow[ featureSelect ] )
        return selectedfeatures

    import configs
    selpnns = selectFeatures(pnnfeatures, FSET_YYY)
    seldk = selectFeatures(dkfeatures, FSET_YYY)
    selgd = selectFeatures(gdfeatures, FSET_YYY)
    selpk = selectFeatures(pkfeatures, FSET_YYY)
    selfi = selectFeatures(fifeatures, FSET_YYY)
    selmal = selectFeatures(malfeatures, FSET_YYY)
    selbgn = selectFeatures(bgnfeatures, FSET_YYY)

    selpnnsample = selectFeatures(pnnsamplefeature, FSET_YYY)
    selpnnsample2 = selectFeatures(pnnsample2feature, FSET_YYY)

    selall = selectFeatures(features, FSET_YYY)

    print "%d \t %d \t %d \t %d" % (len(selpnns), len(selall), len(selpnns[0]), len(selall[0]))

    #print "%s" % numpy.mean(selall, axis=0)
    #print "%s" % numpy.mean(selpnns, axis=0)
    allmean = numpy.mean(selall, axis=0)
    pnnsmean = numpy.mean(selpnns, axis=0)
    dkmean = numpy.mean(seldk, axis=0)
    gdmean = numpy.mean(selgd, axis=0)
    pkmean = numpy.mean(selpk, axis=0)
    fimean = numpy.mean(selfi, axis=0)
    malmean = numpy.mean(selmal, axis=0)
    bgnmean = numpy.mean(selbgn, axis=0)

    pnnsamplemean = numpy.mean(selpnnsample, axis=0)
    pnnsample2mean = numpy.mean(selpnnsample2, axis=0)

    print "sample 1: %s" % (selpnnsample)
    print "sample 2: %s" % (selpnnsample2)

    print "Between PNN mean and PNN sample"
    x=0
    y=0
    for j in range(0,70):
        diff=abs(pnnsmean[j]-pnnsamplemean[j])
        if diff >= 0.02:
            x+=1
        if diff >= 0.05:
            y+=1
    print "%d noticeable, %d disparate" % (x,y)

    print "Between PNN mean and PNN sample 2"
    x=0
    y=0
    for j in range(0,70):
        diff=abs(pnnsmean[j]-pnnsample2mean[j])
        if diff >= 0.02:
            x+=1
        if diff >= 0.05:
            y+=1
    print "%d noticeable, %d disparate" % (x,y)

    print "Between PNN sample and PNN sample 2"
    x=0
    y=0
    for j in range(0,70):
        diff=abs(pnnsample2mean[j]-pnnsamplemean[j])
        if diff >= 0.02:
            x+=1
        if diff >= 0.05:
            y+=1
            print "feature %d: %f vs %f" % (j+1, pnnsample2mean[j], pnnsamplemean[j])
    print "%d noticeable, %d disparate" % (x,y)

    print "Between BENIGN mean and PNN sample"
    x=0
    y=0
    for j in range(0,70):
        diff=abs(bgnmean[j]-pnnsamplemean[j])
        if diff >= 0.02:
            x+=1
        if diff >= 0.05:
            y+=1
    print "%d noticeable, %d disparate" % (x,y)

    print "Between BENIGN mean and PNN sample 2"
    x=0
    y=0
    for j in range(0,70):
        diff=abs(bgnmean[j]-pnnsample2mean[j])
        if diff >= 0.02:
            x+=1
        if diff >= 0.05:
            y+=1
    print "%d noticeable, %d disparate" % (x,y)


    print "Between Plankton and BENGIN"
    x=0
    y=0
    for j in range(0,70):
        diff=abs(bgnmean[j]-pkmean[j])
        if diff >= 0.02:
            x+=1
        if diff >= 0.05:
            y+=1
    print "%d noticeable, %d disparate" % (x,y)

    print "Between FakeInst and BENGIN"
    x=0
    y=0
    for j in range(0,70):
        diff=abs(bgnmean[j]-fimean[j])
        if diff >= 0.02:
            x+=1
        if diff >= 0.05:
            y+=1
    print "%d noticeable, %d disparate" % (x,y)

    print "Between GoldDream and BENGIN"
    x=0
    y=0
    for j in range(0,70):
        diff=abs(bgnmean[j]-gdmean[j])
        if diff >= 0.02:
            x+=1
        if diff >= 0.05:
            y+=1
    print "%d noticeable, %d disparate" % (x,y)

    print "Between DroidKungfu and BENGIN"
    x=0
    y=0
    for j in range(0,70):
        diff=abs(bgnmean[j]-dkmean[j])
        if diff >= 0.02:
            x+=1
        if diff >= 0.05:
            y+=1
    print "%d noticeable, %d disparate" % (x,y)

    print "Between ProxyTrojan/NotCompatible/NioServ and BENGIN"
    x=0
    y=0
    for j in range(0,70):
        diff=abs(bgnmean[j]-pnnsmean[j])
        if diff >= 0.02:
            x+=1
        if diff >= 0.05:
            y+=1
    print "%d noticeable, %d disparate" % (x,y)

    print "Between MALICIOUS and BENGIN"
    x=0
    y=0
    for j in range(0,70):
        diff=abs(bgnmean[j]-malmean[j])
        if diff >= 0.02:
            x+=1
        if diff >= 0.05:
            y+=1
    print "%d noticeable, %d disparate" % (x,y)

    print "Between MALICIOUS and ProxyTrojan/NotCompatible/NioServ"
    x=0
    y=0
    for j in range(0,70):
        diff=abs(malmean[j]-pnnsmean[j])
        if diff >= 0.02:
            x+=1
        if diff >= 0.05:
            y+=1
    print "%d noticeable, %d disparate" % (x,y)
    '''
    for j in range(0,70):
        print "%s" % numpy.mean(selall[:,j], axis=0)
        #print "%f \t %f \t %f" % (numpy.mean(selall, j), numpy.mean(selpnns, j), numpy.mean(selall, j)-numpy.mean(selpnns, j))
    '''

    assert len(Testfeatures)==len(Testlabels)
    assert len(features)==len(labels)

    return (features, labels, Testfeatures, Testlabels)

def getTestingData( app_g, app_icc, app_sec):
    '''
    1. Assemble app features
    '''
    gfeatures_app = load_generalFeatures(app_g)
    iccfeatures_app = load_ICCFeatures(app_icc)
    secfeatures_app = load_securityFeatures(app_sec)

    allapps_app = set(gfeatures_app.keys()).intersection(iccfeatures_app.keys()).intersection(secfeatures_app.keys())
    for app in set(malbenignapps):
        if app in gfeatures_app:
            del gfeatures_app[app]
        if app in iccfeatures_app:
            del iccfeatures_app[app]
        if app in secfeatures_app:
            del secfeatures_app[app]
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

def malwareCatStat(labels):
    l2c={}
    for lab in labels:
        if lab not in l2c.keys():
            l2c[lab]=0
        l2c[lab]=l2c[lab]+1
    return l2c

if __name__=="__main__":
    (features, labels, Testfeatures, Testlabels) = getTrainingData( False, pruneMinor=False)

    l2c = malwareCatStat(labels)
    for lab in l2c.keys():
        print "%s\t%s" % (lab, l2c[lab])

    sys.exit(0)

# hcai: set ts=4 tw=100 sts=4 sw=4
