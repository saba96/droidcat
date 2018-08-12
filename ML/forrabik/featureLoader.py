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

def getBenignTrainingData(\
        benign_g=FTXT_BENIGN_G,\
        benign_icc=FTXT_BENIGN_ICC,\
        benign_sec=FTXT_BENIGN_SEC):

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

    allfeatures_benign = dict()
    for app in gfeatures_benign.keys():
        allfeatures_benign[app] = gfeatures_benign[app] + iccfeatures_benign[app] + secfeatures_benign[app]

    benignLabels={}
    #for j in range(0,len(allfeatures_benign)):
    #    benignLabels.append("BENIGN")
    for app in allfeatures_benign.keys():
        benignLabels[app] = "BENIGN"

    for app in allfeatures_benign.keys():
        if sum(allfeatures_benign[app]) < 0.00005:
            del allfeatures_benign[app]
            del benignLabels[app]

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
