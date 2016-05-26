# Import the random forest package
from sklearn.ensemble import RandomForestClassifier 
import numpy
import random
import os
import sys
import string
import subprocess

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
        if len(allsets)<2:
            print >> sys.err, app + " has one set of general features only!"
            continue
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
        if len(allsets)<2:
            print >> sys.err, app + " has one set of ICC features only!"
            continue
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
        if len(allsets)<2:
            print >> sys.err, app + " has one set of security features only!"
            continue
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
        appname = subprocess.check_output(['/home/hcai/bin/getpackage.sh', fnapk])
    except Exception,e:
        print >> sys.stderr, "error occurred when executing getpackage.sh " + fnapk 
    return string.split(appname.lstrip().rstrip(),'\t')[1]

def malwareCategorize(resultDir,fnmapping):
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

def getTrainingData(featureDir,dichotomous=False):
    '''
    1. Assemble benign app features
    '''
    # these benign apps are found malicious by VirusTotal, will be excluded from the training data set
    malbenignapps=["com.ictap.casm", "com.aob", "com.vaishnavism.vishnusahasranaamam.english", "com.hardcoreapps.loboshaker"]

    gfeatures_benign = load_generalFeatures(featureDir+"/gfeatures-benign.txt")
    iccfeatures_benign = load_ICCFeatures(featureDir+"/iccfeatures-benign.txt")
    secfeatures_benign = load_securityFeatures(featureDir+"/securityfeatures-benign.txt")

    allapps_benign = set(gfeatures_benign.keys()).intersection(iccfeatures_benign.keys()).intersection(secfeatures_benign.keys())
    for app in set(malbenignapps):
        del gfeatures_benign[app]
        del iccfeatures_benign[app]
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
    gfeatures_malware = load_generalFeatures(featureDir+"/gfeatures-malware.txt")
    iccfeatures_malware = load_ICCFeatures(featureDir+"/iccfeatures-malware.txt")
    secfeatures_malware = load_securityFeatures(featureDir+"/securityfeatures-malware.txt")

    allapps_malware = \
        set(gfeatures_malware.keys()).intersection(iccfeatures_malware.keys()).intersection(secfeatures_malware.keys())

    malwareResultDir="/home/hcai/testbed/cg.instrumented/malware/installed"
    malwareMappingFile="/home/hcai/testbed/mapping.malware"
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
            continue
        assert c == len (allfeatures[app])

    allLabels = benignLabels.copy()
    allLabels.update ( malwareLabels )

    assert r == len (allLabels)

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

# 10-fold cross-validation
def cv(features, labels):
    k=10
    r=features.shape[0]
    subsize = r/k
    subsamples=list()
    sublabels=list()
    for j in range(0,k):
        subsamples.append( (features[j*subsize:(j+1)*subsize]) )
        sublabels.append( (labels[j*subsize:(j+1)*subsize]) )

    print len(subsamples), len(sublabels)

    forest = RandomForestClassifier(n_estimators = 100)
    score = 0.0
    for j in range(0,k):
        testFeatures = subsamples[j]
        testLabels = sublabels[j]
        trainFeatures = list()
        trainLabels = list()
        for r in range(0,k):
            if r==j:
                continue
            #trainFeatures.append( subsamples[r] )
            #trainLabels.append( sublabels[r] )
            for fl in subsamples[r]:
                trainFeatures.append(fl)
            for lal in sublabels[r]:
                trainLabels.append( lal )
        forest.fit( trainFeatures, trainLabels )

        curscore = forest.score( testFeatures, testLabels )
        print >> sys.stdout, "score of %d-fold cross-validation, repetition No. %d: %f" % (k,j,curscore)
        score += curscore
    print >> sys.stdout, "average score: " + str(score/k)

def naiveValidation(features, labels, Testfeatures, Testlabels):
    print "TRAINING DATA"
    featureFh = file (os.getcwd()+'/allfeatures.txt','w')
    print >> featureFh, features
    featureFh.close()

    # Create the random forest object which will include all the parameters
    # for the fit
    forest = RandomForestClassifier(n_estimators = 100)

    # Fit the training data to the benign/malware labels and create the decision trees
    forest = forest.fit(features, labels)

    # Take the same decision trees and run it on the test data
    output = forest.predict(Testfeatures)
    print "PREDICTION RESULTS"
    print output

    print "PREDICTION SCORE"
    print forest.score(Testfeatures, Testlabels)

if __name__=="__main__":
    featureDir="/home/hcai/ML/features/"
    (features, labels, Testfeatures, Testlabels) = getTrainingData( featureDir,False)

    print "\n ====== FULL SET OF FEATURES ======"
    cv(features, labels)

    print "\n ====== GENERAL FEATURES ======"
    cv(features[0:29], labels)
    print "\n ====== ICC FEATURES ======"
    cv(features[0:36], labels)
    print "\n ====== SECURITY FEATURES ======"
    cv(features[37:122], labels)

    print "\n ====== MINIMUM SET OF FEATURES ======"
    __featureSelect=[1,2,3,10,13,16,19,35,39,41,53,55]
    featureSelect=[idx-1 for idx in __featureSelect]
    print featureSelect
    cv(features[featureSelect], labels)

    print "\n ====== Y SET OF FEATURES ======"
    __featureSelect=[1,2,3,10,13,16,19,37,39,41,53,55,57,58,59,60,61,63,73,74,75,76,78,80,81,82,83,84,93,94,95,96,105,106,117,118]
    featureSelect=[idx-1 for idx in __featureSelect]
    print featureSelect
    cv(features[featureSelect], labels)

    print "\n ====== Y&Y- SET OF FEATURES ======"
    __featureSelect=[1,2,3,10,13,16,19,37,39,41,53,57,58,59,60,61,63,73,74,75,76,78,80,81,82,83,84,93,94,95,96,105,106,117,118, 11,14,22,24,30,35,38,40,43,44,54,56,62,64,65,67,86,88,99,100,101,102,103,104,107,108]
    featureSelect=[idx-1 for idx in __featureSelect]
    print featureSelect
    cv(features[featureSelect], labels)

    print "\n ====== Y&Y-&Y-- SET OF FEATURES ======"
    __featureSelect=[1,2,3,10,13,16,19,37,39,41,53,55,57,58,59,60,61,63,73,74,75,76,78,80,81,82,83,84,93,94,95,96,105,106,117,118, 11,14,22,24,30,35,38,40,43,44,54,56,62,64,65,67,86,88,99,100,101,102,103,104,107,108, 12,15,23,28,32,34,36,42]
    featureSelect=[idx-1 for idx in __featureSelect]
    print featureSelect
    cv(features[featureSelect], labels)

    sys.exit(0)

