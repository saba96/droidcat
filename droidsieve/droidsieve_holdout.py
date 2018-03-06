# Import all classification package
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, AdaBoostClassifier, BaggingClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB, MultinomialNB, BernoulliNB
from sklearn.neighbors import KNeighborsClassifier

from sklearn.cross_validation import cross_val_score
from sklearn.metrics import precision_score,recall_score,f1_score,roc_auc_score,accuracy_score

from sklearn.metrics import confusion_matrix

#from sklearn.mixture import GaussianMixture
#from sklearn.mixture import BayesianGaussianMixture
from sklearn.gaussian_process import GaussianProcessClassifier
from sklearn.gaussian_process.kernels import RBF

import numpy
import random
import os
import sys
import string

import inspect, re

import pickle

HOLDOUT_RATE=0.33
#HOLDOUT_RATE=0.4

g_binary = False # binary or multiple-class classification

g_fnames = set()

featureframe = {}

def varname(p):
    for line in inspect.getframeinfo(inspect.currentframe().f_back)[3]:
        m = re.search(r'\bvarname\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', line)
        if m:
            return m.group(1)

# hold-out 20% evaluation
def holdout(model, features, labels):
    sr=len(features)
    assert sr==len(labels)

    uniqLabels = set()
    for item in labels:
        uniqLabels.add (item)

    lab2idx=dict()
    for k in range(0, sr):
        lab = labels[k]
        if lab not in lab2idx.keys():
            lab2idx[lab] = list()
        lab2idx[lab].append (k)

    testfeatures=list()
    testlabels=list()

    allidx2rm=list()
    for lab in lab2idx.keys():
        sz = len(lab2idx[lab])
        nrm = int(sz*HOLDOUT_RATE);
        idxrm = set()
        while len(idxrm) < nrm:
            t = random.randint(0,sz-1)
            idxrm.add ( lab2idx[lab][t] )
        for idx in idxrm:
            testfeatures.append ( features[idx] )
            testlabels.append ( labels[idx] )
            allidx2rm.append(idx)

    trainfeatures=list()
    trainlabels=list()
    for l in range(0, sr):
        if l in allidx2rm:
            continue
        trainfeatures.append(features[l])
        trainlabels.append(labels[l])

    print >> sys.stdout, "%d samples for training, %d samples held out will be used for testing" % (len (trainfeatures), len(testfeatures))

    predicted_labels=list()
    model.fit ( trainfeatures, trainlabels )

    for j in range(0, len(testlabels)):
        y_pred = model.predict( [testfeatures[j]] )
        #print >> sys.stderr, "j=%d, testLabels: %s" % (j, str(testlabels[j]))
        #print >> sys.stderr, "j=%d, predicted: %s" % (j, str(y_pred))

        predicted_labels.append ( y_pred )

    '''
    for i in range(0, len(predicted_labels)):
        #print type(predicted_labels[i])
        if predicted_labels[i][0] not in big_families:
            predicted_labels[i] = numpy.array(['MALICIOUS'])
    '''

    #print "%s\n%s\n" % (str(sublabels), str(predicted_labels))
    #big_families=["DroidKungfu", "ProxyTrojan/NotCompatible/NioServ", "GoldDream", "Plankton", "FakeInst", "BENIGN", "MALICIOUS"]

    y_pred = predicted_labels

    if g_binary:
        prec=precision_score(testlabels, y_pred, average='binary', pos_label='MALICIOUS')
        rec=recall_score(testlabels, y_pred, average='binary', pos_label='MALICIOUS')
        f1=f1_score(testlabels, y_pred, average='binary', pos_label='MALICIOUS')

    else:
        prec=precision_score(testlabels, y_pred, average='weighted')
        rec=recall_score(testlabels, y_pred, average='weighted')
        f1=f1_score(testlabels, y_pred, average='weighted')

    '''
    cvprec = cross_val_score(estimator=model, X=features, y=labels, cv=10, scoring='precision_weighted')
    cvrec = cross_val_score(estimator=model, X=features, y=labels, cv=10, scoring='recall_weighted')
    cvf1 = cross_val_score(estimator=model, X=features, y=labels, cv=10, scoring='f1_weighted')
    '''


    acc=accuracy_score( testlabels, y_pred )

    #print "precision=%f, recall=%f, f1=%f, acc=%f" % (prec, rec, f1, acc)

    #return confusion_matrix(testlabels, predicted_labels, labels=list(uniqLabels))
    #return confusion_matrix(sublabels, predicted_labels, labels=big_families)
    return (prec, rec, f1, acc)
    #return (numpy.average(cvprec), numpy.average(cvrec), numpy.average(cvf1), acc)

def selectFeatures(features, selection):
    featureSelect=[idx-1 for idx in selection]
    selectedfeatures=list()
    for featureRow in features:
        selectedfeatures.append ( featureRow[ featureSelect ] )
    return selectedfeatures

def loadFeatures(datatag):
    global g_fnames
    f = open(datatag, 'rb')
    sample_features = {}
    sample_labels = {}
    while 1:
        try:
            sample = pickle.load(f)
            #sample.pprint()
            fnames = [ft.name.lstrip().rstrip().encode('ascii','replace') for ft in sample.features]
            #print sorted(fnames)
            #print len(fnames)
            '''
            if 'com.zws.inventorymng.permission.JPUSH_MESSAGE' in fnames:
                print "got it: %s" % (sorted(fnames))
                sys.exit(2)
            for fname in fnames:
                g_fnames.add (fname)
            '''
            g_fnames = g_fnames.union (set(fnames))

            fdict={}
            for ft in sample.features:
                fdict [ft.name.lstrip().rstrip().encode('ascii','replace')] = ft.freq
            sample_features [ sample.md5 ] = fdict
            if sample.malicious:
                sample_labels [sample.md5] = sample.cli_classification.gt
            else:
                sample_labels [sample.md5] = 'BENIGN'
        except (EOFError, pickle.UnpicklingError):
            break
    f.close()
    print >> sys.stderr, 'loaded from %s: %d feature vectors, %d labels, each sample having %d features' % (datatag, len (sample_features), len(sample_labels), len(g_fnames))
    #print sorted(g_fnames)
    return sample_features, sample_labels

def regularizeFeatures(rawfeatures):
    ret={}
    for md5 in rawfeatures.keys():
        newfdict = featureframe
        for fname in rawfeatures[md5].keys():
            #assert fname in newfdict.keys()
            newfdict[fname] = rawfeatures[md5][fname]
        ret[md5] = newfdict
    return ret

def getfvec(fdict):
    fvecs=dict()
    for md5 in fdict.keys():
        #print md5
        #fnames = [fname for fname in fdict[md5].keys()]
        fvalues = [freq for freq in fdict[md5].values()]
        #print len(fnames), len(fvalues)
        fvecs[md5] = fvalues
    return fvecs

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

if __name__=="__main__":
    if len(sys.argv)<3:
        print >> sys.stderr, "%s malware-datatag benign-datatag [binary|multi]" % (sys.argv[0])
        sys.exit (-1)

    mtag = sys.argv[1]
    btag = sys.argv[2]
    if len(sys.argv)>=4:
        #global g_binary
        g_binary = sys.argv[3].lower()=='true'

    _bfeatures, _blabels  = loadFeatures ( btag )
    print >> sys.stdout, "%d benign samples loaded" % (len(_bfeatures))
    _mfeatures, _mlabels  = loadFeatures ( mtag )
    print >> sys.stdout, "%d malware samples loaded" % (len(_mfeatures))
    if g_binary:
        for md5 in _mlabels.keys():
            _mlabels[md5] = 'MALICIOUS'

    #global featureframe
    for name in g_fnames:
        featureframe[name] = 0.0

    mfeatures = regularizeFeatures ( _mfeatures )
    bfeatures = regularizeFeatures ( _bfeatures )
    #print mfeatures
    #print bfeatures


    '''
    mf, ml = adapt ( getfvec(mfeatures), _mlabels )
    bf, bl = adapt ( getfvec(bfeatures), _blabels )
    print len(mf), len(ml), len(bf), len(bl)
    '''
    bfeatures.update ( mfeatures )
    _blabels.update ( _mlabels )

    bf, bl = adapt ( getfvec(bfeatures), _blabels )


    '''
    mamalist17=[]
    for line in file('list.benign17').readlines():
        line=line.lstrip().rstrip()
        mamalist17.append (line)
    mamalistdrebin=[]
    for line in file('list.malwaredrebin').readlines():
        line=line.lstrip().rstrip()
        mamalistdrebin.append (line)

    melist17=[]
    for line in file('list.benign17.me').readlines():
        line=line.lstrip().rstrip()
        melist17.append (line)
    melistdrebin=[]
    for line in file('list.malwaredrebin.me').readlines():
        line=line.lstrip().rstrip()
        melistdrebin.append (line)

    comlist17=[]
    for line in mamalist17:
        if line in melist17:
            comlist17.append(line)

    comlistdrebin=[]
    for line in mamalistdrebin:
        if line in melistdrebin:
            comlistdrebin.append(line)

    print "common apps in benign17: %d, common apps in malwaredrebin: %d\n" % (len(comlist17), len(comlistdrebin))
    '''

    #bPrune = g_binary
    '''
    bPrune = True

    (bf1, bl1) = loadBenignData('features_large/benign-2017')

    (bf2, bl2) = loadBenignData('features_large/benign-2017')
    for app in bf2.keys():
        if app not in comlist17:
            del bf2[app]
            del bl2[app]
    bf1.update(bf2)
    bl1.update(bl2)

    (mf1, ml1) = loadMalwareData(g_binary, 'features_large/malware-2013','/home/hcai/testbed/cg.instrumented/malware/installed', pruneMinor=bPrune, drebin=False, obf=False)
    bf1.update (mf1)
    bl1.update (ml1)

    (mf2, ml2) = loadMalwareData(g_binary, 'features_large/malware-2017','/home/hcai/testbed/cg.instrumented/newmalwareall/installed', pruneMinor=bPrune, drebin=False, obf=False)
    bf1.update (mf2)
    bl1.update (ml2)

    (mf3, ml3) = loadMalwareData(g_binary, 'features_large/malware-drebin','/home/hcai/Downloads/Drebin', pruneMinor=bPrune, drebin=True, obf=False)
    for app in mf3.keys():
        if app not in comlistdrebin:
            del mf3[app]
            del ml3[app]
    bf1.update (mf3)
    bl1.update (ml3)

    (mf4, ml4) = loadMalwareData(g_binary, 'features_large/malware-zoo/2014','/home/hcai/testbed/cg.instrumented/AndroZoo/2014', pruneMinor=bPrune, drebin=False, obf=False)
    bf1.update (mf4)
    bl1.update (ml4)

    (mf5, ml5) = loadMalwareData(g_binary, 'features_large/malware-zoo/2015','/home/hcai/testbed/cg.instrumented/AndroZoo/2015', pruneMinor=bPrune, drebin=False, obf=False)
    bf1.update (mf5)
    bl1.update (ml5)

    (mf6, ml6) = loadMalwareData(g_binary, 'features_large/malware-zoo/2016','/home/hcai/testbed/cg.instrumented/AndroZoo/2016', pruneMinor=bPrune, drebin=False, obf=False)
    bf1.update (mf6)
    bl1.update (ml6)

    (features, labels) = adapt (bf1, bl1)
    '''

    #models = (RandomForestClassifier(n_estimators = 128, random_state=0), )#GaussianProcessClassifier(), ExtraTreesClassifier(n_estimators=120), AdaBoostClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())
    #models = (ExtraTreesClassifier(n_estimators=128, random_state=0),  AdaBoostClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), )#SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())
    #models = (SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())

    #models = (RandomForestClassifier(n_estimators = 128, random_state=0), SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())

    #models = (RandomForestClassifier(n_estimators = 120, random_state=0), )#ExtraTreesClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), MultinomialNB())
    models = (ExtraTreesClassifier(n_estimators=120), )#GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), MultinomialNB())

    #fsets = (FSET_FULL,FSET_NOICC, FSET_MIN, FSET_YYY_G, FSET_FULL_TOP, FSET_YYY_TOP, FSET_FULL_TOP_G, FSET_YYY_TOP_G)
    #fsets = (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):

    #fsets = (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_YYY, FSET_FULL_TOP, FSET_YYY_TOP, FSET_FULL_TOP_G, FSET_YYY_TOP_G)
    #fsets = (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_YYY, FSET_FULL_TOP_G, FSET_YYY_TOP_G)
    #fsets = (FSET_FULL, FSET_G, FSET_SEC, FSET_YYY, FSET_FULL_TOP_G, FSET_YYY_TOP_G)
    #fsets = (FSET_FULL, FSET_SEC)

    fh = sys.stdout
    #fh = file ('confusion_matrix_formajorfamilyonly_holdout_all.txt', 'w')

    model2ret={}
    for model in models:
        print >> fh, 'model ' + str(model)
        ret = holdout (model, bf, bl)
        model2ret[str(model)] = ret

    tlabs=('precision', 'recall', 'F1', 'accuracy')
    for i in (0,1,2,3):
        print tlabs[i]
        cols=list()
        for model in models:
            #print 'model ' + str(model)
            col=list()
            ret = model2ret[str(model)]
            col.append(ret[i])
            cols.append(col)
        for r in range(0,len(cols[0])):
            for c in range(0,len(cols)):
                print "%s\t" % cols[c][r],
            print

    fh.flush()
    fh.close()

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
