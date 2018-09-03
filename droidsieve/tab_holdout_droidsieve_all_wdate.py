# Import all classification package
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, AdaBoostClassifier, BaggingClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB, MultinomialNB, BernoulliNB
from sklearn.neighbors import KNeighborsClassifier

from sklearn.metrics import precision_score,recall_score,f1_score,roc_auc_score,accuracy_score

from sklearn.metrics import confusion_matrix

#from sklearn.mixture import GaussianMixture
#from sklearn.mixture import BayesianGaussianMixture
from sklearn.gaussian_process import GaussianProcessClassifier
from sklearn.gaussian_process.kernels import RBF
from sklearn import preprocessing
from sklearn.preprocessing import StandardScaler

import numpy
import random
import os
import sys
import string

import inspect, re

#from classes.sample import Sample
import pickle
import copy
from common import *

from sklearn.feature_selection import SelectFromModel

g_binary = False # binary or multiple-class classification
featureframe = {}
g_fnames = set()
tagprefix="/home/hcai/Downloads/droidsieve/features_droidsieve_byfirstseen/static.pickle."
PRUNE_THRESHOLD=0
HOLDOUT_RATE=5/10.0

def malwareCatStat(labels):
    l2c={}
    for lab in labels:
        if lab not in l2c.keys():
            l2c[lab]=0
        l2c[lab]=l2c[lab]+1
    return l2c
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

def get_families(path_md5_families):
    families = {}
    metainfo = open(path_md5_families)
    for line in metainfo.readlines():
        split = line.split()
        if len(split) == 2:
            md5 = str(split[0]).strip()
            date = str(split[1]).strip()
            families[md5] = date
    return families

def varname(p):
    for line in inspect.getframeinfo(inspect.currentframe().f_back)[3]:
        m = re.search(r'\bvarname\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', line)
        if m:
            return m.group(1)

# sort the samples by date, hold out the the newer half for testing
def holdout_bydate(model, trainfeatures, trainlabels, testfeatures, testlabels):
    '''
    trainfeatures = StandardScaler().fit_transform(trainfeatures)
    testfeatures = StandardScaler().fit_transform(testfeatures)
    #preprocessing.scale( trainfeatures )
    #preprocessing.scale( testfeatures )

    sfm = SelectFromModel(model, threshold = 'median')
    sfm.fit( trainfeatures, trainlabels )
    trainfeatures = sfm.transform( trainfeatures )
    testfeatures = sfm.transform( testfeatures )
    '''

    features = numpy.concatenate ( (trainfeatures, testfeatures), axis=0 )
    print "before feature scaling and selection: %d samples each with %d features" % (len(features), len(features[0]))
    print features[0]

    scaled_features = StandardScaler().fit_transform( features )

    sfm = SelectFromModel(model, threshold = 'median')
    sfm.fit( trainfeatures, trainlabels )
    selected_features = sfm.transform ( scaled_features )

    print "after feature scaling and selection: %d samples each with %d features" % (len(selected_features), len(selected_features[0]))
    print selected_features[0]

    _trainfeatures = numpy.zeros( shape=(len(trainfeatures), len(selected_features[0])) )
    _testfeatures = numpy.zeros( shape=(len(testfeatures), len(selected_features[0])) )

    for k in range(0, len(trainfeatures)):
        _trainfeatures[k] = selected_features[k]

    for k in range(0, len(testfeatures)):
        _testfeatures[k] = selected_features[k+len(trainfeatures)]

    trainfeatures = _trainfeatures
    testfeatures = _testfeatures

    predicted_labels=list()
    model.fit ( trainfeatures, trainlabels )
    print "training: %d samples each with %d features" % (len(trainfeatures), len(trainfeatures[0]))

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

    if g_binary and False:
    #if g_binary:
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

def malwareCatStat(labels):
    l2c={}
    for lab in labels:
        if lab not in l2c.keys():
            l2c[lab]=0
        l2c[lab]=l2c[lab]+1
    return l2c

def split(features, labels):
    lab2dates = {}
    lab2features = {}
    for (app,date) in features.keys():
        lab = labels[(app,date)]
        if lab not in lab2dates.keys():
            lab2dates[lab] = []
        lab2dates[lab].append( date )
        if lab not in lab2features.keys():
            lab2features[lab] = {}
        lab2features[lab][(app,date)] = features[(app,date)]

    testfeatures = {}
    testlabels = {}
    trainfeatures = {}
    trainlabels = {}

    for lab in lab2dates.keys():
        alldates = lab2dates[lab]
        alldates.sort()
        #print alldates

        pivot = alldates [ int(len(alldates)*HOLDOUT_RATE) ]
        print "%s pivot=%s" % (lab, pivot)

        itest = 0
        itrain = 0
        for (app,date) in lab2features[lab].keys():
            if date > pivot:
                itest += 1
            else:
                itrain += 1

        # if all samples' dates are the same, then use ordinary random split
        if itest<1 or itrain<1:
            print >> sys.stdout, "applying random split ..."
            idxrm=[]
            for j in range(0, int(len(alldates)*HOLDOUT_RATE)):
                t = random.randint(0,len(lab2features[lab].keys())-1)
                idxrm.append(t)
                key = lab2features[lab].keys()[t]

                trainfeatures[ key ] = features [ key ]
                trainlabels [key] = labels [key]

            for i in range(0, len(lab2features[lab].keys())):
                if i not in idxrm:
                    key = lab2features[lab].keys()[i]
                    testfeatures[key] = features [key]
                    testlabels [key] = labels [key]
        else:
            print >> sys.stdout, "applying split by date..."
            for (app,date) in lab2features[lab].keys():
                key = (app,date)
                if date > pivot:
                    testfeatures[key] = features [key]
                    testlabels [key] = labels [key]
                else:
                    trainfeatures[ key ] = features [ key ]
                    trainlabels [key] = labels [key]

    print >> sys.stdout, "%d samples for training, %d samples held out will be used for testing" % (len (trainfeatures), len(testfeatures))

    return trainfeatures, trainlabels, testfeatures, testlabels

def predict(f, l, fh, i):
    _trainfeatures, _trainlabels, _testfeatures, _testlabels = split(f, l)
    (trainfeatures, trainlabels) = adapt (_trainfeatures, _trainlabels)
    (testfeatures, testlabels) = adapt (_testfeatures, _testlabels)

    labels = list()
    for item in trainlabels:
        labels.append(item)
    for item in testlabels:
        labels.append(item)

    l2c = malwareCatStat(labels)
    for lab in l2c.keys():
        print "%s\t%s" % (lab, l2c[lab])
    print "%d classes in total" % len(l2c.keys())

    uniqLabels = set()
    for item in labels:
        uniqLabels.add (item)

    #models = (RandomForestClassifier(n_estimators = 128, random_state=0), SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())
    models = (ExtraTreesClassifier(n_estimators=1000), )#GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), MultinomialNB())

    print >> fh, '\t'.join(uniqLabels)

    datatag = 'droidsieve_VSGP' if i==0 else 'droidsieve_ZOZO'
    #datatag = 'droidsieve_PRZO1213' if i==0 else ('droidsieve_PRZO1415' if i==1 else 'droidsieve_PRZO1617')
    roc_bydate(g_binary, models[0], trainfeatures, trainlabels, testfeatures, testlabels, datatag)

    model2ret={}
    for model in models:
        print >> fh, 'model ' + str(model)
        ret = holdout_bydate (model, trainfeatures, trainlabels, testfeatures, testlabels)
        model2ret[str(model)] = ret

    tlabs=('precision', 'recall', 'F1', 'accuracy')
    for i in (0,1,2,3):
        print >> fh, tlabs[i]
        cols=list()
        for model in models:
            #print 'model ' + str(model)
            col=list()
            ret = model2ret[str(model)]
            col.append(ret[i])
            cols.append(col)
        for r in range(0,len(cols[0])):
            for c in range(0,len(cols)):
                print >> fh, "%s\t" % cols[c][r],
            print >> fh


def filter_features(fdict):
    icnt=0
    for key in fdict.keys():
        for name in fdict[key][1].keys():
            '''
            if 'incognito' in name:
                print name
            '''
            lname = name.lower()
            if lname.startswith('string_') or lname.startswith('ascii_') or lname.startswith('cert_'):
                del fdict[key][1][name]
                icnt+=1
    print >> sys.stdout, "%d features removed" % (icnt)

def loadFeatures(datatag):
    global g_fnames
    f = open(tagprefix+datatag, 'rb')
    sample_features = {}
    sample_labels = {}

    try:
        fdict = pickle.load (f)
        filter_features(fdict)
        #print fdict
    except (EOFError, pickle.UnpicklingError):
        pass

    for key in fdict.keys():
        sample_features [key] = fdict[key][1]
        sample_labels [key] = fdict[key][0]

        fnames = [ft for ft in fdict[key][1].keys()]
        g_fnames = g_fnames.union (set(fnames))

    f.close()
    print >> sys.stderr, 'loaded from %s: %d feature vectors, %d labels, each sample having %d features' % (datatag, len (sample_features), len(sample_labels), len(g_fnames))
    return sample_features, sample_labels

def _regularizeFeatures(rawfeatures):
    ret={}
    for md5 in rawfeatures.keys():
        newfdict = copy.deepcopy(featureframe)
        for fname in rawfeatures[md5].keys():
            assert fname in newfdict.keys()
            newfdict[fname] = rawfeatures[md5][fname]
        ret[md5] = newfdict
    return ret

def _getfvec(fdict):
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

def resetframe():
    global featureframe, g_fnames
    featureframe={}
    newnames=set()
    icnt=0

    for name in g_fnames:
        '''
        if name.lower().startswith('string_'):
            icnt=icnt+1
            continue
        if name.lower().startswith('ascii_'):
            icnt=icnt+1
            continue
        if name.lower().startswith('cert_'):
            icnt=icnt+1
            continue
        '''
        newnames.add (name)

    g_fnames = newnames

    print >> sys.stdout, "%d features removed" % (icnt)

    for name in g_fnames:
        featureframe[name] = 0.0

if __name__=="__main__":
    if len(sys.argv)>=2:
        g_binary = sys.argv[1].lower()=='true'

    datasets = [ \
                {"benign":["zoobenign2014", "zoobenign2015", "benign2014", "benign2015"], "malware":["vs2014","vs2015","zoo2014","zoo2015"]},
                {"benign":["zoobenign2016", "zoobenign2017", "benign2016", "benign2017"], "malware":["vs2016","zoo2016","zoo2017"]},
                ]

    '''
    datasets = [ {"benign":["benign2015"], "malware":["zoo2015"]} ]
    '''

    '''
    datasets = [ \
                {"benign":["zoobenign2012", "zoobenign2013"], "malware":["obfmg2017"]},
                {"benign":["zoobenign2014", "zoobenign2015"], "malware":["obfmg2017"]},
                {"benign":["zoobenign2016", "benign2017"], "malware":["obfmg2017"]},
                ]

    datasets = [ \
                {"benign":["zoobenign2012", "zoobenign2013"], "malware":["obfmg2017","obfcontagio2017"]},
                {"benign":["zoobenign2014", "zoobenign2015"], "malware":["obfmg2017","obfcontagio2017"]},
                {"benign":["zoobenign2016", "benign2017"], "malware":["obfmg2017","obfcontagio2017"]},
                ]
    '''

    #bPrune = g_binary
    bPrune = True

    fh = sys.stdout
    #fh = file ('confusion_matrix_formajorfamilyonly_holdout_all.txt', 'w')

    for i in range(0, len(datasets)):
        g_fnames=set()
        print "work on %s ... " % ( datasets[i] )
        (bft, blt) = ({}, {})
        for k in range(0, len(datasets[i]['benign'])):
            (bf, bl) = loadFeatures(datasets[i]['benign'][k])
            if g_binary:
                bft.update (bf)
                blt.update (bl)
        for k in range(0, len(datasets[i]['malware'])):
            (mf, ml) = loadFeatures(datasets[i]['malware'][k])
            bft.update (mf)
            blt.update (ml)

        if g_binary:
            for key in blt:
                if blt[key] != 'BENIGN':
                    blt[key] = 'MALICIOUS'
        else:
            pruneMinorMalware(bft, blt)
            g_fnames=set()

            for key in bft.keys():
                fnames = [ft for ft in bft[key].keys()]
                g_fnames = g_fnames.union (set(fnames))

            print >> sys.stderr, 'loaded %d feature vectors, %d labels, each sample having %d features' % (len (bft), len(blt), len(g_fnames))

        '''
        pruneMinorMalware(bft, blt)
        g_fnames=set()

        for key in bft.keys():
            fnames = [ft for ft in bft[key].keys()]
            g_fnames = g_fnames.union (set(fnames))

        print >> sys.stderr, 'loaded %d feature vectors, %d labels, each sample having %d features' % (len (bft), len(blt), len(g_fnames))

        if g_binary:
            for key in blt:
                if blt[key] != 'BENIGN':
                    blt[key] = 'MALICIOUS'
        '''

        resetframe()

        '''
        fhx = file('droidsieve_feature_names.txt', 'w+')
        for name in g_fnames:
            print >> fhx, name
        fhx.close()
        '''

        _bft = _regularizeFeatures ( bft )

        ''' debugging ...
        for x in bft:
            if x[0]=="caf3505926f01934e5f03022105c0b1b":
                print x, bft[x]

        for x in _bft:
            if x[0]=="caf3505926f01934e5f03022105c0b1b":
                print x, _bft[x]
        '''

        predict(_getfvec(_bft),blt, fh, i)

    fh.flush()
    fh.close()

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
