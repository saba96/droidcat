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

import numpy
import random
import os
import sys
import string

import inspect, re

#from classes.sample import Sample
import pickle

HOLDOUT_RATE=0.33

g_binary = False # binary or multiple-class classification
featureframe = {}
g_fnames = set()
tagprefix="/home/hcai/Downloads/droidsieve/features_droidsieve_byfirstseen/static.pickle."

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
    for (app,date) in features.keys():
        lab = labels[(app,date)]
        if lab not in lab2dates.keys():
            lab2dates[lab] = []
        lab2dates[lab].append( date )

    testfeatures = {}
    testlabels = {}
    trainfeatures = {}
    trainlabels = {}

    for lab in lab2dates.keys():
        alldates = lab2dates[lab]
        alldates.sort()
        #print alldates

        pivot = alldates [ len(alldates)*7/10 ]
        print "%s pivot=%s" % (lab, pivot)

        for (app,date) in features.keys():
            key = (app,date)
            if date > pivot:
                testfeatures[key] = features [key]
                testlabels [key] = labels [key]
            else:
                trainfeatures[ key ] = features [ key ]
                trainlabels [key] = labels [key]

    print >> sys.stdout, "%d samples for training, %d samples  held out will be used for testing" % (len (trainfeatures), len(testfeatures))

    return trainfeatures, trainlabels, testfeatures, testlabels

def predict(f, l, fh):
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

    models = (ExtraTreesClassifier(n_estimators=120), )#GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), MultinomialNB())

    print >> fh, '\t'.join(uniqLabels)

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


def loadFeatures(datatag):
    global g_fnames
    f = open(tagprefix+datatag, 'rb')
    sample_features = {}
    sample_labels = {}

    try:
        fdict = pickle.load (f)
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
        newfdict = featureframe
        for fname in rawfeatures[md5].keys():
            #assert fname in newfdict.keys()
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
    global featureframe
    for name in g_fnames:
        featureframe[name] = 0.0

if __name__=="__main__":
    if len(sys.argv)>=2:
        g_binary = sys.argv[1].lower()=='true'

    datasets = [ \
                {"benign":["zoobenign2014", "zoobenign2015", "benign2014", "benign2015"], "malware":["vs2014","vs2015","zoo2014","zoo2015"]},
                {"benign":["zoobenign2016", "zoobenign2017", "benign2016", "benign2017"], "malware":["vs2016","zoo2016","zoo2017"]},
                ]

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

        resetframe()

        _bft = _regularizeFeatures ( bft )

        predict(_getfvec(_bft),blt, fh)

    fh.flush()
    fh.close()

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
