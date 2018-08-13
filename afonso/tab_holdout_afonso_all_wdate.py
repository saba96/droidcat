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
from common import *

g_binary = False # binary or multiple-class classification
featureframe = {}
g_fnames = set()
tagprefix="features_afonso_byfirstseen/afonso.pickle."

HOLDOUT_RATE=0.33
#HOLDOUT_RATE=0.4

PRUNE_THRESHOLD=0

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

        pivot = alldates [ len(alldates)*7/10 ]
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
            for j in range(0, len(alldates)*7/10):
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

    print >> sys.stdout, "%d samples for training, %d samples  held out will be used for testing" % (len (trainfeatures), len(testfeatures))

    return trainfeatures, trainlabels, testfeatures, testlabels

def predict(f, l, fh,i):
    '''
    for a in f.keys():
        if l[a] == "BENIGN":
            print "%s \t %s" % (l[a], f[a])
    '''

    _trainfeatures, _trainlabels, _testfeatures, _testlabels = split(f, l)
    (trainfeatures, trainlabels) = adapt (_trainfeatures, _trainlabels)
    (testfeatures, testlabels) = adapt (_testfeatures, _testlabels)

    print "======== in dataset ======="

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

    models = (RandomForestClassifier(n_estimators = 128, random_state=0), )#ExtraTreesClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), MultinomialNB())

    #datatag = 'afonso_VSGP' if i==0 else 'afonso_ZOZO'
    datatag = 'afonso_PRZO1213' if i==0 else ('afonso_PRZO1415' if i==1 else 'afonso_PRZO1617')
    roc_bydate(g_binary, models[0], trainfeatures, trainlabels, testfeatures, testlabels, datatag)

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

    f.close()

    print >> sys.stderr, 'loaded from %s: %d feature vectors' % (datatag, len (sample_features))
    return (sample_features, sample_labels)

def getfvec(fdict):
    fvecs=dict()
    for (md5,date) in fdict.keys():
        #print md5
        #fnames = [fname for fname in fdict[md5].keys()]
        for key in fdict[(md5,date)].keys():
            if "->>" in key:
                fdict[(md5,date)][key]=0
        fvalues = [freq for freq in fdict[(md5,date)].values()]
        #print len(fnames), len(fvalues)
        fvecs[(md5,date)] = fvalues
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
    if len(sys.argv)>=2:
        g_binary = sys.argv[1].lower()=='true'

    '''
    datasets = [ \
                {"benign":["zoobenign2010", "zoobenign2011"], "malware":["vs2010", "vs2011","zoo2010","zoo2011"]},
                {"benign":["zoobenign2012", "zoobenign2013", "benign2012", "benign2013"], "malware":["vs2012","vs2013","zoo2012","zoo2013"]},
                {"benign":["zoobenign2014", "zoobenign2015", "benign2014", "benign2015"], "malware":["vs2014","vs2015","zoo2014","zoo2015"]},
                {"benign":["zoobenign2016", "zoobenign2017", "benign2016", "benign2017"], "malware":["vs2016","zoo2016","zoo2017"]},
                ]
    '''

    '''
    datasets = [ \
                {"benign":["zoobenign2014", "zoobenign2015", "benign2014", "benign2015"], "malware":["vs2014","vs2015","zoo2014","zoo2015"]},
                {"benign":["zoobenign2016", "zoobenign2017", "benign2016", "benign2017"], "malware":["vs2016","zoo2016","zoo2017"]},
                ]
    '''

    datasets = [ \
                {"benign":["zoobenign2012", "zoobenign2013"], "malware":["obfmg-afonso2017"]},
                {"benign":["zoobenign2014", "zoobenign2015"], "malware":["obfmg-afonso2017"]},
                {"benign":["zoobenign2016", "benign2017"], "malware":["obfmg-afonso2017"]},
                ]

    #bPrune = g_binary
    bPrune = True

    fh = sys.stdout
    #fh = file ('confusion_matrix_formajorfamilyonly_holdout_all.txt', 'w')

    for i in range(0, len(datasets)):
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

        predict(getfvec(bft),blt, fh,i)

    fh.flush()
    fh.close()

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
