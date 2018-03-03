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

from configs import *
from featureLoader import *

#HOLDOUT_RATE=0.33
HOLDOUT_RATE=0.4

g_binary = False # binary or multiple-class classification

def varname(p):
    for line in inspect.getframeinfo(inspect.currentframe().f_back)[3]:
        m = re.search(r'\bvarname\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', line)
        if m:
            return m.group(1)

def span_detect(model, trainfeatures, trainlabels, testfeatures, testlabels):

    print >> sys.stdout, "%d samples for training, %d samples for testing" % (len (trainfeatures), len(testfeatures))

    model.fit ( trainfeatures, trainlabels )

    y_pred = model.predict ( testfeatures )

    if g_binary:
        prec=precision_score(testlabels, y_pred, average='binary', pos_label='MALICIOUS')
        rec=recall_score(testlabels, y_pred, average='binary', pos_label='MALICIOUS')
        f1=f1_score(testlabels, y_pred, average='binary', pos_label='MALICIOUS')
    else:
        prec=precision_score(testlabels, y_pred, average='weighted')
        rec=recall_score(testlabels, y_pred, average='weighted')
        f1=f1_score(testlabels, y_pred, average='weighted')

    acc=accuracy_score( testlabels, y_pred )

    #print "precision=%f, recall=%f, f1=%f, acc=%f" % (prec, rec, f1, acc)

    #return confusion_matrix(testlabels, predicted_labels, labels=list(uniqLabels))
    #return confusion_matrix(sublabels, predicted_labels, labels=big_families)
    return (prec, rec, f1, acc)


def selectFeatures(features, selection):
    featureSelect=[idx-1 for idx in selection]
    selectedfeatures=list()
    for featureRow in features:
        selectedfeatures.append ( featureRow[ featureSelect ] )
    return selectedfeatures

if __name__=="__main__":
    if len(sys.argv)>=2:
        g_binary = sys.argv[1].lower()=='true'

    #bPrune = g_binary
    mode = "family"
    bPrune = True

    if len(sys.argv)>=3:
        mode = sys.argv[2].lower()

    # training dataset
    #(bf1, bl1) = loadMamaFeatures("benign-2014", mode, "BENIGN")
    (bf1, bl1) = loadMamaFeatures("zoo-benign-2010", mode, "BENIGN")
    '''
    for app in bf1.keys():
        if app not in comlist17:
            del bf1[app]
            del bl1[app]
    '''

    '''
    (mf1, ml1) = loadMamaFeatures("malware-2013", mode, "MALICIOUS")
    bf1.update (mf1)
    bl1.update (ml1)

    (mf2, ml2) = loadMamaFeatures("malware-2017", mode, "MALICIOUS")
    bf1.update (mf2)
    bl1.update (ml2)

    (mf3, ml3) = loadMamaFeatures("malware-drebin", mode, "MALICIOUS")
    for app in mf3.keys():
        if app not in comlistdrebin:
            del mf3[app]
            del ml3[app]
    bf1.update (mf3)
    bl1.update (ml3)
    '''

    (mf4, ml4) = loadMamaFeatures("zoo-2010", mode, "MALICIOUS")
    bf1.update (mf4)
    bl1.update (ml4)

    '''
    (mf5, ml5) = loadMamaFeatures("malware-zoo-2015", mode, "MALICIOUS")
    bf1.update (mf5)
    bl1.update (ml5)

    (mf6, ml6) = loadMamaFeatures("malware-zoo-2016", mode, "MALICIOUS")
    bf1.update (mf6)
    bl1.update (ml6)
    '''

    # Testing
    #(bf2, bl2) = loadMamaFeatures("benign-2014", mode, "BENIGN")
    (bf2, bl2) = loadMamaFeatures("zoo-benign-2011", mode, "BENIGN")
    '''
    for app in bf2.keys():
        if app not in comlist17:
            del bf2[app]
            del bl2[app]
    '''

    (mf1, ml1) = loadMamaFeatures("zoo-2011", mode, "MALICIOUS")
    bf2.update (mf1)
    bl2.update (ml1)

    '''
    (mf2, ml2) = loadMamaFeatures("malware-2017", mode, "MALICIOUS")
    bf2.update (mf2)
    bl2.update (ml2)
    '''

    '''
    (mf3, ml3) = loadMamaFeatures("malware-drebin", mode, "MALICIOUS")
    for app in mf3.keys():
        if app not in comlistdrebin:
            del mf3[app]
            del ml3[app]
    bf2.update (mf3)
    bl2.update (ml3)
    '''

    '''
    (mf4, ml4) = loadMamaFeatures("malware-zoo-2016", mode, "MALICIOUS")
    bf2.update (mf4)
    bl2.update (ml4)

    (mf5, ml5) = loadMamaFeatures("malware-zoo-2016", mode, "MALICIOUS")
    bf2.update (mf5)
    bl2.update (ml5)

    (mf6, ml6) = loadMamaFeatures("malware-zoo-2016", mode, "MALICIOUS")
    bf2.update (mf6)
    bl2.update (ml6)
    '''

    (trainfeatures, trainlabels) = adapt (bf1, bl1)
    (testfeatures, testlabels) = adapt (bf2, bl2)

    print "======== in training dataset ======="
    l2c = malwareCatStat(trainlabels)
    for lab in l2c.keys():
        print "%s\t%s" % (lab, l2c[lab])

    print "======== in testing dataset ======="
    l2c = malwareCatStat(testlabels)
    for lab in l2c.keys():
        print "%s\t%s" % (lab, l2c[lab])

    uniqLabels = set()
    for item in testlabels:
        uniqLabels.add (item)

    if mode=="family":
        nt = 51
        dp  = 8
    else:
        nt = 101
        dp = 64


    models = (RandomForestClassifier(n_estimators = nt, max_depth= dp), )#ExtraTreesClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), MultinomialNB())
    #models = (RandomForestClassifier(n_estimators = 120), )#ExtraTreesClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), MultinomialNB())

    #models = (RandomForestClassifier(n_estimators = 128, random_state=0), )#GaussianProcessClassifier(), ExtraTreesClassifier(n_estimators=120), AdaBoostClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())
    #models = (ExtraTreesClassifier(n_estimators=128, random_state=0),  AdaBoostClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), )#SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())
    #models = (SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())

    #models = (RandomForestClassifier(n_estimators = 128, random_state=0), SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())


    fh = sys.stdout
    #fh = file ('confusion_matrix_formajorfamilyonly_holdout_all.txt', 'w')
    print >> fh, '\t'.join(uniqLabels)

    model2ret={}
    for model in models:
        print >> fh, 'model ' + str(model)
        ret = span_detect (model, trainfeatures, trainlabels, testfeatures, testlabels)
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
