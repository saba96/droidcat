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

# hold-out 20% evaluation
def holdout(model, trainfeatures, trainlabels, testfeatures, testlabels):

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
        global g_binary
        g_binary = sys.argv[1].lower()=='true'

    #bPrune = g_binary
    bPrune = True

    # training dataset
    (bf1, bl1) = loadBenignData('features_large/benign-2017')

    '''
    (mf1, ml1) = loadMalwareData(g_binary, 'features_large/malware-2012','/home/hcai/testbed/cg.instrumented/malware/installed', pruneMinor=bPrune, drebin=False, obf=False)
    bf1.update (mf1)
    bl1.update (ml1)
    '''

    (mf3, ml3) = loadMalwareData(g_binary, 'features_large/malware-drebin','/home/hcai/Downloads/Drebin', pruneMinor=bPrune, drebin=True, obf=False)
    bf1.update (mf3)
    bl1.update (ml3)

    '''
    (mf4, ml4) = loadMalwareData(g_binary, 'features_large/malware-zoo/2014','/home/hcai/testbed/cg.instrumented/AndroZoo/2014', pruneMinor=bPrune, drebin=False, obf=False)
    bf1.update (mf4)
    bl1.update (ml4)
    '''

    '''
    (mf5, ml5) = loadMalwareData(g_binary, 'features_large/malware-zoo/2015','/home/hcai/testbed/cg.instrumented/AndroZoo/2015', pruneMinor=bPrune, drebin=False, obf=False)
    bf1.update (mf5)
    bl1.update (ml5)

    (mf6, ml6) = loadMalwareData(g_binary, 'features_large/malware-zoo/2016','/home/hcai/testbed/cg.instrumented/AndroZoo/2016', pruneMinor=bPrune, drebin=False, obf=False)
    bf1.update (mf6)
    bl1.update (ml6)
    '''

    # testing dataset

    (bf2, bl2) = loadBenignData('features_large/benign-2017')

    '''
    (mf2, ml2) = loadMalwareData(g_binary, 'features_large/malware-2017','/home/hcai/testbed/cg.instrumented/newmalwareall/installed', pruneMinor=bPrune, drebin=False, obf=False)
    bf2.update (mf2)
    bl2.update (ml2)
    '''

    '''
    (mf6, ml6) = loadMalwareData(g_binary, 'features_large/malware-zoo/2014','/home/hcai/testbed/cg.instrumented/AndroZoo/2014', pruneMinor=bPrune, drebin=False, obf=False)
    bf2.update (mf6)
    bl2.update (ml6)
    '''

    (mf1, ml1) = loadMalwareData(g_binary, 'features_large/malware-2012','/home/hcai/testbed/cg.instrumented/malware/installed', pruneMinor=bPrune, drebin=False, obf=False)
    bf2.update (mf1)
    bl2.update (ml1)

    if not g_binary:
        trainfeatures = bf1
        trainlabels = bl1
        testfeatures = bf2
        testlabels = bl2
        if not g_binary:
            commonlabels = set (trainlabels.values()).intersection ( set (testlabels.values()) )
            print commonlabels
            trainapps2remove=[]
            for app in trainlabels.keys():
                if trainlabels[app] not in commonlabels:
                    trainapps2remove.append( app )
            testapps2remove=[]
            for app in testlabels.keys():
                if testlabels[app] not in commonlabels:
                    testapps2remove.append( app )
            for app in trainapps2remove:
                del trainfeatures[app]
                del trainlabels[app]
            for app in testapps2remove:
                del testfeatures[app]
                del testlabels[app]

        bf1 = trainfeatures
        bl1 = trainlabels
        bf2 = testfeatures
        bl2 = testlabels

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

    #models = (RandomForestClassifier(n_estimators = 128, random_state=0), )#GaussianProcessClassifier(), ExtraTreesClassifier(n_estimators=120), AdaBoostClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())
    #models = (ExtraTreesClassifier(n_estimators=128, random_state=0),  AdaBoostClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), )#SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())
    #models = (SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())

    #models = (RandomForestClassifier(n_estimators = 128, random_state=0), SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())

    models = (RandomForestClassifier(n_estimators = 120, random_state=0), ExtraTreesClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), MultinomialNB())

    #fsets = (FSET_FULL,FSET_NOICC, FSET_MIN, FSET_YYY_G, FSET_FULL_TOP, FSET_YYY_TOP, FSET_FULL_TOP_G, FSET_YYY_TOP_G)
    #fsets = (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):

    #fsets = (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_YYY, FSET_FULL_TOP, FSET_YYY_TOP, FSET_FULL_TOP_G, FSET_YYY_TOP_G)
    fsets = (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_YYY, FSET_FULL_TOP_G, FSET_YYY_TOP_G)

    fh = sys.stdout
    #fh = file ('confusion_matrix_formajorfamilyonly_holdout_all.txt', 'w')
    print >> fh, '\t'.join(uniqLabels)

    model2ret={}
    for model in models:
        #for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
        #for fset in (FSET_FULL, FSET_YYY, FSET_G):
        #for fset in (FSET_FULL,FSET_NOICC, FSET_MIN, FSET_YYY_G, FSET_FULL_TOP, FSET_YYY_TOP, FSET_FULL_TOP_G, FSET_YYY_TOP_G):
        for fset in fsets:
        #for fset in (FSET_G,):
            print >> fh, 'model ' + str(model) + "\t" + "feature set " + FSET_NAMES[str(fset)]
            ret = holdout (model, selectFeatures( trainfeatures, fset ), trainlabels, selectFeatures( testfeatures, fset), testlabels)
            model2ret[str(model)+str(fset)] = ret

    tlabs=('precision', 'recall', 'F1', 'accuracy')
    for i in (0,1,2,3):
        print tlabs[i]
        cols=list()
        for model in models:
            #print 'model ' + str(model)
            col=list()
            for fset in fsets:
                ret = model2ret[str(model)+str(fset)]
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
