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

    print >> sys.stdout, "%d samples for training, %d samples  held out will be used for testing" % (len (trainfeatures), len(testfeatures))

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

    acc=accuracy_score( testlabels, y_pred )

    print "precision=%f, recall=%f, f1=%f, acc=%f" % (prec, rec, f1, acc)

    return confusion_matrix(testlabels, predicted_labels, labels=list(uniqLabels))
    #return confusion_matrix(sublabels, predicted_labels, labels=big_families)


def selectFeatures2(features, selection):
    featureSelect=[idx-1 for idx in selection]
    selectedfeatures=list()
    for k in features.keys():
        featureRow = features[ k ]
        seg = [featureRow[i] for i in featureSelect ]
        selectedfeatures.append ( seg )
    return selectedfeatures

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

    (bf1, bl1) = loadBenignData('features_large/benign-2014')

    (bf2, bl2) = loadBenignData('features_large/benign-2017')
    bf1.update(bf2)
    bl1.update(bl2)

    (mf1, ml1) = loadMalwareData(g_binary, 'features_large/malware-2013','/home/hcai/testbed/cg.instrumented/malware/installed', pruneMinor=True, drebin=False, obf=False)
    bf1.update (mf1)
    bl1.update (ml1)

    (mf2, ml2) = loadMalwareData(g_binary, 'features_large/malware-2017','/home/hcai/testbed/cg.instrumented/newmalwareall/installed', pruneMinor=True, drebin=False, obf=False)
    bf1.update (mf2)
    bl1.update (ml2)

    (mf3, ml3) = loadMalwareData(g_binary, 'features_large/malware-drebin','/home/hcai/Downloads/Drebin', pruneMinor=True, drebin=True, obf=False)
    bf1.update (mf3)
    bl1.update (ml3)

    (mf4, ml4) = loadMalwareData(g_binary, 'features_large/malware-zoo/2014','/home/hcai/testbed/cg.instrumented/AndroZoo/2014', pruneMinor=True, drebin=False, obf=False)
    bf1.update (mf4)
    bl1.update (ml4)

    (mf5, ml5) = loadMalwareData(g_binary, 'features_large/malware-zoo/2015','/home/hcai/testbed/cg.instrumented/AndroZoo/2015', pruneMinor=True, drebin=False, obf=False)
    bf1.update (mf5)
    bl1.update (ml5)

    (mf6, ml6) = loadMalwareData(g_binary, 'features_large/malware-zoo/2016','/home/hcai/testbed/cg.instrumented/AndroZoo/2016', pruneMinor=True, drebin=False, obf=False)
    bf1.update (mf6)
    bl1.update (ml6)

    (features, labels) = adapt (bf1, bl1)

    #models = (RandomForestClassifier(n_estimators = 128, random_state=0), )#GaussianProcessClassifier(), ExtraTreesClassifier(n_estimators=120), AdaBoostClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())
    #models = (ExtraTreesClassifier(n_estimators=128, random_state=0),  AdaBoostClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), )#SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())
    #models = (SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())

    models = (RandomForestClassifier(n_estimators = 128, random_state=0), SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())

    uniqLabels = set()
    for item in labels:
        uniqLabels.add (item)


    l2c = malwareCatStat(labels)
    for lab in l2c.keys():
        print "%s\t%s" % (lab, l2c[lab])

    fh = sys.stdout
    #fh = file ('confusion_matrix_formajorfamilyonly_holdout_all.txt', 'w')
    print >> fh, '\t'.join(uniqLabels)

    for model in models:
        #for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
        #for fset in (FSET_FULL, FSET_YYY, FSET_G):
        #for fset in (FSET_FULL,FSET_NOICC, FSET_MIN, FSET_YYY_G, FSET_FULL_TOP, FSET_YYY_TOP, FSET_FULL_TOP_G, FSET_YYY_TOP_G):
        for fset in (FSET_FULL,FSET_NOICC, FSET_MIN, FSET_YYY_G, FSET_FULL_TOP, FSET_YYY_TOP, FSET_FULL_TOP_G, FSET_YYY_TOP_G):
        #for fset in (FSET_G,):
            print >> fh, 'model ' + str(model) + "\t" + "feature set " + FSET_NAMES[str(fset)]
            ret = holdout (model, selectFeatures( features, fset ), labels)
            #continue
            for row in ret:
                for x in row:
                    print >> fh, "%d\t" % (x),
                print >> fh

    fh.flush()
    fh.close()

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
