# Import all classification package
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, AdaBoostClassifier, BaggingClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB, MultinomialNB, BernoulliNB
from sklearn.neighbors import KNeighborsClassifier

from sklearn.metrics import precision_score,recall_score,f1_score,roc_auc_score,accuracy_score

from sklearn.metrics import confusion_matrix

import matplotlib.pyplot as plt

import numpy as np
import random
import os
import sys
import string

from configs import *
from featureLoader import *

#HOLDOUT_RATE=0.33
HOLDOUT_RATE=0.4

# hold-out 40% evaluation
def holdout(model, features, labels, fset):
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

    importances = model.feature_importances_
    std = np.std([tree.feature_importances_ for tree in model.estimators_],
            axis=0)
    indices = np.argsort(importances)[::-1]
    print [indices[i] for i in range(0, len(indices))]

    idx2featurenames_ = getFeatureMapping()
    idx2featurenames = dict()
    x=1
    for idx in fset:
        idx2featurenames[x] = idx2featurenames_[fset[x-1]]
        x+=1

    # Print the feature ranking
    print("Feature ranking:")

    sc=len(features[0])
    fnames=list()
    for f in range(0, sc):
        #print("Rank %d: feature %s (%f)" % (f + 1, idx2featurenames[indices[f]+1][0], importances[indices[f]]))
        print("%d: %s\t%f" % (f + 1, idx2featurenames[indices[f]+1][0], importances[indices[f]]))
        fnames.append( idx2featurenames[indices[f]+1][0] )

    # Plot the feature importances of the forest
    plt.figure()
    plt.title("Feature importances")
    '''
    plt.bar(range(0, sc), importances[indices],
            color="r", yerr=std[indices], align="center")
    plt.xticks(range(0,sc), indices)
    plt.xlim([-1, sc])
    '''

    #plt.barh(range(0, sc), importances[indices], color="r", xerr=std[indices], align="center")

    '''
    plt.barh(range(sc-1, -1,-1), importances[indices])
    plt.yticks(range(sc, 0, -1), fnames)
    '''

    plt.barh(range(29, -1,-1), importances[indices[0:30]])
    plt.yticks(range(30, 0, -1), fnames[0:30])

    plt.show()

def selectFeatures(features, selection):
    featureSelect=[idx-1 for idx in selection]
    selectedfeatures=list()
    for featureRow in features:
        selectedfeatures.append ( featureRow[ featureSelect ] )
    return selectedfeatures

if __name__=="__main__":

    (features, labels, Testfeatures, Testlabels) = getTrainingData( False, pruneMinor=True)
    #(features, labels, Testfeatures, Testlabels) = getTrainingData( True, pruneMinor=False)

    models = (RandomForestClassifier(n_estimators = 128, random_state=0), )#ExtraTreesClassifier(n_estimators=120), AdaBoostClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), )#SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())
    #models = (ExtraTreesClassifier(n_estimators=250, random_state=0),) # AdaBoostClassifier(n_estimators=120), GradientBoostingClassifier(n_estimators=120), BaggingClassifier (n_estimators=120), )#SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())
    #models = (SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())

    for model in models:
        #for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
        for fset in (FSET_FULL, FSET_YYY):
        #for fset in (FSET_FULL,):
            holdout (model, selectFeatures( features, fset ), labels, fset)

    sys.exit(0)

# hcai: set ts=4 tw=120 sts=4 sw=4
