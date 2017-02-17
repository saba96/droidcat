# Import all classification package
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB, MultinomialNB, BernoulliNB
from sklearn.neighbors import KNeighborsClassifier

from sklearn.cross_validation import cross_val_score
from sklearn.metrics import precision_score,recall_score,f1_score,roc_auc_score,accuracy_score
from sklearn import cross_validation

from sklearn.feature_selection import RFECV,RFE

from sklearn.metrics import confusion_matrix

import numpy
import random
import os
import sys
import string

from configs import *
from featureLoader import *

# 10-fold cross-validation
def cv(model, features, labels):
    sr=len(features)
    #sr=features.shape[0]
    #k=10
    k=sr
    subsize = sr/k
    subsamples=list()
    sublabels=list()

    lcv = cross_validation.LeaveOneOut(sr-1)

    selector = RFECV(model, step=1, cv=lcv)
    selector_prec = RFECV(model, step=1, cv=lcv, scoring='precision_weighted')
    selector_rec = RFECV(model, step=1, cv=lcv, scoring='recall_weighted')
    selector_f1 = RFECV(model, step=1, cv=lcv, scoring='f1_weighted')

    predicted_labels=list()
    predicted_labels_prec=list()
    predicted_labels_rec=list()
    predicted_labels_f1=list()

    uniqLabels = set()
    for item in labels:
        uniqLabels.add (item)

    for j in range(0,k):
        subsamples.append( (features[j*subsize:(j+1)*subsize]) )
        sublabels.append( (labels[j*subsize:(j+1)*subsize]) )

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

        selector_prec.fit( trainFeatures, trainLabels )
        selector_rec.fit( trainFeatures, trainLabels )
        selector_f1.fit( trainFeatures, trainLabels )
        selector.fit (features, labels)

        y_pred = selector.predict( testFeatures )
        y_pred_prec = selector_prec.predict( testFeatures )
        y_pred_rec = selector_rec.predict( testFeatures )
        y_pred_f1 = selector_f1.predict( testFeatures )

        print >> sys.stderr, "j=%d, testLabels: %s" % (j, str(testLabels))
        print >> sys.stderr, "j=%d, predicted: %s (acc), %s (prec), %s (rec), %s (f1)" % (j, str(y_pred), str(y_pred_prec), str(y_pred_rec), str(y_pred_f1))

        predicted_labels.append ( y_pred )
        predicted_labels_prec.append ( y_pred_prec )
        predicted_labels_rec.append ( y_pred_rec )
        predicted_labels_f1.append ( y_pred_f1 )

    '''
    for i in range(0, len(predicted_labels)):
        #print type(predicted_labels[i])
        if predicted_labels[i][0] not in big_families:
            predicted_labels[i] = numpy.array(['MALICIOUS'])
    '''

    #print "%s\n%s\n" % (str(sublabels), str(predicted_labels))
    big_families=["DroidKungfu", "ProxyTrojan/NotCompatible/NioServ", "GoldDream", "Plankton", "FakeInst", "BENIGN", "MALICIOUS"]

    #return confusion_matrix(labels, predicted_labels, labels=list(uniqLabels))
    return (confusion_matrix(sublabels, predicted_labels, labels=big_families),
            confusion_matrix(sublabels, predicted_labels_prec, labels=big_families),
            confusion_matrix(sublabels, predicted_labels_rec, labels=big_families),
            confusion_matrix(sublabels, predicted_labels_f1, labels=big_families))


def selectFeatures(features, selection):
    featureSelect=[idx-1 for idx in selection]
    selectedfeatures=list()
    for featureRow in features:
        selectedfeatures.append ( featureRow[ featureSelect ] )
    return selectedfeatures

if __name__=="__main__":

    (features, labels, Testfeatures, Testlabels) = getTrainingData( False, pruneMinor=True)

    models = (RandomForestClassifier(n_estimators = 100), SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())
    #models = (SVC(kernel='rbf'), SVC(kernel='linear'), DecisionTreeClassifier(random_state=None), KNeighborsClassifier(n_neighbors=5), GaussianNB(), MultinomialNB(), BernoulliNB())

    uniqLabels = set()
    for item in labels:
        uniqLabels.add (item)

    fh = file ('confusion_matrix_formajorfamilyonly_ext_highcov_10m_all_topfeaturesOnly.txt', 'w')
    print >> fh, '\t'.join(uniqLabels)

    for model in models:
        for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
        #for fset in (FSET_FULL, FSET_YYY):
            print >> fh, 'model ' + str(model) + "\t" + "feature set " + str(fset)
            ret = cv (model, selectFeatures( features, fset ), labels)
            print >> fh, "<< ranking by accuracy >>"
            for row in ret[0]:
                for x in row:
                    print >> fh, "%d\t" % (x),
                print >> fh
            print >> fh, "<< ranking by precision >>"
            for row in ret[1]:
                for x in row:
                    print >> fh, "%d\t" % (x),
                print >> fh
            print >> fh, "<< ranking by recall >>"
            for row in ret[2]:
                for x in row:
                    print >> fh, "%d\t" % (x),
                print >> fh
            print >> fh, "<< ranking by f1 >>"
            for row in ret[3]:
                for x in row:
                    print >> fh, "%d\t" % (x),
                print >> fh
            fh.flush()

    fh.flush()
    fh.close()

    sys.exit(0)

# hcai: set ts=4 tw=100 sts=4 sw=4
