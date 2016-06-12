# Import all classification package
from sklearn.ensemble import RandomForestClassifier 
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB, MultinomialNB, BernoulliNB
from sklearn.neighbors import KNeighborsClassifier

from sklearn.cross_validation import cross_val_score
from sklearn.metrics import precision_score,recall_score,f1_score,roc_auc_score,accuracy_score

from sklearn.feature_selection import RFECV,RFE

import numpy
import random
import os
import sys
import string

from configs import *
from featureLoader import *

global g_accuracy

# 10-fold cross-validation
def cvScore(model, features, labels):
    global g_accuracy
    k=10

    if g_accuracy:
        selector = RFECV(model, step=1, cv=k)
        selector = selector.fit (features, labels)
        score = selector.score (features, labels)
        return score, selector.n_features_, selector.ranking_

    selector_prec = RFECV(model, step=1, cv=k, scoring='precision_weighted')
    selector_prec.fit (features, labels)
    score_prec = selector_prec.score (features, labels)

    selector_rec = RFECV(model, step=1, cv=k, scoring='recall_weighted')
    selector_rec.fit (features, labels)
    score_rec = selector_rec.score (features, labels)

    selector_f1 = RFECV(model, step=1, cv=k, scoring='f1_weighted')
    selector_f1.fit (features, labels)
    score_f1 = selector_f1.score (features, labels)

    return (score_prec, selector_prec.n_features_, selector_prec.ranking_), \
           (score_rec, selector_rec.n_features_, selector_rec.ranking_), \
           (score_f1, selector_f1.n_features_, selector_f1.ranking_)

def cv(model, features, labels):
    global g_accuracy,g_binary
    k=10

    if g_accuracy:
        selector = RFECV(model, step=1, cv=k)
        selector = selector.fit (features, labels)
        score = selector.score (features, labels)
        return score, selector.n_features_, selector.ranking_

    selector_prec = RFECV(model, step=1, cv=k, scoring='precision_weighted')
    selector_rec = RFECV(model, step=1, cv=k, scoring='recall_weighted')
    selector_f1 = RFECV(model, step=1, cv=k, scoring='f1_weighted')

    r=len(features)
    subsize = r/k
    subsamples=list()
    sublabels=list()
    for j in range(0,k):
        subsamples.append( (features[j*subsize:(j+1)*subsize]) )
        sublabels.append( (labels[j*subsize:(j+1)*subsize]) )

    precision = 0.0
    recall = 0.0
    f1s = 0.0
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

        y_pred_prec = selector_prec.predict( testFeatures )
        y_pred_rec = selector_rec.predict( testFeatures )
        y_pred_f1 = selector_f1.predict( testFeatures )
        if g_binary:
            prec=precision_score(testLabels, y_pred_prec, average='binary', pos_label='MALICIOUS')
            rec=recall_score(testLabels, y_pred_rec, average='binary', pos_label='MALICIOUS')
            f1=f1_score(testLabels, y_pred_f1, average='binary', pos_label='MALICIOUS')
        else:
            prec=precision_score(testLabels, y_pred_prec, average='weighted')
            rec=recall_score(testLabels, y_pred_rec, average='weighted')
            f1=f1_score(testLabels, y_pred_f1, average='weighted')

        precision += prec
        recall += rec
        f1s += f1

    return (precision/k, selector_prec.n_features_, selector_prec.ranking_), \
           (recall/k, selector_rec.n_features_, selector_rec.ranking_), \
           (f1s/k, selector_f1.n_features_, selector_f1.ranking_)

def selectFeatures(features, selection):
    featureSelect=[idx-1 for idx in selection]
    selectedfeatures=list()
    for featureRow in features:
        selectedfeatures.append ( featureRow[ featureSelect ] )
    return selectedfeatures
    
if __name__=="__main__":
    global g_accuracy,g_binary
    g_binary = False # binary or multiple-class classification
    g_accuracy = False # compute accuracy score or weighted precision/recall/F1-measure
    if len(sys.argv)>=2:
        g_binary = sys.argv[1].lower()=='true'
    if len(sys.argv)>=3:
        g_accuracy = sys.argv[2].lower()=='true'

    (features, labels, Testfeatures, Testlabels) = getTrainingData( g_binary )

    '''
    models = (RandomForestClassifier(n_estimators = 100),
              SVC(kernel='rbf'),
              SVC(kernel='linear'),
              DecisionTreeClassifier(random_state=None),
              KNeighborsClassifier(n_neighbors=5),
              GaussianNB(), 
              MultinomialNB(), BernoulliNB())
    '''

    models = (RandomForestClassifier(n_estimators = 100),
              SVC(kernel='linear'),
              DecisionTreeClassifier(random_state=None),
              MultinomialNB(), 
              BernoulliNB())

    if g_accuracy:
        for model in models:
            print 'model ' + str(model)
            for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
                ret = cv (model, selectFeatures( features, fset ), labels)
                print ret[0]
    else:
        model2ret={}
        for model in models:
            print 'model ' + str(model)
            for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
                ret = cv (model, selectFeatures( features, fset ), labels)
                model2ret[str(model)+str(fset)] = ret
        tlabs=('precision', 'recall', 'F1')
        for i in (0,1,2):
            print "******     " + str(tlabs[i]) + "    ******"
            for model in models:
                print 'model ' + str(model)
                for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
                    ret = model2ret[str(model)+str(fset)]
                    print ret[i][0]
    sys.exit(0)

# hcai: set ts=4 tw=100 sts=4 sw=4
