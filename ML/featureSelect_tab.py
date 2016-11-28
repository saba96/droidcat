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

# 10-fold cross-validation
def cv(model, features, labels):
    k=10

    selector = RFECV(model, step=1, cv=k)
    selector = selector.fit (features, labels)
    score = selector.score (features, labels)

    selector_prec = RFECV(model, step=1, cv=k, scoring='precision_weighted')
    selector_prec.fit (features, labels)
    score_prec = selector_prec.score (features, labels)

    selector_rec = RFECV(model, step=1, cv=k, scoring='recall_weighted')
    selector_rec.fit (features, labels)
    score_rec = selector_rec.score (features, labels)

    selector_f1 = RFECV(model, step=1, cv=k, scoring='f1_weighted')
    selector_f1.fit (features, labels)
    score_f1 = selector_f1.score (features, labels)

    return (score, selector.n_features_, selector.ranking_), \
           (score_prec, selector_prec.n_features_, selector_prec.ranking_), \
           (score_rec, selector_rec.n_features_, selector_rec.ranking_), \
           (score_f1, selector_f1.n_features_, selector_f1.ranking_)

def selectFeatures(features, selection):
    featureSelect=[idx-1 for idx in selection]
    selectedfeatures=list()
    for featureRow in features:
        selectedfeatures.append ( featureRow[ featureSelect ] )
    return selectedfeatures
    
if __name__=="__main__":
    g_binary = False # binary or multiple-class classification
    if len(sys.argv)>=2:
        g_binary = sys.argv[1].lower()=='true'

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

    model2ret={}
    for model in models:
        print 'model ' + str(model)
        for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
            ret = cv (model, selectFeatures( features, fset ), labels)
            model2ret[str(model)+str(fset)] = ret
    s=1
    for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
        print "=========== feature set %d ===========" % s
        fh = None
        if g_binary:
            fh = file ('binary-fs'+str(s)+'.txt', 'w')
        else:
            fh = file ('multiclass-fs'+str(s)+'.txt', 'w')
        s+=1
        for r in range(0, len(fset)):
            for model in models:
                ret = model2ret[str(model)+str(fset)]
                for i in (0,1,2,3):
                    assert len(fset)==len(ret[i][2])
                    print >> fh, "%s\t" % (ret[i][2][r]),
            print >> fh
        print >> fh
        for model in models:
            ret = model2ret[str(model)+str(fset)]
            for i in (0,1,2,3):
                print >> fh, "%s\t" % (ret[i][1]),
        print >> fh
        fh.close()

    sys.exit(0)

# hcai: set ts=4 tw=100 sts=4 sw=4
