# Import all classification package
from sklearn.ensemble import RandomForestClassifier 
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB, MultinomialNB, BernoulliNB
from sklearn.neighbors import KNeighborsClassifier

from sklearn.cross_validation import cross_val_score
from sklearn.metrics import precision_score,recall_score,f1_score,roc_auc_score,accuracy_score

import numpy
import random
import os
import sys
import string

from configs import *
from featureLoader import *

global g_accuracy,g_binary

# 10-fold cross-validation
def cv(model, features, labels):
    global g_accuracy,g_binary
    k=10
    #r=features.shape[0]
    r=len(features)
    subsize = r/k
    subsamples=list()
    sublabels=list()
    for j in range(0,k):
        subsamples.append( (features[j*subsize:(j+1)*subsize]) )
        sublabels.append( (labels[j*subsize:(j+1)*subsize]) )

    #print len(subsamples), len(sublabels)
    #print "#sets of subsamples=" + str(len(subsamples)) + ", #sets of sublabels=" + str(len(sublabels))

    score = 0.0
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
        model.fit( trainFeatures, trainLabels )

        if g_accuracy:
            curscore = model.score( testFeatures, testLabels )
            #print >> sys.stdout, "score of %d-fold cross-validation, repetition No. %d: %f" % (k,j,curscore)
            score += curscore
        else:
            y_pred = model.predict( testFeatures )
            if g_binary:
                prec=precision_score(testLabels, y_pred, average='binary', pos_label='MALICIOUS')
                rec=recall_score(testLabels, y_pred, average='binary', pos_label='MALICIOUS')
                f1=f1_score(testLabels, y_pred, average='binary', pos_label='MALICIOUS')
            else:
                prec=precision_score(testLabels, y_pred, average='weighted')
                rec=recall_score(testLabels, y_pred, average='weighted')
                f1=f1_score(testLabels, y_pred, average='weighted')
                '''
                print >> sys.stdout, "precision of %d-fold cross-validation, repetition No. %d: %f" % (k,j,prec)
                print >> sys.stdout, "recall of %d-fold cross-validation, repetition No. %d: %f" % (k,j,rec)
                print >> sys.stdout, "f1-measure of %d-fold cross-validation, repetition No. %d: %f" % (k,j,f1)
                #print >> sys.stdout, "accuracy of %d-fold cross-validation, repetition No. %d: %f" % (k,j,accuracy)
                '''

            precision += prec
            recall += rec
            f1s += f1

    if g_accuracy:
        #print >> sys.stdout, "average score: " + str(score/k)
        cvscores = cross_val_score(estimator=model, X=features, y=labels, cv=10)
        #print >> sys.stdout, "auto cv average score: " + str(numpy.average(cvscores))
        return max(score/k, numpy.average(cvscores))
    else:
        '''
        print >> sys.stdout, "average precision: " + str(precision/k)
        print >> sys.stdout, "average recall: " + str(recall/k)
        print >> sys.stdout, "average f1: " + str(f1s/k)
        '''

        cvprec = cross_val_score(estimator=model, X=features, y=labels, cv=10, scoring='precision_weighted')
        cvrec = cross_val_score(estimator=model, X=features, y=labels, cv=10, scoring='recall_weighted')
        cvf1 = cross_val_score(estimator=model, X=features, y=labels, cv=10, scoring='f1_weighted')
        '''
        print >> sys.stdout, "auto cv average precision: " + str(numpy.average(cvprec))
        print >> sys.stdout, "auto cv average recall: " + str(numpy.average(cvrec))
        print >> sys.stdout, "auto cv average f1: " + str(numpy.average(cvf1))
        '''

        return (max(precision/k, numpy.average(cvprec)), max(recall/k, numpy.average(cvrec)), max(f1s/k, numpy.average(cvf1)))

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

    models = (RandomForestClassifier(n_estimators = 100),\
              SVC(kernel='rbf'),
              SVC(kernel='linear'),
              DecisionTreeClassifier(random_state=None),
              KNeighborsClassifier(n_neighbors=5),
              GaussianNB(), MultinomialNB(), BernoulliNB())

    if g_accuracy:
        for model in models:
            print 'model ' + str(model)
            for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
                ret = cv (model, selectFeatures( features, fset ), labels)
                print ret
    else:
        model2ret={}
        for model in models:
            print 'model ' + str(model)
            for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
                ret = cv (model, selectFeatures( features, fset ), labels)
                model2ret[str(model)+str(fset)] = ret
        tlabs=('precision', 'recall', 'F1')
        for i in (0,1,2):
            print tlabs[i]
            for model in models:
                print 'model ' + str(model)
                for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
                    ret = model2ret[str(model)+str(fset)]
                    print ret[i]

    sys.exit(0)

# hcai: set ts=4 tw=100 sts=4 sw=4
