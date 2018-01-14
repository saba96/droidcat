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

# independent evaluation
def indEval(model, features, labels, newfeatures, newlabels):
    global g_accuracy,g_binary

    # use apps, regardless of their coverage, that never participated in the 
    # training (i.e., model construction) to evaluate the prediction performance of the model trained by an entirely 
    # different set of apps' features

    model.fit( features, labels )

    if g_accuracy:
        score = model.score( newfeatures, newlabels )
    else:
        y_pred = model.predict( newfeatures )
        if g_binary:
            prec=precision_score(newlabels, y_pred, average='binary', pos_label='MALICIOUS')
            rec=recall_score(newlabels, y_pred, average='binary', pos_label='MALICIOUS')
            f1=f1_score(newlabels, y_pred, average='binary', pos_label='MALICIOUS')
        else:
            prec=precision_score(newlabels, y_pred, average='weighted')
            rec=recall_score(newlabels, y_pred, average='weighted')
            f1=f1_score(newlabels, y_pred, average='weighted')

    if g_accuracy:
        return score
    else:
        return (prec,rec,f1)

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

    newroot = os.getcwd()+"/features/"+"benign-full/"
    #newroot = os.getcwd()+"/features/"+"benign-firstset/"
    #newroot = os.getcwd()+"/features/"+"benign-full-highcov/"
    #newroot = os.getcwd()+"/features/"+"benign-ext-highcov/"
    (newfeatures, newlabels, newTestfeatures, newTestlabels) = getTrainingData( g_binary,\
            newroot+"gfeatures-benign.txt",newroot+"iccfeatures-benign.txt",newroot+"securityfeatures-benign.txt",\
            newroot+"gfeatures-malware.txt",newroot+"iccfeatures-malware.txt",newroot+"securityfeatures-malware.txt")

    models = (RandomForestClassifier(n_estimators = 100),\
              SVC(kernel='rbf'),
              SVC(kernel='linear'),
              DecisionTreeClassifier(random_state=None),
              KNeighborsClassifier(n_neighbors=5),
              GaussianNB(), MultinomialNB(), BernoulliNB())

    if g_accuracy:
        cols=list()
        for model in models:
            #print 'model ' + str(model)
            col=list()
            for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
                ret = indEval (model, selectFeatures( features, fset ), labels, selectFeatures( newfeatures, fset ), newlabels)
                col.append(ret)
            cols.append(col)
        for r in range(0,len(cols[0])):
            for c in range(0,len(cols)):
                print "%s\t" % cols[c][r],
            print
    else:
        model2ret={}
        for model in models:
            print 'model ' + str(model)
            for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
                ret = indEval (model, selectFeatures( features, fset ), labels, selectFeatures( newfeatures, fset ), newlabels)
                model2ret[str(model)+str(fset)] = ret
        tlabs=('precision', 'recall', 'F1')
        for i in (0,1,2):
            print tlabs[i]
            cols=list()
            for model in models:
                #print 'model ' + str(model)
                col=list()
                for fset in (FSET_FULL, FSET_G, FSET_ICC, FSET_SEC, FSET_Y, FSET_YY, FSET_YYY):
                    ret = model2ret[str(model)+str(fset)]
                    col.append(ret[i])
                cols.append(col)
            for r in range(0,len(cols[0])):
                for c in range(0,len(cols)):
                    print "%s\t" % cols[c][r],
                print

    sys.exit(0)

# hcai: set ts=4 tw=100 sts=4 sw=4
