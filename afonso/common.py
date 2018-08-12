from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import label_binarize
from sklearn.metrics import precision_score,recall_score,f1_score,roc_auc_score,accuracy_score,auc,roc_curve

import matplotlib.pyplot as plt

import numpy as np
import pickle

def roc_bydate(g_binary, model, trainfeatures, trainlabels, testfeatures, testlabels, datatag):
    m = model

    suffix='det' if g_binary else 'cat'
    fnTarget = '../ML/roc_curves/pickle.'+datatag+'.'+suffix

    labels=set()
    for l in trainlabels: labels.add(l)
    for l in testlabels: labels.add(l)
    labels = np.array(list(labels))
    trainlabels = label_binarize(trainlabels, classes=labels)
    testlabels = label_binarize(testlabels, classes=labels)
    n_classes = len(labels)

    if not g_binary:
        m = OneVsRestClassifier(model)
        #test_score = m.fit ( trainfeatures, trainlabels ).decision_function(testfeatures)

    test_score = m.fit ( trainfeatures, trainlabels ).predict_proba(testfeatures)

    if not g_binary:
        '''
        fpr = dict()
        tpr = dict()
        roc_auc = dict()
        for i in range(n_classes):
            fpr[i], tpr[i], _ = roc_curve(testlabels[:, i], test_score[:, i])
            roc_auc[i] = auc(fpr[i], tpr[i])
        fpr["micro"], tpr["micro"], _ = roc_curve(testlabels.ravel(), test_score.ravel())
        roc_auc["micro"] = auc(fpr["micro"], tpr["micro"])
        '''
        fpr, tpr, _ = roc_curve(testlabels.ravel(), test_score.ravel())
        roc_auc = auc(fpr, tpr)
    else:
        fpr, tpr, _ = roc_curve(testlabels, test_score[:,1])
        roc_auc = auc(fpr, tpr)

    fhTarget = file (fnTarget, 'wb')
    pickle.dump( (fpr, tpr, roc_auc), fhTarget )
    fhTarget.close()

