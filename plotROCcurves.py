#!/usr/bin/python3

import numpy as np
import math
import random
from sklearn import ensemble
from sklearn.neural_network import MLPClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score, plot_confusion_matrix, roc_curve, auc
from sklearn.feature_selection import mutual_info_classif
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis
from sklearn.tree import DecisionTreeClassifier
from sklearn.gaussian_process.kernels import RBF
from sklearn.gaussian_process import GaussianProcessClassifier
import matplotlib.pyplot as plt
import pandas as pd
import os
import sys
import gzip
import joblib
import json
import pathsToSave as PA
import heapq
import pickle

dictBinaryLabels={1:'phishy',0:'benign'}   

feature_names=['url_length','is_https','ip_in_url', 'num_external_images', 'num_https_links', 'num_images', 'favicon_matches', 'has_trademark', 
               'days_since_creation', 'days_since_last_update', 'days_until_expiration', 'days_until_cert_expiration', 'num_links', 'mean_link_length', 'num_shortened_urls', 'num_double_slash_redirects', 'url_entropy']


# Load the python lists with phishing and benign features of URLs

# Balance the benign and phishing datasets
tempArray=np.load(PA.pathPhishing)
xTRUE=tempArray.tolist()
tempArray=np.load(PA.pathBenign)
xBenign=tempArray.tolist()

tolerance=1.2
Tm=math.ceil(tolerance*len(xTRUE))
if len(xBenign)>Tm:  # 33,499 > (11,369 * 1.2 ->ceil= 13,643)
	# random.shuffle(BenignList)
	xBenign=xBenign[0:Tm]
elif len(xTRUE)> (tolerance*len(xBenign)):
	random.shuffle(xTRUE)
	xTRUE=xTRUE[0:math.ceil(tolerance*len(xBenign))]

 
phishingFeatures=np.asarray(xTRUE) # shape: (11,369 x 17)
trancofeatures=np.asarray(xBenign) # shape: (13,643 x 17)
NumFeatures=trancofeatures.shape[-1]




# Train the Binary Classifier

yTRUE=[1]*len(xTRUE)

yBenign=[0]*len(xBenign)

print("Number of benign samples in the training set = "+str(len(yBenign))+"\n")
print("Number of phishing samples in the training set = "+str(len(yTRUE))+"\n")
xTRUE.extend(xBenign)
yTRUE.extend(yBenign)

xTRUE=np.asarray(xTRUE)   # xTRUE.shape(11,369+13,643  ,  17) 
yTRUE=np.asarray(yTRUE)


X_train, X_test, y_train, y_test=train_test_split(xTRUE, yTRUE, test_size=0.2, random_state=13)
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# saveBPATH='/Users/kleanthis/GitHub/Phishing-Detection/results/modelSelection/'
# saveBPATHr='/Users/kleanthis/GitHub/Phishing-Detection/results/modelSelectionReducedFeatures/'
models=[{ "CLFname":"KNN" , "Fname":'k-Nearest-Neighbors'},   
        {"CLFname":"RF","Fname":'Random Forest'},
        {"CLFname":"Ada", "Fname":'Adaboost'},
        {"CLFname":"LR","Fname":'Logistic Regression'},
        {"CLFname":"SVM", "Fname":'Support Vector Machine'},
        {"CLFname":"gNB","Fname":'Gaussian Naive Bayes'},
        {"CLFname":"MLP","Fname":'Neural Network'},
        {"CLFname":"DT","Fname":"Decision Tree"},
        {"CLFname":"GPC","Fname":"Gaussian Process Classifier"}
]
plt.figure()
for model in models:
    binclf=joblib.load(PA.saveBPATH+model["CLFname"]+'BinaryClf.sav') # label int 1:'phishy' and label int 0:'benign'
    # Prediction in the validation
    y_predicted=binclf.predict(X_test) # the true labels are: y_test
    prob_y_predicted=binclf.predict_proba(X_test)
    fpr, tpr, thresholds = roc_curve(y_test, prob_y_predicted[:,1], pos_label=1) # type(fpr): np.ndarray , fpr.shape : (n_samples+1,)
    auc= roc_auc_score(y_test,y_predicted)
    plt.plot(fpr, tpr, label='%s ROC (area = %0.2f)' % (model['Fname'], auc))
# Custom settings for the plot 
plt.plot([0, 1], [0, 1],'r--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic')
plt.legend(loc="lower right")
plt.savefig(PA.saveBPATH+'ROCallTogether.png')
# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

mi=mutual_info_classif(xTRUE, yTRUE)
res=dict(zip(feature_names,mi))
print(res)
Hlist=heapq.nlargest(10,res,key=res.get) # list of keys: feature_names
print(Hlist)

indexL=[]
for feature in Hlist:
    indexL.append(feature_names.index(feature))
print(indexL)
xTRUER=xTRUE[:] # copy of features array
xTRUER=xTRUER[:,indexL]
yTRUER=yTRUE[:]
X_trainR, X_testR, y_trainR, y_testR=train_test_split(xTRUER, yTRUER, test_size=0.2, random_state=13)





plt.figure()
for model in models:
    binclf=joblib.load(PA.saveBPATHr+model["CLFname"]+'BinaryClf.sav') # label int 1:'phishy' and label int 0:'benign'
    # Prediction in the validation
    y_predicted=binclf.predict(X_testR) # the true labels are: y_test
    prob_y_predicted=binclf.predict_proba(X_testR)
    fpr, tpr, thresholds = roc_curve(y_testR, prob_y_predicted[:,1], pos_label=1) # type(fpr): np.ndarray , fpr.shape : (n_samples+1,)
    auc= roc_auc_score(y_testR,y_predicted)
    plt.plot(fpr, tpr, label='%s ROC (area = %0.2f)' % (model['Fname'], auc))
# Custom settings for the plot 
plt.plot([0, 1], [0, 1],'r--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic')
plt.legend(loc="lower right")
plt.savefig(PA.saveBPATHr+'ROCallTogetherR.png')
# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

  
