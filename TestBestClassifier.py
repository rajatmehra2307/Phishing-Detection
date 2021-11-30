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
import time

dictBinaryLabels={1:'phishy',0:'benign'}   


# Load Tranco list and Tranco features
tempArray=np.load(PA.pathTrancoRemainingURLs) # URLs
TrancoURLsList=tempArray.tolist()

tempArray=np.load(PA.pathTrancoRemaining) # Features
xTRUE=tempArray.tolist()

X_benign=np.asarray(xTRUE) # X_benign.shape: (n_benign_domains, n_features)=(100,000 , n_features=17)
# Interested in calculating False Positive, i.e Benign Tranco domains characterized as positive (phishy) by our algorithm

print("Number of Tranco samples passed through the Binary Classifier = "+str(len(xTRUE))+"\n")

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

# Load the best binary classifier:
binclf=joblib.load(PA.saveMODEL)  # load the trained model
# binclf.classes_ : np.ndarray of shape (n_classes,) with the order of classes viz. array([0, 1])
# label int 1:'phishy' and label int 0:'benign'

print('Pass the Tranco domains through the binary classifiers.\n')
TS=time.time()
BenignProbabilities=np.zeros((X_benign.shape[0],2)) # ( 100,000 , 2)
BenignProbabilities=binclf.predict_proba(X_benign)
print('Time needed for the binary classifier is '+str(time.time()-TS)+' seconds.\n')
BenignFP=0 # Number of benign domains classified as phishy (misclassifieed)
indicesBenignFP=[] # refer to both lists: 
BenignFPdict=dict()
X_benignFP=[]

for index in range(BenignProbabilities.shape[0]):
    if BenignProbabilities[index,0]-BenignProbabilities[index,1]<0.: # P[benign] < P[phishy]
        X_benignFP.append(xTRUE[index])
        BenignFP+=1
        indicesBenignFP.append(index)
        BenignFPdict[TrancoURLsList[index]]=dict() # {"dga.com":{"ProbMISS":0.6,"F":[]},...}
        BenignFPdict[TrancoURLsList[index]]["ProbPhishy"]=BenignProbabilities[index,1]
        BenignFPdict[TrancoURLsList[index]]["Features"]=list(X_benign[index,:])

print(BenignFPdict)

print("Number of BENIGN Tranco domains classified as phishing: "+str(BenignFP)+", out of total "+str(len(xTRUE))+", viz. "+str(100.0*float(BenignFP/len(xTRUE)))+" %. \n")


fullpath=PA.pathIntermediateData+'featuresTrancoFP.pk'
with open(fullpath, 'wb') as f:
    pickle.dump(X_benignFP, f, pickle.HIGHEST_PROTOCOL)
X_benignFP=[]

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@