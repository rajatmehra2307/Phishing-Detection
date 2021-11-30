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
feature_names=['url_length','is_https','ip_in_url', 'num_external_images', 'num_https_links', 'num_images', 'favicon_matches', 'has_trademark', 
               'days_since_creation', 'days_since_last_update', 'days_until_expiration', 'days_until_cert_expiration', 'num_links', 'mean_link_length', 'num_shortened_urls', 'num_double_slash_redirects', 'url_entropy']


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

BenignFPdict=dict()
ConfidenceScores=[]
Fvalues=[]
for i in range(X_benign.shape[-1]):
    Fvalues.append([])
for index in range(BenignProbabilities.shape[0]):
    if BenignProbabilities[index,0]-BenignProbabilities[index,1]<0.: # P[benign] < P[phishy]
        BenignFP+=1
        BenignFPdict[TrancoURLsList[index]]=dict() # {"nfga.com":{"ProbPhishy":0.6,"Features":[]},...}
        BenignFPdict[TrancoURLsList[index]]["ProbPhishy"]=BenignProbabilities[index,1]
        BenignFPdict[TrancoURLsList[index]]["position"]=int(index)
        ConfidenceScores.append(BenignProbabilities[index,1])
        BenignFPdict[TrancoURLsList[index]]["Features"]=list(X_benign[index,:])
        for i in range(X_benign.shape[-1]):
            Fvalues[i].append(X_benign[index,i])

# print(BenignFPdict)

print("Number of BENIGN Tranco domains classified as phishing: "+str(BenignFP)+", out of total "+str(len(xTRUE))+", viz. "+str(100.0*float(BenignFP/len(xTRUE)))+" %. \n")


# Dictribution of Confidence Scores of 5059 found in top 100k
plt.figure()
fig, axes = plt.subplots(figsize=(7,5), dpi=400)
plt.hist(ConfidenceScores,bins=100, density=True)
plt.title('Distribution of Confidence Scores of top 100k Tranco Domains labeled as phishing')
plt.tight_layout()
plt.savefig(PA.pathIntermediateData+'ConfidenceScoresTrancoFP.png')

# Plot of the distribution of the features of the tranco FP domains
plt.figure()
fig,axes=plt.subplots(17,1, figsize=(10,15),dpi=400)
for i in range(X_benign.shape[-1]):
    axes[i].hist(Fvalues[i],bins=100, density=True)
    axes[i].set_ylabel(feature_names[i], loc='bottom' ,rotation='horizontal')
    axes[i].yaxis.set_label_coords(-0.33,0.17)
# axes[0].set_title('Features of top 100k Tranco Domains labeld as phishing')
axes[16].set(xlabel='Feature Values')
# for ax in axes.flat:
#         ax.set_xticklabels([])
fig.suptitle('Distribution of Feature Values of top 100k Tranco Domains labeled as phishing')
plt.tight_layout()
plt.savefig(PA.pathIntermediateData+'FeaturesDistributionTrancoFP.png') 

# Plot of top-20 domains found in tranco top 100k that are very confident that are phishy

outputdict=dict() 
for k in BenignFPdict:
    outputdict[k]=float(BenignFPdict[k]["ProbPhishy"])
Hlist=heapq.nlargest(20,outputdict,key=outputdict.get) # list of keys
heights=[]
positions=[]
for url in Hlist:
    heights.append(float(outputdict[str(url)]))
    positions.append(BenignFPdict[url]["position"])

print(heights)
print(positions)
plt.figure()
fig, axes = plt.subplots(figsize=(15,8), dpi=400)
bbar=plt.bar(Hlist, height=heights)
# axes.text(positions)
plt.xticks(rotation='82.5')
plt.ylabel("Confidence")
plt.title('Top-20 Tranco Domains labeled as phishing in the top 100k')
for i,rect in enumerate(bbar):
    plt.text(rect.get_x() + rect.get_width() / 2.0, rect.get_height(), positions[i],ha='center', va='bottom')

plt.tight_layout()
plt.savefig(PA.pathIntermediateData+'Top20outoftop100kTranco.png')

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

# fullpath=PA.pathIntermediateData+'featuresTrancoFP.pk'
# with open(fullpath, 'wb') as f:
#     pickle.dump(X_benignFP, f, pickle.HIGHEST_PROTOCOL)
# X_benignFP=[]

fullpath=PA.pathIntermediateData+'featuresAndProbMisClfTrancoFP.pk'
with open(fullpath, 'wb') as f:
    pickle.dump(BenignFPdict, f, pickle.HIGHEST_PROTOCOL)
BenignFPdict=dict()