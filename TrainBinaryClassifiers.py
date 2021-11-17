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
from sklearn.model_selection import cross_val_score
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score, plot_confusion_matrix, roc_curve, auc
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import pandas as pd
import os
import sys
import gzip
import joblib
import pathsToSave as PA


import MODULE # with function COMPUTE_FEATURES()



dictBinaryLabels={1:'phishy',-1:'benign'}   

# Load the python lists with phishing and benign URLs/domains


tempArray=np.load(PA.pathPhishing)
PhishingList=tempArray.tolist()
tempArray=np.load(PA.pathBenign)
BenignList=tempArray.tolist()

# Remove duplicates

PhishingList=list(set(PhishingList))
BenignList=list(set(BenignList))

# Balance the datasets

tolerance=1.2

Tm=math.ceil(tolerance*len(PhishingList))
if len(BenignList)>Tm:
	random.shuffle(BenignList)
	BenignList=BenignList[0:Tm]
elif len(PhishingList)> (tolerance*len(BenignList)):
	random.shuffle(PhishingList)
	PhishingList=PhishingList[0:math.ceil(tolerance*len(BenignList))]

# At this point both training lists are balanced and ready for feature extraction

# Train the Binary Classifier

xTRUE=COMPUTE_FEATURES(PhishingList)
yTRUE=[1]*len(xTRUE)

xBenign=COMPUTE_FEATURES(BenignList)
yBenign=[-1]*len(xBenign)


xTRUE.extend(xBenign)
yTRUE.extend(yBenign)

xTRUE=np.asarray(xTRUE)
yTRUE=np.asarray(yTRUE)


X_train, X_test, y_train, y_test=train_test_split(xTRUE, yTRUE, test_size=0.2, random_state=13)
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# 1)           KNN Classifier
AccuracyScores=[]
for kneighbors in range(5,15,3): #5,8,11,14
    KNN = KNeighborsClassifier(n_neighbors=kneighbors, weights='uniform',n_jobs=5)
    # Choose optimal K using 3-fold cross-validation
    scores = cross_val_score(KNN, X_train, y_train, cv=3)
    AccuracyScores.append(scores.mean())
Kopt=int((3* AccuracyScores.index(max(AccuracyScores)) )+5)

# Fit the Binary classifier with the computed optimal value 
binclf=KNeighborsClassifier(n_neighbors=Kopt, weights='uniform',n_jobs=5).fit(X_train,y_train)
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# 2)           Random Forest
# binclf=ensemble.RandomForestClassifier(n_jobs=5).fit(X_train,y_train) # n_jobs: -1 implies using all processors.
# 3)          AdaBoostClassifier
# binclf=ensemble.AdaBoostClassifier(n_estimators=200).fit(X_train,y_train)
# 4)         Logistic Regression
# binclf= LogisticRegression(random_state=0).fit(X_train,y_train)
# 5)                SVM
# binclf = CalibratedClassifierCV(SVC()).fit(X_train,y_train)
# or binclf=SVC(probability=True).fit(X_train, y_train)
# 6)            Gaussian Naive Bayes
# binclf= GaussianNB().fit(X_train,y_train)
# 7)         Multi-Layer Perceptron Classifier
# binclf=MLPClassifier(alpha=1, max_iter=1000).fit(X_train,y_train)
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@


# PATH to save the model
# !!!!!!!!!! Change File Name along with CLASSIFIER !!!!!!!!!!!
# #MLP' #KNN'   #SVM' #LogisticRegressionBinsClfs' #GaussianNBClfs'   # RandomForestBinClfs'
if not os.path.exists(PA.saveBPATH):
    os.makedirs(PA.saveBPATH)

# After evaluation on the test set we are going to retrain the final Classifier on the ENTIRE dataset


# Evaluation

# Prediction in the validation
y_predicted=binclf.predict(X_test) # the true labels are: y_test
prob_y_predicted=binclf.predict_proba(X_test)

# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
# Calculations  $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

acc=accuracy_score(y_test, y_predicted)
# partial AUC at cutoff 10%
max_fpr = 0.10 # This refers to benign URLs labeled as "phishy". We want this rate to be up-to 10% to be acceptable.
pauc10 = roc_auc_score(y_test, prob_y_predicted[:,1], max_fpr=max_fpr)

# Compute distributions of probabilities
Lprob0=[] # -1:'benign'
Lprob1=[] # 1:malicious'=positive!
for gg in range(prob_y_predicted.shape[0]): # n_samples
        if prob_y_predicted[gg,0]>prob_y_predicted[gg,1]:
            Lprob0.append(prob_y_predicted[gg,0])
        else:
            Lprob1.append(prob_y_predicted[gg,1])

fpr, tpr, thresholds = roc_curve(y_test, prob_y_predicted[:,1], pos_label=1) # type(fpr): np.ndarray , fpr.shape : (n_samples+1,)

# 90% Detection Accuracy
min_mal_detection_rate = 0.90
th_idx = np.where(tpr >= min_mal_detection_rate)[0][0]
detect_th = thresholds[th_idx]
detect_labels = np.array([0]*len(y_test))
detect_labels[np.where(prob_y_predicted[:,1] >= detect_th)] = 1
detect_acc = accuracy_score(y_test, detect_labels)
    
# Want to plot partial ROC
fprpartial=[]
tprpartial=[]
for indexx in range(len(tpr)):
        if fpr[indexx]<= max_fpr:
            fprpartial.append(fpr[indexx])
            tprpartial.append(tpr[indexx])

# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

# Report its performance
# To save the results in a text file!!
Textfile=gzip.open(PA.txtfilename,"wt")
temptext="Classification Report\n\n"
Textfile.write(temptext)
temptext=classification_report(y_test, y_predicted, target_names=['benign','phishy'])
Textfile.write(temptext)
temptext='\n\n##################################################################\n\n'
Textfile.write(temptext)
temptext='\nAccuracy Score for the Binary Classifier is the following: '+str( acc  )+'\n\n'
Textfile.write(temptext)
areaROC=roc_auc_score(y_test, prob_y_predicted[:,1])
temptext='\nArea Under the ROC for the Binary Classifier is the following: '+str(areaROC)+'\n\n'
Textfile.write(temptext)
temptext='\nPartial Area Under the ROC at '+str(max_fpr*100)+'% FPR cut-off for the Binary Classifier is the following: '+str(pauc10)+'\n\n'
Textfile.write(temptext)
temptext="\nMeasuring accuracy at "+str(min_mal_detection_rate*100)+"% detection rate. Detection thershold= "+str(detect_th)+" . Detection Accuracy: "+str(detect_acc)+"\n\n"
Textfile.write(temptext)
####################################################
Textfile.close()



# Save the ROC curve
plt.figure()
plt.plot(fpr, tpr, color='darkorange',lw=2, label='ROC curve (area = %0.4f)' % areaROC)
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
roctitle='Receiver Operating Characteristic for the Binary Classifier'
plt.title(roctitle)
plt.legend(loc="lower right")
plt.savefig(PA.savepathROC)



#Save the Confusion Matrix
labelsCM=['benign','phishy']
disp = plot_confusion_matrix(binclf, X_test, y_test, display_labels=labelsCM,cmap=plt.cm.Blues,normalize='true')
disp.ax_.set_title('Normalized Confusion Matrix')
print('Normalized Confusion Matrix')
print(disp.confusion_matrix)
plt.savefig(PA.savepathCM)


# Fit the Binary classifier ON the ENTIRE dataset
print("Training on the entire dataset!\n")
# Choose the corresponding model 
# 1)                  KNN
binclf=KNeighborsClassifier(n_neighbors=Kopt, weights='uniform',n_jobs=5).fit(xTRUE,yTRUE)
# 2)           Random Forest
# binclf=ensemble.RandomForestClassifier(n_jobs=5).fit(xTRUE,yTRUE) # n_jobs: -1 implies using all processors.
# 3)          AdaBoostClassifier
# binclf=ensemble.AdaBoostClassifier(n_estimators=200).fit(xTRUE,yTRUE)
# 4)         Logistic Regression
# binclf= LogisticRegression(random_state=0).fit(xTRUE,yTRUE)
# 5)                SVM
# binclf = CalibratedClassifierCV(SVC()).fit(xTRUE,yTRUE)
# or binclf=SVC(probability=True).fit(xTRUE,yTRUE)
# 6)            Gaussian Naive Bayes
# binclf= GaussianNB().fit(xTRUE,yTRUE)
# 7)         Multi-Layer Perceptron Classifier
# binclf=MLPClassifier(alpha=1, max_iter=1000).fit(xTRUE,yTRUE)


#Save the final model
joblib.dump(binclf,PA.pathFinalModel)
