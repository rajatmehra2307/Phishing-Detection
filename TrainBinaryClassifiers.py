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
import matplotlib.pyplot as plt
import pandas as pd
import os
import sys
import gzip
import joblib
import json
import pathsToSave as PA

dictBinaryLabels={1:'phishy',0:'benign'}   

# Load the python lists with phishing and benign features of URLs

tempArray=np.load(PA.pathPhishURLs)
PhishingList=tempArray.tolist()
tempArray=np.load(PA.pathTrancoURLs)
BenignList=tempArray.tolist()

# Balance the benign and phishing datasets
tempArray=np.load(PA.pathPhishing)
xTRUE=tempArray.tolist()
tempArray=np.load(PA.pathBenign)
xBenign=tempArray.tolist()

# tolerance=1.2
# Tm=math.ceil(tolerance*len(xTRUE))
# if len(xBenign)>Tm:  # 33,499 > (11,722 * 1.2 ->ceil= 14,067)
# 	# random.shuffle(BenignList)
# 	xBenign=xBenign[0:Tm]
# elif len(xTRUE)> (tolerance*len(xBenign)):
# 	random.shuffle(xTRUE)
# 	xTRUE=xTRUE[0:math.ceil(tolerance*len(xBenign))]
xBenignEval=xBenign[14067:] # Interested in calculating False Positive, i.e Benign domains characterized as positive (phishy) by our algorithm
xBenign=xBenign[:14067]

# At this point both training lists are balanced (with tolerance of 20%) and ready for training

# Train the Binary Classifier

yTRUE=[1]*len(xTRUE)

yBenign=[0]*len(xBenign)


xTRUE.extend(xBenign)
yTRUE.extend(yBenign)

xTRUE=np.asarray(xTRUE)
yTRUE=np.asarray(yTRUE)


X_train, X_test, y_train, y_test=train_test_split(xTRUE, yTRUE, test_size=0.2, random_state=13)

# Directory to save the models
if not os.path.exists(PA.saveBPATH):
    os.makedirs(PA.saveBPATH)
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

def trainBinClf(CLFname):
    AccuracyScores=[]
    if CLFname=="KNN":
        Fname='k-Nearest-Neighbors'
        # 1)           KNN Classifier
        for kneighbors in range(5,15,3): #5,8,11,14
            KNN = KNeighborsClassifier(n_neighbors=kneighbors, weights='uniform',n_jobs=5)
            # Choose optimal K using 10-fold cross-validation
            scores = cross_val_score(KNN, X_train, y_train, cv=10)
            AccuracyScores.append(scores.mean())
        Kopt=int((3* AccuracyScores.index(max(AccuracyScores)) )+5)

        # Fit the Binary classifier with the computed optimal value 
        binclf=KNeighborsClassifier(n_neighbors=Kopt, weights='uniform',n_jobs=5).fit(X_train,y_train)
    # @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    elif CLFname=="RF":
        Fname='Random Forest'
        # 2)           Random Forest
        binclf=ensemble.RandomForestClassifier(n_jobs=5).fit(X_train,y_train) # n_jobs: -1 implies using all processors.
    elif CLFname=="Ada":
        Fname='Adaboost'
        # 3)          AdaBoostClassifier
        binclf=ensemble.AdaBoostClassifier(n_estimators=200).fit(X_train,y_train)
    elif CLFname=="LR":
        Fname='Logistic Regression'
        # 4)         Logistic Regression
        binclf= LogisticRegression(random_state=0).fit(X_train,y_train)
    elif CLFname=="SVM":    
        Fname='Support Vector Machine'
        # 5)                SVM
        binclf = CalibratedClassifierCV(SVC()).fit(X_train,y_train)
        # or binclf=SVC(probability=True).fit(X_train, y_train)
    elif CLFname=="gNB":
        Fname='Gaussian Naive Bayes'
        # 6)            Gaussian Naive Bayes
        binclf= GaussianNB().fit(X_train,y_train)
    elif CLFname=="MLP":
        Fname='Multilayer Perceptron'
        # 7)         Multi-Layer Perceptron Classifier
        binclf=MLPClassifier(alpha=1, max_iter=1000).fit(X_train,y_train)
    # @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

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
    txtfilename= PA.saveBPATH+CLFname+".txt.gz" 
    Textfile=gzip.open(txtfilename,"wt")
    temptext="Classification Report for "+Fname+"\n\n"
    Textfile.write(temptext)
    temptext=classification_report(y_test, y_predicted, target_names=['benign','phishy'])
    Textfile.write(temptext)
    temptext='\n\n##################################################################\n\n'
    Textfile.write(temptext)
    temptext='\nAccuracy Score for the '+Fname+' Binary Classifier is the following: '+str( acc  )+'\n\n'
    Textfile.write(temptext)
    areaROC=roc_auc_score(y_test, prob_y_predicted[:,1])
    temptext='\nArea Under the ROC for the '+Fname+' Binary Classifier is the following: '+str(areaROC)+'\n\n'
    Textfile.write(temptext)
    temptext='\nPartial Area Under the ROC at '+str(max_fpr*100)+'% FPR cut-off for the '+Fname+' Binary Classifier is the following: '+str(pauc10)+'\n\n'
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
    roctitle='Receiver Operating Characteristic for the '+CLFname+' Binary Classifier'
    plt.title(roctitle)
    plt.legend(loc="lower right")
    savepathROC=PA.saveBPATH+'ROC_plot_'+CLFname+'.png'   #  NEEDS to be defined !!!!!!!!!!
    plt.savefig(savepathROC)



    #Save the Confusion Matrix
    labelsCM=['benign','phishy']
    disp = plot_confusion_matrix(binclf, X_test, y_test, display_labels=labelsCM,cmap=plt.cm.Blues,normalize='true')
    htitle='Normalized Confusion Matrix - '+CLFname
    disp.ax_.set_title(htitle)
    print(htitle)
    print(disp.confusion_matrix)
    savepathCM=PA.saveBPATH+'confusion_matrix_'+CLFname+'.png'
    plt.savefig(savepathCM)


    # Fit the Binary classifier ON the ENTIRE dataset
    print("Training on the entire dataset!\n")
    if CLFname=="KNN":
        # 1)                  KNN
        binclf=KNeighborsClassifier(n_neighbors=Kopt, weights='uniform',n_jobs=5).fit(xTRUE,yTRUE)
    elif CLFname=="RF":
        # 2)           Random Forest
        binclf=ensemble.RandomForestClassifier(n_jobs=5).fit(xTRUE,yTRUE) # n_jobs: -1 implies using all processors.
    elif CLFname=="Ada":
        # 3)          AdaBoostClassifier
        binclf=ensemble.AdaBoostClassifier(n_estimators=200).fit(xTRUE,yTRUE)
    elif CLFname=="LR":
        # 4)         Logistic Regression
        binclf= LogisticRegression(random_state=0).fit(xTRUE,yTRUE)
    elif CLFname=="SVM":
        # 5)                SVM
        binclf = CalibratedClassifierCV(SVC()).fit(xTRUE,yTRUE)
        # or binclf=SVC(probability=True).fit(xTRUE,yTRUE)
    elif CLFname=="gNB":
        # 6)            Gaussian Naive Bayes
        binclf= GaussianNB().fit(xTRUE,yTRUE)
    elif CLFname=="MLP":
        # 7)         Multi-Layer Perceptron Classifier
        binclf=MLPClassifier(alpha=1, max_iter=1000).fit(xTRUE,yTRUE)
    #Save the final model
    pathFinalModel=PA.saveBPATH+CLFname+'BinaryClf.sav'
    joblib.dump(binclf,pathFinalModel)


#     example:
#         ./TrainBinaryClassifiers.py  
if __name__ == '__main__':
    trainBinClf(CLFname="KNN")
    trainBinClf(CLFname="RF")
    trainBinClf(CLFname="Ada")
    trainBinClf(CLFname="LR")
    trainBinClf(CLFname="SVM")
    trainBinClf(CLFname="gNB")
    trainBinClf(CLFname="MLP")