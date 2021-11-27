#!/usr/bin/python3

import networkx as nx
from numpy.lib.function_base import vectorize
import pandas as pd
import seaborn as sns
import pickle
import os
import numpy as np
import matplotlib.pyplot as plt
import sys 
import time
plt.switch_backend('agg')
import tensorflow.keras 
from tensorflow.keras import layers, models

# Activate the corresponding virtual environment
# conda env list
# os.system('conda activate tensorflow2_latest_p37')
# ...
# os.system('conda deactivate') 


np.warnings.filterwarnings('ignore', category=np.VisibleDeprecationWarning)                 

def vectorize_sequences(sequences,dimensions=10000):
    results=np.zeros((len(sequences),dimensions))
    for i,seq in enumerate(sequences):
        results[i,seq]=1.
    return results

# Preprocess data
from tensorflow.keras.datasets import imdb
(train_data,train_labels),(test_data,test_labels)=imdb.load_data(num_words=10000)

train_data=vectorize_sequences(train_data)
test_data=vectorize_sequences(test_data)
train_labels=np.asarray(train_labels).astype('float32')
test_labels=np.asarray(test_labels).astype('float32')
# End of data preprocessing

def BinaryClassifier(intermediate_layers=3, units=128,  input_shape=train_data.shape[1:] ):
    ''' intermediate_layers argument does not include the last, output, layer 
    '''
    mymodel=models.Sequential()
    mymodel.add( layers.Dense( units, activation='relu', input_shape=input_shape)  ) 
    for i in range(1,intermediate_layers):
        mymodel.add(layers.Dense(units, activation='relu'))
    # Output Layer
    mymodel.add(layers.Dense(1,activation='sigmoid'))
    # Compilation
    mymodel.compile(optimizer='rmsprop',loss='binary_crossentropy', metrics=['accuracy'])
    return mymodel

# Model Architecture & Compilation
mymodel=BinaryClassifier()
# Training and Validation 
x_val=train_data[:1000]  
x_train_final=train_data[1000:]
y_val=train_labels[:1000]
y_train_final=train_labels[1000:]

history=mymodel.fit(x_train_final, y_train_final, epochs=20, batch_size=512, validation_data=(x_val,y_val))
history_dict=history.history
# print(history_dict.keys()) ['loss', 'accuracy', 'val_loss', 'val_accuracy']

# Loss is the objective function we want to minimize in the validation data
loss_values=history_dict['loss']
val_loss_values=history_dict['val_loss']
optK=np.argmin(val_loss_values)+1
if optK<5:
    optK+=1
epochs=range(1,len(loss_values)+1)
print("\nMinimum VALIDATION loss value achieved for "+str(optK)+" number of epochs during training.\n")
# Metric: Accuracy
acc_values=history_dict["accuracy"]
val_acc_values=history_dict["val_accuracy"]



plt.figure()
plt.plot(epochs,loss_values,'bo',label='Training loss')
plt.plot(epochs,val_loss_values,'b',label='Validation loss')
plt.title('Training and Validation Loss')
plt.xlabel('Epochs')
plt.ylabel('Loss')
plt.legend()
wheretosave='/home/ubuntu/code/results/imdb_LOSS_TrainValidation.png'
plt.savefig(wheretosave)

plt.figure()
plt.plot(epochs,acc_values, 'bo', label='Training Accuracy')
plt.plot(epochs, val_acc_values, 'b', label='Validation Accuracy')
plt.title('Accuracy for Training and Validation Datasets')
plt.xlabel('Epochs')
plt.ylabel('Accuracy')
plt.legend()
wheretosave='/home/ubuntu/code/results/imdb_ACCURACY_TrainValidation.png'
plt.savefig(wheretosave)

# Train on the whole dataset:
final=mymodel.fit(train_data, train_labels, epochs=optK, batch_size=512)
Perfromance=final.history
print('\nModel trained on the whole dataset\n\n')
print('\nMean Training Accuracy: '+str(np.mean(Perfromance['accuracy']))+' and Mean Training Loss: '+str(np.mean(Perfromance['loss']))+'\n')

# Evaluate performance on test set
results=mymodel.evaluate(test_data, test_labels)
print('\nResults on test set (Loss Value, Accuracy): ')
print(results)


# model.save() or tf.keras.models.save_model()
# tf.keras.models.load_model()
wheretosave='/home/ubuntu/code/results/BinaryClassifierIMDB'
mymodel.save(wheretosave)

# loaded_model = tensorflow.keras.models.load_model("my_model")


# if __name__ == '__main__':
#     start_time=time.time()
#     BinaryClassifier()
#     elapsedtime=time.time()- start_time

