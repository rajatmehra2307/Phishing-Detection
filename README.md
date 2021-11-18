# Phishing-Detection

Contains code for feature extraction and the model used for classifying websites as phishing or benign


Notes:

1) The input to the classifier should be an numpy array (saved as benign.npy or phishing.npy)
which is derived from a python list of lists
where each list contains the 17 features of a URL. 
2) The scripts parsePhishTank.py, parseUnseen.py and parseTranco.py compute the 15 features I have found. 
Rajat added two more features whose computation have to be added in the scripts [Needs to be done]
3) The pathsToSave.py script defines the paths where several intermediate and final results are saved.
It needs to be initialized.  
