import sys, traceback
from feature_extractor import parse_args, main_single
from io import StringIO
import json
import numpy as np
import joblib
import pathsToSave as PA

def main(argv=None):
	if len(argv) < 2:
		print("Command usage: python3 <filename> <url>")
		return
	args = parse_args(['single', argv[1], '--active-html-download', '--active-whois-download', '--active-certificate-download', '--current-time'])
	try:
		result = StringIO()
		old_stdout = sys.stdout
		sys.stdout = result
		main_single(args)
		result_string = result.getvalue()
		sys.stdout = old_stdout
		result_json = json.loads(result_string)
		print((result_json))
		# del result_json['url']
		# features = []
		# for key in result_json:
		# 	features.append(False if result_json[key] == None else result_json[key])
		# x = np.array([features])
		# binclf=joblib.load('results/modelSelection/RFBinaryClf.sav') 
		# X_benign=np.asarray(x)
		# BenignProbabilities=np.zeros((1,2))
		# BenignProbabilities=binclf.predict_proba(X_benign)
		# if BenignProbabilities[0,0]-BenignProbabilities[0,1]<0.:
		# 	print("Phishing website")
		# else:
		# 	print("Benign website")	
	except:	
		traceback.print_exc(file=sys.stdout)
		return
	
if __name__ == '__main__':
    main(sys.argv)	