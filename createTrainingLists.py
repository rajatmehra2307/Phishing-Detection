#!/usr/bin/python3

import numpy as np
import math
import random
import os
import sys
import json
import pathsToSave as PA

# Read JSON from a file
def parse_features(filetoparse):
    # Identify "tranco" or "phish"
    R=filetoparse.strip().split("/")[-1]  # R='tranco_output_final.json' or "phish_output_final.json"
    if R.find("tranco") != -1 : 
        nn="tranco"
    elif R.find("phish") != -1:
        nn="phish"
    else:
        nn="XX"
    
    
    if os.path.exists(filetoparse):        
        with open(filetoparse) as f:
            data=json.loads("["+f.read().replace("}\n{", "},\n{")+"]")
    else:
        print("No data file exists!!!")
    # type(data)=<'list'>
    print('Number of elements in '+nn+" list is: "+str(len(data))+"\n")
    outputlist=[]
    urllist=[]
    for elem in data: # elem is type <'dict'>
        temp=[]
        # {'url': 'https://www.ama-premir-jp.acp-1.top/', 'url_length': 36, 'is_https': True, 'ip_in_url': False, 'num_external_images': 0, 'num_https_links': 0, 'num_images': 0, 'favicon_matches': True, 
        # 'has_trademark': False, 'days_since_creation': 2, 'days_since_last_update': 2, 'days_until_expiration': 362, 'days_until_cert_expiration': 87, 'num_links': 0, 'mean_link_length': None, 
        # 'num_shortened_urls': 0, 'num_double_slash_redirects': 0, 'url_entropy': 1.6644977792004616}
        for k in elem: 
            if k=='url':
                urllist.append(elem[k])
            if k=='url_length':
                if type(elem[k])==int :
                    temp.append(elem[k])
                else:
                    temp.append(int(0))
            if k=='is_https':
                if type(elem[k])==bool:
                    if elem[k]==True:
                        temp.append(int(1))
                    else:
                        temp.append(int(0))
                else: # type is 'NoneType'
                    temp.append(int(-1))
            if k=='ip_in_url':
                if type(elem[k])==bool:
                    if elem[k]==True:
                        temp.append(int(1))
                    else:
                        temp.append(int(0))
                else: # type is 'NoneType'
                    temp.append(int(-1))
            if k=='num_external_images':
                if type(elem[k])==int:
                    temp.append(elem[k])
                else:
                    temp.append(int(0))
            if k=='num_https_links':
                if type(elem[k])==int:
                    temp.append(elem[k])
                else:
                    temp.append(int(0))
            if k=='num_images':
                if type(elem[k])==int:
                    temp.append(elem[k])
                else:
                    temp.append(int(0))
            if k=='favicon_matches':
                if type(elem[k])==bool:
                    if elem[k]==True:
                        temp.append(int(1))
                    else:
                        temp.append(int(0))
                else: # type is 'NoneType'
                    temp.append(int(-1))
            if k=='has_trademark':
                if type(elem[k])==bool:
                    if elem[k]==True:
                        temp.append(int(1))
                    else:
                        temp.append(int(0))
                else: # type is 'NoneType'
                    temp.append(int(-1))
            if k=='days_since_creation':
                if type(elem[k])==int:
                    temp.append(elem[k])
                else:
                    temp.append(int(0))
            if k=='days_since_last_update':
                if type(elem[k])==int:
                    temp.append(elem[k])
                else:
                    temp.append(int(0))
            if k=='days_until_expiration':
                if type(elem[k])==int:
                    temp.append(elem[k])
                else:
                    temp.append(int(0))
            if k=='days_until_cert_expiration':
                if type(elem[k])==int:
                    temp.append(elem[k])
                else:
                    temp.append(int(0))
            if k=='num_links':
                if type(elem[k])==int:
                    temp.append(elem[k])
                else:
                    temp.append(int(0))
            if k=='mean_link_length':
                if type(elem[k])==float:
                    temp.append(elem[k])
                else:
                    temp.append(float(0))
            if k=='num_shortened_urls':
                if type(elem[k])==int:
                    temp.append(elem[k])
                else:
                    temp.append(int(0))
            if k=='num_double_slash_redirects':
                if type(elem[k])==int:
                    temp.append(elem[k])
                else:
                    temp.append(int(0))
            if k=='url_entropy':
                if type(elem[k])==float:
                    temp.append(elem[k])
                else:
                    temp.append(float(0))
        outputlist.append(temp)
    # Save the final list with list of features.
    # print(outputlist)
    savename=PA.pathIntermediateData+nn+'listoflistsoffeatures.npy'
    np.save(savename,outputlist)
    savename=PA.pathIntermediateData+nn+'listofURLs.npy'
    np.save(savename,urllist)

#     example:
#         ./createTrainingLists.py  
if __name__ == '__main__':
    parse_features(PA.pathJSONtranco)
    parse_features(PA.pathJSONphish)

