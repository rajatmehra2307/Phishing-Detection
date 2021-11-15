import re

from domain_feature_extractor import getDomainNameFromUrl

regex = "((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

def getUrlLength(url):
	return len(str(url))

def containsIp(url):
	domain = getDomainNameFromUrl(url)
	result = re.match(regex, domain)
	if result:
		print("Valid IP")
	else:
		print("Invalid IP")
