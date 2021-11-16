import requests

phishing_url = "http://data.phishtank.com/data/online-valid.json"

request_headers = {
	'User-Agent': 'Test user agent'
}

resp = requests.get(phishing_url, headers=request_headers)

resp = resp.json()

phishing_dataset = []

phishing_label = 1

for val in resp:
	if val['verified'] == "yes":
		phishing_dataset.append({ 'url': val['url'], 'label': phishing_label} )

f = open('phish_dataset.txt', 'w')
print(phishing_dataset, file= f)

