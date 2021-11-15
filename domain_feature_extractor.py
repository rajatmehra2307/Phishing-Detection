import whois
import ssl,socket
from urllib.parse import urlparse

def getDomainNameFromUrl(url):
	return urlparse(url).hostname

def getDomainCreationDate(url):
	w = whois.whois(url)
	return w.creation_date

def getCertificateDate(url):
	hostname = getDomainNameFromUrl(str(url))
	context = ssl.create_default_context()
	context.check_hostname = False
	conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
	try:
		conn.connect((hostname, 443))
		cert = conn.getpeercert()
		return { 'issuedDate': cert['notBefore'], 'expiryDate': cert['notAfter'] }
	except Exception as e:
		print("The url doesn't have a valid certificate")

			

