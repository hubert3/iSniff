#!/usr/bin/python
#
# SSL_Certificate_CN2.py [2011-08-03]
#
# Extract CN and subjectAltNames from the SSL certificate presented on a remote ip:port
#
# hubert(a)pentest.com

def getCertHostnames(host, port=443): #host is '1.2.3.4' or 'server.com'
	from M2Crypto import SSL, m2

	CNs = []
	subjectAltNames = []

	ctx = SSL.Context()
	c = SSL.Connection(ctx)
	
	try:
		c.connect((host, port))
	#Don't care about any errors whatsoever we just want the certificate
	except:
		pass 
	cert = c.get_peer_cert()
	
	#Using del since close hung sometimes. May leak but the script only runs for 1 host at a time.
	del c 
	
	try:
		#See https://eresearch.jcu.edu.au/wiki/browser/SrbPloneProduct/trunk/Products/SRBContent/Checker.py?rev=3945
		for entry in cert.get_subject().get_entries_by_nid(m2.NID_commonName):
			CN = entry.get_data().as_text()
			CNs.append(CN)
	
		subjectAltName = cert.get_ext('subjectAltName').get_value()
		for certHost in subjectAltName.split(','):
			certHost = certHost.lower().strip()
			if certHost[:4] == 'dns:':
				AltName = certHost[4:]
				subjectAltNames.append(AltName)
	except:
		pass

	printedNames = set()
	uniqueNames = []
	for name in CNs+subjectAltNames:
		if name not in printedNames: #avoid printing duplicate names
			uniqueNames.append(name)
			printedNames.update([name])
	return(uniqueNames)
	
if __name__ == "__main__":
	import sys
	if len(sys.argv) == 2:
		result = getCertHostnames(sys.argv[1],443)
	elif len(sys.argv) == 3:
		result = getCertHostnames(sys.argv[1],int(sys.argv[2]))
	else:
		print './SSL_Certificate_CN2.py <hostname|ip> [port]'
		sys.exit(1)
	for name in result:
		print name
