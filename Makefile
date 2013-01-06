server-cert:
	mkdir server/ssl
	echo Generating new RSA server key...
	openssl genrsa -out server/ssl/server.key 4096 2> /dev/null
	echo Generating new certificate signing request...
	yes "" | openssl req -new -key server/ssl/server.key -out server/ssl/server.csr 2> /dev/null
	echo Self-signing certificate...
	openssl x509 -req -days 99999 -in server/ssl/server.csr -signkey server/ssl/server.key -out server/ssl/server.crt 2> /dev/null
	echo
	echo Your server ssl certificate has been created. Below are the certificate fingerprints.
	echo Please note these fingerprints, as you will be asked to verify them on the client side.
	openssl x509 -sha1 -in server/ssl/server.crt -noout -fingerprint
	openssl x509 -sha256 -in server/ssl/server.crt -noout -fingerprint
	echo
.SILENT: server-cert
