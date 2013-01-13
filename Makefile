server-cert:
	mkdir server/ssl
	echo Generating new RSA server key...
	openssl genrsa -out server/ssl/server.key 4096 2> /dev/null
	echo Generating new certificate signing request...
	yes "" | openssl req -new -key server/ssl/server.key -out server/ssl/server.csr 2> /dev/null
	echo Self-signing certificate...
	openssl x509 -req -days 99999 -in server/ssl/server.csr -signkey server/ssl/server.key -out server/ssl/server.crt 2> /dev/null
	echo
	echo Your server ssl certificate has been created. The next step is to copy the certificate in server/ssl/cerver.crt to the client file client/ssl/cert.crt
	echo
.SILENT: server-cert
