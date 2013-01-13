import socket, ssl, sys

def placeholder():
  pass

class SSLClientWrapper():
  def __init__(self):
    self.connect_handler = placeholder

  def set_connect_handler(self, connect_handler):
    self.connect_handler = connection_handler

  def start(self, host, port, password):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.ssl_sock = ssl.wrap_socket(s,
      ca_certs="./ssl/cert.crt",
      cert_reqs=ssl.CERT_REQUIRED)

    try:
      self.ssl_sock.connect((host, int(port)))
    except ssl.SSLError, e:
      print "An SSL error has occurred:\n\n%s\n" % (str(e))
      print "Please make sure the certificate for your server (server/ssl/server.crt) is placed in client/ssl/cert.crt"
      sys.exit()
    self.ssl_sock.write(password+"\r\n")

  def writeln(self, line):
    self.ssl_sock.write(line+"\r\n")
