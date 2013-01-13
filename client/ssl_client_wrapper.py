import socket, ssl

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
      cert_reqs=ssl.CERT_NONE)

    self.ssl_sock.connect((host, int(port)))
    self.ssl_sock.write(password+"\r\n")

  def writeln(self, line):
    self.ssl_sock.write(line+"\r\n")
