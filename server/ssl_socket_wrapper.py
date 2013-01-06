import socket, ssl

class SSLSocketWrapper():
  def __init__(self, port):
    self.bindsocket = socket.socket()
    self.bindsocket.bind(('localhost', port))

  def listen(self):
    self.bindsocket.listen(0)
