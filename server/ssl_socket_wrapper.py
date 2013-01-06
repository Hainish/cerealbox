import socket, ssl

class SSLSocketWrapper():
  def __init__(self, port):
    self.bindsocket = socket.socket()
    self.bindsocket.bind(('localhost', port))

  def set_message_handler(self, message_handler):
    self.message_handler = message_handler

  def listen(self):
    self.bindsocket.listen(0)
    while True:
      newsocket, fromaddr = self.bindsocket.accept()
      connstream = ssl.wrap_socket(newsocket,
        server_side=True,
        certfile="./ssl/server.crt",
        keyfile="./ssl/server.key",
        ssl_version=ssl.PROTOCOL_TLSv1)
      try:
        data = connstream.read()
        while data:
          self.message_handler(data)
          data = connstream.read()
      except ssl.SSLError, e:
        pass
      finally:
        connstream.shutdown(socket.SHUT_RDWR)
        connstream.close()
