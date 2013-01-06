import socket, ssl

def placeholder():
  pass

class SSLSocketWrapper():
  def __init__(self, port):
    self.bindsocket = socket.socket()
    self.bindsocket.bind(('localhost', port))
    self.message_handler = placeholder
    self.disconnect_handler = placeholder

  def set_message_handler(self, message_handler):
    self.message_handler = message_handler

  def set_disconnect_handler(self, disconnect_handler):
    self.disconnect_handler = disconnect_handler

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
        self.disconnect_handler()
