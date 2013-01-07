import sys
from serial_comm import SerialComm
from ssl_socket_wrapper import SSLSocketWrapper

if len(sys.argv) != 3:
  Server.usage()
  sys.exit()

class Server():
  comm = None

  @staticmethod
  def usage(self):
    print "Usage: python ./server.py [port] [serial_device]"

  def __init__(self, port, serial_device):
    self.port = port
    self.serial_device = serial_device

  def message_handler(self, message):
    self.comm.writeln(message)

  def disconnect_handler(self, addr):
    print "Disconnect from "+addr
    self.comm.close()
    self.comm = SerialComm(self.serial_device)

  def connect_handler(self, addr):
    print "New connection from "+addr

  def start(self):
    self.comm = SerialComm(self.serial_device)
    socket = SSLSocketWrapper(int(self.port))
    socket.set_message_handler(self.message_handler)
    socket.set_connect_handler(self.connect_handler)
    socket.set_disconnect_handler(self.disconnect_handler)
    socket.listen()

s = Server(sys.argv[1], sys.argv[2])
s.start()
