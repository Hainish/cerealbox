import sys
from serial_comm import SerialComm
from ssl_socket_wrapper import SSLSocketWrapper

class Server():

  @staticmethod
  def usage():
    print "Usage: python ./server.py PORT SERIAL_DEVICE PASSWORD"

  def __init__(self, port, serial_device, password):
    self.port = int(port)
    self.serial_device = serial_device
    self.password = password

  def message_handler(self, message):
    self.comm.writeln(message)
    print "Got message: "+message

  def disconnect_handler(self, addr):
    print "Disconnect from "+addr
    self.comm.close()
    self.comm = SerialComm(self.serial_device)

  def connect_handler(self, addr):
    print "New connection from "+addr

  def start(self):
    self.comm = SerialComm(self.serial_device)
    socket = SSLSocketWrapper()
    socket.set_message_handler(self.message_handler)
    socket.set_connect_handler(self.connect_handler)
    socket.set_disconnect_handler(self.disconnect_handler)
    socket.start(self.port, self.password)

if len(sys.argv) != 4:
  Server.usage()
  sys.exit()

s = Server(sys.argv[1], sys.argv[2], sys.argv[3])
s.start()
