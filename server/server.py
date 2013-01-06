import sys
from serial_comm import SerialComm
from ssl_socket_wrapper import SSLSocketWrapper

comm = None

def usage():
  print "Usage: python ./server.py [port] [serial_device]"

def message_handler(message):
  comm.writeln(message)

def disconnect_handler():
  comm.close()

if len(sys.argv) != 3:
  usage()
  sys.exit()
else:
  comm = SerialComm(sys.argv[2])
  socket = SSLSocketWrapper(int(sys.argv[1]))
  socket.set_message_handler(message_handler)
  socket.set_disconnect_handler(disconnect_handler)
  socket.listen()
