import sys
from serial_comm import SerialComm
from ssl_socket_wrapper import SSLSocketWrapper

comm = None

def usage():
  print "Usage: python ./server.py [port] [serial_device]"

def message_handler(message):
  comm.writeln(message)

if len(sys.argv) != 3:
  usage()
  sys.exit()
else:
  comm = SerialComm(sys.argv[2])
  socket = SSLSocketWrapper(int(sys.argv[1]))
  socket.set_message_handler(message_handler)
  socket.listen()
