import sys
from serial_comm import SerialComm
from ssl_socket_wrapper import SSLSocketWrapper


def usage():
  print "Usage: python ./server.py [port] [serial_device]"

if len(sys.argv) != 3:
  usage()
  sys.exit()
else:
  comm = SerialComm(sys.argv[2])
  socket = SSLSocketWrapper(int(sys.argv[1]))
  socket.listen()
