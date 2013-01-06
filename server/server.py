import sys
from serial_comm import SerialComm

def usage():
  print "Usage: python ./server.py [port] [serial_device]"

if len(sys.argv) != 3:
  usage()
  sys.exit()
else:
  comm = SerialComm(sys.argv[2])
