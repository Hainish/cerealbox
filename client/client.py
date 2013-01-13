import sys
import inspect
from ssl_client_wrapper import SSLClientWrapper
from sniffer import Sniffer

class Client():

  @staticmethod
  def usage():
    print "Usage: python ./client.py HOST PORT NET_DEVICE SRC_IPADDR PASSWORD"

  def __init__(self, host, port, net_device, src_ipaddr, password):
    self.host = host
    self.port = port
    self.net_device = net_device
    self.src_ipaddr = src_ipaddr
    self.password = password

  def new_connection_handler(self, connection):
    pass

  def start(self):
    client = SSLClientWrapper()
    client.start(self.host, self.port, self.password)

if len(sys.argv) != 6:
  Client.usage()
  sys.exit()

c = Client(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
c.start()
