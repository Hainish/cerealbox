import sys
import os
from ssl_client_wrapper import SSLClientWrapper
from sniffer import Sniffer

class Client():

  @staticmethod
  def usage():
    print "Usage: python ./client.py HOST PORT NET_DEVICE IPADDR PASSWORD [DNS]"

  def __init__(self, host, port, net_device, my_ipaddr, password, dns):
    self.host = host
    self.port = port
    self.net_device = net_device
    self.my_ipaddr = my_ipaddr
    self.password = password
    self.dns = dns

  def new_connection_handler(self, code, rmac, rip, rport, cc, cont):
    push_arr = [
      str(code),
      Sniffer.mac_to_hex(rmac),
      Sniffer.ip_to_hex(rip),
      Sniffer.port_to_hex(rport),
      cc,
      cont
    ]
    self.client.writeln(",".join(push_arr))

  def start(self):
    self.client = SSLClientWrapper()
    self.client.start(self.host, self.port, self.password)

    sniffer = Sniffer()
    sniffer.set_new_connection_handler(self.new_connection_handler)
    sniffer.sniff(self.net_device, self.my_ipaddr, self.dns)

if len(sys.argv) != 6:
  Client.usage()
  sys.exit()
if not os.geteuid()==0:
  sys.exit("root permission is required to listen on network interface.")

c = None

if len(sys.argv) == 6:
  c = Client(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], False)
if len(sys.argv) == 7 and sys.argv[6] == "DNS":
  c = Client(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], True)

c.start()
