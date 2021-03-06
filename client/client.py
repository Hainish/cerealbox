import sys
import os
from ssl_client_wrapper import SSLClientWrapper
from sniffer import Sniffer
from datetime import datetime
from ssl import SSLError

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

  def new_connection_handler(self, code, lport, rmac, rip, rport, cc, cont):
    push_arr = [
      str(code),
      Sniffer.mac_to_hex(rmac),
      Sniffer.ip_to_hex(rip),
      Sniffer.port_to_hex(rport),
      cc,
      cont
    ]
    push = ",".join(push_arr)
    print push,
    print "(%s:%s <-> %s)" % (rip, rport, lport)
    self._write_to_client(push)

    curr = self.sniffer.numopen - self.sniffer.numclose
    print "close: %s open: %s, current: %s" % (str(self.sniffer.numclose), str(self.sniffer.numopen), str(curr))

  # in case both threads are writing at the same time
  def _write_to_client(self, push):
    try: 
      self.client.writeln(push)
    except SSLError:
      time.sleep(.1)
      self._write_to_client(push)

  def start(self):
    self.client = SSLClientWrapper()
    self.client.start(self.host, self.port, self.password)

    self.sniffer = Sniffer()
    self.sniffer.set_new_connection_handler(self.new_connection_handler)
    self.sniffer.sniff(self.net_device, self.my_ipaddr, self.dns)

if len(sys.argv) != 6 and len(sys.argv) != 7:
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
