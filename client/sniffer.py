import pcapy
import impacket.ImpactDecoder
import impacket.ImpactPacket
import geocode
from datetime import datetime
import multiprocessing
import threading
import time
import sys

SNAPLEN = 90
PROMISC_MODE = 0
TO_MS = 15

class Sniffer():
  def __init__(self):
    self.decoder = impacket.ImpactDecoder.EthDecoder() 
    self.udp_db = {}
    self.tcp_db = {}
    self.numopen = 0
    self.numclose = 0


  def set_new_connection_handler(self, new_connection_handler):
    self.new_connection_handler = new_connection_handler


  def sniff(self, net_device, my_ipaddr, dns):
    self.my_ipaddr = my_ipaddr

    self.reader = None

    # create reader object
    try:
      self.reader = pcapy.open_live(net_device, SNAPLEN, PROMISC_MODE, TO_MS) 
    except Exception, e:
      print "Could not open device '%s' for sniffing. Error: %s" % (net_device, str(e))

    # filter based on dns settings
    try:
      if dns:
        self.reader.setfilter("(tcp or udp) and host "+my_ipaddr)
      else:
        self.reader.setfilter("(tcp or (udp and not port 53)) and host "+my_ipaddr)
    except Exception, e:
      print "Could not filter packets. Error: %s" % (str(e))

    # start listening
    self.loop_process = multiprocessing.Process(name='sniffing', target=self._start_sniffing)
    self.loop_process.start()

    self._keyboard_interrupt()


  def _start_sniffing(self):
    t = threading.Thread(name='regular_timeout_check', target=self._regular_timeout_check)
    t.start()

    self.reader.loop(-1, self.packet_received)


  def _regular_timeout_check(self):
    while True:
      time.sleep(10)

      now = datetime.now()
      print "Open connections:"
      print "TCP"
      for lport in self.tcp_db:
        if self.tcp_db[lport]['close'] == 0:
          if (now - self.tcp_db[lport]['time']).total_seconds() > 60:
            print "timeout "+self.tcp_db[lport]['rip']
            self.s_close(lport)
          else:
            print_arr = [
              Sniffer.mac_to_hex(self.tcp_db[lport]['rmac']),
              Sniffer.ip_to_hex(self.tcp_db[lport]['rip']),
              Sniffer.port_to_hex(self.tcp_db[lport]['rport']),
              self.tcp_db[lport]['cc'],
              self.tcp_db[lport]['cont']
            ]
            print_str = ",".join(print_arr)
            print print_str
      print "UDP"
      for lport in self.udp_db:
        if self.udp_db[lport]['close'] == 0:
          if (now - self.udp_db[lport]['time']).total_seconds() > 20:
            self.u_close(lport)
          else:
            print_arr = [
              Sniffer.mac_to_hex(self.udp_db[lport]['rmac']),
              Sniffer.ip_to_hex(self.udp_db[lport]['rip']),
              Sniffer.port_to_hex(self.udp_db[lport]['rport']),
              self.udp_db[lport]['cc'],
              self.udp_db[lport]['cont']
            ]
            print_str = ",".join(print_arr)
            print print_str


  def _keyboard_interrupt(self):
    try:
      while True:
        pass
    except KeyboardInterrupt:
      self.loop_process.terminate()
      sys.exit()


  def packet_received(self, hdr, data):
    src_ip = None
    dst_ip = None
    proto_id = None

    layer4 = None
    layer2 = None

    # decode packet
    try:
      layer2 = self.decoder.decode(data)
    except (Exception, impacket.ImpactPacket.ImpactPacketException), e:
      print "Could not decode packet: %s" % (str(e))
    try:
      src_ip = layer2.child().get_ip_src()
      dst_ip = layer2.child().get_ip_dst()
      layer4 = layer2.child().child()
      proto_id = layer4.protocol
      #print "IP SRC: "+str(src_ip)+" ("+self.ip_to_hex(str(src_ip))+") DST: "+str(dst_ip)+" ("+self.ip_to_hex(str(dst_ip))+") PROTO: "+str(proto_id)
    except Exception, e:
      print "Exception parsing packet. Error: %s" % (str(e))
    
    lport = None
    rport = None
    rmac = None
    rip = None

    #upd or tcp
    if proto_id == 17 or proto_id == 6:
      if dst_ip == self.my_ipaddr:
        rmac = layer2.get_ether_shost()
        rip = src_ip
      else:
        rmac = layer2.get_ether_dhost()
        rip = dst_ip

    #udp packet
    if proto_id == 17:

      if dst_ip == self.my_ipaddr:
        lport = layer4.get_uh_dport()
        rport = layer4.get_uh_sport()
      else:
        lport = layer4.get_uh_sport()
        rport = layer4.get_uh_dport()

      if lport in self.udp_db:
        if self.udp_db[lport]['close'] == 0:
          self.udp_db[lport]['time'] = datetime.now()
        else:
          self.u_open(lport, rmac, rip, rport)
      else:
        self.u_open(lport, rmac, rip, rport)

    #tcp packet
    if proto_id == 6:

      if dst_ip == self.my_ipaddr:
        lport = layer4.get_th_dport()
        rport = layer4.get_th_sport()
      else:
        lport = layer4.get_th_sport()
        rport = layer4.get_th_dport()

      fin = layer4.get_FIN()
      syn = layer4.get_SYN()
      ack = layer4.get_ACK()
      rst = layer4.get_RST()

      # if a fin or rst is received, close connection
      if fin or rst:
        self.s_close(lport)
      # After we see RST/FIN on a source port, it can only be reopened using SYN+ACK
      elif syn and ack:
        if lport in self.tcp_db:
          if self.tcp_db[lport]['close'] == 1:
            self.s_open(lport, rmac, rip, rport)
        else:
          self.s_open(lport, rmac, rip, rport)
      # Otherwise see if connection exists and create if it doesn't
      # Only do this if sport hasn't been used before
      else:
        # If connection is open, update time
        if lport in self.tcp_db:
          if self.tcp_db[lport]['close'] == 0:
            self.tcp_db[lport]['time'] = datetime.now()
        else:
          self.s_open(lport, rmac, rip, rport)

  
  def u_open(self, lport, rmac, rip, rport):
    cc, cont = geocode.lookup(rip)
    cc = cc if cc else "LL"
    cont = cont if cont else "--"
    self.numopen += 1
    self.new_connection_handler(1, rmac, rip, rport, cc, cont)
    self.udp_db[lport] = {
        'cc': cc,
        'cont': cont,
        'rmac': rmac,
        'rip': rip,
        'rport': rport,
        'close': 0,
        'time': datetime.now()
    }


  def u_close(self, lport):
    if lport in self.udp_db:
      self.numclose += 1
      self.new_connection_handler(
          2,
          self.udp_db[lport]['rmac'],
          self.udp_db[lport]['rip'],
          self.udp_db[lport]['rport'],
          self.udp_db[lport]['cc'],
          self.udp_db[lport]['cont'],
      )
      self.udp_db[lport]['close'] = 1



  def s_open(self, lport, rmac, rip, rport):
    cc, cont = geocode.lookup(rip)
    cc = cc if cc else "LL"
    cont = cont if cont else "--"
    self.numopen += 1
    self.new_connection_handler(1, rmac, rip, rport, cc, cont)
    self.tcp_db[lport] = {
        'cc': cc,
        'cont': cont,
        'rmac': rmac,
        'rip': rip,
        'rport': rport,
        'close': 0,
        'time': datetime.now()
    }

  
  def s_close(self, lport):
    if lport in self.tcp_db:
      if self.tcp_db[lport]['close'] == 0:
        self.numclose += 1
        self.new_connection_handler(
            2,
            self.tcp_db[lport]['rmac'],
            self.tcp_db[lport]['rip'],
            self.tcp_db[lport]['rport'],
            self.tcp_db[lport]['cc'],
            self.tcp_db[lport]['cont'],
        )
        self.tcp_db[lport]['close'] = 1

      
  @staticmethod
  def ip_to_hex(ip):
    ip_s = ip.split(".")
    hex = "%02X%02X%02X%02X" % (int(ip_s[0]),int(ip_s[1]),int(ip_s[2]),int(ip_s[3]))
    return hex

  @staticmethod
  def mac_to_hex(mac):
    hex = "%02X%02X%02X%02X%02X%02X" % tuple(mac)
    return hex

  @staticmethod
  def port_to_hex(port):
    port = "%04X" % (port)
    return port
