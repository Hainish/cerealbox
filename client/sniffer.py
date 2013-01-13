import pcapy
import impacket.ImpactDecoder
from datetime import datetime

SNAPLEN = 90
PROMISC_MODE = 0
TO_MS = 15

class Sniffer():
  def __init__(self):
    self.decoder = impacket.ImpactDecoder.EthDecoder() 
    self.udp_db = {}
    self.tcp_db = {}


  def set_new_connection_handler(self, new_connection_handler):
    self.new_connection_handler = new_connection_handler


  def sniff(self, net_device, my_ipaddr, dns):
    self.my_ipaddr = my_ipaddr

    p = None

    # create reader object
    try:
      p = pcapy.open_live(net_device, SNAPLEN, PROMISC_MODE, TO_MS) 
    except Exception, e:
      print "Could not open device '%s' for sniffing. Error: %s" % (net_device, str(e))

    # filter based on dns settings
    try:
      if dns:
        p.setfilter("(tcp or udp) and host "+my_ipaddr)
      else:
        p.setfilter("(tcp or (udp and not port 53)) and host "+my_ipaddr)
    except Exception, e:
      print "Could not filter packets. Error: %s" % (str(e))

    # start listening
    try:
      p.loop(-1, self.packet_received)
    except Exception, e:
      print "Could not sniff for device '%s'. Error: %s" % (net_device, str(e))


  def packet_received(self, hdr, data):
    src_ip = None
    dst_ip = None
    proto_id = None

    layer4 = None
    layer2 = None

    # decode packet
    try:
      layer2 = self.decoder.decode(data)
    except Exception, e:
      print "Could not decode packet: %s" % (str(e))
    try:
      src_ip = layer2.child().get_ip_src()
      dst_ip = layer2.child().get_ip_dst()
      layer4 = layer2.child().child()
      proto_id = layer4.protocol
      print "IP SRC: "+str(src_ip)+" ("+self.ip_to_hex(str(src_ip))+") DST: "+str(dst_ip)+" ("+self.ip_to_hex(str(dst_ip))+") PROTO: "+str(proto_id)
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
        self.udp_db[lport]['time'] = datetime.now()
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
        self.s_close(lport, rmac, rip, rport)
      # if a syn,ack is received, that's a new connection
      elif syn and ack:
        self.s_open(lport, rmac, rip, rport)
      else:
        # otherwise, it's mid-stream - update time
        if lport in self.tcp_db:
          self.tcp_db[lport]['time'] = datetime.now()
        else:
          self.s_open(lport, rmac, rip, rport)

  
  def u_open(self, lport, rmac, rip, rport):
    pass


  def s_open(self, lport, rmac, rip, rport):
    pass

  
  def s_close(self, lport, rmac, rip, rport):
    pass

      
  def ip_to_hex(self, ip):
    ip_s = ip.split(".")
    hex = "%02x%02x%02x%02x" % (int(ip_s[0]),int(ip_s[1]),int(ip_s[2]),int(ip_s[3]))
    return hex
