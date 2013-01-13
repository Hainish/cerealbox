import pcapy
import impacket.ImpactDecoder

SNAPLEN = 90
PROMISC_MODE = 0
TO_MS = 15

class Sniffer():
  def __init__(self):
    self.decoder = impacket.ImpactDecoder.EthDecoder() 


  def set_new_connection_handler(self, new_connection_handler):
    self.new_connection_handler = new_connection_handler


  def sniff(self, net_device, src_ipaddr, dns):
    p = None

    # create reader object
    try:
      p = pcapy.open_live(net_device, SNAPLEN, PROMISC_MODE, TO_MS) 
    except Exception, e:
      print "Could not open device '%s' for sniffing. Error: %s" % (net_device, str(e))

    # filter based on dns settings
    try:
      if dns:
        p.setfilter("(tcp or udp) and host "+src_ipaddr)
      else:
        p.setfilter("(tcp or (udp and not port 53)) and host "+src_ipaddr)
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
    src_port = None
    dst_port = None

    # decode packet
    try:
      p = self.decoder.decode(data)
    except Exception, e:
      print "Could not decode packet: %s" % (str(e))
    try:
      src_ip = p.child().get_ip_src()
      dst_ip = p.child().get_ip_dst()
      proto_id = p.child().child().protocol
      print "IP SRC: "+str(src_ip)+" ("+self.ip_to_hex(str(src_ip))+") DST: "+str(dst_ip)+" ("+self.ip_to_hex(str(dst_ip))+") PROTO: "+str(proto_id)
    except Exception, e:
      print "Exception parsing packet. Error: %s" % (str(e))
    
    if proto_id == 17:
      dst_port = p.child().child().get_uh_dport()
      src_port = p.child().child().get_uh_sport()
    if proto_id == 6:
      dst_port = p.child().child().get_th_dport()
      src_port = p.child().child().get_th_sport()

      
  def ip_to_hex(self, ip):
    ip_s = ip.split(".")
    hex = "%02x%02x%02x%02x" % (int(ip_s[0]),int(ip_s[1]),int(ip_s[2]),int(ip_s[3]))
    return hex
