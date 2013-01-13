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

    # decode packet
    try:
      p = self.decoder.decode(data)
    except Exception, e:
      print "Could not decode packet: %s" % (str(e))
    try:
      src_ip = p.child().get_ip_src()
      dst_ip = p.child().get_ip_dst()
      proto_id = p.child().child().protocol
      print "IP SRC: "+str(src_ip)+" DST: "+str(dst_ip)+" PROTO: "+str(proto_id)
    except Exception, e:
      print "Exception parsing packet. Error: %s" % (str(e))
