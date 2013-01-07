import serial, sys

class SerialComm():
  def __init__(self, serial_device):
    try:
      self.ser = serial.Serial(serial_device, 9600, timeout=5)
    except serial.serialutil.SerialException, e:
      print "Unable to open serial port "+serial_device
      sys.exit()
  
  def close(self):
    self.ser.close()

  def writeln(self, line):
    self.ser.write(line+"\n")
