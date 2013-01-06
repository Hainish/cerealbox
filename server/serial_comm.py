import serial

class SerialComm():
  def __init__(self, serial_device):
    try:
      self.ser = serial.Serial(serial_device, 9600, timeout=1)
    except serial.serialutil.SerialException, e:
      print e
  
  def close(self):
    self.ser.close()

  def writeln(self, line):
    self.ser.write(line+"\n")
