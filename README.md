# Cerealbox
Arduino-based network monitor, based on the [original](https://github.com/SpiderLabs/cerealbox) by [Steve Ocepek](http://www.spiderlabs.com)



## Requirements
This code should run on any Arduino board with 2k SRAM equipped with Colors Shield, or the all-in-one Colorduino board. Both Colorduino and Colors Shield are available from [iTead Studio](http://iteadstudio.com/). Colorduino does not include a USB port, so novices (like me) should use the Colors Shield + Arduino Uno.

Test/Dev system is: Ardunio Uno, Colors Shield, 8x8 round LED matrix (iTead)

The Colorduino library by Lincomatic is required and can be found [here](http://blog.lincomatic.com/?p=148).



### Client & Server
- python = 2.7.x

### Client Python Packages
- pycapy >= 0.10.8
- impacket >= 0.9.6
- pygeoip >= 0.2.5
- incf.countryutils >= 1.0

### Server Python Packages
- pyserial >= 2.6

### Arduino
- Arduino >= 1
- Colorduino Lib >= 1.2.4

## Installation

You can choose to highlight traffic with certain IP addresses in the Arduino Config.h file.  By default, highlighted traffic is indicated by a red LED.
To change the IPs to highlight, edit arduino/Config.h:

    vim arduino/Config.h

You can highlight as many IPs as you wish.
Next, open cerealbox.ino with the Arduino IDE and upload:
    
    arduino arduino/cerealbox.ino


On the server side, run:

    make server-cert

Then, copy the server cert and start the server:

    cat server/ssl/server.crt
    cd server
    python server.py 8282 /dev/ttyACM0 somepassword

On the client side, create the cert file and paste your certificate:

    mkdir client/ssl
    vi client/ssl/cert.crt

And start the client:

    sudo python client.py 192.168.1.123 8282 eth0 192.168.1.100 somepassword

If all went well, you're now visualizing network traffic on the Arduino board!
