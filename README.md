# Cerealbox
Arduino-based network monitor, by [William Budington](https://github.com/Hainish/), [original](https://github.com/SpiderLabs/cerealbox) by [Steve Ocepek](http://www.spiderlabs.com)



## Requirements
This code should run on any Arduino board with 2k SRAM equipped with Colors Shield, or the all-in-one Colorduino board. Both Colorduino and Colors Shield are available from [iTead Studio](http://iteadstudio.com/). Colorduino does not include a USB port, so novices (like me) should use the Colors Shield + Arduino Uno.

Test/Dev system is: Ardunio Uno, Colors Shield, 8x8 round LED matrix (iTead)

The Colorduino library by Lincomatic is required and can be found [here](https://github.com/lincomatic/Colorduino/downloads).

### Arduino
- Arduino >= 1
- Colorduino Lib >= 1.2.4

The python code is separated into a server and client.  The server is run by the machine connected to the arduino, and the client is the machine you want to monitor.  The server &lt;-&gt; communication is over SSL.  Server/Client Requirements:

### Client & Server
- python = 2.7.x

### Client Python Packages
- pycapy >= 0.10.8
- impacket >= 0.9.6
- pygeoip >= 0.2.5
- incf.countryutils >= 1.0

### Server Python Packages
- pyserial >= 2.6

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

On the client side, create the cert file and paste your certificate:

    mkdir client/ssl
    vi client/ssl/cert.crt

## Usage
On the server, cd into server/ and run:

    python server.py PORT SERIAL_DEVICE PASSWORD

- PORT is the port to listen for incoming client connection
- SERIAL_DEVICE is the  USB serial device that the Arduino is using, ex:
    - /dev/ttyUSB0 on Linux or whichever was assigned to Arduino, use dmesg to find out
    - /dev/tty.usbmodem262312 on Mac OS X.  Use ls /dev/tty.usbmodem* to find this
- PASSWORD is the password, which the client will need to specify to authenticate with the server

On the client, cd into client/ and run:

    sudo python client.py HOST PORT NET_DEVICE IPADDR PASSWORD [DNS]

- HOST is the ip address of the server to connect to
- PORT is the port which the server is listening on
- NET_DEVICE is the network device to listen on, ex. eth0
- IPADDR is the IP address of the host to be monitored
- PASSWORD is the shared password with the server, used for authentication
- DNS specifies that DNS sessions should be tracked and displayed (tends to fill up board pretty quickly)

If all went well, you're now visualizing network traffic on the Arduino board!

## Copyright

cerealbox - Arduino-based network monitor

By William Budington
Copyright (C) 2013

Based on the original by Steve Opecek
Copyright (C) 2011 Trustwave Holdings, Inc.
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program.  If not, see [http://www.gnu.org/licenses/](http://www.gnu.org/licenses/)
