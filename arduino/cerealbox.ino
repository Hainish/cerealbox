/*
cerealbox 
Created by Steve Ocepek
Copyright (C) 2011 Trustwave Holdings, Inc.

Modified by William Budington
Copyright (c) 2013

Contains portions from ColorduinoPlasma
ColorduinoPlasma - Plasma demo using Colorduino Library for Arduino
Copyright (c) 2011 Sam C. Lin lincomatic@hotmail.com ALL RIGHTS RESERVED

ColorduinoPlasma based on  Color cycling plasma   
 Version 0.1 - 8 July 2009
 Copyright (c) 2009 Ben Combee.  All right reserved.
 Copyright (c) 2009 Ken Corey.  All right reserved.
 Copyright (c) 2008 Windell H. Oskay.  All right reserved.
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <Colorduino.h>
#include "Config.h"
#define CMD_BUFFER 35
#define ARRAY_SIZE 128
#define OVERLOAD 90
#define smillis() ((long)millis())

int i=0;                     //serial read counter
int buf;                     //incoming serial data
int pos = 0;                 //led array position
int mode=0;                    //screen mode
unsigned int numcmd;         //counter used to detect overload
char cmd[CMD_BUFFER];        //cmd to be processed
char led[ARRAY_SIZE][9];     //led array
long timeout=smillis()+5000; //for timer
long plasmatimer=smillis()+100; //for plasma timer
boolean flip = true;         //controls screen that gets rendered
boolean doplasma = false;     //used to do plasma every other cycle


// BEGIN PLASMA CODE 
typedef struct
{
  unsigned char r;
  unsigned char g;
  unsigned char b;
} ColorRGB;

//a color with 3 components: h, s and v
typedef struct 
{
  unsigned char h;
  unsigned char s;
  unsigned char v;
} ColorHSV;

unsigned char plasma[ColorduinoScreenWidth][ColorduinoScreenHeight];
long paletteShift;


//Converts an HSV color to RGB color
void HSVtoRGB(void *vRGB, void *vHSV) 
{
  float r, g, b, h, s, v; //this function works with floats between 0 and 1
  float f, p, q, t;
  int i;
  ColorRGB *colorRGB=(ColorRGB *)vRGB;
  ColorHSV *colorHSV=(ColorHSV *)vHSV;

  h = (float)(colorHSV->h / 256.0);
  s = (float)(colorHSV->s / 256.0);
  v = (float)(colorHSV->v / 256.0);

  //if saturation is 0, the color is a shade of grey
  if(s == 0.0) {
    b = v;
    g = b;
    r = g;
  }
  //if saturation > 0, more complex calculations are needed
  else
  {
    h *= 6.0; //to bring hue to a number between 0 and 6, better for the calculations
    i = (int)(floor(h)); //e.g. 2.7 becomes 2 and 3.01 becomes 3 or 4.9999 becomes 4
    f = h - i;//the fractional part of h

    p = (float)(v * (1.0 - s));
    q = (float)(v * (1.0 - (s * f)));
    t = (float)(v * (1.0 - (s * (1.0 - f))));

    switch(i)
    {
      case 0: r=v; g=t; b=p; break;
      case 1: r=q; g=v; b=p; break;
      case 2: r=p; g=v; b=t; break;
      case 3: r=p; g=q; b=v; break;
      case 4: r=t; g=p; b=v; break;
      case 5: r=v; g=p; b=q; break;
      default: r = g = b = 0; break;
    }
  }
  colorRGB->r = (int)(r * 255.0);
  colorRGB->g = (int)(g * 255.0);
  colorRGB->b = (int)(b * 255.0);
}

unsigned int RGBtoINT(void *vRGB)
{
  ColorRGB *colorRGB=(ColorRGB *)vRGB;

  return (((unsigned int)colorRGB->r)<<16) + (((unsigned int)colorRGB->g)<<8) + (unsigned int)colorRGB->b;
}


float
dist(float a, float b, float c, float d) 
{
  return sqrt((c-a)*(c-a)+(d-b)*(d-b));
}

void plasma_morph() {
  unsigned char x,y;
  float value;
  ColorRGB colorRGB;
  ColorHSV colorHSV;

  for(y = 0; y < ColorduinoScreenHeight; y++)
    for(x = 0; x < ColorduinoScreenWidth; x++) {
      {
        value = sin(dist(x + paletteShift, y, 128.0, 128.0) / 8.0)
          + sin(dist(x, y, 64.0, 64.0) / 8.0)
          + sin(dist(x, y + paletteShift / 7, 192.0, 64) / 7.0)
          + sin(dist(x, y, 192.0, 100.0) / 8.0);
        colorHSV.h=(unsigned char)((value) * 128)&0xff;
        colorHSV.s=255; 
        //Reduce value to make sad face stand out
        colorHSV.v=100;
        HSVtoRGB(&colorRGB, &colorHSV);
        
        Colorduino.SetPixel(x, y, colorRGB.r, colorRGB.g, colorRGB.b);
      }
  }
  paletteShift++;
  
  //Sad face
  Colorduino.SetPixel(1,1,255,255,255);
  Colorduino.SetPixel(1,2,255,255,255);
  Colorduino.SetPixel(1,5,255,255,255);
  Colorduino.SetPixel(1,6,255,255,255);
  Colorduino.SetPixel(2,1,255,255,255);
  Colorduino.SetPixel(2,2,255,255,255);
  Colorduino.SetPixel(2,5,255,255,255);
  Colorduino.SetPixel(2,6,255,255,255);
  Colorduino.SetPixel(5,2,255,255,255);
  Colorduino.SetPixel(5,3,255,255,255);
  Colorduino.SetPixel(5,4,255,255,255);
  Colorduino.SetPixel(5,5,255,255,255);
  Colorduino.SetPixel(6,1,255,255,255);
  Colorduino.SetPixel(6,6,255,255,255);
  
  Colorduino.FlipPage(); // swap screen buffers to show it
  doplasma = false;
}



//END PLASMA CODE

void setup() {
  // initialize serial communication:
  Serial.begin(9600);
  Colorduino.Init(); // initialize the board
  Colorduino.FlipPage();
  
  // compensate for relative intensity differences in R/G/B brightness
  // array of 6-bit base values for RGB (0~63)
  // whiteBalVal[0]=red
  // whiteBalVal[1]=green  
  // whiteBalVal[2]=blue
  unsigned char whiteBalVal[3] = {36,63,63}; // for LEDSEE 6x6cm round matrix
  Colorduino.SetWhiteBal(whiteBalVal);
  
  //Zero out led array
  for (int x=0; x < ARRAY_SIZE; x++) {
    for (int y=0; y < 9; y++) {
      led[x][y] = 0;
    }
  }
  
  //PLASMA SETUP
  // start with morphing plasma, but allow going to color cycling if desired.
  paletteShift=128000;
  unsigned char bcolor;
  
  //generate the plasma once
  for(unsigned char y = 0; y < ColorduinoScreenHeight; y++)
    for(unsigned char x = 0; x < ColorduinoScreenWidth; x++)
    {
      //the plasma buffer is a sum of sines
      bcolor = (unsigned char)
      (
            128.0 + (128.0 * sin(x*8.0 / 16.0))
          + 128.0 + (128.0 * sin(y*8.0 / 16.0))
      ) / 2;
      plasma[x][y] = bcolor;
    }
}

//Julian Skidmore's rollover-proof timer
boolean after(long timeout) {
    return smillis()-timeout>0;
}

boolean plasma_after(long plasmatimer) {
    return smillis()-plasmatimer>0;
}

void flush_buffer() {
  for (int x = 0; x < CMD_BUFFER; x++) {
    cmd[x] = 0;
  }
  i=0;
}

int tohex(int a) {
  if (a > 47 && a < 58) {
    return a - 48;
  }
  else if (a > 64 && a < 71) {
    return a - 55;
  }
}

void render() {
  if (mode == 0) {
    if (flip == true || led[64][3] == 0) {
      for (int x=0; x < 64; x++) {
        //Set each led according to values in led array
        Colorduino.SetPixel(x,0,led[x][0],led[x][1],led[x][2]);
      }
      Colorduino.FlipPage();
    }
    else {
      for (int x=64; x < 128; x++) {
        //Set each led according to values in led array
        Colorduino.SetPixel(x-64,0,led[x][0],led[x][1],led[x][2]);
      }
      Colorduino.FlipPage();
    }
  }
  if (mode == 9) {
    if (doplasma == true) {
      plasma_morph();
    }
  }
}

void delete_record(int x) {
  if (led[x+1][3] != 0) {
    for (int y=0; y <= 8; y++) {
      led[x][y] = led[x+1][y];
      led[x+1][y] = 0;
    }
    delete_record(x+1);
  } else {
    for (int y=0; y <= 8; y++) {
      led[x][y] = 0;
    }
  }
}
  
void loop() {
  //Do plasma effect alternate frames
  if (plasma_after(plasmatimer)) {
    doplasma = true;
    plasmatimer=(long)millis()+100;
  }
  //Add timer to render alternating screens if data present
  render();
  if (after(timeout)) {
    flip = !flip;
    
    //Overload detection
    if (numcmd > OVERLOAD) {
      mode = 9;
      //Delete all and start over
      while (pos > 0) {
        delete_record(pos-1);
        pos--;
      }
    } 
    else {
      mode = 0;
    }
     
    numcmd = 0;
    timeout=(long)millis()+5000;
  }
  
  if (i > CMD_BUFFER) {
    flush_buffer();
  }
  else if (Serial.available() > 0) {
    buf = Serial.read();
    //End of command - CR or LF
    //CR+LF is ok, it'll just cause double flush
    if (buf == 10 || buf == 13) {
      if (i == 34) {
        // Add null
        cmd[i+1] = 0;
        
        //Process command
        
        //Increment cmd counter for rate comparison
        
        //"1" - add command
        if (cmd[0] == 49 || cmd[0] == 50) {
          //Check validity of data
          boolean invalid = false;
          
          for (int x=1; x < 28; x++) {
            if ((cmd[x] >= 48 && cmd[x] <= 57) || (cmd[x] >= 65 && cmd[x] <= 90) || (cmd[x] == 44)) {}
            else invalid = true;
          }
          
          if (
               //Country code
               (cmd[29] >= 65 && cmd[29] <= 90) &&
               (cmd[30] >= 65 && cmd[30] <= 90) &&
               invalid == false
             )
           
          if (invalid == true) {
            flush_buffer();
          }
          
          else { 
            
            // 'Add' command
            if (cmd[0] == 49) {
              //Stop adding if at limit
              if (pos < ARRAY_SIZE) {

                // led pos 3-6 are ip
                led[pos][3] = tohex(cmd[15])*16 + tohex(cmd[16]);
                led[pos][4] = tohex(cmd[17])*16 + tohex(cmd[18]);
                led[pos][5] = tohex(cmd[19])*16 + tohex(cmd[20]);
                led[pos][6] = tohex(cmd[21])*16 + tohex(cmd[22]);
            
                //pos 7-8 are port
                led[pos][7] = tohex(cmd[24])*16 + tohex(cmd[25]);
                led[pos][8] = tohex(cmd[26])*16 + tohex(cmd[27]);

                // determine if this is in our special_ips array
                bool special_ip = false;
                for(int x = 0; x < sizeof(special_ips) / 4; x++){
                  int matches = 0;
                  for(int y = 0; y < 4; y++){
                    if(led[pos][y+3] == (special_ips[x][y] > 127 ? special_ips[x][y] - 256 : special_ips[x][y])){
                      matches++;
                    }
                  }
                  if(matches == 4){
                    special_ip = true;
                  }
                }

                //Create color from continent code
                int r, g, b;
                if(special_ip){ // special_ips are red
                  r = 55;
                  g = 0;
                  b = 0;
                } else if(cmd[32] == 69 && cmd[33] == 85){  // EU is blue
                  r = 0;
                  g = 0;
                  b = 55;
                } else if(cmd[32] == 65 && cmd[33] == 83) { // AS is orange
                  r = 200;
                  g = 50;
                  b = 0;
                } else if(cmd[32] == 79 && cmd[33] == 67){ // OC is purple
                  r = 55;
                  g = 0;
                  b = 55;
                } else if(cmd[32] == 65 && cmd[33] == 70){ // AF is yellow
                  r = 90;
                  g = 55;
                  b = 0;
                } else if(cmd[32] == 83 && cmd[33] == 65){ // SA is white
                  r = 255;
                  g = 255;
                  b = 255;
                } else if(cmd[32] == 78 && cmd[33] == 65){ // NA is cyan
                  if(cmd[29] == 85 && cmd[30] == 83){ // US is green
                    r = 0;
                    g = 55;
                    b = 0;
                  } else {
                    r = 0;
                    g = 200;
                    b = 55;
                  }
                } else if(cmd[32] == 45 && cmd[33] == 45){ // -- (local) is pink
                  r = 55;
                  g = 20;
                  b = 20;
                }            
                //Add to array
                led[pos][0] = r;
                led[pos][1] = g;
                led[pos][2] = b;
              
                pos++;
                flush_buffer();
                numcmd++;
              }
            }
            else if (cmd[0] == 50) {
              //Delete command
              //Find entry by IP and Port
              boolean found = false;
              
              char delcmd[6];
              
              delcmd[0] = tohex(cmd[15])*16 + tohex(cmd[16]);
              delcmd[1] = tohex(cmd[17])*16 + tohex(cmd[18]);
              delcmd[2] = tohex(cmd[19])*16 + tohex(cmd[20]);
              delcmd[3] = tohex(cmd[21])*16 + tohex(cmd[22]);
              delcmd[4] = tohex(cmd[24])*16 + tohex(cmd[25]);
              delcmd[5] = tohex(cmd[26])*16 + tohex(cmd[27]);
              
              for (int x=0; x <= pos; x++) {
                for (int y=0; y <= 5; y++) {
                  if (led[x][y+3] != delcmd[y]) {
                    break;
                  }
                  if (y==5) {  
                    found = true;
                  }
                }
                if (found == true) {
                  delete_record(x);
                  flush_buffer();
                  pos--;
                  break;
                } else {
                  flush_buffer();
                }
              }
            }
          }
        }
      }
    }
    
    //Otherwise we're still reading data
    //A-Z, 0-9, and comma, and dash
    else if ((buf >= 48 && buf <= 57) || (buf >= 65 && buf <= 90) || (buf == 44) || (buf == 45)) {
      cmd[i] = buf;
      i++;
    }
    else {
      flush_buffer();
    }
  }
}
