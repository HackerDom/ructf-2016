/* 
  RF Blink - Transmit sketch 
     Written by ScottC 17 Jun 2014
     Arduino IDE version 1.0.5
     Website: http://arduinobasics.blogspot.com
     Transmitter: FS1000A/XY-FST
     Description: A simple sketch used to test RF transmission.          
 ------------------------------------------------------------- */

 long N = 1;
 
 void setup(){
   Serial.begin(115200);
 }

      char buf[]  = "                                                        ";

long last = 0;
long last_pos = 0;

 void loop(){
    static long i = 0;

    if (i % N == 0) {
      int bit = analogRead(A0) > 256;

      if (bit != last) {
//        Serial.println(i - last_pos);
        
        last = bit;
        last_pos = i;
      }
      
      int byte_num = ((i / N) % (14 * 4 * 8)) / 8;
      int bit_num =  ((i / N) % (14 * 4 * 8)) % 8;

      buf[byte_num] &= ~(1 << bit_num);
      buf[byte_num] |= bit << bit_num;
//      Serial.println((analogRead(A0)));

//      Serial.println((analogRead(A0) > 0) + (i / 500000) % 5 );
      Serial.println(buf);
    }

    unsigned long startTime = 0;
    unsigned long delayTime = 10000; //   21.5 mSec 
    
    startTime = micros();
    
    while ( micros() - startTime < delayTime) {
      // do something useful, or not
    }

    i += 1;
 }
