/* 
  RF Blink - Transmit sketch 
     Written by ScottC 17 Jun 2014
     Arduino IDE version 1.0.5
     Website: http://arduinobasics.blogspot.com
     Transmitter: FS1000A/XY-FST
     Description: A simple sketch used to test RF transmission.          
 ------------------------------------------------------------- */

 #define ledpin 13        //Onboard LED = digital pin 13
 #define rfoutput 12
 #define N 1
 
 void setup(){
   Serial.begin(115200);
   pinMode(ledpin, OUTPUT);    
   pinMode(rfoutput, OUTPUT);    
 }

const char flag[] = "Hello world!!!Hello world!!!Hello world!!!Hello world!!!";
      char buf[]  = "                                                        ";

 void loop(){
    static long i = 0;

    if(i%N == 0) {
      int byte_num = ((i / N) % (14 * 4 * 8)) / 8;
      int bit_num =  ((i / N) % (14 * 4 * 8)) % 8;

      int level = (flag[byte_num] >> bit_num) & 1 ? HIGH : LOW ;

      digitalWrite(rfoutput, level);     //Transmit a HIGH signal
      digitalWrite(ledpin, level);     //Transmit a HIGH signal
    }
//      digitalWrite(ledpin, HIGH);     //Transmit a HIGH signal   
//    } else if (i % N == N/2) {
//      digitalWrite(rfoutput,LOW);      //Transmit a LOW signal
//      digitalWrite(ledpin,LOW);      //Transmit a LOW signal
//    }

    if (i % N == N/2) {
      int bit = analogRead(A0) > 0;
      int byte_num = ((i / N) % (14 * 4 * 8)) / 8;
      int bit_num =  ((i / N) % (14 * 4 * 8)) % 8;

      buf[byte_num] &= ~(1 << bit_num);
      buf[byte_num] |= bit << bit_num;
      
       Serial.println(buf);
      
//       Serial.println(analogRead(A0) > 0);
    }

    unsigned long startTime = 0;
    unsigned long delayTime = 10000; //   21.5 mSec 
    
    startTime = micros();
    
    while ( micros() - startTime < delayTime) {
      // do something useful, or not
    }


    i += 1;


    
//    delay(1);     
 }
