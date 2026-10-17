/* Actual production relay event loop with deterministic syscall fixtures only. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define M11_RELAY_TEST
static long sc(long,unsigned long,unsigned long,unsigned long,unsigned long);
#include "kmsg-relay.c"
static int mode,stop,kreads,done;static unsigned ticks;static ulong size;
static ulong event_total,event_given,stop_value;
static char output[2*CAP];
/* Valid runner journal for nonce 7*32 / identity 9*64 (same bytes as test-protocol.py journal()). */
static const char journal[]=
 "M11I1 0 1.00 session identity metadata 0 37373737373737373737373737373737373737373737373737373737373737372039393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939393939\n"
 "M11I1 1 1.00 runtime_transport unsupported metadata 95 6e6f745f696d706c656d656e746564\n"
 "M11I1 2 1.00 graph_topology unsupported metadata 95 6e6f745f696d706c656d656e746564\n"
 "M11I1 3 1.00 amp_disabled unsupported metadata 95 6e6f745f696d706c656d656e746564\n"
 "M11I1 4 1.00 runtime_route unsupported metadata 95 6e6f745f696d706c656d656e746564\n"
 "M11I1 5 1.00 calibration_applied unsupported metadata 95 6e6f745f696d706c656d656e746564\n"
 "M11I1 6 1.00 protection_active unsupported metadata 95 6e6f745f696d706c656d656e746564\n"
 "M11I1 7 1.00 gain_valid unsupported metadata 95 6e6f745f696d706c656d656e746564\n"
 "M11I1 8 1.00 teardown unsupported metadata 95 6e6f745f696d706c656d656e746564\n"
 "M11I1 9 1.00 session final_state metadata 0 616d705f656e61626c655f7065726d69747465643d30206163747561746f725f696d706c656d656e7465643d30\n"
 "M11I1 END 10 75eeb907193346c8fe561c0ebd9e6477b53f7ea3b42dc5497c7c66326c5d35cf\n"
;
#define JLEN (sizeof(journal)-1)
static long sc(long nr,unsigned long a,unsigned long b,unsigned long c,unsigned long d){
 (void)d;
 if(nr==56){
  const char *p=(const char *)b;
  if(!strcmp(p,"/dev/kmsg"))return 10;
  if(!strcmp(p,"/run/m11-instrumentation/journal"))return 20;
  if(!strcmp(p,"/run/m11-instrumentation/logger.stop"))return stop?30:-2;
  if(!strcmp(p,"/run/m11-instrumentation/logger.ready"))return 40;
  if(!strcmp(p,"/run/m11-instrumentation/logger.done")){done=1;return 41;}
  if(!strcmp(p,"/run/m11-instrumentation/usb.ready"))return mode==5?-2:50;
  if(!strcmp(p,"/dev/ttyGS0"))return 60;
  assert(0);
 }
 if(nr==57)return 0;
 if(nr==101){ticks++;assert(ticks<500);return 0;}
 if(nr==278){if(mode==3)return 0;memset((void *)a,7,c/2?c/2:1);return c/2?(long)c/2:1;}
 if(nr==29){if(mode==4)return -5;unsigned *v=(unsigned *)c;if(b==0x5401)v[1]=0;return 0;}
 if(nr==63){
  if(a==20){
   if(event_given>=event_total)return 0;
   ulong n=event_total-event_given;if(n>c)n=c;
   if(mode<6)memcpy((void *)b,journal+event_given,n);else memset((void *)b,'e',n);
   event_given+=n;return (long)n;
  }
  if(a==30){int n=snprintf((char *)b,c,"%lu\n",(unsigned long)stop_value);return n;}
  if(a==10){if(kreads==3){stop=1;return -11;}int n=snprintf((char *)b,c,"6,%d,123,-;synthetic\n",kreads++);return n;}
  assert(0);
 }
 if(nr==64){
  if(a==40 || a==41)return (long)c;
  assert(a==60);
  if(mode==1)return -11;
  if(mode==2)return -5;
  ulong n=mode>=6?c:(c>61?61:c);
  assert(size+n<=sizeof(output));memcpy(output+size,(void *)b,n);size+=n;return (long)n;
 }
 assert(0);return -1;
}
/* Modes: 0 normal journal with 61-byte short writes (output goes to the independent checker);
 * 1 tty EAGAIN deadline; 2 tty write error; 3 getrandom failure; 4 tty termios failure;
 * 5 no usb.ready (RAM-only backlog, no host capture);
 * 6 stop boundary 135168 (> Run20's 131072 limit) accepted; 7 boundary exactly EVENT_RESERVE accepted;
 * 8 boundary EVENT_RESERVE+1 rejected before sealing; 9 event stream overshooting its stop boundary rejected. */
int main(int argc,char **argv){
 mode=argc>1?atoi(argv[1]):0;
 int expected[]={0,7,4,9,8,0,0,0,6,6};
 assert(mode>=0 && mode<10);
 event_total=JLEN;stop_value=JLEN;
 if(mode==6){event_total=135168;stop_value=135168;}
 if(mode==7){event_total=EVENT_RESERVE;stop_value=EVENT_RESERVE;}
 if(mode==8){event_total=EVENT_RESERVE;stop_value=EVENT_RESERVE+1u;}
 if(mode==9){event_total=40000;stop_value=1000;stop=1;}
 int rc=relay();assert(rc==expected[mode]);
 if(mode==0){assert(done && sealed && wire_bytes==tty_bytes && !used && event_bytes==JLEN);assert(argc==3);FILE *f=fopen(argv[2],"wb");assert(f);assert(fwrite(output,1,size,f)==size);assert(!fclose(f));}
 if(mode==1){assert(!done && ticks>=299 && !sealed);}
 if(mode==6){assert(done && sealed && wire_bytes==tty_bytes && !used && event_bytes==135168 && event_bytes>131072u);}
 if(mode==7){assert(done && sealed && wire_bytes==tty_bytes && !used && event_bytes==EVENT_RESERVE);}
 if(mode==8 || mode==9){assert(!done && !sealed);}
 printf("PASS actual relay lifecycle mode=%d rc=%d ticks=%u; syscall fixtures, no hardware\n",mode,rc,ticks);
}
