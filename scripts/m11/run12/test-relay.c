#include <assert.h>
#include <stdio.h>
#include <string.h>
#define M11_RELAY_TEST
static long sc(long, unsigned long, unsigned long, unsigned long, unsigned long);
#include "kmsg-relay.c"
static int event_reads;
static int tick, reads, sent, mode, done, ready, open_tty;
static unsigned int tty_oflag;
static int tcgets, tcsets;
static char output[2*CAP];
static long sc(long nr, unsigned long a, unsigned long b, unsigned long c, unsigned long d)
{
 (void)d;
 if(nr==56) {
  const char *p=(const char *)b;
  if(!strcmp(p,"/dev/kmsg")) { assert(c==NONBLOCK); return 10; }
  if(!strcmp(p,"/run/m11/events")) { assert(c==NONBLOCK); return 11; }
  if(!strcmp(p,"/dev/ttyGS0")) { assert(c==(01|NONBLOCK|0400)); open_tty++; return 20; }
  if(strstr(p,"logger.ready")) { ready++; return 30; }
  if(strstr(p,"logger.done")) { done++; return 30; }
  if(strstr(p,"usb.ready")) return tick>=5 ? 31 : -2;
  if(strstr(p,"logger.stop")) return tick>=10 ? 31 : -2;
  assert(0);
 }
 if(nr==57) return 0;
 if(nr==29) {
  unsigned int *attrs=(unsigned int *)c;
  assert(a==20);
  if(b==0x5401) { tcgets++; attrs[1]=tty_oflag; return 0; }
  if(b==0x5402) {
   tcsets++;
   if(mode==6) return -5;
   tty_oflag=attrs[1]; return 0;
  }
  assert(0);
 }
 if(nr==101) { tick++; assert(tick<=311); return 0; }
 if(nr==63) {
  if(a==31) { char v[32]; int n=snprintf(v,sizeof(v),"%lu\n",(unsigned long)strlen("[M11R12 event] late ALSA sample\n")); memcpy((void *)b,v,(size_t)n); return n; }
  if(a==11) {
   if(mode==5) return -5;
   if(tick>=2 && event_reads++==0) {
    const char line[]="[M11R12 event] late ALSA sample\n";
    memcpy((void *)b,line,sizeof(line)-1); return sizeof(line)-1;
   }
   return 0; /* regular-file EOF before and after a later append */
  }
  assert(a==10 && c==RECORD);
  if(mode==2) return -5;
  if(mode==3 && reads++==0) return -32;
  if(reads++<3) {
   static const char line[]="6,1,123,-;test\n";
   memcpy((void *)b,line,sizeof(line)-1); return sizeof(line)-1;
  }
  return -11;
 }
 if(nr==64) {
  if(a==30) return (long)c;
  assert(a==20 && tick>=5);
  if(mode==1) return -11;
  if(mode==4) return -5;
  /* Partial writes must preserve every queued byte in order. */
  unsigned long n=c>7 ? 7 : c;
  assert(sent+(int)n<(int)sizeof(output)); memcpy(output+sent,(void *)b,n); sent+=(int)n;
  return (long)n;
 }
 assert(0); return -1;
}
static void reset(int m)
{
 head=used=lost=event_bytes=0; event_reads=0; tick=reads=sent=done=ready=open_tty=0; mode=m;
 tty_oflag=5; tcgets=tcsets=0;
 memset(output,0,sizeof(output));
}
int main(void)
{
 reset(0); assert(frame('K',"x\n",2));
 assert(used==sizeof("M11R12 K 2\nx\n")-1);
 assert(!memcmp(queue,"M11R12 K 2\nx\n",used));
 reset(0); assert(relay()==0 && ready && done && open_tty);
 assert(tcgets==2 && tcsets==1 && (tty_oflag&1u)==0);
 assert(strstr(output,"6,1,123,-;test\n") && strstr(output,"late ALSA sample") && strstr(output,"M11R12 F "));
 reset(1); assert(relay()==7 && tick<=311 && !done && used>0 && !sent);
 reset(2); assert(relay()==3 && !done);
 reset(3); assert(relay()==0 && strstr(output,"kernel EPIPE"));
 reset(4); assert(relay()==4 && !done);
 reset(5); assert(relay()==6 && !done);
 reset(6); assert(relay()==8 && !done && tcsets==1);
 reset(0); used=CAP-EVENT_RESERVE; frame('K',"kernel",6); assert(lost==1); assert(frame('E',"event",5)); assert(used>CAP-EVENT_RESERVE+5);
 reset(0); used=CAP; assert(frame('K',"new",3)); assert(lost==1 && used==CAP);
 reset(0); head=CAP-2; enqueue("abcd",4); assert(used==4);
 tick=5; while(used) assert(drain(20)); assert(sent==4 && !memcmp(output,"abcd",4));
 puts("M11R12 production relay: backlog, partial writes, EAGAIN bounded stop, EPIPE, fatal errors and bounded queue PASS");
 return 0;
}
