/* M11 Run21 v2 sender-sealed relay; isolated from frozen Run12/19.
 * Public ARM64 RAM-only kmsg -> USB ACM relay. No partition I/O, no input.
 * One bounded queue retains early records until connector-driven USB exists.
 * Reads/writes are nonblocking; congestion drops NEW kernel records, never blocks
 * the bootstrap or grows memory. kmsg EPIPE and queue losses are marked.
 */
typedef unsigned long ulong;
typedef long slong;
#define CAP (4u * 1024u * 1024u)
#define RECORD 16384u
#define EVENT_RESERVE (1024u * 1024u + 65536u)
#define AT_FDCWD ((ulong)-100)
#define NONBLOCK 04000
#ifndef M11_RELAY_TEST
static slong sc(slong nr, ulong a, ulong b, ulong c, ulong d)
{
 register ulong x8 __asm__("x8")=(ulong)nr;
 register ulong x0 __asm__("x0")=a, x1 __asm__("x1")=b;
 register ulong x2 __asm__("x2")=c, x3 __asm__("x3")=d;
 __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2),"r"(x3) : "memory","cc");
 return (slong)x0;
}
#endif
static char queue[CAP], record[RECORD];
static ulong head, used, lost, event_bytes;
#include "sha256.h"
static Sha256 constructed, accepted;
static ulong sequence, wire_bytes, tty_bytes;
static int sealed;
/* ARM64 asm-generic TCGETS/TCSETS, c_oflag at byte offset 4. OPOST=1. */
static int raw_tty_output(int fd)
{
 unsigned int attrs[16]={0};
 if(sc(29,(ulong)fd,0x5401,(ulong)attrs,0)<0) return 0;
 attrs[1]&=~1u;
 if(sc(29,(ulong)fd,0x5402,(ulong)attrs,0)<0) return 0;
 if(sc(29,(ulong)fd,0x5401,(ulong)attrs,0)<0) return 0;
 return (attrs[1]&1u)==0;
}
static ulong decimal(char *out, ulong n)
{
 char rev[24]; ulong k=0;
 do { rev[k++]=(char)('0'+n%10); n/=10; } while(n);
 for(ulong i=0;i<k;i++) out[i]=rev[k-i-1];
 return k;
}
static void enqueue(const char *p, ulong n)
{
 for(ulong i=0;i<n;i++) queue[(head+used+i)%CAP]=p[i];
 used+=n;
}
/* Length frames keep partial event reads separate from complete kmsg records.
 * Atomic capacity check covers header AND payload; no interleaved fragments. */
static int frame(char type, const char *p, ulong n)
{
 char h[64]="M11I3 "; ulong k=sizeof("M11I3 ")-1;
 if(!n || n>RECORD || sequence>999999999 || (sealed && type!='F')) return 0;
 h[k++]=type; h[k++]=' '; k+=decimal(h+k,sequence); h[k++]=' '; k+=decimal(h+k,n); h[k++]='\n';
 ulong limit=type=='K' ? CAP-EVENT_RESERVE : CAP;
 if(used>limit || k+n>limit-used) {
  if(type=='K') { lost++; return 1; }
  return 0;
 }
 enqueue(h,k); enqueue(p,n);
 if(type!='F') { sha_update(&constructed,h,k);sha_update(&constructed,p,n);wire_bytes+=k+n; }
 sequence++;return 1;
}
static int drain(int fd)
{
 if(!used) return 1;
 ulong n=CAP-head; if(n>used) n=used;
 slong rc=sc(64,(ulong)fd,(ulong)(queue+head),n,0);
 if(rc>0) {
  if((ulong)rc>n) return 0;
  if(!sealed) { sha_update(&accepted,queue+head,(ulong)rc);tty_bytes+=(ulong)rc; }
  head=(head+(ulong)rc)%CAP; used-=(ulong)rc; return 1;
 }
 return rc==0 || rc==-11 || rc==-4;
}
static ulong literal(char *b,ulong at,const char *s) { while(*s)b[at++]=*s++;return at; }
/* F excluded from both hashes. All non-final bytes must have been accepted. */
static int seal(void)
{
 if(used || sealed || tty_bytes!=wire_bytes) return 0;
 char h[64],t[64],b[320];sha_hex(constructed,h);sha_hex(accepted,t);
 for(unsigned i=0;i<64;i++)if(h[i]!=t[i])return 0;
 ulong n=literal(b,0,"frames=");n+=decimal(b+n,sequence);
 n=literal(b,n," bytes=");n+=decimal(b+n,wire_bytes);
 n=literal(b,n," events=");n+=decimal(b+n,event_bytes);
 n=literal(b,n," kernel_drops=");n+=decimal(b+n,lost);
 /* Bind the exact canonical footer metadata as a virtual SHA suffix. These
  * bytes are NOT counted as tty-accepted wire bytes. Hash fields are excluded.
  * Without this, flipping final kernel_drops=1 to0 could hide tail loss. */
 static const char domain[]="M11I3 SEAL\n";
 b[n]='\n';
 sha_update(&constructed,domain,sizeof(domain)-1);sha_update(&constructed,b,n+1);
 sha_update(&accepted,domain,sizeof(domain)-1);sha_update(&accepted,b,n+1);
 sha_hex(constructed,h);sha_hex(accepted,t);
 n=literal(b,n," sha256=");for(unsigned i=0;i<64;i++)b[n++]=h[i];
 n=literal(b,n," tty_sha256=");for(unsigned i=0;i<64;i++)b[n++]=t[i];b[n++]='\n';
 sealed=1;return frame('F',b,n);
}
static int start_frame(void)
{
 unsigned char nonce[16];ulong at=0;int nonzero=0;
 while(at<sizeof(nonce)) {
  slong rc=sc(278,(ulong)(nonce+at),sizeof(nonce)-at,0,0);
  if(rc==-4)continue;
  if(rc<=0 || (ulong)rc>sizeof(nonce)-at)return 0;
  at+=(ulong)rc;
 }
 char b[64];ulong n=literal(b,0,"run=M11R21 nonce=");const char hex[]="0123456789abcdef";
 for(unsigned i=0;i<16;i++){nonzero|=nonce[i];b[n++]=hex[nonce[i]>>4];b[n++]=hex[nonce[i]&15];}
 if(!nonzero)return 0;
 b[n++]='\n';
 sha_init(&constructed);sha_init(&accepted);return frame('S',b,n);
}
static int exists(const char *p)
{
 slong fd=sc(56,AT_FDCWD,(ulong)p,0,0);
 if(fd<0) return 0;
 sc(57,(ulong)fd,0,0,0); return 1;
}
static int marker(const char *p)
{
 slong fd=sc(56,AT_FDCWD,(ulong)p,01|0100|0200,0600);
 if(fd<0) return 0;
 slong rc=sc(64,(ulong)fd,(ulong)"1\n",2,0);
 sc(57,(ulong)fd,0,0,0); return rc==2;
}
static void pause10(void)
{
 struct { slong sec, nsec; } ts={0,10000000};
 sc(101,(ulong)&ts,0,0,0);
}
/* Stop contains a decimal byte boundary, atomically renamed by producer.
 * A final reader pass must reach it; observing an empty queue alone is unsafe. */
static int stop_boundary(ulong *target)
{
 slong fd=sc(56,AT_FDCWD,(ulong)"/run/m11-instrumentation/logger.stop",0,0);
 if(fd==-2) return 0;
 if(fd<0) return -1;
 char b[32]; slong n=sc(63,(ulong)fd,(ulong)b,sizeof(b),0);
 sc(57,(ulong)fd,0,0,0);
 if(n<=0 || n>=(slong)sizeof(b)) return -1;
 ulong v=0; int digits=0,tail=0;
 for(slong i=0;i<n;i++) {
  if(b[i]>='0' && b[i]<='9') {
   if(tail) return -1;
   digits=1; v=v*10+(ulong)(b[i]-'0');
   if(v>EVENT_RESERVE) return -1;
  } else if(b[i]==' ' || b[i]=='\n' || b[i]=='\t') {
   if(digits) tail=1;
  } else return -1;
 }
 if(!digits) return -1;
 *target=v; return 1;
}
static int relay(void)
{
 static const char overrun[]="kernel EPIPE: records lost\n";
 slong kfd=sc(56,AT_FDCWD,(ulong)"/dev/kmsg",NONBLOCK,0), tfd=-1, efd=-1;
 int stopping=0, ticks=0, final=0, quiet=0;
 ulong target=0;
 if(kfd<0) return 1;
 if(!start_frame()) return 9;
 if(!marker("/run/m11-instrumentation/logger.ready")) return 2;
 for(;;) {
  if(!stopping) {
   int rc=stop_boundary(&target);
   if(rc<0) return 6;
   if(rc>0) stopping=1;
  }
  if(!final && (!stopping || event_bytes<target)) {
   if(efd<0) efd=sc(56,AT_FDCWD,(ulong)"/run/m11-instrumentation/journal",NONBLOCK,0);
   if(efd>=0) for(int i=0;i<8;i++) {
    slong n=sc(63,(ulong)efd,(ulong)record,RECORD,0);
    if(n>0) {
     if(!frame('E',record,(ulong)n)) return 6;
     event_bytes+=(ulong)n;
    } else if(n==0 || n==-11 || n==-4) break;
    else return 6;
   }
   if(!stopping) for(int i=0;i<64;i++) {
    slong n=sc(63,(ulong)kfd,(ulong)record,RECORD,0);
    if(n>0) frame('K',record,(ulong)n);
    else if(n==-32) { lost++; if(!frame('W',overrun,sizeof(overrun)-1)) return 6; }
    else if(n==-11 || n==-4 || n==0) break;
    else return 3;
   }
   if(stopping && event_bytes>target) return 6;

  }
  if(tfd<0 && exists("/run/m11-instrumentation/usb.ready")) {
   tfd=sc(56,AT_FDCWD,(ulong)"/dev/ttyGS0",01|NONBLOCK|0400,0);
   if(tfd>=0 && !raw_tty_output((int)tfd)) return 8;
  }
  if(tfd>=0 && !drain((int)tfd)) return 4;
  if(stopping && !final && event_bytes==target && !used && tfd>=0) {
   if(!seal())return 6;
   final=1;
  }
  if(stopping) {
   /* Earlier color branches intentionally never start USB. Their RAM-only
    * backlog cannot be delivered; finish locally, never claim host capture. */
   if(!exists("/run/m11-instrumentation/usb.ready")) break;
   /* One-second bounded grace after all writes; NOT a host delivery ACK.
    * F must actually be received on PC before claiming a complete journal. */
   if(final && !used && ++quiet>=100) break;
   if(++ticks>=300) return 7;
  }
  pause10();
 }
 sc(57,(ulong)kfd,0,0,0);
 if(tfd>=0) sc(57,(ulong)tfd,0,0,0);
 if(efd>=0) sc(57,(ulong)efd,0,0,0);
 if(!marker("/run/m11-instrumentation/logger.done")) return 5;
 return 0;
}
#ifndef M11_RELAY_TEST
void entry(void) __attribute__((noreturn,used));
void entry(void)
{
 int rc=relay(); sc(94,(ulong)rc,0,0,0);
 for(;;) {}
}
__asm__(".global _start\n_start:\nb entry\n");
#endif
