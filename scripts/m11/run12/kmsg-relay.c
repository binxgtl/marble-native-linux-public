/* Public ARM64 RAM-only kmsg -> USB ACM relay. No partition I/O, no input.
 * One bounded queue retains early records until connector-driven USB exists.
 * Reads/writes are nonblocking; congestion drops NEW kernel records, never blocks
 * the bootstrap or grows memory. kmsg EPIPE and queue losses are marked.
 */
typedef unsigned long ulong;
typedef long slong;
#define CAP (1024u * 1024u)
#define RECORD 16384u
#define EVENT_RESERVE 131072u
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
 char h[48]="M11R12 "; ulong k=sizeof("M11R12 ")-1;
 h[k++]=type; h[k++]=' '; k+=decimal(h+k,n); h[k++]='\n';
 ulong limit=type=='K' ? CAP-EVENT_RESERVE : CAP;
 if(used>limit || k+n>limit-used) {
  if(type=='K') { lost++; return 1; }
  return 0;
 }
 enqueue(h,k); enqueue(p,n); return 1;
}
static int drain(int fd)
{
 if(!used) return 1;
 ulong n=CAP-head; if(n>used) n=used;
 slong rc=sc(64,(ulong)fd,(ulong)(queue+head),n,0);
 if(rc>0) { head=(head+(ulong)rc)%CAP; used-=(ulong)rc; return 1; }
 return rc==0 || rc==-11 || rc==-4;
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
 slong fd=sc(56,AT_FDCWD,(ulong)"/run/m11/logger.stop",0,0);
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
 if(!marker("/run/m11/logger.ready")) return 2;
 for(;;) {
  if(!stopping) {
   int rc=stop_boundary(&target);
   if(rc<0) return 6;
   if(rc>0) stopping=1;
  }
  if(!final) {
   if(efd<0) efd=sc(56,AT_FDCWD,(ulong)"/run/m11/events",NONBLOCK,0);
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
   if(stopping && event_bytes==target) {
    char b[100]="events="; ulong n=7;
    n+=decimal(b+n,event_bytes);
    static const char suffix[]=" kernel_drops=";
    for(ulong j=0;j<sizeof(suffix)-1;j++) b[n++]=suffix[j];
    n+=decimal(b+n,lost); b[n++]='\n';
    if(!frame('F',b,n)) return 6;
    final=1;
   }
  }
  if(tfd<0 && exists("/run/m11/usb.ready")) {
   tfd=sc(56,AT_FDCWD,(ulong)"/dev/ttyGS0",01|NONBLOCK|0400,0);
   if(tfd>=0 && !raw_tty_output((int)tfd)) return 8;
  }
  if(tfd>=0 && !drain((int)tfd)) return 4;
  if(stopping) {
   /* Earlier color branches intentionally never start USB. Their RAM-only
    * backlog cannot be delivered; finish locally, never claim host capture. */
   if(final && !exists("/run/m11/usb.ready")) break;
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
 if(!marker("/run/m11/logger.done")) return 5;
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
