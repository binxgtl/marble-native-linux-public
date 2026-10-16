/* Execute production framing/SHA/partial-write code with no device operations. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define M11_RELAY_TEST
static long sc(long,unsigned long,unsigned long,unsigned long,unsigned long);
#include "kmsg-relay.c"
static char output[3*CAP];static unsigned long out_size,calls;static int fatal,backpressure;
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
static char big[RECORD];
static long sc(long nr,unsigned long a,unsigned long b,unsigned long c,unsigned long d) {
 (void)a;(void)d;assert(nr==64);calls++;
 if(fatal)return (long)c+1;
 if(backpressure || calls%19==0)return -11;
 if(calls%23==0)return -4;
 if(calls%29==0)return 0;
 unsigned long n=1+calls%4096;if(n>c)n=c;
 assert(out_size+n<=sizeof(output));memcpy(output+out_size,(void *)b,n);out_size+=n;return (long)n;
}
int main(int argc,char **argv) {
 (void)&relay;assert(sizeof(u32)==4 && sizeof(u64)==8);
 assert(CAP==4194304u && EVENT_RESERVE==1114112u);
 Sha256 s;char hex[64];sha_init(&s);sha_hex(s,hex);
 assert(!memcmp(hex,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",64));
 sha_update(&s,"abc",3);sha_hex(s,hex);
 assert(!memcmp(hex,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",64));
 sha_init(&s);for(unsigned i=0;i<1000000;i++)sha_update(&s,"a",1);sha_hex(s,hex);
 assert(!memcmp(hex,"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",64));
 sha_init(&constructed);sha_init(&accepted);
 const char start[]="run=M11R22 nonce=0123456789abcdef0123456789abcdef\n";
 assert(frame('S',start,sizeof(start)-1));
 backpressure=1;ulong prior=used;assert(drain(1) && used==prior && !tty_bytes);backpressure=0;
 /* 24000 frames (~5.6 MB) exceed the 4 MiB ring, so the ring wraps. */
 for(unsigned i=0;i<24000;i++){
  char payload[1024];int n=snprintf(payload,sizeof(payload),"6,%u,123,-;",i);
  memset(payload+n,'a'+i%26,201);payload[n+201]='\n';assert(frame('K',payload,(ulong)n+202));
  while(used>4096)assert(drain(1));
 }
 assert(frame('E',journal,sizeof(journal)-1));event_bytes=sizeof(journal)-1;
 if(argc>2)lost=1; /* Inject truthful terminal loss with no interior seq gap. */
 assert(!seal());while(used){assert(drain(1));}assert(seal());
 while(used){assert(drain(1));}assert(tty_bytes==wire_bytes && wire_bytes>CAP);
 if(argc>1){FILE *f=fopen(argv[1],"wb");assert(f);assert(fwrite(output,1,out_size,f)==out_size);assert(!fclose(f));}
 lost=0;sealed=0;head=0;used=CAP-EVENT_RESERVE-1;ulong old=used,seq=sequence;
 assert(frame('K',"xx",2) && used==old && lost==1 && sequence==seq);
 used=CAP-1;assert(!frame('E',"xx",2));
 /* Run20's whole 131072-byte reserve is now only a fraction of the 1 MiB + 64 KiB event reserve:
  * nine undrained 16 KiB E frames (> 131072) and a full-size E frame at the K limit are accepted. */
 memset(big,'e',sizeof(big));head=0;used=0;lost=0;
 for(unsigned i=0;i<9;i++)assert(frame('E',big,sizeof(big)));
 assert(used>131072u && lost==0);
 head=0;used=CAP-EVENT_RESERVE;assert(frame('E',big,sizeof(big)) && lost==0);
 head=0;used=CAP-EVENT_RESERVE;assert(frame('K',big,sizeof(big)) && lost==1);
 used=1;head=0;fatal=1;assert(!drain(1));
 puts("PASS SHA known answers, >4MiB ring wrap, 24000 frames, short writes/EAGAIN/EINTR/backpressure, seal after drain only, oversized-write rejection, >131072-byte E backlog and 1MiB+64KiB reserve; no hardware");
}
