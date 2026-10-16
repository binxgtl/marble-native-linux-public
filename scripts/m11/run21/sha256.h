/* FIPS 180-4 SHA-256, fixed-width unsigned arithmetic; freestanding C.
 * Validated against independent hashlib and published known-answer vectors. */
typedef unsigned int u32;
typedef unsigned long long u64;
typedef struct { u32 h[8]; u64 bytes; unsigned char block[64]; unsigned at; } Sha256;
static u32 rotr(u32 x,unsigned n) { return (x>>n)|(x<<(32-n)); }
static void sha_block(Sha256 *s)
{
 static const u32 k[64]={
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
 u32 w[64];
 for(unsigned i=0;i<16;i++) w[i]=(u32)s->block[4*i]<<24|(u32)s->block[4*i+1]<<16|(u32)s->block[4*i+2]<<8|s->block[4*i+3];
 for(unsigned i=16;i<64;i++) {
  u32 a=w[i-15],b=w[i-2];w[i]=w[i-16]+(rotr(a,7)^rotr(a,18)^(a>>3))+w[i-7]+(rotr(b,17)^rotr(b,19)^(b>>10));
 }
 u32 a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
 for(unsigned i=0;i<64;i++) {
  u32 t=h+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^(~e&g))+k[i]+w[i];
  u32 v=(rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c));
  h=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+v;
 }
 s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static void sha_init(Sha256 *s) {
 const u32 h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
 for(unsigned i=0;i<8;i++){s->h[i]=h[i];}
 s->bytes=0;s->at=0;
}
static void sha_update(Sha256 *s,const char *p,ulong n) {
 s->bytes+=n;
 for(ulong i=0;i<n;i++){s->block[s->at++]=(unsigned char)p[i];if(s->at==64){sha_block(s);s->at=0;}}
}
static void sha_hex(Sha256 s,char *out) {
 u64 bits=s.bytes*8;s.block[s.at++]=0x80;
 if(s.at>56){while(s.at<64)s.block[s.at++]=0;sha_block(&s);s.at=0;}
 while(s.at<56)s.block[s.at++]=0;
 for(unsigned i=0;i<8;i++)s.block[56+i]=(unsigned char)(bits>>(56-8*i));
 sha_block(&s);
 const char hex[]="0123456789abcdef";
 for(unsigned i=0;i<32;i++){unsigned char v=(unsigned char)(s.h[i/4]>>(24-8*(i%4)));out[2*i]=hex[v>>4];out[2*i+1]=hex[v&15];}
}
