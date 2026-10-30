/* SPDX-License-Identifier: GPL-2.0-only */
/* ISO/IEC 18004 symbol writer reduced to one version, level and mask. RAM only. */
#include "qr.h"
#include <stdint.h>
#include <string.h>
#define VERSION 30
#define DATA_WORDS 1735
#define EC_WORDS 30
#define SHORT_BLOCKS 5
#define SHORT_DATA 115
#define BLOCKS 15
#define FORMAT_L_MASK0 0x08 /* level L is 01, mask is 000 */
static const int align[]={6,26,52,78,104,130};
static uint8_t mul(uint8_t a,uint8_t b){
 uint8_t r=0;
 for(int i=0;i<8;i++){if(b&1)r^=a;b>>=1;a=(uint8_t)((a<<1)^((a&0x80)?0x1d:0));}
 return r;
}
static void generator(uint8_t g[EC_WORDS]){
 /* Coefficients below x^30 of the product of (x + 2^i). */
 uint8_t root=1;memset(g,0,EC_WORDS);g[EC_WORDS-1]=1;
 for(int i=0;i<EC_WORDS;i++){
  for(int j=0;j<EC_WORDS;j++){g[j]=mul(g[j],root);if(j+1<EC_WORDS)g[j]^=g[j+1];}
  root=mul(root,2);
 }
}
static void remainder_of(const uint8_t *data,size_t n,const uint8_t g[EC_WORDS],uint8_t out[EC_WORDS]){
 memset(out,0,EC_WORDS);
 for(size_t i=0;i<n;i++){
  uint8_t factor=data[i]^out[0];
  memmove(out,out+1,EC_WORDS-1);out[EC_WORDS-1]=0;
  for(int j=0;j<EC_WORDS;j++)out[j]^=mul(g[j],factor);
 }
}
static void codewords(const uint8_t *text,size_t n,uint8_t out[DATA_WORDS+BLOCKS*EC_WORDS]){
 uint8_t data[DATA_WORDS]={0};size_t bit=0;
 #define PUT(value,bits) for(int b=(bits)-1;b>=0;b--,bit++)if(((value)>>b)&1)data[bit/8]|=(uint8_t)(0x80>>(bit%8))
 PUT(4u,4);PUT((unsigned)n,16);
 for(size_t i=0;i<n;i++)PUT((unsigned)text[i],8);
 #undef PUT
 bit+=4;/* terminator; capacity leaves room */
 size_t at=(bit+7)/8;
 for(int pad=0xec;at<DATA_WORDS;at++,pad^=0xfd)data[at]=(uint8_t)pad;
 uint8_t g[EC_WORDS],ec[BLOCKS][EC_WORDS];generator(g);
 const uint8_t *start[BLOCKS];size_t lengths[BLOCKS],offset=0;
 for(int i=0;i<BLOCKS;i++){
  lengths[i]=SHORT_DATA+(i>=SHORT_BLOCKS);start[i]=data+offset;offset+=lengths[i];
  remainder_of(start[i],lengths[i],g,ec[i]);
 }
 size_t w=0;
 for(size_t i=0;i<=SHORT_DATA;i++)for(int b=0;b<BLOCKS;b++)if(i<lengths[b])out[w++]=start[b][i];
 for(int i=0;i<EC_WORDS;i++)for(int b=0;b<BLOCKS;b++)out[w++]=ec[b][i];
}
static unsigned bch(unsigned data,int degree,unsigned poly){
 unsigned r=data<<degree;
 for(int i=31;i>=degree;i--)if((r>>i)&1)r^=poly<<(i-degree);
 return (data<<degree)|r;
}
int m15_qr_encode(const void *text,size_t n,unsigned char m[M15_QR_SIZE][M15_QR_SIZE]){
 if(n>M15_QR_CAPACITY)return -1;
 static unsigned char fixed[M15_QR_SIZE][M15_QR_SIZE];
 const int size=M15_QR_SIZE;
 memset(m,0,M15_QR_SIZE*M15_QR_SIZE);memset(fixed,0,sizeof(fixed));
 #define SET(x,y,v) do{m[y][x]=(unsigned char)(v);fixed[y][x]=1;}while(0)
 for(int i=0;i<size;i++){SET(6,i,!(i&1));SET(i,6,!(i&1));}
 const int corner[3][2]={{3,3},{size-4,3},{3,size-4}};
 for(int c=0;c<3;c++)for(int dy=-4;dy<=4;dy++)for(int dx=-4;dx<=4;dx++){
  int x=corner[c][0]+dx,y=corner[c][1]+dy,d=(dx<0?-dx:dx)>(dy<0?-dy:dy)?(dx<0?-dx:dx):(dy<0?-dy:dy);
  if(x>=0&&y>=0&&x<size&&y<size)SET(x,y,d!=2&&d!=4);
 }
 for(int a=0;a<6;a++)for(int b=0;b<6;b++){
  if((a==0&&b==0)||(a==0&&b==5)||(a==5&&b==0))continue;
  for(int dy=-2;dy<=2;dy++)for(int dx=-2;dx<=2;dx++){
   int d=(dx<0?-dx:dx)>(dy<0?-dy:dy)?(dx<0?-dx:dx):(dy<0?-dy:dy);
   SET(align[b]+dx,align[a]+dy,d!=1);
  }
 }
 unsigned format=bch(FORMAT_L_MASK0,10,0x537)^0x5412;
 for(int i=0;i<=5;i++)SET(8,i,(format>>i)&1);
 SET(8,7,(format>>6)&1);SET(8,8,(format>>7)&1);SET(7,8,(format>>8)&1);
 for(int i=9;i<15;i++)SET(14-i,8,(format>>i)&1);
 for(int i=0;i<8;i++)SET(size-1-i,8,(format>>i)&1);
 for(int i=8;i<15;i++)SET(8,size-15+i,(format>>i)&1);
 SET(8,size-8,1);
 unsigned version=bch(VERSION,12,0x1f25);
 for(int i=0;i<18;i++){
  int a=size-11+i%3,b=i/3,v=(version>>i)&1;
  SET(a,b,v);SET(b,a,v);
 }
 #undef SET
 uint8_t words[DATA_WORDS+BLOCKS*EC_WORDS];codewords(text,n,words);
 size_t bit=0,total=sizeof(words)*8;
 for(int right=size-1;right>=1;right-=2){
  if(right==6)right=5;
  int upward=((right+1)&2)==0;
  for(int step=0;step<size;step++)for(int j=0;j<2;j++){
   int x=right-j,y=upward?size-1-step:step;
   if(fixed[y][x])continue;
   int dark=bit<total&&((words[bit/8]>>(7-bit%8))&1);
   bit++;
   m[y][x]=(unsigned char)(dark^!((x+y)%2));
  }
 }
 return 0;
}
