/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "report.h"
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define JOURNAL_TAIL 4096
#define BOOT_TAIL 768
#define ERROR_TAIL 6144
#define KERNEL_TAIL 9216
#define PAGE_TEXT 1700
#define KERNEL_MAX (8u*1024*1024)
#define WIDTH 1080
#define HEIGHT 2400
#define SCALE 7
#define QUIET 4
#define DWELL_MS 5000
#define GLYPH 5
#define TEXT_X 30
#define TEXT_Y 170
#define TEXT_LINE 50
#define TEXT_COLUMNS 34
#define TEXT_LINES 6
/* Rows of ASCII 32..95, bit 4 on the left. Lower case is drawn as upper case. */
static const unsigned char font[64][7]={
 {0x00,0x00,0x00,0x00,0x00,0x00,0x00},{0x04,0x04,0x04,0x04,0x04,0x00,0x04},{0x0a,0x0a,0x00,0x00,0x00,0x00,0x00},{0x0a,0x1f,0x0a,0x0a,0x0a,0x1f,0x0a},
 {0x04,0x0f,0x14,0x0e,0x05,0x1e,0x04},{0x18,0x19,0x02,0x04,0x08,0x13,0x03},{0x08,0x14,0x14,0x08,0x15,0x12,0x0d},{0x04,0x04,0x00,0x00,0x00,0x00,0x00},
 {0x02,0x04,0x08,0x08,0x08,0x04,0x02},{0x08,0x04,0x02,0x02,0x02,0x04,0x08},{0x00,0x0a,0x04,0x1f,0x04,0x0a,0x00},{0x00,0x04,0x04,0x1f,0x04,0x04,0x00},
 {0x00,0x00,0x00,0x00,0x04,0x04,0x08},{0x00,0x00,0x00,0x1f,0x00,0x00,0x00},{0x00,0x00,0x00,0x00,0x00,0x00,0x04},{0x01,0x01,0x02,0x04,0x08,0x10,0x10},
 {0x0e,0x11,0x13,0x15,0x19,0x11,0x0e},{0x04,0x0c,0x04,0x04,0x04,0x04,0x0e},{0x0e,0x11,0x01,0x02,0x04,0x08,0x1f},{0x1f,0x02,0x04,0x02,0x01,0x11,0x0e},
 {0x02,0x06,0x0a,0x12,0x1f,0x02,0x02},{0x1f,0x10,0x1e,0x01,0x01,0x11,0x0e},{0x06,0x08,0x10,0x1e,0x11,0x11,0x0e},{0x1f,0x01,0x02,0x04,0x08,0x08,0x08},
 {0x0e,0x11,0x11,0x0e,0x11,0x11,0x0e},{0x0e,0x11,0x11,0x0f,0x01,0x02,0x0c},{0x00,0x00,0x04,0x00,0x00,0x04,0x00},{0x00,0x00,0x04,0x00,0x04,0x04,0x08},
 {0x02,0x04,0x08,0x10,0x08,0x04,0x02},{0x00,0x00,0x1f,0x00,0x1f,0x00,0x00},{0x08,0x04,0x02,0x01,0x02,0x04,0x08},{0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
 {0x0e,0x11,0x17,0x15,0x17,0x10,0x0e},{0x0e,0x11,0x11,0x1f,0x11,0x11,0x11},{0x1e,0x11,0x11,0x1e,0x11,0x11,0x1e},{0x0e,0x11,0x10,0x10,0x10,0x11,0x0e},
 {0x1e,0x11,0x11,0x11,0x11,0x11,0x1e},{0x1f,0x10,0x10,0x1e,0x10,0x10,0x1f},{0x1f,0x10,0x10,0x1e,0x10,0x10,0x10},{0x0e,0x11,0x10,0x17,0x11,0x11,0x0f},
 {0x11,0x11,0x11,0x1f,0x11,0x11,0x11},{0x0e,0x04,0x04,0x04,0x04,0x04,0x0e},{0x07,0x02,0x02,0x02,0x02,0x12,0x0c},{0x11,0x12,0x14,0x18,0x14,0x12,0x11},
 {0x10,0x10,0x10,0x10,0x10,0x10,0x1f},{0x11,0x1b,0x15,0x15,0x11,0x11,0x11},{0x11,0x19,0x15,0x13,0x11,0x11,0x11},{0x0e,0x11,0x11,0x11,0x11,0x11,0x0e},
 {0x1e,0x11,0x11,0x1e,0x10,0x10,0x10},{0x0e,0x11,0x11,0x11,0x15,0x12,0x0d},{0x1e,0x11,0x11,0x1e,0x14,0x12,0x11},{0x0f,0x10,0x10,0x0e,0x01,0x01,0x1e},
 {0x1f,0x04,0x04,0x04,0x04,0x04,0x04},{0x11,0x11,0x11,0x11,0x11,0x11,0x0e},{0x11,0x11,0x11,0x11,0x11,0x0a,0x04},{0x11,0x11,0x11,0x15,0x15,0x1b,0x11},
 {0x11,0x11,0x0a,0x04,0x0a,0x11,0x11},{0x11,0x11,0x0a,0x04,0x04,0x04,0x04},{0x1f,0x01,0x02,0x04,0x08,0x10,0x1f},{0x0e,0x08,0x08,0x08,0x08,0x08,0x0e},
 {0x10,0x10,0x08,0x04,0x02,0x01,0x01},{0x0e,0x02,0x02,0x02,0x02,0x02,0x0e},{0x04,0x0a,0x11,0x00,0x00,0x00,0x00},{0x00,0x00,0x00,0x00,0x00,0x00,0x1f},
};
static char raw[KERNEL_MAX],formatted[KERNEL_MAX],errors[KERNEL_MAX];
static size_t load(const char *dir,const char *name,char *b,size_t cap){
 char path[256];if(snprintf(path,sizeof(path),"%s/%s",dir,name)>=(int)sizeof(path))return 0;
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NONBLOCK);if(fd<0)return 0;
 size_t n=0;
 while(n<cap){ssize_t k=read(fd,b+n,cap-n);if(k<=0)break;n+=(size_t)k;}
 close(fd);return n;
}
static char printable(char c){return c>=32&&c<127?c:'?';}
/* The last bytes of b, from a line start, as printable text. */
static size_t tail(char *out,size_t cap,const char *title,const char *b,size_t n,size_t keep){
 size_t at=n>keep?n-keep:0,w=0;
 if(at){while(at<n&&b[at]!='\n')at++;if(at<n)at++;}
 int z=snprintf(out,cap,"--%s %zu\n",title,n);
 if(z<0||(size_t)z>=cap)return 0;
 w=(size_t)z;
 for(;at<n&&w<cap-1;at++)out[w++]=b[at]=='\n'?'\n':printable(b[at]);
 if(w&&w<cap-1&&out[w-1]!='\n')out[w++]='\n';
 return w;
}
/* kmsg records: "prio,seq,usec,flags[,...];text". Continuation lines start with a space. */
static void kernel_lines(size_t n,size_t *all,size_t *bad){
 size_t at=0,a=0,e=0;
 while(at<n){
  char *nl=memchr(raw+at,'\n',n-at);size_t end=nl?(size_t)(nl-raw):n;
  char *semi=memchr(raw+at,';',end-at);
  unsigned level=0;unsigned long long seq=0,usec=0;
  if(raw[at]!=' '&&semi&&sscanf(raw+at,"%u,%llu,%llu,",&level,&seq,&usec)==3){
   size_t text=(size_t)(semi-raw)+1;
   int z=snprintf(formatted+a,sizeof(formatted)-a,"%llu.%03llu %.*s\n",usec/1000000,usec/1000%1000,(int)(end-text),raw+text);
   if(z<0||(size_t)z>=sizeof(formatted)-a)break;
   if((level&7)<=3&&e+(size_t)z<sizeof(errors)){memcpy(errors+e,formatted+a,(size_t)z);e+=(size_t)z;}
   a+=(size_t)z;
  }
  at=end+1;
 }
 *all=a;*bad=e;
}
/* Journal lines read "<ms> text". PID1 journals "RED" right after the failing line. */
static void failing_line(const char *b,size_t n,char error[M15_REPORT_ERROR]){
 const char *line[2]={NULL,NULL},*found=NULL;size_t size[2]={0,0},found_n=0,at=0;
 while(at<n){
  const char *nl=memchr(b+at,'\n',n-at);size_t end=nl?(size_t)(nl-b):n;
  const char *p=b+at;size_t k=end-at;
  size_t digits=0;while(digits<k&&p[digits]>='0'&&p[digits]<='9')digits++;
  if(digits&&digits<k&&p[digits]==' '){p+=digits+1;k-=digits+1;}
  at=end+1;
  if(!k)continue;
  if(k==3&&!memcmp(p,"RED",3)){
   /* A connector failure journals its errno one line above its verdict. */
   int back=size[1]==16&&line[1]&&!memcmp(line[1],"CONNECTOR_FAILED",16)&&line[0];
   found=line[back?0:1];found_n=size[back?0:1];continue;
  }
  line[0]=line[1];size[0]=size[1];line[1]=p;size[1]=k;
 }
 if(!found){found=line[1];found_n=size[1];}
 if(!found){found="no PID1 journal";found_n=15;}
 if(found_n>M15_REPORT_ERROR-1)found_n=M15_REPORT_ERROR-1;
 for(size_t i=0;i<found_n;i++)error[i]=printable(found[i]);
 error[found_n]=0;
}
size_t m15_report_text(const char *dir,char *out,size_t cap,char error[M15_REPORT_ERROR]){
 size_t w=0,n,all,bad;
 n=load(dir,"pid1.journal",raw,sizeof(raw));failing_line(raw,n,error);
 int z=snprintf(out,cap,"--error %s\n",error);if(z<0||(size_t)z>=cap)return 0;
 w=(size_t)z;w+=tail(out+w,cap-w,"journal",raw,n,JOURNAL_TAIL);
 n=load(dir,"bootstrap.log",raw,sizeof(raw));w+=tail(out+w,cap-w,"bootstrap",raw,n,BOOT_TAIL);
 n=load(dir,"kernel.raw",raw,sizeof(raw));kernel_lines(n,&all,&bad);
 w+=tail(out+w,cap-w,"kernel-errors",errors,bad,ERROR_TAIL);
 w+=tail(out+w,cap-w,"kernel-tail",formatted,all,KERNEL_TAIL);
 return w;
}
unsigned m15_report_paginate(const char *text,size_t n,size_t start[M15_REPORT_PAGES+1]){
 unsigned pages=0;size_t at=0;
 while(pages<M15_REPORT_PAGES){
  start[pages++]=at;
  size_t left=n-at,take=left>PAGE_TEXT?PAGE_TEXT:left;
  if(take==left){at=n;break;}
  size_t cut=take;
  while(cut>PAGE_TEXT/2&&text[at+cut-1]!='\n')cut--;
  at+=text[at+cut-1]=='\n'?cut:take;
 }
 start[pages]=at;
 return pages;
}
size_t m15_report_page(const char *text,const size_t start[M15_REPORT_PAGES+1],unsigned page,unsigned pages,char *out,size_t cap){
 int z=snprintf(out,cap,"M15 RED %u/%u\n",page+1,pages);
 if(z<0||(size_t)z>=cap)return 0;
 size_t n=start[page+1]-start[page];
 if(n>cap-(size_t)z)n=cap-(size_t)z;
 memcpy(out+z,text+start[page],n);
 return (size_t)z+n;
}
static void box(void *map,uint32_t pitch,unsigned x0,unsigned y0,unsigned w,unsigned h,uint32_t color){
 for(unsigned y=y0;y<y0+h&&y<HEIGHT;y++){
  volatile uint32_t *row=(volatile uint32_t *)((unsigned char *)map+(size_t)y*pitch);
  for(unsigned x=x0;x<x0+w&&x<WIDTH;x++)row[x]=color;
 }
}
static void letter(void *map,uint32_t pitch,unsigned x,unsigned y,char c){
 if(c>='a'&&c<='z')c=(char)(c-'a'+'A');
 if(c<32||c>95)c='?';
 const unsigned char *g=font[c-32];
 for(unsigned r=0;r<7;r++)for(unsigned k=0;k<5;k++)if((g[r]>>(4-k))&1)
  box(map,pitch,x+k*GLYPH,y+r*GLYPH,GLYPH,GLYPH,0x00ffffff);
}
static void words(void *map,uint32_t pitch,const char *s,unsigned first){
 for(unsigned line=first;line<TEXT_LINES&&*s;line++)
  for(unsigned i=0;i<TEXT_COLUMNS&&*s;i++)letter(map,pitch,TEXT_X+i*6*GLYPH,TEXT_Y+line*TEXT_LINE,*s++);
}
void m15_report_show(void *map,uint32_t pitch,const char *error,const unsigned char m[M15_QR_SIZE][M15_QR_SIZE],unsigned page,unsigned pages){
 const unsigned side=(M15_QR_SIZE+2*QUIET)*SCALE,x0=(WIDTH-side)/2,y0=(HEIGHT-side)/2;
 words(map,pitch,"M15 ERROR:",0);words(map,pitch,error,1);
 box(map,pitch,x0,y0,side,side,0x00ffffff);
 for(unsigned y=0;y<M15_QR_SIZE;y++)for(unsigned x=0;x<M15_QR_SIZE;x++)if(m[y][x])
  box(map,pitch,x0+(QUIET+x)*SCALE,y0+(QUIET+y)*SCALE,SCALE,SCALE,0);
 /* Position marks: the bright square is the page on screen. */
 for(unsigned i=0;i<pages;i++)box(map,pitch,(WIDTH-pages*60)/2+i*60,y0+side+60,44,44,i==page?0x00ffffff:0x00600000);
}
_Noreturn void m15_report_loop(void *map,uint32_t pitch,const char *dir){
 static char text[24576],page[M15_QR_CAPACITY];
 static unsigned char modules[M15_QR_SIZE][M15_QR_SIZE];
 char error[M15_REPORT_ERROR];size_t start[M15_REPORT_PAGES+1];
 size_t n=m15_report_text(dir,text,sizeof(text),error);
 unsigned pages=m15_report_paginate(text,n,start);
 for(unsigned i=0;;i=(i+1)%pages){
  size_t k=m15_report_page(text,start,i,pages,page,sizeof(page));
  if(!m15_qr_encode(page,k,modules))m15_report_show(map,pitch,error,modules,i,pages);
  (void)poll(NULL,0,DWELL_MS);
 }
}
