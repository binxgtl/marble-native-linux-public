/* SPDX-License-Identifier: GPL-2.0-only */
/* Writes each RED page as PBM plus one full frame. test-report.py reads them with a real QR reader. */
#include "qr.h"
#include "report.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(int argc,char **argv){
 assert(argc==3);
 static char text[24576],page[M15_QR_CAPACITY];
 static unsigned char m[M15_QR_SIZE][M15_QR_SIZE];
 static uint32_t frame[1080*2400];
 char error[M15_REPORT_ERROR],name[256];
 size_t start[M15_REPORT_PAGES+1];
 size_t n=m15_report_text(argv[1],text,sizeof(text),error);
 assert(n&&n<sizeof(text));
 unsigned pages=m15_report_paginate(text,n,start);
 assert(pages&&pages<=M15_REPORT_PAGES&&start[0]==0&&start[pages]==n);
 for(unsigned i=0;i<pages;i++){
  assert(start[i]<start[i+1]);
  size_t k=m15_report_page(text,start,i,pages,page,sizeof(page));
  assert(k&&k<=M15_QR_CAPACITY&&!m15_qr_encode(page,k,m));
  snprintf(name,sizeof(name),"%s/page-%02u.pbm",argv[2],i);
  FILE *f=fopen(name,"w");assert(f);
  const int scale=4,quiet=4,side=(M15_QR_SIZE+2*quiet)*scale;
  fprintf(f,"P1\n%d %d\n",side,side);
  for(int y=0;y<side;y++){
   for(int x=0;x<side;x++){
    int my=y/scale-quiet,mx=x/scale-quiet;
    fputc(my>=0&&mx>=0&&my<M15_QR_SIZE&&mx<M15_QR_SIZE&&m[my][mx]?'1':'0',f);
   }
   fputc('\n',f);
  }
  assert(!fclose(f));
  snprintf(name,sizeof(name),"%s/page-%02u.txt",argv[2],i);
  f=fopen(name,"wb");assert(f);assert(fwrite(page,1,k,f)==k);assert(!fclose(f));
 }
 /* The first page as the panel gets it: red fill, error text, QR, page marks. */
 size_t k=m15_report_page(text,start,0,pages,page,sizeof(page));
 assert(!m15_qr_encode(page,k,m));
 for(size_t i=0;i<sizeof(frame)/sizeof(frame[0]);i++)frame[i]=0x00ff0000;
 m15_report_show(frame,1080*4,error,m,0,pages);
 assert(frame[0]==0x00ff0000&&frame[1080*2400-1]==0x00ff0000);
 snprintf(name,sizeof(name),"%s/frame.raw",argv[2]);
 FILE *f=fopen(name,"wb");assert(f);assert(fwrite(frame,sizeof(frame),1,f)==1);assert(!fclose(f));
 snprintf(name,sizeof(name),"%s/error.txt",argv[2]);
 f=fopen(name,"wb");assert(f);fputs(error,f);assert(!fclose(f));
 assert(m15_qr_encode(page,M15_QR_CAPACITY+1,m)<0);
 printf("%u\n",pages);
}
