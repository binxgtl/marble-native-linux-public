/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "display-loop.h"
#include "report.h"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifndef M15_REPORT_DIR
#define M15_REPORT_DIR "/run/m15"
#endif
const char *m15_display_ready="M15DISPLAY 0 BLUE committed\n";
static void paint(void *map,uint32_t pitch,uint32_t color){
 for(unsigned y=0;y<2400;y++){
  volatile uint32_t *row=(volatile uint32_t *)((unsigned char *)map+(size_t)y*pitch);
  for(unsigned x=0;x<1080;x++)row[x]=color;
 }
 __sync_synchronize();
}
_Noreturn void m15_display_loop(void *map,uint32_t pitch){
 signal(SIGPIPE,SIG_IGN);
 unsigned seq=1;char line[64];size_t at=0;
 size_t ready=strlen(m15_display_ready);
 ssize_t n=write(3,m15_display_ready,ready);
 if(n!=(ssize_t)ready)goto hold;
 for(;;){
  struct pollfd p={0,POLLIN,0};int r=poll(&p,1,-1);
  if(r<0&&errno==EINTR)continue;
  if(r<=0)goto hold;
  char c;n=read(0,&c,1);
  if(n<0&&errno==EINTR)continue;
  if(n!=1||at>=sizeof(line)-1)goto hold;
  if(c!='\n'){if(c<32||c>126)goto hold;line[at++]=c;continue;}
  line[at]=0;at=0;
  char expected[64],ack[64];const char *colors[]={"BLUE","YELLOW","GREEN","CYAN","COMPLETE","RED"};
  uint32_t rgb[]={0x000000ff,0x00ffff00,0x0000ff00,0x0000ffff,0x00ffffff,0x00ff0000};
  int found=-1;
  for(int i=0;i<6;i++){snprintf(expected,sizeof(expected),"M15COLOR %u %s",seq,colors[i]);if(!strcmp(line,expected)){found=i;break;}}
  if(found<0)goto hold;
  paint(map,pitch,rgb[found]);
  int z=snprintf(ack,sizeof(ack),"M15DISPLAY %u %s mapped\n",seq++,colors[found]);
  n=write(3,ack,(size_t)z);if(n!=z)goto hold;
  if(!strcmp(colors[found],"RED"))m15_report_loop(map,pitch,M15_REPORT_DIR);
 }
hold:
 paint(map,pitch,0x00ff0000);
 /* No close, disable, free, retry or reboot on IPC/renderer failure. */
 m15_report_loop(map,pitch,M15_REPORT_DIR);
}
