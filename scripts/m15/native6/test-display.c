/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "display-loop.h"
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void){
 size_t size=1080*2400*4;uint32_t *map=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
 assert(map!=MAP_FAILED);int in[2],out[2];assert(!pipe(in)&&!pipe(out));pid_t p=fork();assert(p>=0);
 if(!p){assert(dup2(in[0],0)==0);assert(dup2(out[1],3)==3);m15_display_loop(map,4320);}
 close(in[0]);close(out[1]);FILE *f=fdopen(out[0],"r");assert(f);char b[128];
 assert(fgets(b,sizeof(b),f)&&!strcmp(b,"M15DISPLAY 0 BLUE committed\n"));
 const char *names[]={"YELLOW","GREEN","CYAN","COMPLETE"};uint32_t colors[]={0xffff00,0xff00,0xffff,0xffffff};
 for(unsigned i=0;i<4;i++){
  int n=snprintf(b,sizeof(b),"M15COLOR %u %s\n",i+1,names[i]);assert(write(in[1],b,(size_t)n)==n);
  assert(fgets(b,sizeof(b),f));assert(strstr(b," mapped\n"));
  assert(map[0]==colors[i]&&map[1080*2400-1]==colors[i]);
  int status;assert(waitpid(p,&status,WNOHANG)==0);
 }
 /* Invalid sequence retains renderer alive, paints RED. */
 assert(write(in[1],"M15COLOR 4 GREEN\n",17)==17);
 for(int i=0;i<1000&&map[0]!=0xff0000;i++)usleep(1000);
 assert(map[0]==0xff0000);int status;assert(waitpid(p,&status,WNOHANG)==0);
 assert(!kill(p,SIGKILL));assert(waitpid(p,&status,0)==p); /* fixture cleanup only */
 fclose(f);close(in[1]);assert(!munmap(map,size));puts("PASS continuous shared-canvas transitions and invalid-sequence retention; no DRM");
}
