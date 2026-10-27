/* SPDX-License-Identifier: GPL-2.0-only */
#include "connector.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static int feed(struct connector *s,unsigned seq,const char *action,const char *path,int peer,int trunc){
 char b[1200];int n=snprintf(b,sizeof(b),"%s@%s%cACTION=%s%cDEVPATH=%s%cSUBSYSTEM=typec%cSEQNUM=%u%c",action,path,0,action,0,path,0,0,seq,0);
 return connector_event(s,b,(size_t)n,peer,trunc);
}
int main(void){
 const char *p="/devices/fixture/typec/port0/port0-partner";struct connector s={.attached=1};strcpy(s.partner,p);
 assert(feed(&s,1,"remove",p,1,0)==2);assert(!s.attached);
 assert(feed(&s,2,"change","/devices/unrelated",1,0)==0);
 assert(feed(&s,3,"add",p,1,0)==1);assert(s.attached);
 assert(feed(&s,4,"remove",p,1,0)==2);assert(feed(&s,5,"add",p,1,0)==1);
 for(int mode=0;mode<8;mode++){
  struct connector x={.attached=1};strcpy(x.partner,p);assert(feed(&x,10,"change",p,1,0)==0);
  int r=feed(&x,mode==0?12:mode==1?10:11,mode==2?"add":mode==3?"bind":"remove",p,mode!=4,mode==5);
  if(mode<6){assert(r<0&&x.failed);assert(feed(&x,13,"remove",p,1,0)<0);}
  else {assert(r==2);assert(feed(&x,12,"remove",p,1,0)<0);}
 }
 for(size_t n=0;n<20;n++){struct connector x={0};strcpy(x.partner,p);char b[20];memset(b,'x',sizeof(b));assert(connector_event(&x,b,n,1,0)<0);}
 struct connector x={0};strcpy(x.partner,p);
 const char duplicate[]="add@/x\0ACTION=add\0ACTION=remove\0DEVPATH=/x\0SUBSYSTEM=typec\0SEQNUM=1\0";
 assert(connector_event(&x,duplicate,sizeof(duplicate)-1,1,0)<0);
 puts("PASS connector kernel-peer, strict sequence, add/remove, wrong path, loss, duplicate and truncation fixtures; physical runtime UNKNOWN");
}
