/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "connector.h"
#include <stdio.h>
#include <string.h>
static int fail(struct connector *s){s->failed=1;return -1;}
int connector_event(struct connector *s,const void *data,size_t size,int kernel,int truncated){
 const char *b=data,*action=NULL,*path=NULL,*sub=NULL,*seq=NULL;
 if(s->failed||!kernel||truncated||!size||size>16384||b[size-1])return fail(s);
 size_t at=0,first=0;
 while(at<size){
  size_t n=strnlen(b+at,size-at);if(n==size-at)return fail(s);
  const char *p=b+at;if(!at)first=n;
  else if(!strncmp(p,"ACTION=",7)){if(action)return fail(s);action=p+7;}
  else if(!strncmp(p,"DEVPATH=",8)){if(path)return fail(s);path=p+8;}
  else if(!strncmp(p,"SUBSYSTEM=",10)){if(sub)return fail(s);sub=p+10;}
  else if(!strncmp(p,"SEQNUM=",7)){if(seq)return fail(s);seq=p+7;}
  at+=n+1;
 }
 if(!action||!path||!sub||!seq||!*seq)return fail(s);
 uint64_t value=0;
 for(const char *p=seq;*p;p++){if(*p<'0'||*p>'9'||value>(UINT64_MAX-(*p-'0'))/10)return fail(s);value=value*10+(*p-'0');}
 if(!value||(s->have&&(s->sequence==UINT64_MAX||value!=s->sequence+1)))return fail(s);
 char header[1024];int z=snprintf(header,sizeof(header),"%s@%s",action,path);
 if(z<0||(size_t)z!=first||memcmp(header,b,first))return fail(s);
 s->sequence=value;s->have=1;
 if(strcmp(sub,"typec")||strcmp(path,s->partner))return 0;
 if(!strcmp(action,"add")){if(s->attached)return fail(s);s->attached=1;return 1;}
 if(!strcmp(action,"remove")){if(!s->attached)return fail(s);s->attached=0;return 2;}
 if(strcmp(action,"change"))return fail(s);
 return 0;
}
