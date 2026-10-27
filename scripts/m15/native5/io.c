/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "io.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
struct read_fact read_attribute(const char *path,char *b,size_t cap){
 struct read_fact r={-1,0,0};
 if(!path||!b||cap<2){r.error=EINVAL;return r;}
 int fd=open(path,O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW);
 if(fd<0){r.error=errno;return r;}
 r.count=read(fd,b,cap);if(r.count<0)r.error=errno;
 else if((size_t)r.count==cap)r.error=EOVERFLOW;
 if(close(fd))r.close_error=errno;
 return r;
}
int configured_pc(const char *b,size_t n){return n==11&&!memcmp(b,"configured\n",11);}
static int decimal(const unsigned char *b,size_t n,size_t *p,uint64_t *v,unsigned char end){
 *v=0;size_t start=*p;
 while(*p<n&&b[*p]>='0'&&b[*p]<='9'){
  unsigned d=b[(*p)++]-'0';if(*v>(UINT64_MAX-d)/10)return -1;*v=*v*10+d;
 }
 if(*p==start||*p>=n||b[(*p)++]!=end)return -1;
 return 0;
}
int klog_record(struct klog *s,const unsigned char *b,size_t n,size_t budget){
 size_t p=0;uint64_t priority,seq,time;
 if(s->failed)return -1;
 if(!n||n>budget||s->bytes>budget-n||b[n-1]!='\n'||
    decimal(b,n,&p,&priority,',')||decimal(b,n,&p,&seq,',')||decimal(b,n,&p,&time,','))goto fail;
 (void)priority;(void)time;
 size_t flags=p;while(p<n&&b[p]!=';'&&b[p]!='\n')p++;
 if(p==flags||p==n||b[p++]!=';')goto fail;
 for(size_t i=p;i<n;i++)if(!b[i])goto fail;
 if(s->have&&(s->last==UINT64_MAX||seq!=s->last+1))goto fail;
 if(!s->have)s->first=seq;
 s->have=1;s->last=seq;s->bytes+=n;return 0;
fail:s->failed=1;return -1;
}
int klog_read(int fd,struct klog *s,unsigned char *b,size_t cap,size_t budget,struct read_fact *r){
 r->count=read(fd,b,cap);r->error=r->count<0?errno:0;r->close_error=0;
 if(r->count<0&&(r->error==EAGAIN||r->error==EINTR))return 0;
 if(r->count<=0){s->failed=1;return -1;}
 return klog_record(s,b,(size_t)r->count,budget)?-1:1;
}
