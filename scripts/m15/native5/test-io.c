/* SPDX-License-Identifier: GPL-2.0-only */
#include "io.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
int main(void){
 struct klog s={0};const unsigned char a[]="6,123,456,-;message\n KEY=value\n",b[]="6,124,457,c;continuation\n";
 assert(!klog_record(&s,a,sizeof(a)-1,1000));assert(!klog_record(&s,b,sizeof(b)-1,1000));assert(s.first==123&&s.last==124);
 assert(klog_record(&s,b,sizeof(b)-1,1000)<0&&s.failed);
 s=(struct klog){0};assert(klog_record(&s,a,sizeof(a)-1,2)<0);
 s=(struct klog){0};assert(klog_record(&s,a,sizeof(a)-2,1000)<0);
 s=(struct klog){0};const unsigned char bad[]="6,18446744073709551616,0,-;bad\n";assert(klog_record(&s,bad,sizeof(bad)-1,1000)<0);
 char buf[16];struct read_fact f=read_attribute("/m15-does-not-exist",buf,sizeof(buf));assert(f.count==-1&&f.error==ENOENT);
 assert(configured_pc("configured\n",11));assert(!configured_pc("configured",10));assert(!configured_pc("USB_PD\n",7));
 puts("PASS kernel record gap/overflow/extended record and real getter errno; no device opened");return 0;
}
