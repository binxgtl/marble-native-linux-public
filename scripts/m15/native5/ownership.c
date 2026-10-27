/* SPDX-License-Identifier: GPL-2.0-only */
#include "ownership.h"
#include <sys/wait.h>
int parent_add(struct parent_ledger *s,pid_t pid,enum role role){
 if(s->failed||pid<=1||s->count==4||role<CUSTODIAN||role>KMSG){s->failed=1;return -1;}
 for(unsigned i=0;i<s->count;i++)if(s->owners[i].pid==pid||s->owners[i].role==role){s->failed=1;return -1;}
 s->owners[s->count++]=(struct parent_owner){pid,role,0,0};return 0;
}
int parent_wait(struct parent_ledger *s,pid_t pid,int status){
 if(status<0||status>65535||(!WIFEXITED(status)&&!WIFSIGNALED(status))){s->failed=1;return -1;}
 for(unsigned i=0;i<s->count;i++)if(s->owners[i].pid==pid&&!s->owners[i].reaped){
  s->owners[i].reaped=1;s->owners[i].status=status;
  /* No release command exists in this preparation, so custodian death always
   * loses sole-owner RAM. Keep waiting adopted children without clearing HOLD. */
  if(s->owners[i].role==CUSTODIAN){s->escrow_lost=1;s->failed=1;return -1;}
  if(status){s->failed=1;return -1;}return 0;
 }
 s->failed=1;return -1;
}
int parent_custodian_live(const struct parent_ledger *s){
 if(s->failed)return 0;
 for(unsigned i=0;i<s->count;i++)if(s->owners[i].role==CUSTODIAN)return !s->owners[i].reaped;
 return 0;
}
