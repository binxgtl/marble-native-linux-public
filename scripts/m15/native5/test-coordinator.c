/* SPDX-License-Identifier: GPL-2.0-only */
#include "coordinator.h"
#include "ownership.h"
#include <assert.h>
#include <stdio.h>
static void next(struct coordinator *s,enum fact f){assert(!coord_fact(s,f,s->sequence,s->last+1));}
static void reach(struct coordinator *s,enum stage stop){
 coord_init(s,0);if(stop==START)return;next(s,INITIALIZED);next(s,PC_ADMITTED);if(stop==BLUE)return;
 next(s,PC_DETACHED);if(stop==YELLOW_WAIT)return;next(s,WALL_ATTACHED);if(stop==YELLOW_CAPTURE)return;
 s->collector_reaped=1;s->census_closed=1;next(s,COLLECTOR_FROZEN);if(stop==GREEN)return;
 next(s,PC_RECONNECTED);if(stop==CYAN)return;next(s,HOST_ACK);
}
int main(void){
 struct coordinator s;reach(&s,COMPLETE);next(&s,PARENT_RECEIPT);assert(s.parent_receipt&&s.custodian_owned&&!s.custodian_reaped);int n=1;
 struct parent_ledger l={0};assert(!parent_custodian_live(&l));
 assert(!parent_add(&l,12,CUSTODIAN));assert(!parent_add(&l,13,DISPLAY));assert(parent_custodian_live(&l));
 assert(!parent_wait(&l,13,0));assert(parent_custodian_live(&l));
 assert(parent_wait(&l,12,0)<0&&l.escrow_lost&&!parent_custodian_live(&l));n++;
 assert(parent_wait(&l,14,0)<0);n++;
 for(enum stage st=START;st<=CYAN;st++){
  reach(&s,st);assert(coord_tick(&s,s.deadline)<0&&s.stage==RED);n++;
  reach(&s,st);assert(coord_fact(&s,CUSTODIAN_EXIT,s.sequence,s.last+1)<0&&s.escrow_lost);n++;
  reach(&s,st);assert(coord_fact(&s,IO_FAILED,s.sequence,s.last+1)<0);n++;
 }
 for(int mask=0;mask<3;mask++){
  reach(&s,YELLOW_CAPTURE);s.collector_reaped=mask&1;s.census_closed=mask&2;
  assert(coord_fact(&s,COLLECTOR_FROZEN,s.sequence,s.last+1)<0);n++;
 }
 reach(&s,BLUE);assert(coord_fact(&s,WALL_ATTACHED,s.sequence,s.last+1)<0);n++;
 reach(&s,CYAN);assert(coord_fact(&s,HOST_ACK,s.sequence+1,s.last+1)<0);n++;
 reach(&s,GREEN);assert(coord_fact(&s,HOST_ACK,s.sequence,s.last+1)<0);n++;
 reach(&s,YELLOW_CAPTURE);assert(coord_fact(&s,COLLECTOR_FAILED,s.sequence,s.last+1)<0);n++;
 printf("PASS %d color admission cases; facts injected; no physical safety proof\n",n);return 0;
}
