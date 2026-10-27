/* SPDX-License-Identifier: GPL-2.0-only */
#include "coordinator.h"
#include <string.h>
static int hold(struct coordinator *s){s->stage=RED;return -1;}
const char *coord_name(enum stage s){static const char *n[]={"START","BLUE_PC_READY","YELLOW_CONNECT_UGREEN","YELLOW_CAPTURING","GREEN_FROZEN","CYAN_EXPORT","COMPLETE_EVIDENCE_ONLY","RED_HOLD"};return s<=RED?n[s]:"RED_HOLD";}
void coord_init(struct coordinator *s,uint64_t now){memset(s,0,sizeof(*s));s->last=now;s->deadline=now+300000;}
int coord_tick(struct coordinator *s,uint64_t now){if(now<s->last)return hold(s);s->last=now;if(s->stage==RED)return -1;if(s->stage!=COMPLETE&&now>=s->deadline)return hold(s);return 0;}
int coord_fact(struct coordinator *s,enum fact f,unsigned seq,uint64_t now){
 if(coord_tick(s,now)||seq!=s->sequence)return hold(s);
 s->sequence++;
 if(f==CUSTODIAN_EXIT){s->custodian_reaped=1;s->escrow_lost=1;return hold(s);}
 if(f==COLLECTOR_FAILED||f==IO_FAILED)return hold(s);
 switch(s->stage){
 case START:
  if(f==INITIALIZED&&!s->initialized){s->initialized=1;s->custodian_owned=1;return 0;}
  if(f!=PC_ADMITTED||!s->initialized||s->admitted)return hold(s);
  s->admitted=1;s->stage=BLUE;break;
 case BLUE:
  if(f!=PC_DETACHED)return hold(s);
  s->stage=YELLOW_WAIT;break;
 case YELLOW_WAIT:
  if(f!=WALL_ATTACHED)return hold(s);
  s->collector_owned=1;s->stage=YELLOW_CAPTURE;break;
 case YELLOW_CAPTURE:
  if(f!=COLLECTOR_FROZEN||!s->collector_owned||!s->collector_reaped||!s->census_closed)return hold(s);
  s->stage=GREEN;break;
 case GREEN:
  if(f!=PC_RECONNECTED)return hold(s);
  s->stage=CYAN;break;
 case CYAN:
  if(f!=HOST_ACK)return hold(s);
  s->ack=1;s->stage=COMPLETE;break;
 case COMPLETE:
  if(f!=PARENT_RECEIPT||s->parent_receipt)return hold(s);
  s->parent_receipt=1;return 0;
 default:return hold(s);
 }
 s->deadline=now+(s->stage==YELLOW_CAPTURE?100000:300000);return 0;
}
