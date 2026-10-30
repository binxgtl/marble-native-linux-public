/* SPDX-License-Identifier: GPL-2.0-only */
#include "journal.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#x);exit(1);}}while(0)

static const unsigned char nonce[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
struct buffer { unsigned char data[8192]; size_t used,limit; int errors; };
static ssize_t sink(void *arg,const void *p,size_t n) {
 struct buffer *b=arg;
 if(b->errors){b->errors--;errno=EIO;return -1;}
 if(b->limit&&n>b->limit)n=b->limit; /* always a short write */
 memcpy(b->data+b->used,p,n);
 b->used+=n;
 return (ssize_t)n;
}
static ssize_t again(void *arg,const void *p,size_t n) { (void)arg;(void)p;(void)n;errno=EAGAIN;return -1; }
static ssize_t liar(void *arg,const void *p,size_t n) { (void)arg;(void)p;return (ssize_t)n+1; }
static void head_hex(const struct m16_journal *j,char *out) { m16_hex(j->head,32,out); }
static void init(struct m16_journal *j,struct m16_record *r,uint32_t n) { CHECK(!m16_journal_init(j,r,n,nonce)); }

static void test_order(void) {
 struct m16_record r[16];struct m16_journal j;
 init(&j,r,16);
 const struct m16_clock a={2000000000,1000000000},b={3000000000,2000000000};
 CHECK(!m16_journal_append(&j,M16_EV_OPEN,&a,"x",1));
 CHECK(r[0].seq==0&&r[0].type==M16_EV_OPEN&&r[0].length==1);
 CHECK(!m16_journal_append(&j,M16_EV_PHASE,&b,NULL,0));
 /* Rejections change nothing: neither count, head nor state. */
 unsigned char head[32];memcpy(head,j.head,32);
 const struct m16_clock older={2500000000,2000000000},mono_back={4000000000,1500000000};
 const struct m16_clock gap_shrank={3500000000,3000000000},zero={0,0},mono_ahead={1000000000,2000000000};
 CHECK(m16_journal_append(&j,M16_EV_PHASE,&older,NULL,0)==-ERANGE);
 CHECK(m16_journal_append(&j,M16_EV_PHASE,&mono_back,NULL,0)==-ERANGE);
 CHECK(m16_journal_append(&j,M16_EV_PHASE,&gap_shrank,NULL,0)==-ERANGE);
 CHECK(m16_journal_append(&j,M16_EV_PHASE,&zero,NULL,0)==-ERANGE);
 CHECK(m16_journal_append(&j,M16_EV_PHASE,&mono_ahead,NULL,0)==-ERANGE);
 CHECK(j.count==2&&!memcmp(head,j.head,32)&&j.state==M16_J_OPEN);
 /* Small pair jitter is not a regression. */
 const struct m16_clock jitter={3100000000,2100000000+M16_JITTER_NS};
 CHECK(!m16_journal_append(&j,M16_EV_PHASE,&jitter,NULL,0));
 /* A real sleep grows the gap and is accepted. */
 const struct m16_clock slept={63100000000ull,2200000000ull};
 CHECK(!m16_journal_append(&j,M16_EV_PHASE,&slept,NULL,0));
}
static void test_arguments(void) {
 struct m16_record r[8];struct m16_journal j;
 CHECK(m16_journal_init(&j,r,M16_RESERVED,nonce)==-EINVAL);
 CHECK(m16_journal_init(NULL,r,8,nonce)==-EINVAL);
 init(&j,r,8);
 const struct m16_clock c={2,1};
 unsigned char big[M16_PAYLOAD+1]={0};
 CHECK(m16_journal_append(&j,0,&c,NULL,0)==-EINVAL);
 CHECK(m16_journal_append(&j,M16_EV_LIMIT,&c,NULL,0)==-EINVAL);
 CHECK(m16_journal_append(&j,M16_EV_SEAL,&c,NULL,0)==-EINVAL);
 CHECK(m16_journal_append(&j,M16_EV_FAIL,&c,NULL,0)==-EINVAL);
 CHECK(m16_journal_append(&j,M16_EV_PHASE,&c,big,sizeof(big))==-EINVAL);
 CHECK(m16_journal_append(&j,M16_EV_PHASE,&c,NULL,1)==-EINVAL);
 CHECK(m16_journal_append(&j,M16_EV_PHASE,NULL,NULL,0)==-EINVAL);
 /* No accepted clock yet: nothing can honestly be stamped. */
 CHECK(m16_journal_fail(&j,1,0,0)==-ENODATA);
 CHECK(m16_journal_seal(&j)==-ENODATA);
}
static void test_capacity_keeps_reserved_slots(void) {
 struct m16_record r[6];struct m16_journal j;
 init(&j,r,6);
 struct m16_clock c={2000000000,1000000000};
 for(int i=0;i<3;i++){CHECK(!m16_journal_append(&j,M16_EV_PHASE,&c,NULL,0));c.boot_ns++;c.mono_ns++;}
 CHECK(m16_journal_append(&j,M16_EV_PHASE,&c,NULL,0)==-ENOSPC);
 CHECK(j.state==M16_J_OPEN&&j.count==3);
 CHECK(!m16_journal_fail(&j,7,-5,2));
 CHECK(!m16_journal_append(&j,M16_EV_CLEANUP,&c,"c",1));
 CHECK(!m16_journal_seal(&j));
 CHECK(j.count==6&&j.state==M16_J_SEALED);
 CHECK(r[3].type==M16_EV_FAIL&&r[4].type==M16_EV_CLEANUP&&r[5].type==M16_EV_SEAL);
 CHECK(r[3].boot_ns==2000000002ull); /* stamped with the last accepted pair */
}
static void test_sealed_is_final(void) {
 struct m16_record r[8];struct m16_journal j;
 init(&j,r,8);
 const struct m16_clock c={2,1};
 CHECK(!m16_journal_append(&j,M16_EV_OPEN,&c,NULL,0));
 CHECK(!m16_journal_seal(&j));
 CHECK(m16_journal_append(&j,M16_EV_PHASE,&c,NULL,0)==-EPERM);
 CHECK(m16_journal_fail(&j,1,0,0)==-EPERM);
 CHECK(m16_journal_seal(&j)==-EPERM);
 CHECK(j.count==2);
}
static void test_export_retains_until_ack(void) {
 struct m16_record r[8];struct m16_journal j;
 init(&j,r,8);
 const struct m16_clock c={2,1};
 CHECK(!m16_journal_append(&j,M16_EV_OPEN,&c,NULL,0));
 static struct buffer b,second;
 CHECK(m16_journal_export(&j,sink,&b)==-1); /* not sealed */
 CHECK(!m16_journal_seal(&j));
 CHECK(m16_journal_wire_size(&j)==M16_HEADER_SIZE+2*M16_RECORD_SIZE);
 char good[M16_ACK_HEX+1]={0},bad[M16_ACK_HEX+1]={0};
 head_hex(&j,good);memcpy(bad,good,sizeof(bad));bad[0]=bad[0]=='0'?'1':'0';
 CHECK(m16_journal_ack(&j,good)==-EPERM); /* nothing was sent yet */
 CHECK(m16_journal_release(&j)==-EBUSY);
 b.limit=7;
 int done=0,rounds=0;
 while(!(done=m16_journal_export(&j,sink,&b))&&rounds++<1000){}
 CHECK(done==1&&b.used==m16_journal_wire_size(&j));
 CHECK(m16_journal_release(&j)==-EBUSY); /* sent is not verified */
 CHECK(m16_journal_ack(&j,bad)==-EBADMSG&&j.ack_failures==1&&j.state==M16_J_SEALED);
 char notation[M16_ACK_HEX+1]={0};memset(notation,'Z',M16_ACK_HEX);
 CHECK(m16_journal_ack(&j,notation)==-EBADMSG&&j.ack_failures==2);
 CHECK(j.count==2&&r[0].type==M16_EV_OPEN);
 /* Repeated export is byte-identical, and short and whole writes agree. */
 m16_journal_rewind(&j);
 while(!m16_journal_export(&j,sink,&second)){}
 CHECK(second.used==b.used&&!memcmp(second.data,b.data,b.used));
 CHECK(!m16_journal_ack(&j,good)&&j.state==M16_J_ACKED);
 CHECK(!m16_journal_release(&j)&&j.state==M16_J_RELEASED&&!j.count&&!r[0].type);
 CHECK(m16_journal_release(&j)==-EBUSY);
}
static void test_export_errors(void) {
 struct m16_record r[8];struct m16_journal j;
 init(&j,r,8);
 const struct m16_clock c={2,1};
 CHECK(!m16_journal_append(&j,M16_EV_OPEN,&c,NULL,0));
 CHECK(!m16_journal_seal(&j));
 static struct buffer b;
 b.errors=1;
 CHECK(m16_journal_export(&j,sink,&b)==-1&&!j.export_offset);
 CHECK(!m16_journal_export(&j,again,NULL)&&!j.export_offset);
 CHECK(m16_journal_export(&j,liar,NULL)==-1&&!j.export_offset);
 CHECK(m16_journal_export(NULL,sink,&b)==-1&&m16_journal_export(&j,NULL,&b)==-1);
}
static void test_chain_binds_nonce(void) {
 struct m16_record a[4],b[4];struct m16_journal x,y;
 unsigned char other[16]={9};
 init(&x,a,4);
 CHECK(!m16_journal_init(&y,b,4,other));
 const struct m16_clock c={2,1};
 CHECK(!m16_journal_append(&x,M16_EV_OPEN,&c,NULL,0));
 CHECK(!m16_journal_append(&y,M16_EV_OPEN,&c,NULL,0));
 CHECK(memcmp(a[0].chain,b[0].chain,32));
}
int main(void) {
 test_order();test_arguments();test_capacity_keeps_reserved_slots();test_sealed_is_final();
 test_export_retains_until_ack();test_export_errors();test_chain_binds_nonce();
 printf("journal: %u checks passed\n",checks);
 return 0;
}
