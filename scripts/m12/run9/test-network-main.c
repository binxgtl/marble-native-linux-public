/* Execute the production main with no real radio, socket, process or file IO. */
#define M12_NETWORK_TEST
#define main network_main
#include "network.c"
#undef main
#include <assert.h>
#include <setjmp.h>

static int mode,calls[24],rows,held;
static jmp_buf escape;
static struct result output[8];
static char boundaries[128][48];
static int boundary_rc[128],boundary_count;
static int fail(int n){calls[n]++;if(mode==n){errno=EIO;return -1;}return 0;}
static int cfg(struct m12_wifi_credentials *c){if(fail(1))return -1;memset(c,0,sizeof(*c));memcpy(c->ssid,"fixture",7);c->ssid_len=7;return 0;}
static int stack(char *b,size_t bc,char *i,size_t ic,unsigned *idx){assert(bc>10&&ic>7);if(fail(2))return -1;strcpy(b,"0000:01:00.0");strcpy(i,"teststa");*idx=7;return 0;}
static int index_if(const char *i){assert(!strcmp(i,"teststa"));return fail(3)?-1:7;}
static int nl(unsigned i){assert(i==7);return fail(4);}
static int directory(void){return fail(5);}
static int hook(void){return fail(6);}
static pid_t start(char *const a[]){if(!strcmp(a[0],WPA)){assert(!strcmp(a[2],"-i")&&!strcmp(a[3],"teststa"));return fail(7)?-1:101;}assert(!strcmp(a[0],BB)&&!strcmp(a[1],"udhcpc"));return fail(14)?-1:102;}
static int pathwait(const char *p,unsigned t){assert(strstr(p,"teststa")&&t==12000);return fail(8);}
static int events(const char *i,char *p,size_t cap){assert(!strcmp(i,"teststa")&&cap>10);if(fail(9))return -1;strcpy(p,"test-event");return 5;}
static int scan(const char *i,int fd,const unsigned char *s,size_t n){assert(!strcmp(i,"teststa")&&fd==5&&n==7&&!memcmp(s,"fixture",7));return fail(10);}
static int selectnet(const char *i,const char *c){assert(!strcmp(i,"teststa")&&!strcmp(c,"SELECT_NETWORK 0"));return fail(11);}
static int wpastate(const char *i,int assoc,unsigned t){assert(!strcmp(i,"teststa")&&t==30000);return fail(assoc?12:13);}
static int command(const char *s,char *const a[],unsigned t){assert(!strcmp(a[0],BB)&&t>0);int n=!strcmp(s,"link_up")?15:!strcmp(s,"address_add")?18:!strcmp(s,"default_route_add")?19:20;if(n==20){assert(!strcmp(s,"gateway_ping"));assert(!strcmp(a[8],"192.0.2.1"));}return fail(n);}
static int child(pid_t p,unsigned t,int *st){assert(p==102&&t==45000);if(fail(16)||mode==24){errno=ETIMEDOUT;return -1;}*st=mode==22?1<<8:0;return 0;}
static int stop(pid_t p,unsigned t){assert(p==102&&t==1000);calls[23]++;return mode==24?-1:0;}
static int lease(char *i,size_t ic,char *m,size_t mc,char *g,size_t gc,unsigned *pre){assert(ic>=16&&mc>=16&&gc>=16);if(fail(17))return -1;strcpy(i,"192.0.2.2");strcpy(m,"255.255.255.0");strcpy(g,"192.0.2.1");*pre=24;return 0;}
static int stat_path(const char *p,struct stat *s){(void)s;assert(!strcmp(p,LEASE)||!strcmp(p,"/run/m12/dhcp.lease.tmp"));errno=ENOENT;return -1;}
static int cleanup(const char *i,pid_t p,int fd,const char *e,int l,int tmp,int h,int c){(void)i;(void)p;(void)fd;(void)e;(void)l;(void)tmp;(void)h;(void)c;return fail(21);}
static void trace(const char *s,int rc){assert(boundary_count<128&&strlen(s)<48);strcpy(boundaries[boundary_count],s);boundary_rc[boundary_count++]=rc;}
static void hold_mock(void){held=1;longjmp(escape,1);}
static int result(struct result *r){assert(rows<8);output[rows++]=*r;return 0;}
int main(void){
 m12_test_ops=(struct m12_network_test_ops){.config_load=cfg,.wait_stack_ready=stack,.if_index=index_if,.nl80211_ready=nl,.make_ctrl_dir=directory,.prepare_hook=hook,.spawn=start,.supplicant_spawn=start,.wait_path=pathwait,.event_socket=events,.scan_target=scan,.command_ok=selectnet,.wait_wpa=wpastate,.run_cmd=command,.wait_child=child,.stop_child=stop,.lstat=stat_path,.lease_read=lease,.cleanup_network=cleanup,.crumb=trace,.emit=result,.hold=hold_mock};
 for(mode=0;mode<=24;mode++){
  memset(calls,0,sizeof(calls));rows=held=boundary_count=0;
  volatile int rc=-1;if(!setjmp(escape))rc=network_main();
  if(mode==21||mode==24){assert(held&&!rows);if(mode==24)assert(!calls[21]&&!calls[17]&&calls[23]==1);continue;}
  assert(!held&&rows==8&&calls[21]==1);
  if(mode==0){assert(rc==0);for(int i=0;i<8;i++)assert(output[i].state==PASS&&!output[i].rc);}
  else if(mode==23){assert(rc==0);}
  else {assert(rc==2);assert(output[7].state==PASS);}
  if(mode==1||mode==2||mode==3||mode==4||mode==5||mode==6)assert(!calls[7]&&!calls[10]&&!calls[11]&&!calls[14]);
  if(mode==10)assert(!calls[11]&&!calls[14]);
  if(mode==11||mode==12||mode==13)assert(!calls[14]);
  if(mode==16)assert(calls[23]==1&&!calls[17]&&!calls[20]);
  if(mode==17||mode==18||mode==19||mode==22)assert(!calls[20]);
  assert(!strcmp(boundaries[0],"network_begin"));
  assert(!strcmp(boundaries[boundary_count-1],"network_return"));
 }
 puts("Production network main:25 mock scenarios; success, prerequisite denial, no downstream RF, WPA/DHCP/ping failures and teardown hold PASS; no hardware");
 return 0;
}
