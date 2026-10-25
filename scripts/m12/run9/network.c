#define _GNU_SOURCE
#include "network.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CONF "/m12/private/wpa.conf"
#ifndef WDIR
#define WDIR "/run/m12/wpa"
#endif
#define SCRIPT "/run/m12/udhcpc.sh"
#define LEASE "/run/m12/dhcp.lease"
#define TRACE "/run/m12-instrumentation/breadcrumbs"
#define BB "/bin/busybox"
#define WPA "/sbin/wpa_supplicant"

enum { BLOCKED, PASS, FAIL };
struct result { const char *name; int state, rc; };
#ifdef M12_NETWORK_TEST
/* Test-only dependency seams let the regression drive the production main
 * state machine without opening radios, sockets, or device nodes. */
struct m12_network_test_ops {
 int (*config_load)(struct m12_wifi_credentials *);
 int (*wait_stack_ready)(char *,size_t,char *,size_t,unsigned *);
 int (*if_index)(const char *);
 int (*nl80211_ready)(unsigned);
 int (*make_ctrl_dir)(void);
 int (*prepare_hook)(void);
 pid_t (*spawn)(char *const []);
 pid_t (*supplicant_spawn)(char *const []);
 int (*wait_path)(const char *,unsigned);
 int (*event_socket)(const char *,char *,size_t);
 int (*scan_target)(const char *,int,const unsigned char *,size_t);
 int (*command_ok)(const char *,const char *);
 int (*wait_wpa)(const char *,int,unsigned);
 int (*run_cmd)(const char *,char *const [],unsigned);
 int (*wait_child)(pid_t,unsigned,int *);
 int (*stop_child)(pid_t,unsigned);
 int (*lstat)(const char *,struct stat *);
 int (*emit)(struct result *);
 void (*hold)(void);
 int (*lease_read)(char *,size_t,char *,size_t,char *,size_t,unsigned *);
 int (*cleanup_network)(const char *,pid_t,int,const char *,int,int,int,int);
 void (*crumb)(const char *,int);
};
static struct m12_network_test_ops m12_test_ops;
#define TEST_CALL(fn, ...) (m12_test_ops.fn ? m12_test_ops.fn(__VA_ARGS__) : fn(__VA_ARGS__))
#define TEST_CALL0(fn) (m12_test_ops.fn ? m12_test_ops.fn() : fn())
#else
#define TEST_CALL(fn, ...) fn(__VA_ARGS__)
#define TEST_CALL0(fn) fn()
#endif
static uint64_t mono_ns(void) {
 struct timespec t; if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;
 return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec;
}
static void secret_clear(void *p,size_t n){volatile unsigned char *q=p;while(n--)*q++=0;}
static int hexval(unsigned char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}

/* Exact local format, intentionally unrelated to any actual network value:
 * globals ctrl_interface/ap_scan (CONFIG_NO_CONFIG_WRITE keeps writes disabled); one network block with hex
 * ssid, 64-hex PSK, WPA-PSK, scan_ssid=0 and disabled=1. */
int m12_parse_wpa_config(const char *b,size_t n,struct m12_wifi_credentials *out){
 unsigned ctrl=0,ap=0,net=0,ssid=0,psk=0,key=0,scan=0,disabled=0;int in=0;
 size_t pos=0,sl=0;struct m12_wifi_credentials c;char l[160]={0};memset(&c,0,sizeof(c));
 if(!b||!out)return -1;
 memset(out,0,sizeof(*out));if(!n||n>4096||memchr(b,0,n)||memchr(b,'\r',n)||b[n-1]!='\n')return -1;
 while(pos<n){size_t s=pos;while(pos<n&&b[pos]!='\n')pos++;size_t z=pos-s;if(pos<n)pos++;if(z&&b[s+z-1]=='\r')z--;if(!z||b[s]=='#'){secret_clear(l,sizeof(l));continue;}if(z>=sizeof(l))goto bad;memcpy(l,b+s,z);l[z]=0;
  if(!in){if(!strcmp(l,"ctrl_interface=DIR=/run/m12/wpa GROUP=0")){if(ctrl++)goto bad;}
   else if(!strcmp(l,"ap_scan=1")){if(ap++)goto bad;}
   else if(!strcmp(l,"network={")){if(net++)goto bad;in=1;}else goto bad;
  }else if(!strcmp(l,"}")){in=0;}
  else if(!strncmp(l,"ssid=",5)){if(ssid++)goto bad;const char *v=l+5;size_t vn=strlen(v);if(vn<2||vn>64||(vn&1))goto bad;sl=vn/2;if(sl>sizeof(c.ssid))goto bad;for(size_t i=0;i<sl;i++){int h=hexval(v[2*i]),lo=hexval(v[2*i+1]);if(h<0||lo<0)goto bad;c.ssid[i]=(unsigned char)((h<<4)|lo);}}
  else if(!strncmp(l,"psk=",4)){if(psk++)goto bad;const char *v=l+4;if(strlen(v)!=64)goto bad;for(size_t i=0;i<64;i++)if(hexval((unsigned char)v[i])<0)goto bad;}
  else if(!strcmp(l,"key_mgmt=WPA-PSK")){if(key++)goto bad;}
  else if(!strcmp(l,"scan_ssid=0")){if(scan++)goto bad;}
  else if(!strcmp(l,"disabled=1")){if(disabled++)goto bad;}
  else goto bad;
  secret_clear(l,sizeof(l));
 }
 if(in||net!=1||!ctrl||!ap||!ssid||!psk||!key||!scan||!disabled||!sl)goto bad;
 c.ssid_len=sl;*out=c;return 0;
bad: secret_clear(l,sizeof(l));secret_clear(&c,sizeof(c));if(out)memset(out,0,sizeof(*out));return -1;
}

int m12_scan_results_contains(const char *b,size_t n,const unsigned char *ssid,size_t sl){
 size_t p=0;int first=1;if(!b||!ssid||!sl)return 0;
 while(p<n){size_t e=p;while(e<n&&b[e]!='\n')e++;size_t z=e-p;if(z&&b[p+z-1]=='\r')z--;
  if(first)first=0;else if(z){unsigned tabs=0;size_t at=z;for(size_t i=0;i<z;i++)if(b[p+i]=='\t'&&++tabs==4){at=i+1;break;}if(tabs==4&&z-at==sl&&!memcmp(b+p+at,ssid,sl))return 1;}
  p=e<n?e+1:e;
 }return 0;
}
static int state_is_network0(const char *b,size_t n,const char *wanted){size_t p=0,wl=strlen(wanted);unsigned states=0,ids=0;int state_ok=0,id_ok=0;while(p<n){size_t e=p;while(e<n&&b[e]!='\n')e++;size_t z=e-p;if(z>=10&&!memcmp(b+p,"wpa_state=",10)){if(++states!=1)return 0;state_ok=z==10+wl&&!memcmp(b+p+10,wanted,wl);}if(z>=3&&!memcmp(b+p,"id=",3)){if(++ids!=1)return 0;id_ok=z==4&&b[p+3]=='0';}p=e<n?e+1:e;}return states==1&&ids==1&&state_ok&&id_ok;}
int m12_status_associated(const char *b,size_t n){return state_is_network0(b,n,"ASSOCIATED")||state_is_network0(b,n,"4WAY_HANDSHAKE")||state_is_network0(b,n,"GROUP_HANDSHAKE")||state_is_network0(b,n,"COMPLETED");}
int m12_status_wpa_completed(const char *b,size_t n){return state_is_network0(b,n,"COMPLETED");}

static uint64_t now_ms(void);
#include "supplicant.h"
static struct m12_supplicant supplicant={.pid=-1};
static pid_t supplicant_spawn(char *const av[]);
static int if_index(const char *ifn);
static int find_if(char *out,size_t cap,const char *bdf,unsigned *outidx);

static void crumb_real(const char *name,int rc){char b[128];uint64_t t=mono_ns();if(!t)for(;;)pause();int n=snprintf(b,sizeof(b),"M12D3 %llu %s %d\n",(unsigned long long)t,name,rc);if(n<=0||(size_t)n>=sizeof(b))for(;;)pause();int fd=open(TRACE,O_WRONLY|O_APPEND|O_CLOEXEC|O_NOFOLLOW);if(fd<0)for(;;)pause();struct stat s;if(fstat(fd,&s)||!S_ISREG(s.st_mode)||s.st_uid||s.st_nlink!=1){close(fd);for(;;)pause();}ssize_t z;do z=write(fd,b,(size_t)n);while(z<0&&errno==EINTR);int e=errno,closed=close(fd);if(z!=n||closed){errno=e;for(;;)pause();}}
static void crumb(const char *name,int rc){
#ifdef M12_NETWORK_TEST
 if(m12_test_ops.crumb){m12_test_ops.crumb(name,rc);return;}
#endif
 crumb_real(name,rc);
}
static int emit(struct result *r){const char *s=r->state==PASS?"PASS":r->state==FAIL?"FAIL":"BLOCKED";char b[128];int n=snprintf(b,sizeof(b),"M12NET %s %s rc=%d\n",r->name,s,r->rc);if(n<=0||(size_t)n>=sizeof(b))return -1;size_t p=0;while(p<(size_t)n){ssize_t z=write(1,b+p,(size_t)n-p);if(z<0&&errno==EINTR)continue;if(z<=0)return -1;p+=(size_t)z;}return 0;}
static int mark(struct result *r,int s,int rc){r->state=s;r->rc=rc;crumb(r->name,rc);return 0;}
static int readfile(const char *p,char *b,size_t cap,size_t *n){int fd=open(p,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;size_t u=0;while(u+1<cap){ssize_t r=read(fd,b+u,cap-u-1);if(r<0&&errno==EINTR)continue;if(r<0){int e=errno;close(fd);errno=e;return -1;}if(!r)break;u+=(size_t)r;}char x;ssize_t q=read(fd,&x,1);int e=errno,cr=close(fd);if(q||cr){errno=q<0?e:EOVERFLOW;return -1;}b[u]=0;if(n)*n=u;return 0;}
static int config_load(struct m12_wifi_credentials *c){int fd=open(CONF,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;struct stat s;if(fstat(fd,&s)){int e=errno;close(fd);errno=e;return -1;}if(!S_ISREG(s.st_mode)||s.st_uid||s.st_gid||(s.st_mode&07777)!=0600||s.st_nlink!=1||s.st_size<1||s.st_size>4096){close(fd);errno=EPERM;return -1;}char b[4097];size_t n=0;while(n<(size_t)s.st_size){ssize_t r=read(fd,b+n,(size_t)s.st_size-n);if(r<0&&errno==EINTR)continue;if(r<=0){int e=r<0?errno:EIO;close(fd);secret_clear(b,sizeof(b));errno=e;return -1;}n+=(size_t)r;}if(close(fd)||n!=(size_t)s.st_size||m12_parse_wpa_config(b,n,c)){secret_clear(b,sizeof(b));errno=EINVAL;return -1;}secret_clear(b,sizeof(b));return 0;}
static int loaded(const char *name){FILE*f=fopen("/proc/modules","re");if(!f)return 0;char l[512];size_t n=strlen(name);int ok=0;while(fgets(l,sizeof(l),f))if(!strncmp(l,name,n)&&l[n]==' '){ok=1;break;}fclose(f);return ok;}
static int driver_is(const char *p,const char *name){char r[PATH_MAX];if(!realpath(p,r))return 0;char *b=strrchr(r,'/');return b&&!strcmp(b+1,name);}
static int readtrim(const char *p,char *b,size_t z){size_t n;if(readfile(p,b,z,&n))return -1;while(n&&(b[n-1]=='\n'||b[n-1]=='\r'))b[--n]=0;return 0;}
static int pci_ready(char *bdf,size_t cap){DIR*d=opendir("/sys/bus/pci/devices");if(!d)return -1;int found=0;struct dirent*e;while((e=readdir(d))){if(e->d_name[0]=='.')continue;char p[PATH_MAX],v[32],x[32];snprintf(p,sizeof(p),"/sys/bus/pci/devices/%s/vendor",e->d_name);if(readtrim(p,v,sizeof(v))||strcmp(v,"0x17cb"))continue;snprintf(p,sizeof(p),"/sys/bus/pci/devices/%s/device",e->d_name);if(readtrim(p,x,sizeof(x))||strcmp(x,"0x1103"))continue;snprintf(p,sizeof(p),"/sys/bus/pci/devices/%s/driver",e->d_name);if(!driver_is(p,"cnss_pci"))continue;if(++found!=1||strlen(e->d_name)>=cap){found=2;break;}strcpy(bdf,e->d_name);}closedir(d);if(found!=1){errno=found?EEXIST:ENODEV;return -1;}return 0;}

struct abuf{unsigned char b[128];size_t n;};
static int attr(struct abuf*a,uint16_t type,const void*d,size_t n){size_t x=sizeof(struct nlattr)+n,y=NLA_ALIGN(x);if(a->n+y>sizeof(a->b))return -1;struct nlattr h={(uint16_t)x,type};memcpy(a->b+a->n,&h,sizeof(h));memcpy(a->b+a->n+sizeof(h),d,n);memset(a->b+a->n+x,0,y-x);a->n+=y;return 0;}
static int genreq(int fd,uint16_t fam,uint8_t cmd,uint32_t seq,const void*a,size_t an){unsigned char b[512]={0};struct nlmsghdr*h=(void*)b;h->nlmsg_len=NLMSG_HDRLEN+GENL_HDRLEN+an;h->nlmsg_type=fam;h->nlmsg_flags=NLM_F_REQUEST;h->nlmsg_seq=seq;struct genlmsghdr*g=(void*)(b+NLMSG_HDRLEN);g->cmd=cmd;if(an)memcpy(b+NLMSG_HDRLEN+GENL_HDRLEN,a,an);struct sockaddr_nl dst={.nl_family=AF_NETLINK};struct iovec i={b,h->nlmsg_len};struct msghdr m={.msg_name=&dst,.msg_namelen=sizeof(dst),.msg_iov=&i,.msg_iovlen=1};return sendmsg(fd,&m,0)==(ssize_t)h->nlmsg_len?0:-1;}
static int receive_nl(int fd,uint32_t seq,unsigned char*b,size_t cap,ssize_t*out){struct pollfd p={fd,POLLIN,0};int z=poll(&p,1,3000);if(z<=0){errno=z?errno:ETIMEDOUT;return -1;}struct sockaddr_nl src={0};struct iovec i={b,cap};struct msghdr m={.msg_name=&src,.msg_namelen=sizeof(src),.msg_iov=&i,.msg_iovlen=1};ssize_t n=recvmsg(fd,&m,0);if(n<=0||(m.msg_flags&MSG_TRUNC)||m.msg_namelen!=sizeof(src)||src.nl_family!=AF_NETLINK||src.nl_pid){errno=EPROTO;return -1;}ssize_t left=n;for(struct nlmsghdr*h=(void*)b;NLMSG_OK(h,left);h=NLMSG_NEXT(h,left)){if(h->nlmsg_seq!=seq)continue;if(h->nlmsg_type==NLMSG_ERROR){if(h->nlmsg_len<NLMSG_LENGTH(sizeof(struct nlmsgerr))){errno=EPROTO;return -1;}struct nlmsgerr*e=NLMSG_DATA(h);if(e->error){errno=-e->error;return -1;}}}if(left){errno=EPROTO;return -1;}*out=n;return 0;}
static int nl_attrs(const unsigned char *p,size_t n,uint16_t t,void *value,size_t need){int found=0;size_t off=0;while(off<n){if(n-off<sizeof(struct nlattr))return -1;const struct nlattr*a=(const void*)(p+off);if(a->nla_len<sizeof(*a)||a->nla_len>n-off)return -1;size_t payload=(size_t)a->nla_len-sizeof(*a);if((a->nla_type&NLA_TYPE_MASK)==t){if(found++||payload!=need)return -1;memcpy(value,p+off+sizeof(*a),need);}size_t step=NLA_ALIGN(a->nla_len);if(step>n-off)return -1;off+=step;}return found;}
static int one_genl_reply(unsigned char *b,ssize_t n,uint32_t seq,uint16_t type,uint8_t cmd,unsigned char **attrs,size_t *alen){int left=(int)n,found=0;for(struct nlmsghdr*h=(void*)b;NLMSG_OK(h,left);h=NLMSG_NEXT(h,left)){if(h->nlmsg_seq!=seq||h->nlmsg_type!=type)continue;if(h->nlmsg_len<NLMSG_LENGTH(GENL_HDRLEN)||found++)return -1;struct genlmsghdr*g=NLMSG_DATA(h);if(g->cmd!=cmd)return -1;*attrs=(unsigned char*)g+GENL_HDRLEN;*alen=h->nlmsg_len-NLMSG_LENGTH(GENL_HDRLEN);}return found==1&&!left?0:-1;}
static int nl80211_ready(unsigned idx){int fd=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_GENERIC);if(fd<0)return -1;struct sockaddr_nl s={.nl_family=AF_NETLINK};if(bind(fd,(void*)&s,sizeof(s)))goto bad;struct abuf a={0};const char name[]="nl80211";if(attr(&a,CTRL_ATTR_FAMILY_NAME,name,sizeof(name))||genreq(fd,GENL_ID_CTRL,CTRL_CMD_GETFAMILY,1,a.b,a.n))goto bad;unsigned char b[65536],*p;ssize_t n;size_t z;if(receive_nl(fd,1,b,sizeof(b),&n)||one_genl_reply(b,n,1,GENL_ID_CTRL,CTRL_CMD_NEWFAMILY,&p,&z))goto proto;uint16_t family=0;if(nl_attrs(p,z,CTRL_ATTR_FAMILY_ID,&family,sizeof(family))!=1||family<GENL_ID_CTRL+1)goto proto;
 memset(&a,0,sizeof(a));if(attr(&a,NL80211_ATTR_IFINDEX,&idx,sizeof(idx))||genreq(fd,family,NL80211_CMD_GET_INTERFACE,2,a.b,a.n)||receive_nl(fd,2,b,sizeof(b),&n)||one_genl_reply(b,n,2,family,NL80211_CMD_NEW_INTERFACE,&p,&z))goto proto;uint32_t gotidx=0,wiphy=0;uint32_t typeif=0;if(nl_attrs(p,z,NL80211_ATTR_IFINDEX,&gotidx,sizeof(gotidx))!=1||nl_attrs(p,z,NL80211_ATTR_IFTYPE,&typeif,sizeof(typeif))!=1||nl_attrs(p,z,NL80211_ATTR_WIPHY,&wiphy,sizeof(wiphy))!=1||gotidx!=idx||typeif!=NL80211_IFTYPE_STATION){errno=ENODEV;goto bad;}if(wiphy==UINT32_MAX){errno=EPROTO;goto bad;}close(fd);return 0;
proto:errno=EPROTO;
bad:{int e=errno?errno:EIO;close(fd);errno=e;return -1;}}

static int dir_has_entry(const char *path){DIR*d=opendir(path);if(!d)return 0;struct dirent*e;int yes=0;while((e=readdir(d)))if(e->d_name[0]!='.'){yes=1;break;}closedir(d);return yes;}
static int cnss_platform_ready(void){char p[PATH_MAX];snprintf(p,sizeof(p),"/sys/bus/platform/devices/b0000000.qcom,cnss-qca6490/driver");return driver_is(p,"cnss2");}
static int firmware_prereqs(char *bdf,size_t cap){if(!loaded("qca6490")||!loaded("cnss_utils")||pci_ready(bdf,cap)||!cnss_platform_ready()||!dir_has_entry("/sys/bus/mhi/devices")){errno=ENODEV;return -1;}return 0;}
static int wait_stack_ready(char *bdf,size_t bcap,char *ifn,size_t icap,unsigned *idx){uint64_t end=now_ms()+25000;do{if(!firmware_prereqs(bdf,bcap)&&!find_if(ifn,icap,bdf,idx))return 0;struct timespec t={0,250000000};nanosleep(&t,NULL);}while(now_ms()<end);errno=ETIMEDOUT;return -1;}
static int path_below(const char *child,const char *parent){size_t n=strlen(parent);return !strncmp(child,parent,n)&&(child[n]=='/'||child[n]=='\0');}
/* Prove the one WLAN netdev and its wiphy descend from this marble CNSS
 * platform device or its exact 17cb:1103 PCI function. No qca driver
 * symlink-name assumption is made: qca_cld3 registers through CNSS hooks. */
static int find_if(char *out,size_t cap,const char *bdf,unsigned *outidx){DIR*d=opendir("/sys/class/net");if(!d)return -1;char pci_link[PATH_MAX],pci_real[PATH_MAX],plat[PATH_MAX],platlink[PATH_MAX];snprintf(pci_link,sizeof(pci_link),"/sys/bus/pci/devices/%s",bdf);snprintf(platlink,sizeof(platlink),"/sys/bus/platform/devices/b0000000.qcom,cnss-qca6490");int havepci=realpath(pci_link,pci_real)!=NULL,haveplat=realpath(platlink,plat)!=NULL;struct dirent*e;int found=0;while((e=readdir(d))){if(e->d_name[0]=='.'||strlen(e->d_name)>=IFNAMSIZ)continue;char p[PATH_MAX],dev[PATH_MAX],phy[PATH_MAX],phydev[PATH_MAX];snprintf(p,sizeof(p),"/sys/class/net/%s/phy80211",e->d_name);if(!realpath(p,phy))continue;snprintf(p,sizeof(p),"/sys/class/net/%s/device",e->d_name);if(!realpath(p,dev))continue;snprintf(p,sizeof(p),"/sys/class/net/%s/phy80211/device",e->d_name);if(!realpath(p,phydev))continue;int ancestry=(havepci&&path_below(dev,pci_real)&&path_below(phydev,pci_real))||(haveplat&&path_below(dev,plat)&&path_below(phydev,plat));if(!ancestry)continue;int idx=if_index(e->d_name);if(idx<=0||nl80211_ready((unsigned)idx))continue;if(++found!=1||strlen(e->d_name)+1>cap){found=2;break;}strcpy(out,e->d_name);*outidx=(unsigned)idx;}closedir(d);if(found!=1){errno=found?EEXIST:ENODEV;return -1;}return 0;}

static int if_index(const char *ifn){int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);if(fd<0)return -1;struct ifreq q;memset(&q,0,sizeof(q));if(strlen(ifn)>=sizeof(q.ifr_name)){close(fd);errno=ENAMETOOLONG;return -1;}strcpy(q.ifr_name,ifn);if(ioctl(fd,SIOCGIFINDEX,&q)){int e=errno;close(fd);errno=e;return -1;}close(fd);return q.ifr_ifindex;}
static uint64_t now_ms(void){return mono_ns()/1000000ULL;}
static int wait_child(pid_t pid,unsigned timeout_ms,int *status){uint64_t end=now_ms()+timeout_ms;for(;;){int st;pid_t r=waitpid(pid,&st,WNOHANG);if(r==pid){if(status)*status=st;return 0;}if(r<0&&errno!=EINTR)return -1;if(now_ms()>=end){errno=ETIMEDOUT;return -1;}struct timespec t={0,20000000};nanosleep(&t,NULL);}}
static int stop_child(pid_t pid,unsigned timeout_ms){if(pid<=0)return 0;if(kill(pid,SIGTERM)&&errno!=ESRCH)return -1;int st;if(wait_child(pid,timeout_ms,&st)==0)return 0;if(errno!=ETIMEDOUT)return -1;if(kill(pid,SIGKILL)&&errno!=ESRCH)return -1;return wait_child(pid,2000,&st);}
static void null_stdio(void){int fd=open("/dev/null",O_RDWR);if(fd<0)_exit(126);for(int i=0;i<3;i++)if(dup2(fd,i)<0)_exit(126);if(fd>2)close(fd);long max=sysconf(_SC_OPEN_MAX);if(max<0||max>4096)max=4096;for(int i=3;i<max;i++)close(i);}
static pid_t spawn(char *const av[]){pid_t p=fork();if(p<0)return -1;if(!p){null_stdio();execv(av[0],av);_exit(127);}return p;}
static pid_t supplicant_spawn(char *const av[]){return sup_spawn(&supplicant,av,"/run/m12/supplicant.log",crumb);}
static void unresolved_hold(void){
 crumb("child_unreaped",-ETIMEDOUT);
#ifdef M12_NETWORK_TEST
 if(m12_test_ops.hold)m12_test_ops.hold();
#endif
 for(;;)pause();
}
static int run_cmd(const char *stage,char *const av[],unsigned ms){char begin[48],finish[48];snprintf(begin,sizeof(begin),"%s_begin",stage);snprintf(finish,sizeof(finish),"%s_return",stage);crumb(begin,0);pid_t p=spawn(av);if(p<0){int e=errno;crumb(finish,-e);return -1;}int st;if(wait_child(p,ms,&st)){int e=errno;if(stop_child(p,1000))unresolved_hold();crumb(finish,-e);errno=e;return -1;}if(!WIFEXITED(st)){errno=ECHILD;crumb(finish,-ECHILD);return -1;}if(WEXITSTATUS(st)){errno=EIO;crumb(finish,-EIO);return WEXITSTATUS(st);}crumb(finish,0);return 0;}
static int wait_path(const char *p,unsigned ms){return sup_ctrl_wait(&supplicant,p,ms);}
#include "control.h"
static int wait_wpa(const char *ifn,int associated,unsigned ms){uint64_t end=now_ms()+ms;do{char b[4096];size_t n;if(!ctrl_cmd(ifn,"STATUS",b,sizeof(b),&n)){if(associated?m12_status_associated(b,n):m12_status_wpa_completed(b,n))return 0;}struct timespec t={0,250000000};nanosleep(&t,NULL);}while(now_ms()<end);errno=ETIMEDOUT;return -1;}

static const char dhcp_hook[]=
"#!/bin/busybox sh\n"
"case \"$1\" in bound|renew) ;; deconfig) exit 0 ;; *) exit 1 ;; esac\n"
"ip=$ip; mask=$subnet; gw=${router%% *}\n"
"case \"$ip\" in ''|*[!0-9.]*) exit 1 ;; esac\n"
"case \"$mask\" in ''|*[!0-9.]*) exit 1 ;; esac\n"
"case \"$gw\" in ''|*[!0-9.]*) exit 1 ;; esac\n"
"umask 077\n"
"printf '%s\\n%s\\n%s\\n' \"$ip\" \"$mask\" \"$gw\" > /run/m12/dhcp.lease.tmp || exit 1\n"
"/bin/busybox chmod 600 /run/m12/dhcp.lease.tmp || exit 1\n"
"/bin/busybox mv -f /run/m12/dhcp.lease.tmp /run/m12/dhcp.lease\n";
static int prepare_hook(void){int fd=open(SCRIPT,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0700);if(fd<0)return -1;size_t n=sizeof(dhcp_hook)-1,p=0;while(p<n){ssize_t z=write(fd,dhcp_hook+p,n-p);if(z<0&&errno==EINTR)continue;if(z<=0){int e=errno;close(fd);unlink(SCRIPT);errno=e?e:EIO;return -1;}p+=(size_t)z;}if(fchmod(fd,0700)||fsync(fd)){int e=errno;close(fd);unlink(SCRIPT);errno=e;return -1;}return close(fd);}
static int ipv4_parse(const char*s,uint32_t*out){struct in_addr a;if(!s||inet_pton(AF_INET,s,&a)!=1)return -1;*out=ntohl(a.s_addr);return 0;}
static int parse_lease(char b[256],char *ip,size_t ic,char *mask,size_t mc,char *gw,size_t gc,unsigned *prefix){char *a=strchr(b,'\n');if(!a)goto bad;*a++=0;char *m=strchr(a,'\n');if(!m)goto bad;*m++=0;char *g=strchr(m,'\n');if(!g)goto bad;*g=0;if(g[1]!='\0'||strlen(b)>=ic||strlen(a)>=mc||strlen(m)>=gc)goto bad;uint32_t ia,ma,ga;if(ipv4_parse(b,&ia)||ipv4_parse(a,&ma)||ipv4_parse(m,&ga)||!ia||!ga)goto bad;unsigned bits=0;int zero=0;for(int i=31;i>=0;i--){int bit=(ma>>i)&1;if(zero&&bit)goto bad;if(bit)bits++;else zero=1;}if(bits<1||bits>30)goto bad;strcpy(ip,b);strcpy(mask,a);strcpy(gw,m);*prefix=bits;secret_clear(b,256);return 0;bad:secret_clear(b,256);errno=EPROTO;return -1;}
static int lease_read(char *ip,size_t ic,char *mask,size_t mc,char *gw,size_t gc,unsigned *prefix){
 char b[256];size_t n;if(readfile(LEASE,b,sizeof(b),&n))return -1;
 return parse_lease(b,ip,ic,mask,mc,gw,gc,prefix);
}
static int dir_empty(const char *p){DIR*d=opendir(p);if(!d)return 0;struct dirent*e;int empty=1;while((e=readdir(d)))if(strcmp(e->d_name,".")&&strcmp(e->d_name,"..")){empty=0;break;}closedir(d);return empty;}
static int make_ctrl_dir(void){if(mkdir("/run/m12",0700)&&errno!=EEXIST)return -1;if(mkdir(WDIR,0700)&&errno!=EEXIST)return -1;struct stat s;if(lstat(WDIR,&s)||!S_ISDIR(s.st_mode)||s.st_uid||s.st_gid||(s.st_mode&07777)!=0700||s.st_nlink!=2||!dir_empty(WDIR)){errno=EPERM;return -1;}return 0;}
static int cleanup_network(const char *ifn,pid_t wp,int evfd,const char *event_path,int lease_exists,int temp_owned,int hook_exists,int config_exists){char reply[128];size_t n;if(supplicant.pid>0){if(!supplicant.reaped)(void)ctrl_cmd(ifn,"TERMINATE",reply,sizeof(reply),&n);if(sup_stop(&supplicant,8000))return -1;}else if(wp>0){(void)ctrl_cmd(ifn,"TERMINATE",reply,sizeof(reply),&n);if(stop_child(wp,8000))return -1;}if(sup_diagnostics(&supplicant))return -1;(void)event_path;if(evfd>=0&&ctrl_release(evfd))return -1;if(ifn&&*ifn){char *r1[]={BB,"ip","route","flush","dev",(char*)ifn,NULL};char *r2[]={BB,"ip","addr","flush","dev",(char*)ifn,NULL};char *r3[]={BB,"ip","link","set","dev",(char*)ifn,"down",NULL};if(run_cmd("route_flush",r1,5000)||run_cmd("addr_flush",r2,5000)||run_cmd("link_down",r3,5000))return -1;char sock[PATH_MAX];snprintf(sock,sizeof(sock),"%s/%s",WDIR,ifn);if(unlink(sock)&&errno!=ENOENT)return -1;}if(lease_exists&&unlink(LEASE)&&errno!=ENOENT)return -1;if(temp_owned&&unlink("/run/m12/dhcp.lease.tmp")&&errno!=ENOENT)return -1;if(hook_exists&&unlink(SCRIPT)&&errno!=ENOENT)return -1;if(!hook_exists&&!access(SCRIPT,F_OK)){errno=EEXIST;return -1;}if(config_exists&&unlink(CONF)&&errno!=ENOENT)return -1;if(rmdir(WDIR)&&errno!=ENOENT)return -1;return 0;}

int main(void){
 struct result r[]={{"firmware",BLOCKED,0},{"interface",BLOCKED,0},{"scan",BLOCKED,0},{"association",BLOCKED,0},{"wpa",BLOCKED,0},{"dhcp",BLOCKED,0},{"ping",BLOCKED,0},{"network_cleanup",BLOCKED,0}};
 struct m12_wifi_credentials cred;memset(&cred,0,sizeof(cred));char bdf[64]={0},ifn[IFNAMSIZ]={0},event_path[sizeof(((struct sockaddr_un*)0)->sun_path)]={0};pid_t wp=-1;int evfd=-1,config_exists=0,hook_exists=0,lease_exists=0,temp_owned=0,operated=0,all=0;
 crumb("network_begin",0);crumb("config_begin",0);
 if(TEST_CALL(config_load,&cred)){int e=errno;crumb("config_return",-e);mark(&r[0],BLOCKED,-e);goto done;}config_exists=1;crumb("config_return",0);
 crumb("firmware_begin",0);unsigned idx=0;if(TEST_CALL(wait_stack_ready,bdf,sizeof(bdf),ifn,sizeof(ifn),&idx)){int e=errno;crumb("firmware_return",-e);mark(&r[0],FAIL,-e);crumb("interface_begin",0);crumb("interface_return",-ENODEV);mark(&r[1],BLOCKED,-ENODEV);goto done;}crumb("firmware_return",0);mark(&r[0],PASS,0);
 crumb("interface_begin",0);int ix=TEST_CALL(if_index,ifn);if(ix<0||!idx||(unsigned)ix!=idx||TEST_CALL(nl80211_ready,(unsigned)ix)){int e=errno?errno:ENODEV;crumb("interface_return",-e);mark(&r[1],FAIL,-e);goto done;}crumb("interface_return",0);mark(&r[1],PASS,0);
 if(TEST_CALL0(make_ctrl_dir)){mark(&r[2],FAIL,-errno);goto done;}if(TEST_CALL0(prepare_hook)){mark(&r[2],FAIL,-errno);goto done;}hook_exists=1;
 crumb("supplicant_spawn_begin",0);char *wa[]={WPA,"-Dnl80211","-i",ifn,"-c",CONF,NULL};wp=TEST_CALL(supplicant_spawn,wa);int we=errno;crumb("supplicant_spawn_return",wp<0?-we:0);if(wp<0){mark(&r[2],FAIL,-we);goto done;}operated=1;
 char server[PATH_MAX];snprintf(server,sizeof(server),"%s/%s",WDIR,ifn);if(TEST_CALL(wait_path,server,12000)){int e=errno;if(supplicant.reaped)wp=-1;mark(&r[2],FAIL,-e);goto done;}crumb("ctrl_attach_begin",0);evfd=TEST_CALL(event_socket,ifn,event_path,sizeof(event_path));int ae=errno;crumb("ctrl_attach_result",evfd<0?-ae:0);if(evfd<0){mark(&r[2],FAIL,-ae);goto done;}
 crumb("scan_begin",0);int sr=TEST_CALL(scan_target,ifn,evfd,cred.ssid,cred.ssid_len);int se=errno;crumb("scan_return",sr?-se:0);if(sr){mark(&r[2],FAIL,-se);goto done;}mark(&r[2],PASS,0);
 crumb("association_begin",0);if(TEST_CALL(command_ok,ifn,"SELECT_NETWORK 0")||TEST_CALL(wait_wpa,ifn,1,30000)){int e=errno;crumb("association_return",-e);mark(&r[3],FAIL,-e);goto done;}crumb("association_return",0);mark(&r[3],PASS,0);
 crumb("wpa_begin",0);if(TEST_CALL(wait_wpa,ifn,0,30000)){int e=errno;crumb("wpa_return",-e);mark(&r[4],FAIL,-e);goto done;}crumb("wpa_return",0);mark(&r[4],PASS,0);
 crumb("dhcp_begin",0);struct stat pre;if(!TEST_CALL(lstat,LEASE,&pre)||errno!=ENOENT){crumb("dhcp_return",-EEXIST);mark(&r[5],FAIL,-EEXIST);goto done;}if(!TEST_CALL(lstat,"/run/m12/dhcp.lease.tmp",&pre)||errno!=ENOENT){crumb("dhcp_return",-EEXIST);mark(&r[5],FAIL,-EEXIST);goto done;}char *up[]={BB,"ip","link","set","dev",ifn,"up",NULL};if(TEST_CALL(run_cmd,"link_up",up,5000)){int e=errno;crumb("dhcp_return",-e);mark(&r[5],FAIL,-e);goto done;}char *dh[]={BB,"udhcpc","-f","-n","-q","-t","5","-T","3","-i",ifn,"-s",SCRIPT,NULL};pid_t dp=TEST_CALL(spawn,dh);if(dp<0){int e=errno;crumb("dhcp_return",-e);mark(&r[5],FAIL,-e);goto done;}temp_owned=1;int dst;if(TEST_CALL(wait_child,dp,45000,&dst)){int e=errno;if(TEST_CALL(stop_child,dp,1000))unresolved_hold();crumb("dhcp_return",-e);mark(&r[5],FAIL,-e);goto done;}if(!TEST_CALL(lstat,LEASE,&pre))lease_exists=1;if(!WIFEXITED(dst)||WEXITSTATUS(dst)){crumb("dhcp_return",-EIO);mark(&r[5],FAIL,-EIO);goto done;}char ip[16]={0},mask[16]={0},gw[16]={0},cidr[32]={0};unsigned prefix;if(TEST_CALL(lease_read,ip,sizeof(ip),mask,sizeof(mask),gw,sizeof(gw),&prefix)){int e=errno?errno:EPROTO;crumb("dhcp_return",-e);mark(&r[5],FAIL,-e);goto done;}lease_exists=1;snprintf(cidr,sizeof(cidr),"%s/%u",ip,prefix);char *ad[]={BB,"ip","addr","add",cidr,"dev",ifn,NULL};if(TEST_CALL(run_cmd,"address_add",ad,5000)){int e=errno;crumb("dhcp_return",-e);mark(&r[5],FAIL,-e);goto done;}char *rt[]={BB,"ip","route","add","default","via",gw,"dev",ifn,NULL};if(TEST_CALL(run_cmd,"default_route_add",rt,5000)){int e=errno;crumb("dhcp_return",-e);mark(&r[5],FAIL,-e);goto done;}crumb("dhcp_return",0);mark(&r[5],PASS,0);secret_clear(ip,sizeof(ip));secret_clear(mask,sizeof(mask));secret_clear(cidr,sizeof(cidr));
 crumb("ping_begin",0);char *pg[]={BB,"ping","-c","1","-W","5","-I",ifn,gw,NULL};if(TEST_CALL(run_cmd,"gateway_ping",pg,7000)){int e=errno;crumb("ping_return",-e);mark(&r[6],FAIL,-e);goto done;}crumb("ping_return",0);mark(&r[6],PASS,0);secret_clear(gw,sizeof(gw));
 all=1;
done:
 secret_clear(&cred,sizeof(cred));crumb("cleanup_begin",0);if(TEST_CALL(cleanup_network,ifn,wp,evfd,event_path,lease_exists,temp_owned,hook_exists,config_exists)){crumb("cleanup_return",-errno);mark(&r[7],FAIL,-errno);/* Unresolved teardown is unsafe: remain alive for the parent timeout/hold. */unresolved_hold();}crumb("cleanup_return",0);mark(&r[7],PASS,0);if(!operated&&r[0].state==BLOCKED)r[7].state=PASS;crumb("network_return",all?0:-EIO);
 if(all&&r[7].state==PASS){for(size_t i=0;i<sizeof(r)/sizeof(r[0]);i++)r[i].state=PASS;}
 int ok=1;for(size_t i=0;i<sizeof(r)/sizeof(r[0]);i++){if(TEST_CALL(emit,&r[i]))ok=0;}return ok&&all&&r[7].state==PASS?0:2;
}
