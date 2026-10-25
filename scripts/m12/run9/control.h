#ifndef M12_CONTROL_H
#define M12_CONTROL_H
/* One process, at most one monitor and one request in flight. No pre-bind
 * unlink. A pathname is retired only after its bound inode is verified. */
struct ctrl_owner { int used,fd; uint64_t id; dev_t dev; ino_t ino; char path[108]; };
static struct ctrl_owner ctrl_owners[4];
static uint64_t ctrl_sequence;
static int ctrl_monitor_fd=-1;
#ifndef M12_CTRL_CLOSE
#define M12_CTRL_CLOSE close
#endif
static struct ctrl_owner *ctrl_owner(int fd){for(unsigned i=0;i<4;i++)if(ctrl_owners[i].used&&ctrl_owners[i].fd==fd)return &ctrl_owners[i];return NULL;}
static int ctrl_owned(int fd){struct ctrl_owner *o=ctrl_owner(fd);struct stat s;if(!o){errno=EBADF;return -1;}if(lstat(o->path,&s)){return -1;}if(!S_ISSOCK(s.st_mode)||s.st_dev!=o->dev||s.st_ino!=o->ino){errno=ESTALE;return -1;}return 0;}
__attribute__((noinline)) static int ctrl_release(int fd){struct ctrl_owner *o=ctrl_owner(fd);if(!o){errno=EBADF;return -1;}int e=0;if(M12_CTRL_CLOSE(fd))e=errno;
 struct stat s;if(lstat(o->path,&s)){if(errno!=ENOENT&&!e)e=errno;}else if(!S_ISSOCK(s.st_mode)||s.st_dev!=o->dev||s.st_ino!=o->ino){if(!e)e=ESTALE;}else if(unlink(o->path)&&!e)e=errno;
 if(ctrl_monitor_fd==fd)ctrl_monitor_fd=-1;
 memset(o,0,sizeof(*o));if(e){errno=e;return -1;}return 0;
}
/* Kept out of line for the independent ARM64 symbol/call inspection. */
__attribute__((noinline)) static int ctrl_connect(const char *ifn,char *local,size_t cap){
 char remote[108],path[108];if(cap)local[0]=0;
 if(ctrl_sequence>=INT_MAX){errno=EOVERFLOW;return -1;}uint64_t id=++ctrl_sequence;
 int n=snprintf(path,sizeof(path),"%s/c-%ld-%llu",WDIR,(long)getpid(),(unsigned long long)id);
 int r=snprintf(remote,sizeof(remote),"%s/%s",WDIR,ifn);
 if(n<0||r<0||(size_t)n>=sizeof(path)||(size_t)r>=sizeof(remote)||(size_t)n>=cap){errno=ENAMETOOLONG;return -1;}
 struct ctrl_owner *o=NULL;for(unsigned i=0;i<4;i++)if(!ctrl_owners[i].used){o=&ctrl_owners[i];break;}
 if(!o){errno=EMFILE;return -1;}
 int fd=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0);if(fd<0)return -1;
 struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,path);
 if(bind(fd,(void*)&a,sizeof(a))){int e=errno;close(fd);errno=e;return -1;}
 struct stat st;if(lstat(path,&st)||!S_ISSOCK(st.st_mode)){int e=errno?errno:EPROTO;close(fd);errno=e;return -1;}
 *o=(struct ctrl_owner){.used=1,.fd=fd,.id=id,.dev=st.st_dev,.ino=st.st_ino};strcpy(o->path,path);
 struct sockaddr_un dst={.sun_family=AF_UNIX};strcpy(dst.sun_path,remote);
 struct timeval tv={.tv_sec=2};
 if(connect(fd,(void*)&dst,sizeof(dst))||setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv))){int e=errno;(void)ctrl_release(fd);errno=e;return -1;}
 strcpy(local,path);crumb("ctrl_channel_id",(int)id);
 if(ctrl_monitor_fd>=0&&fd!=ctrl_monitor_fd){struct ctrl_owner *monitor=ctrl_owner(ctrl_monitor_fd);if(!monitor||!strcmp(o->path,monitor->path)||o->id==monitor->id){(void)ctrl_release(fd);local[0]=0;errno=ESTALE;return -1;}crumb("ctrl_distinct",1);}
 return fd;
}
static int recv_ctrl(int fd,char *b,size_t cap){if(cap<2){errno=EINVAL;return -1;}struct iovec i={b,cap-1};struct msghdr m={.msg_iov=&i,.msg_iovlen=1};ssize_t n=recvmsg(fd,&m,0);if(n<0)return -1;if(m.msg_flags&MSG_TRUNC){errno=EMSGSIZE;return -1;}if(!n||memchr(b,0,(size_t)n)){errno=EPROTO;return -1;}b[n]=0;return (int)n;}
static int ctrl_cmd(const char *ifn,const char *cmd,char *reply,size_t cap,size_t *n){char local[108];int fd=ctrl_connect(ifn,local,sizeof(local));if(fd<0)return -1;ssize_t sent=send(fd,cmd,strlen(cmd),0);int got=-1,e=0;if(sent!=(ssize_t)strlen(cmd))e=sent<0?errno:EIO;else{got=recv_ctrl(fd,reply,cap);if(got<0)e=errno;}if(ctrl_release(fd)&&!e)e=errno;if(e){errno=e;return -1;}if(n)*n=(size_t)got;return 0;}
static int command_ok(const char *ifn,const char *cmd){char b[4097];size_t n;if(ctrl_cmd(ifn,cmd,b,sizeof(b),&n))return -1;return n==3&&!memcmp(b,"OK\n",3)?0:(errno=EPROTO,-1);}
static int event_socket(const char *ifn,char *local,size_t cap){int fd=ctrl_connect(ifn,local,cap);if(fd<0)return -1;int e=0;ssize_t sent=send(fd,"ATTACH",6,0);char b[4097];int n=-1;if(sent!=6)e=sent<0?errno:EIO;else{n=recv_ctrl(fd,b,sizeof(b));if(n<0)e=errno;else if(n!=3||memcmp(b,"OK\n",3))e=EPROTO;}if(e){(void)ctrl_release(fd);local[0]=0;errno=e;return -1;}ctrl_monitor_fd=fd;return fd;}
static int ctrl_alive(void){if(supplicant.pid<=0)return 0;int r=sup_check(&supplicant);if(r){if(r>0)errno=ECHILD;return -1;}return 0;}
static int ctrl_poll(int fd,uint64_t end){for(;;){if(ctrl_alive())return -1;if(ctrl_owned(fd)){int e=errno;crumb("monitor_path_error",-e);errno=ENOTCONN;return -1;}uint64_t now=now_ms();if(now>=end){errno=ETIMEDOUT;return -1;}unsigned left=(unsigned)(end-now);struct pollfd p={fd,POLLIN,0};int r=poll(&p,1,left>100?100:(int)left);if(r<0&&errno==EINTR)continue;if(r<0)return -1;if(p.revents&(POLLERR|POLLHUP|POLLNVAL)){errno=ENOTCONN;return -1;}if(r)return 0;}}
/* PING proves reply reachability. LEVEL3 also verifies this exact sender is
 * still an attached monitor (pinned2.12 ctrl_iface_unix.c/ctrl_iface_level).
 * Both round trips share one1s budget; arbitrary event text is never logged. */
static int monitor_probe(int ev){uint64_t end=now_ms()+1000;const char *cmds[]={"PING","LEVEL 3"},*answers[]={"PONG\n","OK\n"};unsigned skipped=0;
 for(unsigned i=0;i<2;i++){ssize_t n=send(ev,cmds[i],strlen(cmds[i]),0);if(n!=(ssize_t)strlen(cmds[i])){if(n>=0)errno=EIO;return -1;}
  for(;;){if(ctrl_poll(ev,end))return -1;char b[4097];int z=recv_ctrl(ev,b,sizeof(b));if(z<0)return -1;if((size_t)z==strlen(answers[i])&&!memcmp(b,answers[i],(size_t)z))break;if(b[0]!='<'||++skipped>64){errno=ENOTCONN;return -1;}}
 }crumb("monitor_probe_events",(int)skipped);return 0;
}
enum scan_event { SCAN_OTHER,SCAN_STARTED,SCAN_RESULTS,SCAN_FAILED,SCAN_DISCONNECTED };
static int scan_event_parse(const char *b,int *ret){size_t n=strlen(b);if(n<4||b[0]!='<'||b[1]<'0'||b[1]>'7'||b[2]!='>'){errno=EPROTO;return -1;}const char *s=b+3;
 static const char *names[]={"CTRL-EVENT-SCAN-STARTED","CTRL-EVENT-SCAN-RESULTS","CTRL-EVENT-SCAN-FAILED","CTRL-EVENT-TERMINATING"};
 for(unsigned i=0;i<4;i++){size_t z=strlen(names[i]);if(strncmp(s,names[i],z)||!(s[z]==0||s[z]==' '||s[z]=='\n'))continue;
  if(i==2){s+=z;if(strncmp(s," ret=",5)){errno=EPROTO;return -1;}s+=5;char *end;errno=0;long value=strtol(s,&end,10);if(errno||end==s||value<INT_MIN||value>INT_MAX||!(*end==0||*end==' '||*end=='\n')){errno=EPROTO;return -1;}*ret=(int)value;}
  return (int)i+1;
 }return SCAN_OTHER;
}
/* Decode pinned printf_encode SSIDs before comparison. Never emit SSID/BSSID. */
static int scan_ssid(const char *p,size_t n,unsigned char out[32],size_t *used){size_t k=0;for(size_t i=0;i<n;i++){unsigned char c=(unsigned char)p[i];if(c=='\\'){if(++i>=n)return -1;c=(unsigned char)p[i];if(c=='x'){if(i+2>=n)return -1;int hi=hexval(p[i+1]),lo=hexval(p[i+2]);if(hi<0||lo<0)return -1;c=(unsigned char)(hi*16+lo);i+=2;}else if(c=='n')c='\n';else if(c=='r')c='\r';else if(c=='t')c='\t';else if(c=='e')c=27;else if(c!='\\'&&c!='"')return -1;}if(k>=32)return -1;out[k++]=c;}*used=k;return 0;}
static int scan_inventory(const char *b,size_t n,const unsigned char *ssid,size_t sl){
 const char header[]="bssid / frequency / signal level / flags / ssid\n";
 if(n>=4000){crumb("scan_results_truncated",1);errno=EOVERFLOW;return -1;}
 if(n<sizeof(header)-1||memcmp(b,header,sizeof(header)-1)){errno=EPROTO;return -1;}
 size_t pos=sizeof(header)-1;unsigned aps=0;int found=0;
 while(pos<n){size_t end=pos;while(end<n&&b[end]!='\n')end++;if(end==n){errno=EPROTO;return -1;}if(end==pos){errno=EPROTO;return -1;}
  size_t at=pos;unsigned tabs=0;for(size_t j=pos;j<end;j++)if(b[j]=='\t'&&++tabs==4){at=j+1;break;}
  if(tabs!=4){errno=EPROTO;return -1;}unsigned char decoded[32];size_t z;if(scan_ssid(b+at,end-at,decoded,&z)){errno=EPROTO;return -1;}if(z==sl&&!memcmp(decoded,ssid,sl))found=1;secret_clear(decoded,sizeof(decoded));aps++;pos=end+1;
 }
 crumb("scan_ap_count",(int)aps);if(!aps){crumb("scan_zero_aps",1);errno=ENODATA;return -1;}if(!found){crumb("scan_target_absent",1);errno=ENOENT;return -1;}crumb("scan_target_found",1);return 0;
}
static int scan_target(const char *ifn,int ev,const unsigned char *ssid,size_t sl){
 int fl=fcntl(ev,F_GETFL);if(fl<0||fcntl(ev,F_SETFL,fl|O_NONBLOCK))return -1;unsigned stale=0;int error=0;
 for(;;){char b[4097];int n=recv_ctrl(ev,b,sizeof(b));if(n<0){if(errno==EINTR)continue;if(errno==EAGAIN||errno==EWOULDBLOCK)break;error=errno;break;}if(++stale>64){error=EOVERFLOW;break;}}
 if(fcntl(ev,F_SETFL,fl)&&!error)error=errno;
 if(error){errno=error;return -1;}crumb("scan_stale_events",(int)stale);crumb("monitor_health_begin",0);
 if(monitor_probe(ev)){int e=errno;crumb("monitor_health_result",-e);errno=e;return -1;}crumb("monitor_health_result",0);
 char ack[4097];size_t an;crumb("scan_command_begin",0);
 if(ctrl_cmd(ifn,"SCAN",ack,sizeof(ack),&an)){int e=errno;crumb("scan_command_error",-e);errno=e;return -1;}
 if(an!=3||memcmp(ack,"OK\n",3)){int e=(an==10&&!memcmp(ack,"FAIL-BUSY\n",10))?EBUSY:EIO;crumb("scan_rejected",-e);errno=e;return -1;}crumb("scan_ack",0);
 uint64_t end=now_ms()+25000;unsigned other=0,started=0;
 for(;;){if(ctrl_poll(ev,end)){int e=errno;
   if(e==ETIMEDOUT){crumb("scan_timeout_started",(int)started);if(monitor_probe(ev)){int pe=errno;crumb("monitor_lost",-pe);if(pe!=ECHILD)pe=ENOTCONN;errno=pe;return -1;}crumb("monitor_timeout_health",0);}
   else crumb(e==ECHILD?"scan_child_exit":"scan_monitor_error",-e);
   errno=e;return -1;
  }
  char b[4097];int n=recv_ctrl(ev,b,sizeof(b));if(n<0){int e=errno;crumb("scan_event_read_error",-e);errno=e;return -1;}
  int ret=0,kind=scan_event_parse(b,&ret);if(kind<0){crumb("scan_event_malformed",-EPROTO);errno=EPROTO;return -1;}
  if(kind==SCAN_STARTED){if(++started>16){crumb("scan_started_overflow",-EOVERFLOW);errno=EOVERFLOW;return -1;}crumb("scan_started",(int)started);}
  else if(kind==SCAN_FAILED){crumb("scan_failed_event",ret);errno=ret<0&&ret>=-4095?-ret:EIO;return -1;}
  else if(kind==SCAN_DISCONNECTED){crumb("scan_monitor_disconnect",1);errno=ENOTCONN;return -1;}
  else if(kind==SCAN_RESULTS){crumb("scan_results_event",1);break;}
  else if(++other>256){crumb("scan_other_events",(int)other);errno=EOVERFLOW;return -1;}
 }
 crumb("scan_other_events",(int)other);char results[4097];size_t n;
 if(ctrl_cmd(ifn,"SCAN_RESULTS",results,sizeof(results),&n)){int e=errno;crumb("scan_results_error",-e);errno=e;return -1;}
 return scan_inventory(results,n,ssid,sl);
}
#endif
