/* SPDX-License-Identifier: GPL-2.0-only */
/* Observations only. No charger, Type-C, thermal, ADSP or module control API. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct field { const char *supply, *name, *unit; };
static const struct field fields[] = {
 {"battery","type","text"}, {"battery","present","bool"},
 {"battery","status","text"}, {"battery","health","text"},
 {"battery","capacity","percent"}, {"battery","voltage_now","uV"},
 {"battery","current_now","uA"}, {"battery","temp","deciC"},
 {"battery","charge_control_limit","index"},
 {"battery","charge_control_limit_max","index"},
 {"usb","type","text"}, {"usb","online","bool"},
 {"usb","usb_type","selection"}, {"usb","voltage_now","uV"},
 {"usb","current_now","uA"}, {"usb","voltage_max","uV"},
 {"usb","current_max","uA"}, {"usb","input_current_limit","uA"},
 {"usb","temp","deciC"}
};
#define NF (sizeof(fields)/sizeof(fields[0]))
static unsigned seq;
static const struct field vendor_fields[] = {
 {"qcom-battery","pdo2","hex32"},
 {"qcom-battery","apdo_max","vendor_raw_u32"},
 {"qcom-battery","power_max","vendor_raw_u32"}
};
static const char *const partner_fields[]={
 "supports_usb_power_delivery", "usb_power_delivery_revision"
};
#define NV (sizeof(vendor_fields)/sizeof(vendor_fields[0]))
#define NP (sizeof(partner_fields)/sizeof(partner_fields[0]))
static long long now_ms(void) {
 struct timespec t;
 if (clock_gettime(CLOCK_MONOTONIC,&t)) _exit(90);
 return (long long)t.tv_sec*1000+t.tv_nsec/1000000;
}
static void quoted(const char *s) {
 putchar('"');
 for (const unsigned char *p=(const unsigned char *)s; *p; ++p) {
  if (*p=='"'||*p=='\\') { putchar('\\'); putchar(*p); }
  else if (*p<32 || *p>=127) printf("\\u%04x",*p);
  else putchar(*p);
 }
 putchar('"');
}
static void header(const char *kind, unsigned sample) {
 printf("{\"schema\":\"M15O2\",\"seq\":%u,\"kind\":\"%s\",\"sample\":%u,\"mono_ms\":%lld",
        seq++,kind,sample,now_ms());
}
static void finish(void) {
 puts("}");
 if (fflush(stdout) || ferror(stdout)) _exit(91);
}
static int optional_value(const char *group,const char *name,const char *s) {
 if(!strcmp(group,"qcom-battery")) {
  if(!strcmp(name,"pdo2")) {
   if(strlen(s)!=8)return 0;
   for(const char *p=s;*p;p++)if(!((*p>='0'&&*p<='9')||(*p>='a'&&*p<='f')||(*p>='A'&&*p<='F')))return 0;
   return 1;
  }
  if(!*s || (s[0]=='0' && s[1]))return 0;
  for(const char *p=s;*p;p++)if(*p<'0'||*p>'9')return 0;
  errno=0;char *end;unsigned long long n=strtoull(s,&end,10);
  return !errno && !*end && n<=UINT32_MAX;
 }
 const char *leaf=strrchr(name,'/');leaf=leaf?leaf+1:name;
 if(!strcmp(leaf,"supports_usb_power_delivery"))return !strcmp(s,"yes")||!strcmp(s,"no");
 /* Kernel prints the cached revision as two unsigned decimal components.
  * Accept the format only, not the revision's claimed meaning or freshness. */
 if(strlen(s)>6)return 0;
 unsigned a=0,b=0;char tail;
 if(sscanf(s,"%u.%u%c",&a,&b,&tail)!=2 || a>255 || b>15)return 0;
 char canonical[16];snprintf(canonical,sizeof(canonical),"%u.%u",a,b);
 return !strcmp(s,canonical);
}
static void observe(const char *root, unsigned sample, const char *group,
                    const char *name, const char *unit) {
 char path[PATH_MAX],value[513];
 int n=snprintf(path,sizeof(path),"%s/class/%s/%s",root,group,name);
 header("read_begin",sample); printf(",\"path\":"); quoted(name);
 printf(",\"group\":");quoted(group); finish();
 int err=0;size_t used=0;
 if (n<0 || (size_t)n>=sizeof(path)) err=ENAMETOOLONG;
 int fd=err?-1:open(path,O_RDONLY|O_CLOEXEC|O_NONBLOCK);
 if (!err && fd<0) err=errno;
 if (!err) {
  struct stat st;
  if (fstat(fd,&st)) err=errno;
  else if (!S_ISREG(st.st_mode)) err=EINVAL;
  while (!err && used<sizeof(value)) {
   ssize_t got=read(fd,value+used,sizeof(value)-used);
   if (got<0) { if (errno==EINTR) continue;err=errno;break; }
   if (!got) break;
   used+=(size_t)got;
  }
  if (!err && used==sizeof(value)) err=EOVERFLOW;
  if (!err && !used) err=ENODATA;
  if (!err && memchr(value,0,used)) err=EILSEQ;
  if (close(fd) && !err) err=errno;
 }
 if (err) value[0]=0;
 else { value[used]=0; if (used && value[used-1]=='\n') value[used-1]=0; }
 int optional=!strcmp(group,"qcom-battery") || strstr(name,"-partner/")!=NULL;
 int value_valid=!err && (!optional || optional_value(group,name,value));
 /* Malformed optional data is never echoed: preserve actual syscall rc/errno,
  * and mark format invalid separately instead of inventing an I/O errno. */
 if(optional && !value_valid)value[0]=0;
 header("read_end",sample);printf(",\"path\":");quoted(name);
 printf(",\"group\":");quoted(group);printf(",\"unit\":");quoted(unit);
 printf(",\"rc\":%d,\"errno\":%d,\"value\":",err?-1:0,err);quoted(value);
 if(optional)printf(",\"value_valid\":%s",value_valid?"true":"false");
 finish();
}
static int port_name(const char *s) {
 if (strncmp(s,"port",4) || !s[4]) return 0;
 for (s+=4;*s;s++) if (*s<'0'||*s>'9') return 0;
 return 1;
}
static void collect(const char *root,unsigned samples,unsigned interval) {
 header("start",0);printf(",\"samples\":%u,\"power_fields\":%zu,\"control_permitted\":false",samples,NF);printf(",\"extension\":\"vendor-partner-v1\",\"vendor_fields\":%zu,\"partner_fields_per_port\":%zu",NV,NP);finish();
 for (unsigned sample=0;sample<samples;sample++) {
  for (size_t i=0;i<NF;i++) {
   char name[96];snprintf(name,sizeof(name),"%s/%s",fields[i].supply,fields[i].name);
   observe(root,sample,"power_supply",name,fields[i].unit);
  }
  for (size_t i=0;i<NV;i++) {
   observe(root,sample,"qcom-battery",vendor_fields[i].name,vendor_fields[i].unit);
  }
  char dir[PATH_MAX];snprintf(dir,sizeof(dir),"%s/class/typec",root);
  struct dirent **entries=NULL;int count=scandir(dir,&entries,NULL,alphasort);
  int error=count<0?errno:0;unsigned ports=0;
  if (count>=0) {
   for (int i=0;i<count;i++) {
    if (port_name(entries[i]->d_name)) {
     if (++ports<=8) {
      const char *names[]={"power_role","data_role","power_operation_mode"};
      for (size_t j=0;j<3;j++) {
       char name[320];snprintf(name,sizeof(name),"%s/%s",entries[i]->d_name,names[j]);
       observe(root,sample,"typec",name,"text");
      }
      /* Derive the partner from the discovered port, never from partner census.
       * Absent/disappeared partner paths still get one real open/read attempt. */
      for (size_t j=0;j<NP;j++) {
       char name[320];snprintf(name,sizeof(name),"%s-partner/%s",entries[i]->d_name,partner_fields[j]);
       observe(root,sample,"typec",name,"text");
      }
     } else error=EOVERFLOW;
    }
    free(entries[i]);
   }
   free(entries);
  }
  header("typec_inventory",sample);printf(",\"ports\":%u,\"errno\":%d",ports,error);finish();
  if (sample+1<samples) {
   struct timespec t={(time_t)(interval/1000),(long)(interval%1000)*1000000};
   while (nanosleep(&t,&t) && errno==EINTR) {}
  }
 }
 header("end",samples-1);printf(",\"records\":%u,\"control_permitted\":false",seq);finish();
}
static int write_all(int fd,const void *data,size_t n) {
 const char *p=data;
 while(n) { ssize_t k=write(fd,p,n);if(k<0 && errno==EINTR)continue;if(k<=0)return -1;p+=k;n-=(size_t)k; }
 return 0;
}
static int wait_bounded(pid_t child,int *status,long long until) {
 do {
  pid_t p=waitpid(child,status,WNOHANG);
  if(p==child)return 0;
  if(p<0 && errno!=EINTR)return -1;
  struct timespec t={0,1000000};nanosleep(&t,NULL);
 } while(now_ms()<until);
 return -1;
}
static int number(const char *s,unsigned lo,unsigned hi,unsigned *out) {
 char *end=NULL;errno=0;unsigned long n=strtoul(s,&end,10);
 if (!*s || *s=='-' || errno || *end || n<lo || n>hi)return -1;
 *out=(unsigned)n;return 0;
}
int main(int argc,char **argv) {
 const char *root=NULL;unsigned samples=3,interval=1000,deadline=90000;
 for(int i=1;i<argc;i++) {
  if(!strcmp(argv[i],"--sysfs")) { if(root)return 64;root="/sys"; }
  else if(!strcmp(argv[i],"--fixture-root") && i+1<argc) { if(root)return 64;root=argv[++i]; }
  else if(!strcmp(argv[i],"--samples") && i+1<argc) { if(number(argv[++i],1,10,&samples))return 64; }
  else if(!strcmp(argv[i],"--interval-ms") && i+1<argc) { if(number(argv[++i],1,10000,&interval))return 64; }
  else if(!strcmp(argv[i],"--deadline-ms") && i+1<argc) { if(number(argv[++i],10,120000,&deadline))return 64; }
  else return 64;
 }
 if(!root) { fputs("Explicit --sysfs or --fixture-root required; observations only\n",stderr);return 64; }
 int pipefd[2];if(pipe2(pipefd,O_CLOEXEC))return 70;
 signal(SIGPIPE,SIG_IGN);
 pid_t child=fork();if(child<0)return 70;
 if(!child) {
  close(pipefd[0]);if(dup2(pipefd[1],STDOUT_FILENO)<0)_exit(92);close(pipefd[1]);
  setvbuf(stdout,NULL,_IONBF,0);collect(root,samples,interval);_exit(0);
 }
 close(pipefd[1]);long long until=now_ms()+deadline;int failure=0,eof=0,status=0;
 /* Parent stdout must not block an acquisition deadline. Backpressure fails
  * the transcript instead of silently dropping records or claiming a seal. */
 int flags=fcntl(STDOUT_FILENO,F_GETFL);
 if(flags<0 || fcntl(STDOUT_FILENO,F_SETFL,flags|O_NONBLOCK)<0)failure=EIO;
 while(!failure && !eof) {
  long long remaining=until-now_ms();if(remaining<=0){failure=ETIMEDOUT;break;}
  struct pollfd p={pipefd[0],POLLIN,0};int rc=poll(&p,1,(int)remaining);
  if(rc<0){if(errno==EINTR)continue;failure=errno;break;}
  if(!rc){failure=ETIMEDOUT;break;}
  if(p.revents&(POLLERR|POLLNVAL)){failure=EIO;break;}
  char buf[4096];ssize_t n=read(pipefd[0],buf,sizeof(buf));
  if(n<0){if(errno==EINTR)continue;failure=errno;break;}
  if(!n)eof=1;else if(write_all(STDOUT_FILENO,buf,(size_t)n))failure=errno?errno:EIO;
 }
 close(pipefd[0]);
 if(failure)kill(child,SIGKILL);
 int reaped=wait_bounded(child,&status,now_ms()+500)==0;
 if(!reaped || failure || !WIFEXITED(status) || WEXITSTATUS(status)) {
  if(flags>=0)fcntl(STDOUT_FILENO,F_SETFL,flags);
  fprintf(stderr,"{\"supervisor\":\"FAIL\",\"errno\":%d,\"reaped\":%s,\"raw_status\":%d,\"control_permitted\":false}\n",failure,reaped?"true":"false",status);
  return 1;
 }
 const char receipt[]="{\"schema\":\"M15O2-supervisor\",\"reaped\":true,\"raw_status\":0,\"errno\":0,\"control_permitted\":false}\n";
 int delivered=write_all(STDOUT_FILENO,receipt,sizeof(receipt)-1)==0;
 if(flags>=0)fcntl(STDOUT_FILENO,F_SETFL,flags);
 if(!delivered){fputs("supervisor receipt output failed\n",stderr);return 1;}
 return 0;
}
