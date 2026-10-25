/* Offline cleanup successor of frozen Run5: golden-scoped kernel CBC; receipt-gated networking; no audio, userspace calibration, GPU or persistent writes. */
#define _GNU_SOURCE
#include <stdint.h>
#include <grp.h>
#include <sys/prctl.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "../run7/hwid.h"
static struct m12_hwid hwid_input;
static char hwid_params[160];
static int hwid_verified;
int m12_fs_ready_main(int argc,char **argv);
int m12_readiness_main(void);

static unsigned seq;
static int trace_fd=-1;
static char prequery_row[1024];
static int journal_sealed;
/* Own the label: retirement derives module names in a temporary stack array. */
static char current_job[256]="startup";
static char line[66000];
static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t)) return 0;
    return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec;
}
static void pump(void);
static void pause10(void) { pump();(void)poll(NULL,0,10); }
static int readtext(const char *path, char *b, size_t cap) {
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC); if (fd<0) return -1;
    ssize_t n=read(fd,b,cap-1); int rc=close(fd);
    if (n<0 || n==(ssize_t)cap-1 || rc) return -1;
    b[n]=0; return 0;
}
static int writefile(const char *path, const char *b) {
    int fd=open(path,O_WRONLY|O_CLOEXEC|O_NOFOLLOW); if (fd<0) return -1;
    size_t n=strlen(b); ssize_t rc=write(fd,b,n); int cr=close(fd);
    return rc==(ssize_t)n && !cr?0:-1;
}
static int marker(const char *path) {
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd<0) return -1;
    ssize_t n=write(fd,"1\n",2); int rc=close(fd); return n==2 && !rc?0:-1;
}
static int record(const char *operation, const char *payload, int rc) {
    size_t n=strlen(payload); uint64_t t=now();
    if (n>32768 || !t) return -1;
    int prefix=snprintf(line,sizeof(line),"M12I2 %u %llu.%09llu session %s metadata %d ",seq,
        (unsigned long long)(t/1000000000),(unsigned long long)(t%1000000000),operation,rc);
    if (prefix<0 || (size_t)prefix+2*n+2>=sizeof(line)) return -1;
    static const char hex[]="0123456789abcdef";
    size_t used=(size_t)prefix;
    for (size_t i=0;i<n;i++) { unsigned char c=(unsigned char)payload[i]; line[used++]=hex[c>>4]; line[used++]=hex[c&15]; }
    if (!n) line[used++]='-';
    line[used++]='\n'; line[used]=0;
    int fd=open("/run/m12-instrumentation/journal",O_WRONLY|O_APPEND|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return -1;
    ssize_t got=write(fd,line,used); int cr=close(fd);
    if (got!=(ssize_t)used || cr) return -1;
    seq++; char b[32]; snprintf(b,sizeof(b),"%u\n",seq);
    return writefile("/run/m12/jseq",b);
}
static int breadcrumb(const char *stage, long long rc) {
    if (trace_fd<0 || journal_sealed) return 0; /* prepare precedes opening the RAM sink */
    char b[384]; uint64_t t=now();
    int n=snprintf(b,sizeof(b),"M12DN %llu %s %lld\n",(unsigned long long)t,stage,rc);
    return !t || n<=0 || (size_t)n>=sizeof(b) || write(trace_fd,b,(size_t)n)!=n?-1:0;
}
static void hold(const char *why) __attribute__((noreturn));
static void hold(const char *why) {
    if (!journal_sealed) (void)record("hold",why,1);
    for (;;) (void)poll(NULL,0,60000);
}
/* Never retry or silently kill a still-running device/control syscall. */
static int reap(pid_t pid, unsigned ms) {
    uint64_t begin=now(), delta=(uint64_t)ms*1000000, last=begin; int status;
    if (!begin || pid<=1 || !ms || UINT64_MAX-begin<delta) return -1;
    uint64_t until=begin+delta;
    for (;;) {
        pid_t rc=waitpid(pid,&status,WNOHANG);
        if (rc==pid) return WIFEXITED(status)?WEXITSTATUS(status):-1;
        if (rc<0 && errno!=EINTR) return -1;
        uint64_t tick=now();
        if (!tick || tick<last) hold("monotonic clock invalid; child unresolved");
        last=tick;
        if (tick>=until) break;
        pause10();
    }
    if(!journal_sealed) (void)record("unresolved_child",current_job,-1);
    hold("unresolved control/helper child; resources retained");
}
static int control_job(const char *script, const char *arg, unsigned ms) {
    snprintf(current_job,sizeof(current_job),"%s",arg?arg:script);
    if (breadcrumb(arg?arg:script,-9223372036854775807LL)) hold("pre-job evidence failed");
    pid_t p=fork();
    if (!p) {
     int fd=open("/run/m12-control-output",O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);
     if(fd<0 || dup2(fd,1)<0 || dup2(fd,2)<0 || close(fd)) _exit(126);
     execl("/bin/busybox","busybox","sh",script,arg,(char *)NULL); _exit(127);
    }
    int rc=reap(p,ms);
    if(seq && !journal_sealed) {
     char output[4096];
     if(readtext("/run/m12-control-output",output,sizeof(output))) hold("control output absent/truncated");
     if(output[0] && record("control_output",output,rc)) hold("control output evidence failed");
    }
    if (breadcrumb(arg?arg:script,rc)) hold("post-job evidence failed");
    return rc;
}
/* Capture the same single result lifecycle while the USB evidence owner lives.
 * Helper stdout/stderr and returned status are journaled before the final seal. */
static int checkpoint(const char *color) {
    snprintf(current_job,sizeof(current_job),"%s",color);
    if (record("result_checkpoint_begin",color,0) ||
        breadcrumb(color,-9223372036854775807LL)) hold("checkpoint intent evidence failed");
    pid_t p=fork();
    if (!p) {
     int fd=open("/run/m12-checkpoint-output",O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);
     if(fd<0 || dup2(fd,1)<0 || dup2(fd,2)<0 || close(fd)) _exit(126);
     execl("/sbin/m12-checkpoint","m12-checkpoint",color,(char *)NULL); _exit(127);
    }
    int rc=reap(p,10000);
    char output[4096];
    if(readtext("/run/m12-checkpoint-output",output,sizeof(output))) hold("checkpoint output absent/truncated");
    if((output[0] && record("checkpoint_output",output,rc)) ||
       record("result_checkpoint_return",color,rc) || breadcrumb(color,rc)) hold("checkpoint return evidence failed");
    return rc;
}
static int wait_marker(const char *path, unsigned ms) {
    uint64_t begin=now(), until=begin+(uint64_t)ms*1000000; struct stat st;
    if (!begin) return -1;
    do { if (!lstat(path,&st)) return S_ISREG(st.st_mode)?0:-1; pause10(); } while (now() && now()<until);
    return -1;
}
static int receipt(void) {
    const char *path="/run/m12-instrumentation/host.receipt";
    struct stat st; char b[4];
    if (wait_marker(path,35000) || lstat(path,&st) || !S_ISREG(st.st_mode) ||
        st.st_uid!=65534 || st.st_gid!=65534 || (st.st_mode&0777)!=0600 || st.st_nlink!=1 ||
        readtext(path,b,sizeof(b)) || strcmp(b,"1\n")) return -1;
    return 0;
}
/* The requested row is generated and written by PID1. The relay can only
 * publish its exact host-ACKed bytes; identity ACK alone is insufficient. */
static int startup_barrier(void) {
    char nonce[80], identity[80], payload[256], actual[1024]; struct stat st;
    if (readtext("/m12/instrumentation/nonce",nonce,sizeof(nonce)) ||
        readtext("/m12/instrumentation/identity",identity,sizeof(identity)) ||
        strlen(nonce)!=33 || strlen(identity)!=65) return -1;
    nonce[32]=0; identity[64]=0;
    snprintf(payload,sizeof(payload),"pre-query %s %s amplifier_enable_permitted=0",nonce,identity);
    if (record("pre_query",payload,0)) return -1;
    /* record() leaves the exact line in the buffer, terminated by LF. */
    size_t n=0; while(n<sizeof(line) && line[n]!='\n') n++;
    if(n+1>=sizeof(prequery_row)) return -1;
    memcpy(prequery_row,line,n+1); prequery_row[n+1]=0;
    int fd=open("/run/m12-instrumentation/prequery.request",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0644);
    if(fd<0) return -1;
    ssize_t got=write(fd,prequery_row,n+1); int cr=close(fd);
    if(got!=(ssize_t)n+1 || cr || chmod("/run/m12-instrumentation/prequery.request",0644) || marker("/run/m12-instrumentation/prequery.ready")) return -1;
    /* Relay uid65534 must read ready; the request itself is world-readable. */
    if(chmod("/run/m12-instrumentation/prequery.ready",0644)) return -1;
    const char *p="/run/m12-instrumentation/prequery.receipt";
    if(wait_marker(p,35000) || lstat(p,&st) || !S_ISREG(st.st_mode) ||
       st.st_uid!=65534 || st.st_gid!=65534 || (st.st_mode&0777)!=0600 || st.st_nlink!=1 ||
       readtext(p,actual,sizeof(actual)) || strcmp(actual,prequery_row)) return -1;
    return record("pre_query_ack","PID1 accepted exact PC receipt of pre_query; amplifier_enable_permitted=0",0);
}

static const char *const usb_modules[] = {
 "i2c-msm-geni.ko", "regmap-spmi.ko", "qcom-spmi-pmic.ko",
 "pinctrl-spmi-gpio.ko", "qti_battery_charger_main.ko"
};
static const char *const wifi_modules[] = {
 "msm_qmp.ko", "pci-msm-drv.ko", "mhi.ko", "qrtr-mhi.ko",
 "cnss_plat_ipc_qmi_svc.ko", "hwid.ko", "memory_dump_v2.ko",
 "wlan_firmware_service.ko", "cnss2.ko"
};
static unsigned loaded_count=95;
static int module_call_attempted, module_call_returned;
static long module_rc;
static unsigned wifi_loaded;
static unsigned data_loaded;
#include "../run3/wlan-modules.inc"
#include "../run3/module-names.h"
static int module_count(void) {
 FILE *f=fopen("/proc/modules","re");
 if(!f) return -1;
 char b[4096]; int count=0;
 while(fgets(b,sizeof(b),f)) {
  if(!strchr(b,'\n')) { (void)fclose(f); return -1; }
  count++;
 }
 int bad=ferror(f); if(fclose(f) || bad) return -1;
 return count;
}
/* Separate child deadlines from a promise that a driver operation is bounded.
 * On unresolved child, reap() holds with the relay alive; it never proceeds to
 * removal/reboot while a loader, sysfs reader or teardown job may be in flight. */
static int executable_job(const char *kind, const char *name, unsigned ms) {
 snprintf(current_job,sizeof(current_job),"%s",name?name:kind);
 if(breadcrumb(name?name:kind,-9223372036854775807LL)) hold("pre-child evidence failed");
 pid_t p=fork();
 if(!p) {
  int fd=open("/run/m12/child-output",O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);
  if(fd<0 || dup2(fd,1)<0 || dup2(fd,2)<0 || close(fd)) _exit(126);
  if(!strcmp(kind,"load")) {
   char path[256]; int n=snprintf(path,sizeof(path),"/lib/modules/%s",name);
   if(n<=0 || (size_t)n>=sizeof(path)) _exit(126);
   if(!strcmp(name,"hwid.ko")) execl("/sbin/m12-load-one","m12-load-one",path,hwid_params,(char *)NULL);
   else execl("/sbin/m12-load-one","m12-load-one",path,(char *)NULL);
  } else if(!strcmp(kind,"observe")) {
   execl("/sbin/m12-observe","m12-observe","--root","/",(char *)NULL);
  } else if(!strcmp(kind,"remove")) {
   execl("/sbin/m12-remove-one","m12-remove-one",name,(char *)NULL);
  } else if(!strcmp(kind,"network")) {
   execl("/sbin/m12-network","m12-network",(char *)NULL);
  } else if(!strcmp(kind,"readiness")) {
   execl("/sbin/m12-run11","m12-run11","--readiness",(char *)NULL);
  } else if(!strcmp(kind,"fs_ready")) {
   execl("/sbin/m12-run11","m12-run11","--fs-ready",(char *)NULL);
  }
  _exit(127);
 }
 int rc=reap(p,ms);
 if(breadcrumb(name?name:kind,rc)) hold("post-child evidence failed");
 return rc;
}
/* A returned module call/count is not proof that HWID identity reached CNSS. */
static int hwid_read(const char *path,char *b,size_t cap,size_t *len) {
 int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return -errno;
 ssize_t n=read(fd,b,cap-1);int e=errno,cr=close(fd);
 if(n<0)return -e;
 if(cr)return -errno;
 if(!n || n==(ssize_t)cap-1)return -EOVERFLOW;
 b[n]=0;*len=(size_t)n;return 0;
}
static int hwid_prepare(void) {
 char b[16384];size_t n=0;
 int rc=hwid_read("/proc/cmdline",b,sizeof(b),&n);
 if(!rc && (m12_hwid_parse(b,n,1,&hwid_input) || m12_hwid_format(&hwid_input,hwid_params,sizeof(hwid_params))))rc=-EINVAL;
 if(record("hwid_input",rc?"invalid/missing bootloader identity; CNSS denied":hwid_params,rc))hold("HWID input evidence failed");
 return rc;
}
static int hwid_readback(void) {
 hwid_verified=0;
 for(unsigned i=0;i<4;i++) {
  char path[128],b[64],payload[256];size_t n=0;unsigned v=0;
  snprintf(path,sizeof(path),"/sys/module/hwid/parameters/%s",m12_hwid_keys[i]);
  int rc=hwid_read(path,b,sizeof(b),&n);
  if(!rc && m12_hwid_uint(b,n,&v))rc=-EPROTO;
  if(!rc && v!=hwid_input.v[i])rc=-EXDEV;
  snprintf(payload,sizeof(payload),"parameter=%s expected=%u observed=%u valid=%d",m12_hwid_keys[i],hwid_input.v[i],v,!rc);
  if(record("hwid_readback",payload,rc))hold("HWID readback evidence failed");
  if(rc)return rc;
 }
 hwid_verified=1;
 if(record("hwid_verified","all4 module parameters match current bootloader identity; CNSS admission allowed",0))hold("HWID admission evidence failed");
 return 0;
}
static int load_module(const char *name) {
 char payload[1024], raw[512], expected[300], *end;
 module_call_attempted=0; module_call_returned=0; module_rc=0;
 if(!strcmp(name,"cnss2.ko") && !hwid_verified) {if(record("hwid_denied","CNSS requires verified HWID parameters",-EPERM))hold("HWID denial evidence failed");return 1;}
 if(!strcmp(name,"hwid.ko") && hwid_prepare())return 1;
 module_call_attempted=1;
 snprintf(payload,sizeof(payload),"name=%s loaded_count=%u params=%s flags=0",name,loaded_count,!strcmp(name,"hwid.ko")?hwid_params:"empty");
 if(record("module_begin",payload,0)) hold("module begin evidence failed");
 int exitcode=executable_job("load",name,60000);
 if(readtext("/run/m12/child-output",raw,sizeof(raw))) hold("raw module evidence missing/truncated");
 snprintf(expected,sizeof(expected),"M11: finit_module path=/lib/modules/%s raw_rc=",name);
 if(strncmp(raw,expected,strlen(expected)) || (exitcode!=0 && exitcode!=1)) {
  (void)record("loader_error",raw,exitcode);
  hold("open/helper failure; syscall return not proven");
 }
 errno=0; module_rc=strtol(raw+strlen(expected),&end,10);
 if(errno || end==raw+strlen(expected) || strcmp(end,"\n") || module_rc>0 ||
    (exitcode==0)!=(module_rc==0)) hold("invalid raw finit_module result");
 module_call_returned=1;
 if(module_rc==0) loaded_count++;
 snprintf(payload,sizeof(payload),"name=%s attempted=%d returned=%d raw_rc=%ld loaded_count=%u",name,
          module_call_attempted,module_call_returned,module_rc,loaded_count);
 if(record("module_return",payload,exitcode)) hold("module return evidence failed");
 if(module_count()!=(int)loaded_count) hold("kernel module count differs after returned call");
 return module_rc==0?0:1;
}
/* A helper exit0 alone cannot authorize the success checkpoint. */
static int network_results(const char *text,int exitcode) {
 static const char *names[]={"firmware","interface","scan","association","wpa","dhcp","ping","disconnect","lease_reset","reconnect","reassociation","rewpa","redhcp","reping","network_cleanup"};
 unsigned seen=0;int all_pass=1,cleanup_ok=0;
 while(*text) {
  const char *end=strchr(text,'\n');if(!end || end-text>127)return -1;
  char row[128],name[32],state[16];int raw=0,used=0;
  memcpy(row,text,(size_t)(end-text));row[end-text]=0;
  if(sscanf(row,"M12NET %31s %15s rc=%d%n",name,state,&raw,&used)!=3 || row[used])return -1;
  unsigned i;for(i=0;i<15;i++)if(!strcmp(name,names[i]))break;
  if(i==15 || (seen&(1u<<i)))return -1;
  seen|=1u<<i;
  if(strcmp(state,"PASS") && strcmp(state,"FAIL") && strcmp(state,"BLOCKED") && strcmp(state,"UNKNOWN"))return -1;
  if(!strcmp(state,"PASS") && raw)return -1;
  if(strcmp(state,"PASS") || raw)all_pass=0;
  if(i==14)cleanup_ok=!strcmp(state,"PASS") && !raw;
  text=end+1;
 }
 return seen==32767 && cleanup_ok && ((exitcode==0 && all_pass)||(exitcode==2 && !all_pass))?0:-1;
}
#include "../next/retirement-policy.h"
#include "../cleanup/retention-policy.h"
static void retire(const char *module) {
 if(m12_retention_reason(module))hold("retained provider retirement denied");
 char name[128],raw[2048],prefix[256],payload[4096],*end;
 const char *registered=wlan_registered_name(module);
 if(registered) snprintf(name,sizeof(name),"%s",registered);
 else {
  snprintf(name,sizeof(name),"%s",module);
  char *suffix=strstr(name,".ko");if(!suffix || suffix[3]) hold("retirement key invalid");*suffix=0;
  for(char *p=name;*p;p++) if(*p=='-') *p='_';
 }
 if(record("remove_begin",name,0)) hold("remove evidence failed");
 unsigned budget=m12_retirement_budget(name);
 char deadline[256];
 int dn=snprintf(deadline,sizeof(deadline),"name=%s budget_ms=%u bounded_kernel_exit=UNKNOWN",name,budget);
 if(dn<0 || (size_t)dn>=sizeof(deadline)) hold("retirement budget evidence truncated");
 if(record("remove_budget",deadline,0)) hold("retirement budget evidence failed");
 int rc=executable_job("remove",name,budget);
 if(readtext("/run/m12/child-output",raw,sizeof(raw))) hold("retirement raw evidence missing/truncated");
 snprintf(prefix,sizeof(prefix),"M12: delete_module name=%s raw_rc=",name);
 if(strncmp(raw,prefix,strlen(prefix))) {
  (void)record("remove_invalid",raw,rc);
  hold("retirement raw evidence malformed");
 }
 errno=0;long value=strtol(raw+strlen(prefix),&end,10);
 int error_number;char trailing;
 if(errno || end==raw+strlen(prefix) || value>0 || value< -4095 ||
    sscanf(end," errno=%d%c",&error_number,&trailing)!=2 || trailing!='\n' ||
    error_number!=(value<0?(int)-value:0) || (rc==0)!=(value==0) || (rc!=0 && rc!=1)) hold("retirement syscall evidence invalid");
 snprintf(payload,sizeof(payload),"%shelper_exit=%d",raw,rc);
 if(record("remove_return",payload,rc)) hold("remove evidence failed");
 if(rc) hold("Wi-Fi retirement failed; firmware and USB evidence retained");
 loaded_count--;
 if(module_count()!=(int)loaded_count) hold("retirement module count differs");
}
static int readiness_evidence(const char *text,int exitcode) {
 int ready,raw,loaded,present,triggered,used=0;
 if(sscanf(text,"M12READY ready=%d raw_rc=%d qca6490_loaded=%d fs_ready_present=%d fs_ready_triggered=%d\n%n",
           &ready,&raw,&loaded,&present,&triggered,&used)!=5 || !used || text[used] ||
    text[used-1]!='\n' || (ready!=0 && ready!=1) || (loaded!=0 && loaded!=1) ||
    (present!=0 && present!=1) || triggered!=1) return -1;
 if(ready) return exitcode==0 && raw==0 && loaded==1?0:-1;
 return exitcode==2 && raw<0 && raw>=-4095?0:-1;
}
static int observe_snapshot(const char *label) {
 int rc=executable_job("observe",NULL,10000);
 static char snapshot[65537];
 if(readtext("/run/m12/child-output",snapshot,sizeof(snapshot))) hold("snapshot absent/truncated");
 size_t n=strlen(snapshot);
 if(!n || snapshot[n-1]!='\n' || (rc!=0 && rc!=2)) hold("observer/helper failure");
 for(size_t i=0;i<n;i+=8192) {
  char part[8193]; size_t len=n-i>8192?8192:n-i;
  memcpy(part,snapshot+i,len); part[len]=0;
  if(record(label,part,rc)) hold("snapshot evidence failed");
 }
 return rc==0 && strstr(snapshot,"\"enumeration_evidence\":\"SINGLE_PCI_ID_OBSERVED\"") ? 1:0;
}
static pid_t launch_relay(void) {
 snprintf(current_job,sizeof(current_job),"%s","relay_start");
 pid_t p=fork();
 if(!p) {
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) || prctl(PR_SET_KEEPCAPS,0,0,0,0)) _exit(126);
  for(int cap=0;cap<64;cap++) {
   int have=prctl(PR_CAPBSET_READ,cap,0,0,0);
   if(have<0) { if(errno==EINVAL) break; _exit(126); }
   if(prctl(PR_CAPBSET_DROP,cap,0,0,0)) _exit(126);
  }
  if(setgroups(0,NULL) || setresgid(65534,65534,65534) || setresuid(65534,65534,65534)) _exit(126);
  execl("/sbin/m12-kmsg-relay","m12-kmsg-relay",(char *)NULL); _exit(127);
 }
 return p;
}
static int alive(pid_t pid) {
 int status;
 return waitpid(pid,&status,WNOHANG)==0;
}
#include "../run10/runtime.inc"
int main(int argc, char **argv) {
 /* Share libc bytes, not process state: each fixed job remains a supervised
  * exec child with separate stdout/result and deadline. Ordinary shells cannot
  * reach a device operation. PID1 itself accepts no child command. */
 if(getpid()!=1) {
  if(argc!=2 || getppid()!=1)return 2;
  if(!strcmp(argv[1],"--fs-ready"))return m12_fs_ready_main(1,NULL);
  if(!strcmp(argv[1],"--readiness"))return m12_readiness_main();
  return 2;
 }
 if(argc!=1)return 2;
 umask(077);
 if(control_job("/m12/control","journal",10000)) hold("journal initialization failed");
 seq=1; /* journal identity is the first and only shell-created record */
 trace_fd=open("/run/m12-instrumentation/breadcrumbs",O_WRONLY|O_APPEND|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0644);
 if(trace_fd<0 || chmod("/run/m12-instrumentation/breadcrumbs",0644)) hold("RAM breadcrumbs failed");
 if(record("scope","Run11 gated Wi-Fi connectivity; credentials private; no BT power, audio, GPU or persist; scoped CBC bootstrap; readiness UNKNOWN",0)) hold("scope record failed");
 pid_t logger=launch_relay();
 if(logger<=1 || wait_marker("/run/m12-instrumentation/logger.ready",5000)) hold("relay not ready");
 if(control_job("/m12/control","prepare",120000)) hold("read-only firmware inventory/path preparation failed");
 if(record("firmware_verified","all canonical qca6490 inventory hashes verified on read-only modem_a; CNSS chooses filename; not firmware readiness",0)) hold("firmware evidence failed");
 for(unsigned i=0;i<sizeof(usb_modules)/sizeof(*usb_modules);i++)
  if(load_module(usb_modules[i])) hold("required USB supplier returned error");
 if(loaded_count!=100 || control_job("/m12/control","start",40000) ||
    control_job("/m12/control","usb_start",65000)) hold("ADSP/USB bootstrap failed");
 if(record("usb_started","connector-created ACM; awaiting actual host receipts",0)) hold("USB evidence failed");
 if(receipt()) hold("identity receipt missing/invalid; Wi-Fi denied");
 if(startup_barrier()) hold("exact PID1 pre-query receipt missing/invalid; Wi-Fi denied");
 if(!alive(logger)) hold("relay exited before Wi-Fi insertion");
 (void)observe_snapshot("snapshot_before");
 kernel_fd=open("/dev/kmsg",O_RDONLY|O_NONBLOCK|O_CLOEXEC);
 if(kernel_fd<0 || lseek(kernel_fd,0,SEEK_END)<0)hold("CBC kernel cursor absent; bootstrap denied");
 int error=0;
 for(unsigned i=0;i<sizeof(wifi_modules)/sizeof(*wifi_modules);i++) {
  if(!alive(logger)) hold("relay exited; remaining Wi-Fi insertion denied");
  if(load_module(wifi_modules[i])) { error=1; break; }
  wifi_loaded++;
  if(!strcmp(wifi_modules[i],"hwid.ko") && hwid_readback()) {error=1;break;}
 }
 if(!error && (wifi_loaded!=9 || loaded_count!=109)) hold("Wi-Fi closure mismatch");
 if(control_job("/m12/control","settle",25000)) hold("PCI settle failed");
 int enumeration=observe_snapshot("pci");
 if(record("pci_result",enumeration?"PASS unique PCI17cb:1103":"FAIL PCI prerequisite",enumeration?0:1)) hold("PCI evidence failed");
 if(!error && enumeration) {
  for(unsigned i=0;i<sizeof(wlan_modules)/sizeof(*wlan_modules);i++) {
   if(!alive(logger)) hold("relay exited before WLAN load");
   if(load_module(wlan_modules[i])) { error=1; break; }
   data_loaded++;
  }
 }
 int connected=0;
 int readiness=2;
 if(!error && enumeration && data_loaded==sizeof(wlan_modules)/sizeof(*wlan_modules)) {
  /* Keep the post-driver sysfs/PCI/netdev census before privacy cutoff.
   * The observer never reads credentials, SSID, scan replies or addresses. */
  (void)observe_snapshot("wlan_census");
  int cbc_rc=bootstrap_cbc(logger);
  if(record("cbc_result",cbc_rc?"FAIL/BLOCKED actual bootstrap/CBC evidence":"PASS native BDF/requirement/CAL_DONE/MISSION observations",cbc_rc))hold("CBC result evidence failed");
  if(cbc_rc)error=1;
  if(!error)readiness=executable_job("readiness",NULL,35000);
  else readiness=2;
  if(!error) {
  char readiness_raw[1024];
  if(readtext("/run/m12/child-output",readiness_raw,sizeof(readiness_raw))) hold("readiness evidence absent/truncated");
  if(record("readiness",readiness_raw,readiness) || readiness_evidence(readiness_raw,readiness)) hold("invalid/unresolved readiness evidence");
  (void)observe_snapshot("wlan_after_readiness");
  }
 }
 if(!error && enumeration && readiness==0 && owner_idle()) {
  /* Before any credential consumption, relay permanently stops reading kmsg.
   * Kernel records can include SSIDs. E/D remain streamed and digested. */
  if(kernel_fd>=0) {if(close(kernel_fd))hold("kernel observer close failed");kernel_fd=-1;}
  if(record("kernel_privacy","Intentional kernel capture cutoff before secret/network activity; kernel_complete=0",0) ||
     marker("/run/m12-instrumentation/privacy.request") ||
     chmod("/run/m12-instrumentation/privacy.request",0644) ||
     wait_marker("/run/m12-instrumentation/privacy.ready",5000)) hold("privacy barrier failed; networking denied");
  char accepted_privacy[8]; struct stat privacy_st;
  if(lstat("/run/m12-instrumentation/privacy.ready",&privacy_st) ||
     privacy_st.st_uid!=65534 || privacy_st.st_gid!=65534 || privacy_st.st_nlink!=1 ||
     (privacy_st.st_mode&0777)!=0600 ||
     readtext("/run/m12-instrumentation/privacy.ready",accepted_privacy,sizeof(accepted_privacy)) ||
     strcmp(accepted_privacy,"1\n")) hold("privacy ACK invalid; networking denied");
  int rc=executable_job("network",NULL,300000);
  char results[16385];
  if(readtext("/run/m12/child-output",results,sizeof(results)) || !results[0]) hold("network evidence absent");
  if(record("connectivity",results,rc)) hold("network evidence failed");
  if(rc!=0 && rc!=2) hold("network teardown unresolved/helper failed");
  if(network_results(results,rc)) hold("network stage proof invalid; teardown not qualified");
  connected=rc==0;
 } else if(record("connectivity","M12NET firmware BLOCKED rc=2\nM12NET interface BLOCKED rc=2\nM12NET scan BLOCKED rc=2\nM12NET association BLOCKED rc=2\nM12NET wpa BLOCKED rc=2\nM12NET dhcp BLOCKED rc=2\nM12NET ping BLOCKED rc=2\nM12NET disconnect BLOCKED rc=2\nM12NET lease_reset BLOCKED rc=2\nM12NET reconnect BLOCKED rc=2\nM12NET reassociation BLOCKED rc=2\nM12NET rewpa BLOCKED rc=2\nM12NET redhcp BLOCKED rc=2\nM12NET reping BLOCKED rc=2\nM12NET network_cleanup PASS rc=0\n",2)) hold("blocked evidence failed");
 /* Reverse consumer dependency order. Keep shared/non-exit providers and
  * vendor instances with unsafe removal paths until reboot. No force/retry. */
 for(unsigned i=data_loaded;i>0;i--) retire(wlan_modules[i-1]);
 qca_retired=1;
 for(unsigned i=wifi_loaded;i>0;i--) {
  const char *module=wifi_modules[i-1],*reason=m12_retention_reason(module);
  if(reason) {
   char retained[256];
   int n=snprintf(retained,sizeof(retained),"module=%s reason=%s",module,reason);
   if(n<0 || (size_t)n>=sizeof(retained) || record("retain",retained,0))hold("retain evidence failed");
   continue;
  }
  if(!strcmp(module,"cnss_plat_ipc_qmi_svc.ko"))retire_owner();
  retire(module);
  if(!strcmp(module,"cnss2.ko"))cnss_retired=1;
 }
 if(owner.fd>=0) {cnss_retired=1;retire_owner();}
 if(kernel_fd>=0) {if(close(kernel_fd))hold("kernel observer close failed");kernel_fd=-1;}
 connected=connected && !owner_fault;
 unsigned expected_final=100+m12_retained_count(wifi_modules,wifi_loaded);
 if(loaded_count!=expected_final || module_count()!=(int)expected_final) hold("final retirement count differs");
 char final_count[96];snprintf(final_count,sizeof(final_count),"expected=%u actual=%u full_probe_expected=104",expected_final,loaded_count);
 if(record("cleanup_count",final_count,0)) hold("cleanup count evidence failed");
 if(record("cleanup_scope","module_syscall_returns_and_count=VERIFIED kernel_teardown_clean=UNKNOWN retained_providers=UNTIL_REBOOT cnss_unregister_wait_ms=80000 qca_observation_budget_ms=180000 reboot_retained_pcie=UNQUALIFIED",0))hold("cleanup scope evidence failed");
 if(checkpoint(connected?"green":"red")) hold("result checkpoint failed; USB evidence retained");
 if(record("pre_transport_teardown","Wi-Fi consumers retired; QMP/PCIe/hwid/table provider/USB retained to reboot; result helper returned; later USB/ADSP/mount/reboot outside sealed capture",0)) hold("teardown evidence failed");
 if(close(trace_fd)) hold("breadcrumb close failed");
 trace_fd=-1;
 journal_sealed=1;
 if(control_job("/m12/control","seal",10000) || reap(logger,35000)) hold("journal/relay finish failed");
 char b[16];
 if(readtext("/run/m12-instrumentation/logger.done",b,sizeof(b)) || strcmp(b,"1\n")) hold("relay completion absent");
 if(control_job("/m12/control","usb_stop",10000) ||
    control_job("/m12/control","stop_adsp",40000) ||
    control_job("/m12/control","common",15000)) hold("USB/ADSP/firmware cleanup failed");
 if(control_job("/m12/control","unmount",10000)) hold("proc/sys teardown failed");
 (void)reboot(RB_AUTOBOOT);
 hold("reboot returned");
}
