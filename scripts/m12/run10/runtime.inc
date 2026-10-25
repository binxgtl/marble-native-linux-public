/* PID1 integration; no daemonization, retry, force-kill or persistent sink. */
#include "owner-supervisor.h"
#include "../run5/cbc-evidence.h"
#include <sys/socket.h>
static struct m12_owner_supervisor owner={.fd=-1,.child=-1};
static struct m12_cbc_evidence cbc;
static int owner_ready,owner_fault,kernel_fd=-1,qca_retired,cnss_retired;
static uint64_t kernel_seq;
static int kernel_seen;
static int owner_idle(void) {
 return owner_ready && !owner_fault && !owner.poisoned &&
  owner.latest.phase==M12_DB_IDLE && !owner.latest.waiting_message;
}
static void pump(void) {
 if(owner.fd>=0 && !owner.final_received) {
  for(unsigned i=0;i<64 && !owner.final_received;i++) {
   int rc=m12_owner_receive(&owner,0);
   if(!rc)break;
   if(rc<0) { if(!owner_fault && record("owner_transport_error","typed owner receipt failed; resources retained",rc))hold("owner error evidence failed");owner_fault=1;break; }
   struct m12_owner_record *r=&owner.latest;
   char b[512];snprintf(b,sizeof(b),"sequence=%u event=%u phase=%u node=%u port=%u raw_rc=%d qmi_result=%u qmi_error=%u transaction=%u waiting_message=%u segment=%u offset=%u size=%u ram_valid=%u seed_verified=%u driver_status=%llu",
    r->sequence,r->event,r->phase,r->node,r->port,r->rc,r->qmi_result,r->qmi_error,r->transaction,r->waiting_message,r->segment,r->offset,r->size,r->ram_valid,r->seed_verified,(unsigned long long)r->driver_status);
   if(record("cnssd_state",b,r->rc))hold("owner evidence failed");
   if(r->event==M12_RETIRED) {
    char final[128];snprintf(final,sizeof(final),"sequence=%u final_rc=%d poisoned=%d final_received=%d",r->sequence,r->rc,owner.poisoned,owner.final_received);
    if(record("owner_final_received",final,r->rc))hold("owner final evidence failed");
   }
   if(r->event==M12_READY)owner_ready=1;
   if(owner.poisoned)owner_fault=1;
  }
 }
 if(kernel_fd>=0) {
  for(unsigned i=0;i<64;i++) {
   char b[8192];ssize_t n=read(kernel_fd,b,sizeof(b)-1);
   if(n<0) {
    if(errno==EAGAIN || errno==EINTR)break;
    int e=errno;cbc.fault=-e;
    if(record("cbc_kernel_error","kernel reader lost evidence; readiness denied",-e))hold("kernel reader evidence failed");
    if(close(kernel_fd))hold("kernel reader close failed");
    kernel_fd=-1;break;
   }
   if(!n){cbc.fault=-EIO;break;}
   b[n]=0;char *m=strchr(b,';');unsigned pri;unsigned long long sq,us;
   if(!m || sscanf(b,"%u,%llu,%llu,",&pri,&sq,&us)!=3) {cbc.fault=-EPROTO;break;}
   if(kernel_seen && sq!=kernel_seq+1)cbc.fault=-EOVERFLOW;
   kernel_seq=sq;kernel_seen=1;m++;
   char *nl=strchr(m,'\n');if(nl)*nl=0;
   int event=m12_cbc_line(&cbc,m);
   if(event) {
    char payload[1024];snprintf(payload,sizeof(payload),"kernel_seq=%llu kernel_us=%llu event=%d requirement=%d raw_host_bdf_data=UNKNOWN message=%s",sq,us,event,cbc.requirement,m);
    if(record("cnss_cbc",payload,cbc.fault))hold("CBC evidence failed");
   }
  }
 }
}
static int launch_owner(void) {
 int f[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,f))return -errno;
 owner.fd=f[0];owner.child=fork();
 if(!owner.child) {
  char b[32];snprintf(b,sizeof(b),"%d",f[1]);
  if(close(f[0]) || fcntl(f[1],F_SETFD,0))_exit(126);
  execl("/sbin/m12-cnssd","m12-cnssd",b,(char *)NULL);_exit(127);
 }
 if(close(f[1]))hold("owner child-end close failed");
 if(owner.child<1) {int e=errno;if(close(owner.fd))hold("owner socket close failed");
 owner.fd=-1;return -e;}
 uint64_t until=now()+20000000000ULL;
 while(now()<until && !owner_ready && !owner_fault) {pump();pause10();}
 if(!owner_idle())return owner_fault?-EPROTO:-ETIMEDOUT;
 return record("cnssd_ack","unique local0x42e:1:0 REG_CLIENT6/ID1 and INIT_SETUP1 ACK; not firmware readiness",0);
}
static int bootstrap_cbc(pid_t logger) {
 /* Trusted control has already verified all mounted firmware hashes. The
  * golden job additionally binds hardware identity and the golden profile. */
 int rc=control_job("/m12/control","golden",10000);
 if(record("golden_binding",rc?"BLOCKED exact device/firmware/BDF source binding":"PASS exact device/firmware/BDF source binding",rc))hold("golden evidence failed");
 if(rc)return rc;
 if(kernel_fd<0)return -EBADF;
 rc=launch_owner();if(rc)return rc;
 if(cbc.fault || !cbc.firmware)return -EXDEV;
 struct m12_caldb state={.phase=M12_DB_IDLE,.registered=1,.setup_ack=1};
 struct m12_bootstrap_facts f={1,1,1,1,1,1,1,0,M12_CAL_UNKNOWN};
 struct m12_golden_scope g={1,1,1,1,1,1};
 f.owner_live=owner_idle();f.logger_live=alive(logger);
 if(!m12_golden_admitted(&state,&f,&g))return -EPERM;
 if(record("cbc_admission","READY scoped golden bootstrap; native requirement UNKNOWN; no seed; no inferred response",0))hold("admission evidence failed");
 /* Sysfs write is isolated in a supervised child: pump continues to receive
  * QRTR metadata and kernel evidence if store blocks. Exactly one write. */
 rc=executable_job("fs_ready",NULL,10000);
 char raw[512];int result,e,used=0;
 if(readtext("/run/m12/child-output",raw,sizeof(raw)))hold("fs_ready raw evidence absent");
 if(record("fs_ready_return",raw,rc))hold("fs_ready evidence failed");
 char *last=strstr(raw,"M12FS final ");
 if(!last || sscanf(last,"M12FS final raw_rc=%d errno=%d\n%n",&result,&e,&used)!=2 ||
    !used || last[used] || last[used-1]!='\n' || result>0 || result< -4095 ||
    e!=(result<0?-result:0) || (rc!=0 && rc!=2) || (rc==0)!=(result==0))hold("invalid fs_ready syscall evidence");
 if(rc)return rc;
 uint64_t until=now()+180000000000ULL;
 while(now()<until) {
  pump();
  if(owner_fault || cbc.fault)return owner_fault?-EPROTO:cbc.fault;
  if(cbc.requirement==M12_CAL_REQUIRED && !owner.latest.seed_verified)return -ENODATA;
  if(m12_cbc_ready(&cbc,owner_idle(),owner.latest.seed_verified))return 0;
  pause10();
 }
 return -ETIMEDOUT;
}
static void retire_owner(void) {
 if(owner.fd<0)return;
 if(!m12_caldb_stop_admitted(qca_retired,cnss_retired,0,owner.latest.waiting_message!=0))hold("owner consumers/transaction not retired");
 int rc=m12_owner_stop(&owner,qca_retired,cnss_retired,0,0);
 if(record("owner_stop","QCA/CNSS returned retirement; keep IPC service until owner exit",rc))hold("owner stop evidence failed");
 if(rc)hold("owner stop not sent");
 uint64_t until=now()+10000000000ULL;
 while(!owner.final_received && now()<until){pump();pause10();}
 if(!owner.final_received)hold("owner final receipt missing; IPC/USB retained");
 /* Final receipt can consume its complete budget while pump drains CBC logs.
  * Reaping has a separate bounded phase; never inherit an expired deadline. */
 until=now()+10000000000ULL;
 while(now()<until) {
  rc=m12_owner_reap(&owner);
  if(owner.reaped || rc<0) {
   char b[192];snprintf(b,sizeof(b),"reaped=%d waitpid_errno=%d wait_calls=%u raw_status=%d exited=%d exit_code=%d signal=%d lifecycle_rc=%d",
    owner.reaped,owner.reap_errno,owner.wait_calls,owner.exit_status,
    owner.reaped?WIFEXITED(owner.exit_status):0,
    owner.reaped && WIFEXITED(owner.exit_status)?WEXITSTATUS(owner.exit_status):-1,
    owner.reaped && WIFSIGNALED(owner.exit_status)?WTERMSIG(owner.exit_status):0,rc);
   if(record("owner_child_reap",b,owner.reap_errno?-owner.reap_errno:0))hold("owner reap evidence failed");
  }
  if(owner.reaped)break;
  if(rc<0)hold("owner waitpid unresolved");
  pause10();
 }
 if(!owner.reaped)hold("owner unresolved exit; IPC/USB retained");
 int eof=m12_owner_finish(&owner);
 char terminal[192];snprintf(terminal,sizeof(terminal),"final_received=%d final_rc=%d raw_status=%d poisoned=%d reaped=%d eof_verified=%d terminal_rc=%d lifecycle_rc=%d",
  owner.final_received,owner.latest.rc,owner.exit_status,owner.poisoned,owner.reaped,owner.eof_verified,eof,rc);
 if(record("owner_terminal_eof",terminal,eof))hold("owner EOF evidence failed");
 if(eof && eof!=-EPROTO)hold("owner terminal peer unresolved; IPC/USB retained");
 /* Abnormal or unexpected exits retain IPC/USB just as before. Other returned
  * retirement failures remain RED; they never qualify owner success. */
 if(!WIFEXITED(owner.exit_status) ||
    (WEXITSTATUS(owner.exit_status)!=0 && WEXITSTATUS(owner.exit_status)!=1))hold("owner unresolved exit; IPC/USB retained");
 int result=rc==1?eof:rc;
 if(record("owner_retired",terminal,result))hold("owner retirement evidence failed");
 if(result)owner_fault=1;
 if(close(owner.fd))hold("owner socket close failed");
 owner.fd=-1;
}
