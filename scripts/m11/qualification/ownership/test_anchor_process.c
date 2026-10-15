/* Real Linux processes and descriptors with a STAND-IN character device: a /dev/ptmx master is
 * the anchor OFD, and its pty slave is the observer, because the master's release (its last
 * fput, like audio_pkt_release) hangs the slave up. pty masters, like audio_pkt_fops, have no
 * .flush. No real endpoint, driver, ADSP or DMA is touched; D-state is not reproducible here
 * (model only). */
#define _GNU_SOURCE
#include "m11_anchor_linux.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static unsigned cases;
static void pass(const char *s) { ++cases; printf("PASS %s\n",s); }
static const m11_anchor_contract evidence={.endpoint_has_no_flush=true,
    .release_on_last_fput_only=true,.owner_single_threaded=true};
static const char *standin;
static int slave=-1;

static bool hung_up(void) {
    struct pollfd p={slave,POLLIN,0};
    int rc=poll(&p,1,0); assert(rc>=0);
    return rc>0 && (p.revents & (POLLHUP|POLLERR));
}
static char from_slave(void) {
    struct pollfd p={slave,POLLIN,0}; int rc;
    do { rc=poll(&p,1,3000); } while (rc<0 && errno==EINTR);
    assert(rc==1 && (p.revents & POLLIN));
    char c; assert(read(slave,&c,1)==1); return c;
}
static int bind_standin(m11_pid1_anchor *a, m11_anchor_linux *l, int census_root) {
    m11_anchor_ops ops; struct stat st;
    assert(!m11_anchor_linux_ops(l,standin,census_root,&ops) && !stat(standin,&st));
    memset(a,0,sizeof(*a));
    int rc=m11_anchor_bind(a,&ops,NULL,&evidence,getpid(),(uint64_t)st.st_rdev);
    if (a->state!=M11_ANCHOR_HELD) return rc;
    assert(!grantpt(a->anchor_fd) && !unlockpt(a->anchor_fd));
    const char *name=ptsname(a->anchor_fd); assert(name);
    if (slave>=0) close(slave);
    slave=open(name,O_RDWR|O_NOCTTY|O_NONBLOCK|O_CLOEXEC); assert(slave>=0);
    struct termios t; assert(!tcgetattr(slave,&t)); cfmakeraw(&t); assert(!tcsetattr(slave,TCSANOW,&t));
    assert(!hung_up());
    return rc;
}
/* Harness only: this process is not global init, so a RETAINED or latched anchor is dropped
 * here between scenarios (the census would otherwise see its OFD as another holder). */
static void end_scenario(m11_pid1_anchor *a) {
    if (a->anchor_fd>=0) close(a->anchor_fd);
    if (a->guard_fd>=0) close(a->guard_fd);
    a->anchor_fd=a->guard_fd=-1;
}
static int send_q(int fd, void *arg) { (void)arg; return write(fd,"Q",1)==1 ? 0 : 1; }
static int stall(int fd, void *arg) { (void)fd; (void)arg; for (;;) pause(); }
static int no_second_open(int fd, void *arg) {
    int other=open((const char *)arg,O_RDONLY|O_CLOEXEC);
    if (other>=0 || errno!=EACCES) return 1; /* permission is checked at open(2), not at use */
    return write(fd,"D",1)==1 ? 0 : 1;
}
static void reaped(pid_t pid) {
    int status; pid_t rc;
    do { rc=waitpid(pid,&status,0); } while (rc<0 && errno==EINTR);
    assert(rc==pid);
}
/* Records, after each close the adapter performs, whether the observer was hung up. */
static int (*real_close)(void *, int);
static bool hup_after[4]; static unsigned closes;
static int observed_close(void *v, int fd) {
    int rc=real_close(v,fd);
    if (closes<4) hup_after[closes]=hung_up();
    closes++;
    return rc;
}

int main(void) {
    alarm(60); /* finite harness bound, not a recovery mechanism */
    struct stat st;
    standin=!lstat("/dev/ptmx",&st) && S_ISCHR(st.st_mode) ? "/dev/ptmx" : "/dev/pts/ptmx";
    m11_anchor_linux l; m11_anchor_ops ops;
    const char *refused[]={"/dev/aud_pasthru_adsp","/dev/msm_audio_ion","/dev/snd/pcmC0D0p","/tmp/endpoint"};
    for (unsigned i=0;i<4;i++) assert(m11_anchor_linux_ops(&l,refused[i],getpid(),&ops)==-EPERM);
    pass("backend refuses the real endpoint, the ION node, PCM nodes and any non-allowlisted path");

    m11_pid1_anchor a;
    assert(!bind_standin(&a,&l,getpid()));
    assert(a.anchor_fd>=M11_ANCHOR_RESERVED_FD && a.guard_fd==a.anchor_fd+1);
    assert((fcntl(a.anchor_fd,F_GETFD) & FD_CLOEXEC) && (fcntl(a.guard_fd,F_GETFD) & FD_CLOEXEC));
    pass("bind on the stand-in: one open, anchor + guard CLOEXEC at reserved numbers, census clean");

    m11_worker_end end;
    assert(!m11_anchor_linux_lend(&a,send_q,NULL,3000,1000,&end) && end==M11_WORKER_EXIT_OK);
    assert(from_slave()=='Q' && !hung_up() && a.state==M11_ANCHOR_HELD);
    pass("forked worker does I/O on the borrowed OFD and exits: non-final close, no release");
    assert(!m11_anchor_linux_lend(&a,stall,NULL,50,3000,&end) && end==M11_WORKER_EXIT_ABNORMAL);
    assert(!hung_up() && (a.latches & M11_ANCHOR_LATCH_WORKER_ABNORMAL) && !m11_anchor_check(&a));
    pass("worker SIGKILLed at the deadline: exit_files() is a non-final close, observer not hung up");

    char dir[]="/tmp/m11-anchor-XXXXXX"; assert(mkdtemp(dir));
    char forbidden[64]; snprintf(forbidden,sizeof(forbidden),"%s/node",dir);
    int made=open(forbidden,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600); assert(made>=0); close(made);
    if (geteuid()) assert(!chmod(forbidden,0)); /* non-root: owner without CAP_DAC_OVERRIDE */
    assert(!m11_anchor_linux_lend(&a,no_second_open,forbidden,3000,1000,&end) && end==M11_WORKER_EXIT_OK);
    assert(from_slave()=='D' && !hung_up());
    printf("INFO worker DAC check ran as %s\n",geteuid() ? "non-root (mode 0000 file)" : "root (dropped to 65534)");
    pass("worker cannot open(2) a protected node yet keeps using the borrowed fd");
    unlink(forbidden); rmdir(dir);

    pid_t job=fork(); assert(job>=0);
    if (!job) { execl("/bin/true","true",(char *)NULL); _exit(127); }
    reaped(job);
    assert(!m11_anchor_check(&a) && !hung_up());
    pass("fork+exec job: CLOEXEC drops the inherited references at exec; census clean");
    int ready[2]; assert(!pipe2(ready,O_CLOEXEC));
    pid_t child=fork(); assert(child>=0);
    if (!child) { close(ready[0]); char c='R'; (void)!write(ready[1],&c,1); for (;;) pause(); }
    close(ready[1]); char c; assert(read(ready[0],&c,1)==1); close(ready[0]);
    assert(m11_anchor_final_close(&a)==-EBUSY && (a.latches & M11_ANCHOR_LATCH_FOREIGN_HOLDER));
    assert(!kill(child,SIGKILL)); reaped(child);
    assert(m11_anchor_final_close(&a)==-EOWNERDEAD && !hung_up());
    pass("final close refused while a forked child shares the OFD; the refusal stays latched");
    m11_anchor_end how;
    assert(!m11_anchor_end_boot(&a,M11_TERMINAL_RESET_RETAINING_ANCHORS,&how) && how==M11_ANCHOR_END_PID1_EXIT);
    assert(a.state==M11_ANCHOR_RETAINED && !hung_up());
    end_scenario(&a);

    assert(!bind_standin(&a,&l,getpid()));
    assert(!pipe2(ready,O_CLOEXEC));
    pid_t intruder=fork(); assert(intruder>=0);
    if (!intruder) {
        close(ready[0]);
        int second=open(standin,O_RDWR|O_NOCTTY|O_CLOEXEC); /* a second OFD of the same node */
        char r=second>=0 ? 'O' : 'E'; (void)!write(ready[1],&r,1);
        for (;;) pause();
    }
    close(ready[1]); assert(read(ready[0],&c,1)==1 && c=='O'); close(ready[0]);
    int fd=-1;
    assert(m11_anchor_check(&a)==-EBUSY && m11_anchor_lend_begin(&a,&fd)==-EOWNERDEAD);
    assert(!kill(intruder,SIGKILL)); reaped(intruder);
    assert(!hung_up());
    pass("second OFD of the node detected by identity; its own release does not touch the anchor");
    end_scenario(&a);

    assert(!bind_standin(&a,&l,getpid()));
    int null=open("/dev/null",O_RDONLY|O_CLOEXEC); assert(null>=0);
    assert(dup3(null,a.anchor_fd,O_CLOEXEC)==a.anchor_fd); close(null);
    assert(m11_anchor_check(&a)==-EBADF && (a.latches & M11_ANCHOR_LATCH_FD_DISCIPLINE) && !hung_up());
    pass("anchor number replaced by another file: identity mismatch latched; guard keeps the OFD");
    end_scenario(&a);

    assert(!bind_standin(&a,&l,getpid()));
    assert(!m11_anchor_linux_lend(&a,send_q,NULL,3000,1000,&end) && from_slave()=='Q');
    real_close=a.ops.close_fd; a.ops.close_fd=observed_close; closes=0;
    assert(!m11_anchor_final_close(&a) && a.state==M11_ANCHOR_RELEASED && closes==2);
    assert(!hup_after[0] && hup_after[1] && hung_up());
    assert(!m11_anchor_end_boot(&a,M11_TERMINAL_ORDERLY_SHUTDOWN,&how) && how==M11_ANCHOR_END_REBOOT);
    pass("final close as sole holder: release observed after the second close, not the first");

    if (geteuid()) {
        int rc=bind_standin(&a,&l,0);
        assert(rc<0 && a.state==M11_ANCHOR_HELD && (a.latches & M11_ANCHOR_LATCH_CENSUS_ERROR));
        assert(m11_anchor_lend_begin(&a,&fd)==-EOWNERDEAD && m11_anchor_final_close(&a)==-EOWNERDEAD);
        pass("whole-system census as non-root cannot read every fd table: fails closed");
        end_scenario(&a);
    } else {
        puts("SKIP whole-system census fail-closed case: running as root");
    }
    alarm(0);
    printf("PID1 anchor process qualification: %u cases PASS (stand-in node; real endpoint not opened)\n",cases);
    return 0;
}
