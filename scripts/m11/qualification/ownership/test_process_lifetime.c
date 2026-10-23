#define _GNU_SOURCE
#include "m11_custodian.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* Real Linux processes/fds; ordinary memfd+pipe only. No DMA-BUF/device/ioctl.
 * Pipe EOF witnesses final open-file-description release. It does not emulate
 * character-device release, global ION cleanup, IOVA retention or DSP quiescence. */
static void put(int fd, char c) { assert(write(fd,&c,1)==1); }
static char get(int fd) {
    struct pollfd p={fd,POLLIN,0}; int rc;
    do { rc=poll(&p,1,3000); } while(rc<0 && errno==EINTR);
    assert(rc==1 && p.revents&POLLIN);
    char c; assert(read(fd,&c,1)==1); return c;
}
static void reaped(pid_t pid, int signal_number) {
    int status; pid_t rc;
    do { rc=waitpid(pid,&status,0); } while(rc<0 && errno==EINTR);
    assert(rc==pid);
    if (signal_number) assert(WIFSIGNALED(status) && WTERMSIG(status)==signal_number);
    else assert(WIFEXITED(status) && WEXITSTATUS(status)==0);
    assert(waitpid(pid,&status,WNOHANG)==-1 && errno==ECHILD);
}
static void eof_state(int fd, bool expected) {
    struct pollfd p={fd,POLLIN,0};
    assert(poll(&p,1,0)==(expected ? 1:0));
    if (expected) { char c; assert(read(fd,&c,1)==0); }
}
int main(void) {
    alarm(20); /* finite harness bound, not a safe hardware recovery mechanism */
    m11_boot_ledger boot={0};
    assert(!m11_model_new_boot(&boot,17,100));
    /* This ledger is held by the independent supervisor, not its child. */
    m11_custodian owner_metadata={.boot=&boot,.recovery_budget_ms=100};
    int backing=memfd_create("m11-offline-backing",MFD_CLOEXEC);
    assert(backing>=0 && ftruncate(backing,4096)==0);
    assert(pwrite(backing,"owner",5,0)==5);
    void *mapping=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,backing,0);
    assert(mapping!=MAP_FAILED);
    int ep[2],control[2]; assert(!pipe2(ep,O_CLOEXEC) && !pipe2(control,O_CLOEXEC));
    pid_t custodian=fork(); assert(custodian>=0);
    if (!custodian) {
        close(control[0]); close(ep[0]);
        int report[2]; assert(!pipe2(report,O_CLOEXEC));
        pid_t worker=fork(); assert(worker>=0);
        if (!worker) {
            close(report[0]); close(control[1]); close(ep[1]); close(backing);
            /* Explicit fork hygiene is required: CLOEXEC alone does not close on fork. */
            assert(!munmap(mapping,4096)); /* Closing fd alone leaves inherited VMA alive. */
            unsigned char residency;
            assert(mincore(mapping,4096,&residency)==-1 && errno==ENOMEM);
            assert(fcntl(backing,F_GETFD)==-1 && errno==EBADF);
            assert(fcntl(ep[1],F_GETFD)==-1 && errno==EBADF);
            put(report[1],'W');
            for (;;) pause();
        }
        close(report[1]); assert(get(report[0])=='W'); close(report[0]);
        assert(kill(worker,SIGKILL)==0); reaped(worker,SIGKILL);
        assert(fcntl(backing,F_GETFD)>=0 && fcntl(ep[1],F_GETFD)>=0);
        assert(lseek(backing,123,SEEK_SET)==123); /* shared open-file description */
        put(control[1],'C');
        for (;;) pause();
    }
    close(control[1]); assert(get(control[0])=='C'); close(control[0]);
    m11_custodian_worker_exit(&owner_metadata,101);
    assert(boot.state==M11_ADSP_TAINTED && boot.reasons&M11_TAINT_WORKER_EXIT);
    assert(lseek(backing,0,SEEK_CUR)==123);
    eof_state(ep[0],false);
    assert(kill(custodian,SIGKILL)==0); reaped(custodian,SIGKILL);
    m11_custodian_owner_exit(&owner_metadata,102);
    assert(!boot.owner_alive && boot.reasons&M11_TAINT_CUSTODIAN_EXIT);
    assert(m11_model_new_boot(&boot,17,103)==-EALREADY);
    assert(m11_custodian_request_recovery(&owner_metadata)==-ENOTSUP);
    char bytes[5]; assert(pread(backing,bytes,5,0)==5);
    assert(bytes[0]=='o' && bytes[4]=='r');
    assert(((char *)mapping)[0]=='o' && ((char *)mapping)[4]=='r');
    eof_state(ep[0],false); /* supervisor anchor outlives custodian */
    assert(close(ep[1])==0); eof_state(ep[0],true);
    close(ep[0]); assert(!munmap(mapping,4096) && close(backing)==0);
    puts("PASS real fork/SIGKILL/reap: worker has no owner fds; supervisor OFD/backing anchors survive custodian death");
    puts("LIMIT: retaining a memfd/OFD does not preserve a vendor ION attachment or stop global cleanup");

    /* Counterexample without an independent anchor: owner exit drops the last fd. */
    assert(!pipe2(ep,O_CLOEXEC) && !pipe2(control,O_CLOEXEC));
    custodian=fork(); assert(custodian>=0);
    if (!custodian) {
        close(ep[0]); close(control[0]); put(control[1],'A'); close(control[1]);
        for (;;) pause();
    }
    close(ep[1]); close(control[1]); assert(get(control[0])=='A'); close(control[0]);
    eof_state(ep[0],false);
    assert(kill(custodian,SIGKILL)==0); reaped(custodian,SIGKILL);
    eof_state(ep[0],true); close(ep[0]);
    puts("PASS negative witness: no anchor => custodian SIGKILL releases final OFD; userspace cleanup is not called");
    /* Real fd-number reuse counterexample. Not an injected close EIO: pinned
     * kernel source independently establishes consumption before filp_close. */
    backing=memfd_create("m11-fd-disposition",MFD_CLOEXEC); assert(backing>=0);
    int stale_number=backing; assert(!close(backing));
    backing=memfd_create("m11-new-owner",MFD_CLOEXEC); assert(backing>=0);
    if (backing!=stale_number) { assert(dup2(backing,stale_number)==stale_number); close(backing); }
    assert(fcntl(stale_number,F_GETFD)>=0);
    assert(!close(stale_number)); /* erroneous retry consumes the NEW owner's fd */
    assert(fcntl(stale_number,F_GETFD)==-1 && errno==EBADF);
    puts("PASS real stale-fd retry counterexample; no physical close-error adapter qualified");
    alarm(0);
    return 0;
}
