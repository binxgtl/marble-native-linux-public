/* R2 owner seal over two anchor pairs (endpoint + ION), offline on STAND-INS only.
 *  1. The single-pair seal (Run22's) refuses every close of a second pair, so an ION anchor needs
 *     the two-pair seal (the reason for m11_anchor_owner_seal_pairs).
 *  2. The two-pair filter protects all four reserved numbers exactly as the single-pair filter
 *     protects two (close, dup, dup3, fcntl F_DUPFD/F_DUPFD_CLOEXEC/F_SETFD/F_SETFL, every other
 *     close_range), refuses exec and mknodat, still forks, and permits close_range(a_i, a_i+1, 0)
 *     for each pair, nothing wider.
 *  3. Two real adapters (pty multiplexer and null stand-ins, bound by the actual Linux backend)
 *     are sealed together; both final closes then succeed through close_range.
 * The real endpoint and ION nodes are never named. */
#define _GNU_SOURCE
#include "anchor_native.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr,"FAIL %s:%d %s (errno %d)\n",__FILE__,__LINE__,#c,errno); _exit(10); } } while (0)
static int refused(long rc) { return rc==-1 && errno==EPERM; }
static long crange(unsigned a, unsigned b, unsigned flags) { return syscall(SYS_close_range,a,b,flags); }
static void at(int fd, int want) {
    int f=open("/dev/zero",O_RDONLY|O_CLOEXEC); CHECK(f>=0);
    if (f!=want) { CHECK(dup2(f,want)==want); CHECK(!close(f)); }
    CHECK(fcntl(want,F_SETFD,FD_CLOEXEC)==0);
}
static int run(int (*body)(void)) {
    fflush(stdout);
    pid_t p=fork(); assert(p>=0);
    if (!p) _exit(body());
    int st; assert(waitpid(p,&st,0)==p);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128+WTERMSIG(st);
}

/* The single-pair filter (Run22's seal) leaves a second pair unprotected and never closable by
 * close_range: an ION anchor needs the two-pair seal. */
static int single_pair_leaves_second_open(void) {
    at(600,600); at(601,601); at(602,602); at(603,603);
    CHECK(!m11_anchor_owner_filter(600,601));
    CHECK(refused(crange(602,603,0)));
    CHECK(!close(602) && !close(603));      /* unprotected: any code could close the ION pair */
    return 0;
}
static int two_pairs(void) {
    for (int fd=600;fd<=603;fd++) at(fd,fd);
    at(700,700);
    const int bad[][2]={{600,601},{602,601},{-1,600}};
    for (unsigned i=0;i<3;i++) CHECK(m11_anchor_owner_filter_pairs(bad[i],2)==-EINVAL); /* overlap/invalid */
    const int fds[2]={600,602};
    CHECK(!m11_anchor_owner_filter_pairs(fds,2));
    for (int fd=600;fd<=603;fd++) {
        CHECK(refused(close(fd)));
        CHECK(refused(dup(fd)));
        CHECK(refused(dup3(700,fd,0)));
        CHECK(refused(fcntl(fd,F_DUPFD,0)) && refused(fcntl(fd,F_DUPFD_CLOEXEC,0)));
        CHECK(refused(fcntl(fd,F_SETFD,0)) && refused(fcntl(fd,F_SETFL,O_NONBLOCK)));
        CHECK(fcntl(fd,F_GETFD)==FD_CLOEXEC);
    }
    CHECK(refused(crange(600,603,0)) && refused(crange(601,602,0)) && refused(crange(599,601,0)));
    CHECK(refused(crange(600,601,4u)) && refused(crange(602,604,0)) && refused(crange(0,~0u,0)));
    CHECK(refused(syscall(SYS_mknodat,AT_FDCWD,"/nonexistent-m11",S_IFCHR|0600,makedev(1,3))));
    char *const argv[]={"/bin/true",NULL}, *const env[]={NULL};
    CHECK(refused(execve(argv[0],argv,env)));
    int other=dup(700); CHECK(other>=0 && !close(other) && !close(700)); /* unreserved: allowed */
    pid_t p=fork(); CHECK(p>=0);
    if (!p) _exit(0);
    int st; CHECK(waitpid(p,&st,0)==p && WIFEXITED(st) && !WEXITSTATUS(st));
    CHECK(!crange(602,603,0));                                  /* the ION pair, exactly */
    CHECK(fcntl(602,F_GETFD)==-1 && errno==EBADF && fcntl(603,F_GETFD)==-1 && errno==EBADF);
    CHECK(fcntl(600,F_GETFD)==FD_CLOEXEC);
    CHECK(!crange(600,601,0));                                  /* the endpoint pair, exactly */
    CHECK(fcntl(600,F_GETFD)==-1 && errno==EBADF);
    return 0;
}
static const m11_anchor_contract evidence={.endpoint_has_no_flush=true,
    .release_on_last_fput_only=true,.owner_single_threaded=true};
/* A stand-in census counts every holder of the device number in this process tree; move any
 * inherited stdio that is the null device out of the way first. */
static void stdio_off_null(void) {
    for (int fd=0;fd<3;fd++) {
        struct stat st;
        if (fstat(fd,&st) || !S_ISCHR(st.st_mode) || st.st_rdev!=makedev(1,3)) continue;
        int p[2]; CHECK(!pipe(p)); CHECK(dup2(fd==0 ? p[0] : p[1],fd)==fd); close(p[0]); close(p[1]);
    }
}
static int adapters(void) {
    stdio_off_null();
    static m11_anchor_linux le, li; static m11_pid1_anchor ep, io; m11_anchor_ops oe, oi; struct stat se, si;
    CHECK(!stat("/dev/ptmx",&se) && !stat("/dev/null",&si));
    CHECK(!m11_anchor_linux_ops(&le,"/dev/ptmx",getpid(),&oe) && !m11_anchor_linux_ops(&li,"/dev/null",getpid(),&oi));
    CHECK(!m11_anchor_bind(&ep,&oe,NULL,&evidence,getpid(),(uint64_t)se.st_rdev));
    CHECK(!m11_anchor_bind(&io,&oi,NULL,&evidence,getpid(),(uint64_t)si.st_rdev));
    CHECK(ep.anchor_fd==M11_ANCHOR_RESERVED_FD && io.anchor_fd==ep.guard_fd+1 && io.guard_fd==io.anchor_fd+1);
    m11_pid1_anchor *both[2]={&ep,&io}, *twice[2]={&ep,&ep}, *three[3]={&ep,&io,&ep};
    CHECK(m11_anchor_owner_seal_pairs(twice,NULL,2)==-EINVAL);
    CHECK(m11_anchor_owner_seal_pairs(three,NULL,3)==-EINVAL);
    CHECK(!m11_anchor_owner_seal_pairs(both,NULL,2));
    CHECK(ep.ops.close_pair && io.ops.close_pair && !m11_anchor_check(&ep) && !m11_anchor_check(&io));
    CHECK(refused(close(io.anchor_fd)) && refused(close(ep.guard_fd)));
    CHECK(m11_anchor_owner_seal_pairs(both,NULL,2)==-EINVAL); /* sealed once */
    CHECK(!m11_anchor_final_close(&io) && io.state==M11_ANCHOR_OWNER_FDS_DROPPED);
    CHECK(!m11_anchor_check(&ep) && ep.state==M11_ANCHOR_HELD);
    CHECK(!m11_anchor_final_close(&ep) && ep.state==M11_ANCHOR_OWNER_FDS_DROPPED);
    return 0;
}

int main(void) {
    setvbuf(stdout,NULL,_IONBF,0);
    assert(run(single_pair_leaves_second_open)==0);
    puts("PASS single-pair seal: a second (ION) pair is unprotected and can never be closed by close_range");
    int rc=run(two_pairs);
    if (rc) printf("two-pair filter body exit %d\n",rc);
    assert(!rc);
    puts("PASS two-pair seal filter: all four reserved numbers protected; exec/mknodat refused; fork "
         "allowed; only close_range(a_i, a_i+1, 0) per pair; overlapping pairs refused");
    rc=run(adapters);
    if (rc) printf("adapter body exit %d\n",rc);
    assert(!rc);
    puts("PASS two real adapters (stand-ins) sealed together: duplicate or third anchors refused, "
         "seal once, each final close through its own close_range");
    puts("R2 two-pair owner seal: 3 groups PASS (stand-ins only)");
    return 0;
}
