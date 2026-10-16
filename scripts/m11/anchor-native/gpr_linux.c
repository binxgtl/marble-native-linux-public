/* Native anchor integration of runtime/gpr_linux.c (which stays byte-identical: frozen
 * manifests pin it). The worker never opens or closes the endpoint: it borrows the PID1
 * anchor by fork, keeps only the fds it needs, drops privileges and runs confined. */
#define _GNU_SOURCE
#include "gpr_native_internal.h"
#include "audio_runtime_internal.h"
#include "anchor_native.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int now_ns(uint64_t *n) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC,&ts)) return -1;
    *n=(uint64_t)ts.tv_sec*1000000000u+(uint64_t)ts.tv_nsec;
    return 0;
}
static int control(const struct m11_gpr_session *s) {
    int live=m11_audio_control(s);
    if (live) return live;
    struct pollfd p[2]={{s->service_down_fd,POLLIN,0},{s->cancel_fd,POLLIN,0}};
    int r=poll(p,2,0);
    if (r<0) return -1;
    if (p[0].revents) return 1;
    if (p[1].revents) return 2;
    return 0;
}
static enum m11_gpr_outcome invalidated(int c) {
    return c==1?M11_GPR_SERVICE_DOWN:c==2?M11_GPR_CANCELLED:M11_GPR_IO_ERROR;
}
static m11_pid1_anchor *anchor;  /* PID1's sealed anchor; NULL refuses every query */
static int borrowed_fd=-1;         /* the loan's fd number, set before fork */
static int extra_keep[4]; static unsigned extra_n;
static int last_worker_status=-1;  /* raw wait status of the last reaped worker, -1 if none */
int m11_gpr_last_worker_status(void) { return last_worker_status; }
int m11_gpr_anchor_attach(m11_pid1_anchor *a, const int *keep, unsigned nkeep) {
    if (!a || a->state!=M11_ANCHOR_HELD || nkeep>4 || (nkeep && !keep)) return -1;
    anchor=a; extra_n=nkeep;
    for (unsigned i=0;i<nkeep;i++) extra_keep[i]=keep[i];
    return 0;
}
static int pipe_or_socket(int fd) {
    struct stat st;
    return fd>=0 && !fstat(fd,&st) && (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode));
}
static int nonzero(const unsigned char *p, size_t n) {
    unsigned int x=0;
    for (size_t i=0;i<n;i++) x|=p[i];
    return x!=0;
}
static uint32_t get32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static int complete_ready_transcript(const struct m11_gpr_session *s, const struct m11_gpr_result *r) {
    if (r->event_count!=9) return 0;
    for (unsigned int i=0;i<9;i++)
        if (r->events[i].stage!=i || r->events[i].monotonic_ns>=r->deadline_ns) return 0;
    for (unsigned int i=5;i<9;i++)
        if (r->events[i].outcome!=M11_GPR_SPF_READY) return 0;
    const struct m11_gpr_event *tx=&r->events[M11_GPR_TX_RETURN], *rx=&r->events[M11_GPR_RX_RETURN];
    const unsigned char *p=tx->packet, *q=rx->packet;
    return r->events[M11_GPR_OPEN].rc>=0 && r->events[M11_GPR_PREFLIGHT].rc==-EAGAIN &&
        tx->rc==24 && tx->size==24 && get32(p)==0x1860 && p[4]==2 && p[5]==3 && !p[6] && !p[7] &&
        get32(p+8)==M11_GPR_SOURCE_PORT && get32(p+12)==1 && get32(p+16)==s->token && get32(p+20)==M11_GPR_GET_SPF &&
        r->events[M11_GPR_TX_BEGIN].size==24 && !memcmp(r->events[M11_GPR_TX_BEGIN].packet,p,24) &&
        rx->rc==28 && rx->size==28 && get32(q)==0x1c60 && q[4]==3 && q[5]==2 && !q[6] && !q[7] &&
        get32(q+8)==1 && get32(q+12)==M11_GPR_SOURCE_PORT && get32(q+16)==s->token &&
        get32(q+20)==M11_GPR_SPF_RESPONSE && get32(q+24)==1;
}
static int accept_event(struct m11_gpr_result *r, const struct m11_gpr_event *e, ssize_t size, int *done) {
    if (*done || size!=(ssize_t)sizeof(*e) || e->reserved || e->size>M11_GPR_MAX ||
        e->stage>M11_GPR_DONE || e->outcome>M11_GPR_CLOSE_FAILED || r->event_count==M11_GPR_EVENTS ||
        e->monotonic_ns<r->start_ns || (r->event_count && e->monotonic_ns<r->events[r->event_count-1].monotonic_ns)) return -1;
    r->events[r->event_count++]=*e;
    if (e->stage==M11_GPR_CLOSE_RETURN) { r->close_returned=1; r->close_ok=e->rc==0; }
    if (e->stage==M11_GPR_DONE) { *done=1; r->ipc_complete=1; r->outcome=(enum m11_gpr_outcome)e->outcome; }
    return 0;
}
/* The parent (PID1) holds the anchor; the worker borrows it for exactly one loan. The parent
 * never performs I/O on it. No blocking waitpid/join. */
int m11_gpr_supervise(struct m11_gpr_session *s, struct m11_gpr_result *r, m11_gpr_child child) {
    int ipc[2], status=0, stop=0, done=0;
    pid_t pid;
    uint64_t n, last;
    if (!r) return -1;
    memset(r,0,sizeof(*r));
    if (!s || !child || s->consumed || s->exclusive_native_owner!=1 || !s->expected_device ||
        !s->token || !s->budget_ms || s->budget_ms>4000 || !s->reap_grace_ms || s->reap_grace_ms>200 ||
        s->service_down_fd==s->cancel_fd || !pipe_or_socket(s->service_down_fd) || !pipe_or_socket(s->cancel_fd) ||
        !nonzero(s->capture_nonce,16) || !nonzero(s->image_sha256,32)) return -1;
    s->consumed=1;
    memcpy(r->capture_nonce,s->capture_nonce,16); memcpy(r->image_sha256,s->image_sha256,32);
    r->token=s->token;
    if (now_ns(&n)) { r->outcome=M11_GPR_IO_ERROR; return -1; }
    r->start_ns=n; r->deadline_ns=n+(uint64_t)s->budget_ms*1000000u; last=n;
    int c=control(s);
    if (c) { r->outcome=invalidated(c); return -1; }
    if (socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,ipc)) {
        r->outcome=M11_GPR_IO_ERROR; return -1;
    }
    /* One loan: the census refuses any other holder before the fork. */
    if (!anchor || m11_anchor_lend_begin(anchor,&borrowed_fd)) {
        close(ipc[0]); close(ipc[1]); r->outcome=M11_GPR_OPEN_FAILED; return -1;
    }
    pid=fork(); /* a separate fd table: never clone(CLONE_FILES) (the seal refuses it) */
    if (pid<0) {
        (void)m11_anchor_lend_abort(anchor);
        close(ipc[0]); close(ipc[1]); r->outcome=M11_GPR_IO_ERROR; return -1;
    }
    if (!pid) { close(ipc[0]); child(ipc[1],s,r->start_ns,r->deadline_ns); _exit(0); }
    int lent=m11_anchor_lend_started(anchor,pid);
    close(ipc[1]);
    while (!stop) {
        c=control(s);
        if (c) { r->outcome=invalidated(c); break; }
        if (now_ns(&n) || n<last) { r->outcome=M11_GPR_IO_ERROR; break; }
        last=n;
        if (n>=r->deadline_ns) { r->outcome=M11_GPR_TIMEOUT; break; }
        struct pollfd p[3]={{ipc[0],POLLIN,0},{s->service_down_fd,POLLIN,0},{s->cancel_fd,POLLIN,0}};
        unsigned int ms=(unsigned int)((r->deadline_ns-n+999999u)/1000000u);
        if (ms>10) ms=10;
        int pr=poll(p,3,(int)ms);
        if (pr<0 && errno!=EINTR) { r->outcome=M11_GPR_IO_ERROR; break; }
        if (control(s)) continue; /* Next iteration invalidates before reading IPC. */
        struct m11_gpr_event e;
        ssize_t got=recv(ipc[0],&e,sizeof(e),MSG_DONTWAIT|MSG_TRUNC);
        if (got>0) {
            if (accept_event(r,&e,got,&done)) {
                r->outcome=M11_GPR_PROTOCOL_ERROR; break;
            }
        } else if (got<0 && errno!=EAGAIN && errno!=EINTR) { r->outcome=M11_GPR_IO_ERROR; break; }
        else if (!got && !done) { r->outcome=M11_GPR_IO_ERROR; break; }
        if (done) {
            pid_t wr=waitpid(pid,&status,WNOHANG);
            if (wr==pid) { r->worker_reaped=1; r->worker_exit_ok=WIFEXITED(status) && WEXITSTATUS(status)==0; stop=1; }
            else if (wr<0) { r->outcome=M11_GPR_IO_ERROR; break; }
            else (void)poll(0,0,1);
        }
    }
    if (!r->worker_reaped) {
        uint64_t until=0;
        if (!now_ns(&n)) until=n+(uint64_t)s->reap_grace_ms*1000000u;
        /* DOWN/cancel first gives the worker half the SAME reap budget to
         * observe its latched notification, explicitly close and return DONE.
         * Preserve invalidation even if queued terminal records say READY. */
        enum m11_gpr_outcome primary=r->outcome;
        uint64_t cooperative=until? n+(uint64_t)s->reap_grace_ms*500000u:0;
        if (primary==M11_GPR_SERVICE_DOWN || primary==M11_GPR_CANCELLED) {
            while (cooperative && !now_ns(&n) && n<cooperative) {
                struct m11_gpr_event e;
                ssize_t got=recv(ipc[0],&e,sizeof(e),MSG_DONTWAIT|MSG_TRUNC);
                if (got>0 && accept_event(r,&e,got,&done)) { r->ipc_complete=0; break; }
                if (got<0 && errno!=EAGAIN && errno!=EINTR) break;
                if (done) {
                    pid_t wr=waitpid(pid,&status,WNOHANG);
                    if (wr==pid) {
                        r->worker_reaped=1;
                        r->worker_exit_ok=WIFEXITED(status) && WEXITSTATUS(status)==0;
                        break;
                    }
                    if (wr<0) break;
                }
                (void)control(s); /* keep PDR serviced; DOWN ACK remains deferred */
                (void)poll(0,0,1);
            }
            r->outcome=primary;
        }
        /* SIGKILL cannot force a D-state syscall to finish. A killed/reaped
         * child does not count as normally completed explicit cleanup. */
        if (!r->worker_reaped) (void)kill(pid,SIGKILL);
        while (!r->worker_reaped) {
            pid_t wr=waitpid(pid,&status,WNOHANG);
            if (wr==pid) { r->worker_reaped=1; break; }
            if (wr<0 || !until || now_ns(&n) || n>=until) break;
            (void)poll(0,0,1);
        }
        if (!r->worker_reaped) r->unresolved_worker=pid;
    }
    /* End the loan. UNRESOLVED keeps it open for the rest of the boot: the worker still holds
     * a reference, so no new loan and no final close. A census refusal after a reaped worker
     * fails the query. */
    m11_worker_end end=!r->worker_reaped ? M11_WORKER_UNRESOLVED :
        r->worker_exit_ok ? M11_WORKER_EXIT_OK : M11_WORKER_EXIT_ABNORMAL;
    int returned=lent ? -1 : m11_anchor_lend_end(anchor,end);
    if (returned && end!=M11_WORKER_UNRESOLVED) r->outcome=M11_GPR_IO_ERROR;
    last_worker_status=r->worker_reaped ? status : -1;
    close(ipc[0]);
    c=control(s);
    if (c) r->outcome=invalidated(c);
    if (now_ns(&n) || n<last) r->outcome=M11_GPR_IO_ERROR;
    else if (n>=r->deadline_ns && r->outcome==M11_GPR_SPF_READY) r->outcome=M11_GPR_TIMEOUT;
    r->query_consistent=r->outcome==M11_GPR_SPF_READY && r->worker_reaped && r->worker_exit_ok &&
        r->close_returned && r->close_ok && r->ipc_complete && complete_ready_transcript(s,r);
    return r->query_consistent?0:-1;
}

struct linux_io { int ipc; const struct m11_gpr_session *session; };
/* "Open" = take the borrowed anchor fd, already validated by m11_anchor_worker_accept().
 * The worker has no open(2) at all (seccomp) and the node path no longer exists. */
static int64_t lx_open(void *v) {
    struct linux_io *l=v;
    struct stat st;
    if (borrowed_fd<0 || fstat(borrowed_fd,&st) || !S_ISCHR(st.st_mode) ||
        st.st_rdev!=l->session->expected_device) return -ENODEV;
    return borrowed_fd;
}
static int64_t lx_write(void *v, int fd, const void *p, size_t n) {
    (void)v; ssize_t r=write(fd,p,n); return r<0?-errno:r;
}
static int64_t lx_read(void *v, int fd, void *p, size_t n) {
    (void)v; ssize_t r=read(fd,p,n); return r<0?-errno:r;
}
static int64_t lx_wait(void *v, int fd, unsigned int ms) {
    struct linux_io *l=v;
    struct pollfd p[3]={{fd,POLLIN,0},{l->session->service_down_fd,POLLIN,0},{l->session->cancel_fd,POLLIN,0}};
    int r=poll(p,3,(int)ms);
    if (r<0) return -errno;
    if (p[0].revents&(POLLERR|POLLHUP|POLLNVAL)) return -ENETRESET;
    return r;
}
/* "Close" = return the borrow. The worker never closes the endpoint fd: exiting returns the
 * loan, and a close would not be a release anyway (PID1 holds anchor and guard). */
static int64_t lx_close(void *v, int fd) { (void)v; return fd==borrowed_fd ? 0 : -EBADF; }
static int lx_now(void *v, uint64_t *n) { (void)v; return now_ns(n); }
static int lx_control(void *v) { return control(((struct linux_io *)v)->session); }
static int lx_record(void *v, const struct m11_gpr_event *e) {
    struct linux_io *l=v;
    if (l->session->observe && l->session->observe(l->session->observe_context,e)) return -1;
    return send(l->ipc,e,sizeof(*e),MSG_DONTWAIT|MSG_NOSIGNAL)==(ssize_t)sizeof(*e)?0:-1;
}
/* The worker keeps stdio, the borrowed fd (and its guard copy under a seal), the IPC socket,
 * the DOWN and cancel pipes and the runner's extra fds; everything else inherited is closed. */
int m11_gpr_worker_hygiene(int ipc, const struct m11_gpr_session *s) {
    int keep[3+4]; unsigned n=0;
    keep[n++]=ipc; keep[n++]=s->service_down_fd; keep[n++]=s->cancel_fd;
    for (unsigned i=0;i<extra_n;i++) keep[n++]=extra_keep[i];
    return m11_anchor_linux_worker_hygiene(borrowed_fd,anchor->guard_fd,keep,n);
}
static void linux_child(int ipc, const struct m11_gpr_session *s, uint64_t start, uint64_t deadline) {
    m11_audio_child_detach(s);
    /* Validate the borrow, keep only what the worker needs, lose root, confine. A failure
     * exits before any endpoint I/O; the parent sees no DONE and fails the query. */
    if (m11_anchor_worker_accept(anchor,borrowed_fd)) _exit(M11_WORKER_EXIT_ACCEPT);
    if (m11_gpr_worker_hygiene(ipc,s)) _exit(M11_WORKER_EXIT_HYGIENE); /* worker fd hygiene */
    if (geteuid()==0 && m11_anchor_linux_drop_privileges()) _exit(M11_WORKER_EXIT_PRIVILEGE);
    if (m11_anchor_linux_confine()) _exit(M11_WORKER_EXIT_CONFINE);
    struct linux_io l={ipc,s};
    struct m11_gpr_io io={&l,lx_open,lx_write,lx_read,lx_wait,lx_close,lx_now,lx_control,lx_record};
    m11_gpr_worker(&io,s->token,start,deadline);
}
int m11_gpr_linux_query(struct m11_gpr_session *s, struct m11_gpr_result *r) {
    if (!r) return -1;
    memset(r,0,sizeof(*r));
    if (!s || m11_audio_admit(s)) return -1;
    int rc=m11_gpr_supervise(s,r,linux_child);
    m11_audio_finish(s,r);
    return rc;
}
