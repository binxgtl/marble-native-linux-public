#define _GNU_SOURCE /* S_IFCHR under -std=c11 */
#include "m11_pid1_anchor.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

static bool same_id(const m11_anchor_id *a, const m11_anchor_id *b) {
    return a->dev==b->dev && a->ino==b->ino && a->rdev==b->rdev && a->type==b->type;
}
static bool owner(const m11_pid1_anchor *a) {
    return a && a->ops.self_pid && a->owner_pid>0 && a->ops.self_pid(a->ops.ctx)==a->owner_pid;
}
static bool holds_any(const m11_pid1_anchor *a) {
    return a->bind_attempted && (a->raw_fd>=0 || a->anchor_fd>=0 || a->guard_fd>=0);
}
/* Latches are permanent; each new one is reported once. */
static uint32_t latch(m11_pid1_anchor *a, uint32_t why) {
    uint32_t fresh=why & ~a->latches;
    a->latches|=why;
    if ((fresh & (M11_ANCHOR_LATCH_WORKER_ABNORMAL|M11_ANCHOR_LATCH_WORKER_UNRESOLVED)) && a->sink.worker_lost)
        a->sink.worker_lost(a->sink.ctx);
    if ((fresh & M11_ANCHOR_LATCH_FOREIGN_HOLDER) && a->sink.foreign_holder)
        a->sink.foreign_holder(a->sink.ctx);
    return fresh;
}
/* The fd number still names the bound OFD's node, with FD_CLOEXEC and the recorded flags.
 * Identity cannot distinguish two OFDs of one node; the census bounds that separately. */
static bool fd_ok(const m11_pid1_anchor *a, int fd) {
    m11_anchor_id id;
    if (fd<0 || a->ops.identify(a->ops.ctx,fd,&id) || !same_id(&id,&a->id)) return false;
    int fdf=a->ops.fd_flags(a->ops.ctx,fd);
    return fdf>=0 && (fdf & FD_CLOEXEC) && a->ops.status_flags(a->ops.ctx,fd)==a->status_flags;
}
/* Allowed holders: PID1 at exactly the anchor and guard numbers, and while a loan is
 * active the one reported worker at those numbers (it inherited both by fork). */
static int census(m11_pid1_anchor *a) {
    m11_anchor_holder h[M11_ANCHOR_MAX_HOLDERS];
    unsigned n=0;
    int rc=a->ops.holders(a->ops.ctx,&a->id,h,M11_ANCHOR_MAX_HOLDERS,&n);
    if (rc || n>M11_ANCHOR_MAX_HOLDERS) { latch(a,M11_ANCHOR_LATCH_CENSUS_ERROR); return rc?rc:-E2BIG; }
    bool anchor_seen=false, guard_seen=false, foreign=false;
    for (unsigned i=0;i<n;i++) {
        bool ours=h[i].fd==a->anchor_fd || h[i].fd==a->guard_fd;
        if (h[i].pid==a->owner_pid && h[i].fd==a->anchor_fd) anchor_seen=true;
        else if (h[i].pid==a->owner_pid && h[i].fd==a->guard_fd) guard_seen=true;
        else if (a->state==M11_ANCHOR_LENT && a->lent_pid>0 && h[i].pid==a->lent_pid && ours) continue;
        else foreign=true; /* includes a second fd or a second OFD of the node in PID1 itself */
    }
    if (foreign) { latch(a,M11_ANCHOR_LATCH_FOREIGN_HOLDER); return -EBUSY; }
    if (!anchor_seen || !guard_seen) { latch(a,M11_ANCHOR_LATCH_CENSUS_ERROR); return -EIO; }
    return 0;
}

int m11_anchor_bind(m11_pid1_anchor *a, const m11_anchor_ops *ops, const m11_anchor_sink *sink,
                    const m11_anchor_contract *ct, int owner_pid, uint64_t expected_rdev) {
    if (!a || !ops || !ct) return -EINVAL;
    if (a->bind_attempted) return -EALREADY; /* one open per boot, even after a failure */
    *a=(m11_pid1_anchor){.ops=*ops, .contract=*ct, .state=M11_ANCHOR_FAILED, .bind_attempted=true,
                         .owner_pid=owner_pid, .raw_fd=-1, .anchor_fd=-1, .guard_fd=-1};
    if (sink) a->sink=*sink;
    if (!ops->self_pid || !ops->open_endpoint || !ops->identify || !ops->dup_min ||
        !ops->fd_flags || !ops->status_flags || !ops->close_fd || !ops->holders) return -EINVAL;
    if (!ct->endpoint_has_no_flush || !ct->release_on_last_fput_only || !ct->owner_single_threaded)
        return -EPERM;
    if (!owner(a)) return -EPERM;
    int fd=a->ops.open_endpoint(a->ops.ctx);
    a->opens++;
    if (fd<0) return fd;
    a->raw_fd=fd;
    /* From here on nothing is closed unless two validated references exist. */
    m11_anchor_id id;
    if (a->ops.identify(a->ops.ctx,fd,&id) || id.type!=S_IFCHR || id.rdev!=expected_rdev) {
        latch(a,M11_ANCHOR_LATCH_FD_DISCIPLINE); return -ENODEV;
    }
    int fl=a->ops.status_flags(a->ops.ctx,fd);
    if (fl<0 || (fl & O_ACCMODE)!=O_RDWR || !(fl & O_NONBLOCK)) return -EINVAL;
    a->id=id; a->status_flags=fl;
    /* Two references to one OFD: no single close(2) in PID1 is a last close. */
    a->anchor_fd=a->ops.dup_min(a->ops.ctx,fd,M11_ANCHOR_RESERVED_FD);
    a->guard_fd=a->anchor_fd<0 ? -1 : a->ops.dup_min(a->ops.ctx,fd,a->anchor_fd+1);
    if (a->anchor_fd<0 || a->guard_fd<0) return -EMFILE;
    int rc=a->ops.close_fd(a->ops.ctx,fd); /* non-final: anchor and guard still hold the OFD */
    a->raw_fd=-1; /* Linux consumes the fd number even when close reports an error */
    if (rc) { latch(a,M11_ANCHOR_LATCH_CLOSE_ERROR); return rc; }
    a->state=M11_ANCHOR_HELD;
    return m11_anchor_check(a);
}
int m11_anchor_check(m11_pid1_anchor *a) {
    if (!owner(a)) return -EPERM;
    if (a->state!=M11_ANCHOR_HELD && a->state!=M11_ANCHOR_LENT) return -EBADFD;
    bool anchor_ok=fd_ok(a,a->anchor_fd), guard_ok=fd_ok(a,a->guard_fd);
    if (!anchor_ok || !guard_ok) {
        /* One lost reference cannot have released the OFD (the other still holds it); two
         * lost references may have, now or at the exit of whoever else still holds it. */
        if ((latch(a,M11_ANCHOR_LATCH_FD_DISCIPLINE) & M11_ANCHOR_LATCH_FD_DISCIPLINE) && a->sink.anchor_lost)
            a->sink.anchor_lost(a->sink.ctx,!anchor_ok && !guard_ok);
        return -EBADF;
    }
    return census(a);
}
int m11_anchor_lend_begin(m11_pid1_anchor *a, int *fd) {
    if (!fd) return -EINVAL;
    *fd=-1;
    if (!owner(a)) return -EPERM;
    if (a->state!=M11_ANCHOR_HELD) return -EBUSY; /* one loan at a time; none after the end */
    if (a->latches & M11_ANCHOR_LATCH_REFUSE) return -EOWNERDEAD;
    int rc=0;
    if ((rc=m11_anchor_check(a))) return rc; /* no other holder may share the loan */
    a->state=M11_ANCHOR_LENT; a->lent_pid=0; a->lends++;
    *fd=a->anchor_fd;
    return rc;
}
int m11_anchor_lend_started(m11_pid1_anchor *a, int pid) {
    if (!owner(a)) return -EPERM;
    if (a->state!=M11_ANCHOR_LENT || a->lent_pid || pid<=1 || pid==a->owner_pid) return -EINVAL;
    a->lent_pid=pid;
    return 0;
}
int m11_anchor_lend_abort(m11_pid1_anchor *a) {
    if (!owner(a)) return -EPERM;
    if (a->state!=M11_ANCHOR_LENT || a->lent_pid) return -EINVAL; /* a forked worker must be ended */
    a->state=M11_ANCHOR_HELD;
    return m11_anchor_check(a);
}
int m11_anchor_lend_end(m11_pid1_anchor *a, m11_worker_end how) {
    if (!owner(a)) return -EPERM;
    if (a->state!=M11_ANCHOR_LENT || a->lent_pid<=0) return -EBADFD;
    if (a->latches & M11_ANCHOR_LATCH_WORKER_UNRESOLVED) return -EBUSY;
    if (how==M11_WORKER_UNRESOLVED) {
        /* The worker still holds a reference: the loan never ends in this boot, so no new
         * loan and no final close (PID1's close would not be the last fput). */
        latch(a,M11_ANCHOR_LATCH_WORKER_UNRESOLVED);
        return -EINPROGRESS;
    }
    if (how!=M11_WORKER_EXIT_OK) latch(a,M11_ANCHOR_LATCH_WORKER_ABNORMAL);
    a->state=M11_ANCHOR_HELD; a->lent_pid=0;
    return m11_anchor_check(a); /* a reaped worker holds nothing; anything else is foreign */
}
int m11_anchor_worker_accept(const m11_pid1_anchor *a, int fd) {
    if (!a || a->state!=M11_ANCHOR_LENT || !a->ops.self_pid) return -EINVAL;
    int self=a->ops.self_pid(a->ops.ctx);
    if (self<=0 || self==a->owner_pid) return -EPERM; /* only the forked worker borrows */
    if (fd!=a->anchor_fd || !fd_ok(a,fd) || !fd_ok(a,a->guard_fd)) return -ENODEV;
    /* Non-final close of the worker's guard copy; PID1 still holds anchor and guard. */
    return a->ops.close_fd(a->ops.ctx,a->guard_fd);
}
int m11_anchor_final_close(m11_pid1_anchor *a) {
    if (!owner(a)) return -EPERM;
    if (a->state!=M11_ANCHOR_HELD) return -EBUSY;
    if (a->latches & M11_ANCHOR_LATCH_REFUSE) return -EOWNERDEAD;
    int rc=0;
    if ((rc=m11_anchor_check(a))) return rc; /* sole holder: the second close is the last fput */
    rc=a->ops.close_fd(a->ops.ctx,a->guard_fd);
    a->guard_fd=-1;
    if (rc) {
        /* Unexplained error: never let the anchor's close become the last one now. */
        latch(a,M11_ANCHOR_LATCH_CLOSE_ERROR); a->state=M11_ANCHOR_RETAINED; return rc;
    }
    a->final_closes++;
    rc=a->ops.close_fd(a->ops.ctx,a->anchor_fd); /* last fput: audio_pkt_release runs here */
    a->anchor_fd=-1; a->state=M11_ANCHOR_RELEASED;
    if (rc) latch(a,M11_ANCHOR_LATCH_CLOSE_ERROR);
    return rc;
}
int m11_anchor_end_boot(m11_pid1_anchor *a, m11_terminal_action t, m11_anchor_end *out) {
    if (!a || !out) return -EINVAL;
    *out=M11_ANCHOR_END_PID1_EXIT;
    if (t==M11_TERMINAL_HOLD || t==M11_TERMINAL_HOLD_RECONCILE) return -EBUSY;
    if (t==M11_TERMINAL_ORDERLY_SHUTDOWN && !holds_any(a) && !(a->latches & M11_ANCHOR_LATCH_CLOSE_ERROR) &&
        (a->state==M11_ANCHOR_RELEASED || a->state==M11_ANCHOR_UNBOUND || a->state==M11_ANCHOR_FAILED)) {
        *out=M11_ANCHOR_END_REBOOT; /* the anchor's last close already ran, or nothing was opened */
        return 0;
    }
    /* Retain: PID1 exits holding the OFD; global init panics before exit_files(). */
    bool consistent=t!=M11_TERMINAL_ORDERLY_SHUTDOWN;
    if (a->state!=M11_ANCHOR_RELEASED) a->state=M11_ANCHOR_RETAINED;
    return consistent ? 0 : -EPROTO; /* ledger said orderly while PID1 still holds a reference */
}
const char *m11_anchor_state_name(m11_anchor_state s) {
    switch (s) {
    case M11_ANCHOR_UNBOUND: return "UNBOUND";
    case M11_ANCHOR_HELD: return "HELD";
    case M11_ANCHOR_LENT: return "LENT";
    case M11_ANCHOR_RELEASED: return "RELEASED";
    case M11_ANCHOR_RETAINED: return "RETAINED";
    case M11_ANCHOR_FAILED: return "FAILED";
    }
    return "?";
}
