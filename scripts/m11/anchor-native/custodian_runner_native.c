/* The composed native custodian runner core — see custodian_runner_native.h. */
#define _GNU_SOURCE
#include "custodian_runner_native.h"
#include "heap_node_native.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FAIL(n, rc) do { if (step) *step = (n); return (rc); } while (0)
#define MAX_PROCS 4096

static int crunner_started_once; /* one runner start per process (the pool and its seal are one-shot) */

static int is_open(int fd) { return fd >= 0 && fcntl(fd, F_GETFD) != -1; }

/* ---- the tree-wide part of the census: no descendant of this process holds a pool buffer or the
 * heap device. An unreadable or exiting descendant is inconclusive and fails the census. ---- */
static const char *proc_root(const m11_crunner *r) { return r->cfg.proc_root ? r->cfg.proc_root : "/proc"; }
/* 0 with *ppid; 1 when the process is gone (its /proc directory no longer exists); -1 when it exists
 * but its stat cannot be read or parsed (inconclusive: the census fails closed). */
static int read_ppid(const m11_crunner *r, pid_t pid, pid_t *ppid) {
    char path[300], dir[300], b[512];
    snprintf(dir, sizeof dir, "%s/%ld", proc_root(r), (long)pid);
    snprintf(path, sizeof path, "%s/stat", dir);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t n = -1;
    if (fd >= 0) { n = read(fd, b, sizeof b - 1); close(fd); }
    if (n <= 0) {
        struct stat st;
        if (stat(dir, &st) && errno == ENOENT) return 1; /* gone between readdir and read */
        return -1;                                       /* exists, unreadable */
    }
    b[n] = 0;
    char *rp = strrchr(b, ')'); /* comm may contain spaces and parentheses */
    char state; long pp;
    if (!rp || sscanf(rp + 1, " %c %ld", &state, &pp) != 2) return -1;
    *ppid = (pid_t)pp;
    return 0;
}
static int holds_forbidden(const m11_crunner *r, pid_t pid) {
    char path[300], item[300 + 256 + 8];
    snprintf(path, sizeof path, "%s/%ld/fd", proc_root(r), (long)pid);
    DIR *d = opendir(path);
    if (!d) return -1;
    int bad = 0;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(d);
        if (!e) { if (errno) bad = -1; break; }
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        snprintf(item, sizeof item, "%s/%s", path, e->d_name);
        struct stat st;
        if (stat(item, &st)) { bad = -1; break; }
        if (S_ISCHR(st.st_mode) && st.st_rdev == r->cfg.heap_rdev) { bad = 1; break; }
        if (st.st_dev == r->pool.dev)
            for (unsigned i = 0; i < r->pool.count; i++) if (st.st_ino == r->pool.ino[i]) { bad = 1; break; }
        if (bad) break;
    }
    closedir(d);
    return bad;
}
static int tree_census(const m11_crunner *r) {
    static pid_t pids[MAX_PROCS], ppids[MAX_PROCS];
    static unsigned char desc[MAX_PROCS];
    unsigned n = 0;
    DIR *d = opendir(proc_root(r));
    if (!d) return -1;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(d);
        if (!e) { if (errno) { closedir(d); return -1; } break; }
        char *end; long v = strtol(e->d_name, &end, 10);
        if (e->d_name[0] < '0' || e->d_name[0] > '9' || *end || v <= 0) continue;
        if (n == MAX_PROCS) { closedir(d); return -1; }
        pid_t pp = 0;
        int rc = read_ppid(r, (pid_t)v, &pp);
        if (rc == 1) continue;                    /* gone: not in the tree any more */
        if (rc) { closedir(d); return -1; }       /* exists but unreadable: its ancestry is unknown */
        pids[n] = (pid_t)v; ppids[n] = pp; desc[n] = 0; n++;
    }
    closedir(d);
    const pid_t self = getpid();
    for (int changed = 1; changed;) { /* mark descendants of self */
        changed = 0;
        for (unsigned i = 0; i < n; i++) {
            if (desc[i] || pids[i] == self) continue;
            int parent = ppids[i] == self;
            for (unsigned j = 0; !parent && j < n; j++) if (desc[j] && pids[j] == ppids[i]) parent = 1;
            if (parent) { desc[i] = 1; changed = 1; }
        }
    }
    for (unsigned i = 0; i < n; i++)
        if (desc[i] && holds_forbidden(r, pids[i]) != 0) return -1;
    return 0;
}

/* A failed census proves an ownership violation (a foreign or unknowable holder), not that a global
 * cleanup ran: the custodian's ledger is NOT tainted with one. The runner latches it, refuses every
 * later MAP, UNMAP and close, and forces the retaining end itself (m11_crunner_end). */
static void census_failed(m11_crunner *r) {
    r->census_failed = 1;
}

int m11_crunner_census(m11_crunner *r) {
    if (!r || r->stage < 5) return -1;
    unsigned why = 0;
    if (r->cfg.endpoint->state != M11_ANCHOR_HELD || m11_anchor_check(r->cfg.endpoint) != 0) why |= M11_CRUNNER_CENSUS_ENDPOINT;
    if (r->cfg.ion->state != M11_ANCHOR_HELD || m11_anchor_check(r->cfg.ion) != 0) why |= M11_CRUNNER_CENSUS_ION;
    if (m11_heap_census_pid(getpid(), r->cfg.heap_rdev, -1) != 0) why |= M11_CRUNNER_CENSUS_HEAP;
    if (m11_dmabuf_census_pid(&r->pool, getpid(), 1) != 0) why |= M11_CRUNNER_CENSUS_POOL;
    if (tree_census(r) != 0) why |= M11_CRUNNER_CENSUS_TREE;
    r->census_why |= why; /* every reason seen in this boot */
    if (why) census_failed(r);
    return why ? -1 : 0;
}

int m11_crunner_start(m11_crunner *r, const m11_crunner_config *cfg, uint64_t now_ms, int *step) {
    if (step) *step = 0;
    if (!r || !cfg || !cfg->endpoint || !cfg->ion || cfg->heap_fd < 0 || !cfg->pd || !cfg->journal ||
        !cfg->cmdline || !cfg->boot_epoch || !cfg->timeout_ms || !cfg->recovery_budget_ms ||
        !cfg->endpoint->ops.close_pair || !cfg->ion->ops.close_pair) return -EINVAL; /* sealed pairs only */
    if (crunner_started_once) return -EALREADY; /* never wipe a runner that may own a sealed pool */
    crunner_started_once = 1;
    memset(r, 0, sizeof *r);
    r->cfg = *cfg;
    const m11_shmem_native_sys *sys = cfg->sys ? cfg->sys : &m11_shmem_native_libc;

    /* 1. the effective cmdline gate */
    m11_custodian_model_contract ct = {.exclusive_importer = true, .no_other_endpoint = true,
        .no_pcm_clients = true, .strict_iommu = m11_custodian_cmdline_allowed(cfg->cmdline),
        .graph_quiescent = true, .nack_atomicity_model = true, .final_anchor_pid1 = true};
    if (!ct.strict_iommu) FAIL(1, -EPERM);
    r->stage = 1;
    /* 2. the PD must be UP */
    if (cfg->pd->pump_fn(cfg->pd->user, now_ms) != 1) FAIL(2, -ENETRESET);
    r->stage = 2;
    /* 3. pool from the heap, heap closed, pool sealed over the owner pairs */
    int rc = m11_dmabuf_pool_build(&r->pool, cfg->heap_fd, cfg->pool_count, cfg->pool_len, cfg->pool_base, cfg->sys);
    if (rc) FAIL(3, rc);
    int crc = sys->close_fn(cfg->heap_fd);
    r->cfg.heap_fd = -1; /* Linux releases the descriptor even when close(2) reports an error */
    if (crc) FAIL(3, -EIO); /* nothing allocates after the pool */
    const int base[2] = {cfg->endpoint->anchor_fd, cfg->ion->anchor_fd};
    if ((rc = m11_dmabuf_pool_seal(&r->pool, base, 2))) FAIL(3, rc);
    r->stage = 3;
    /* 4. ledger, transport (anchor + PD monitor) wrapped by the journal, engine */
    if ((rc = m11_model_new_boot(&r->boot, cfg->boot_epoch, now_ms))) FAIL(4, rc);
    if ((rc = m11_gpr_native_transport_pd(&r->link, cfg->endpoint, cfg->pd, &r->inner))) FAIL(4, rc);
    if ((rc = m11_intent_transport(&r->journal, &r->inner, cfg->journal, &r->boot, &r->transport))) FAIL(4, rc);
    if ((rc = m11_gpr_engine_init(&r->eng, &r->transport, cfg->src_port ? cfg->src_port : 0x0100u)) ||
        (rc = m11_gpr_engine_open(&r->eng))) FAIL(4, rc);
    r->stage = 4;
    /* 5. pooled backend over the ION anchor, manager, custodian, PDR loop */
    if ((rc = m11_shmem_native_backend_pool(&r->shm, cfg->ion, &r->pool, cfg->sys, &r->backend))) FAIL(5, rc);
    if ((rc = m11_shmem_mgr_init(&r->mgr, &r->backend, &r->eng, cfg->timeout_ms))) FAIL(5, rc);
    if ((rc = m11_custodian_init(&r->cust, &r->boot, &r->mgr, &ct, cfg->recovery_budget_ms))) FAIL(5, rc);
    if ((rc = m11_pdr_loop_init(&r->loop, &r->cust, &r->link))) FAIL(5, rc);
    r->term = (m11_terminal_native){.c = &r->cust, .anchors = {cfg->endpoint, cfg->ion}, .nanchors = 2,
                                    .pool = &r->pool, .sink = cfg->journal, .ops = cfg->terminal_ops};
    r->stage = 5;
    r->started = 1; /* the custodian is enrolled: from here the G8 terminal ends the boot */
    /* 6. the composed census */
    if (m11_crunner_census(r)) FAIL(6, -EOWNERDEAD);
    r->stage = 6;
    return 0;
}

/* Every custodian call: census before (latched refusal), the call, PDR settle, census after. */
int m11_crunner_map(m11_crunner *r, size_t bytes, uint64_t now_ms, unsigned *slot) {
    if (!r || !r->started || !slot) return -EINVAL;
    *slot = (unsigned)-1;
    if (r->census_failed || m11_crunner_census(r)) return -EOWNERDEAD; /* census before MAP */
    int rc = m11_custodian_map(&r->cust, bytes, now_ms, slot);
    (void)m11_pdr_loop_settle(&r->loop, now_ms); /* settle after MAP */
    if (m11_crunner_census(r) && !rc) rc = -EOWNERDEAD;
    return rc;
}
int m11_crunner_retire(m11_crunner *r, unsigned slot, uint64_t now_ms) {
    if (!r || !r->started) return -EINVAL;
    if (r->census_failed || m11_crunner_census(r)) return -EOWNERDEAD; /* census before UNMAP */
    int rc = m11_custodian_retire(&r->cust, slot, now_ms);
    (void)m11_pdr_loop_settle(&r->loop, now_ms); /* settle after UNMAP */
    if (m11_crunner_census(r) && !rc) rc = -EOWNERDEAD;
    return rc;
}
int m11_crunner_idle(m11_crunner *r, uint32_t budget_ms, uint64_t now_ms) {
    if (!r || !r->started) return -EINVAL;
    int rc = m11_pdr_loop_idle(&r->loop, budget_ms, now_ms);
    if (m11_crunner_census(r) && !rc) rc = -EOWNERDEAD; /* census after idle */
    return rc;
}
/* Close makes a clean boot eligible for the orderly end: never with a foreign holder. */
int m11_crunner_close(m11_crunner *r) {
    if (!r || !r->started) return -EINVAL;
    if (r->census_failed || m11_crunner_census(r)) return -EOWNERDEAD; /* census before close */
    int rc = m11_custodian_close(&r->cust);
    (void)m11_pdr_loop_settle(&r->loop, r->boot.last_ms);
    if (m11_crunner_census(r) && !rc) rc = -EOWNERDEAD;
    return rc;
}
m11_terminal_action m11_crunner_action(m11_crunner *r, uint64_t now_ms) {
    if (!r || !r->started) return M11_TERMINAL_RESET_RETAINING_ANCHORS;
    return m11_pdr_loop_settle(&r->loop, now_ms);
}

/* The end of a start that never enrolled the custodian: no G8 decision exists, so the only end is
 * the retaining one (nothing was ever mapped, but nothing is closed either). */
static int end_partial(m11_crunner *r) {
    unsigned open_fds = (unsigned)is_open(r->cfg.endpoint->anchor_fd) + (unsigned)is_open(r->cfg.endpoint->guard_fd) +
                        (unsigned)is_open(r->cfg.ion->anchor_fd) + (unsigned)is_open(r->cfg.ion->guard_fd);
    int pool_held = r->pool.count && m11_dmabuf_census_pid(&r->pool, getpid(), 1) == 0;
    char rec[M11_INTENT_RECORD_MAX + 64];
    int n = snprintf(rec, sizeof rec,
                     "<6>M11TERMINAL v=2 boot=%llu action=START_FAILED end=pid1_exit step=%d anchor_fds_open=%u/4 "
                     "pool=%s heap_open=%d note=start_failed\n",
                     (unsigned long long)r->cfg.boot_epoch, r->stage + 1, open_fds,
                     !r->pool.count ? "none" : pool_held ? "held" : "NOT_HELD", is_open(r->cfg.heap_fd));
    if (n > 0 && (size_t)n < sizeof rec && r->cfg.journal) (void)r->cfg.journal->append_fn(r->cfg.journal->user, rec, (size_t)n);
    r->cfg.terminal_ops.exit_fn(r->cfg.terminal_ops.user);
    return -EFAULT;
}

int m11_crunner_end(m11_crunner *r, uint64_t now_ms) {
    if (!r || !r->cfg.endpoint || !r->cfg.ion || !r->cfg.terminal_ops.exit_fn) return -EINVAL;
    if (!r->started) return end_partial(r);
    (void)m11_crunner_census(r); /* a foreign holder now still turns the end into the retaining one */
    (void)m11_pdr_loop_settle(&r->loop, now_ms);
    if (r->census_failed) { /* ownership violation: forced conservative end, custodian ledger untouched */
        snprintf(r->force_note, sizeof r->force_note, "foreign_holder_why=%u", r->census_why);
        r->term.force_retain_note = r->force_note;
    }
    return m11_terminal_native_end(&r->term, now_ms);
}
